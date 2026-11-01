//! The sidecar's VM: launched through NVX's supervisor with the runtime adapter's guest agent, and
//! served by one thread that owns everything the launch holds (the locked store, the starting
//! handle, the control session), because the starting handle borrows the locked store.
//!
//! The thread carries the execution messages between the host and the guest and reports the
//! executions' output and end through an [`Events`] callback. Commands reach it through a channel.
//!
//! Scaffold limits (see README): one VM, no limits/isolation/mounts, and the adapter's
//! `HostExecution` keeps the output it forwarded until the execution ends (at most 16 MiB per
//! execution), so a streaming sink of our own is still to be written.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nvx::Hypervisor;
use nvx::exec::peer::{Event as PeerEvent, Peer};
use nvx::exec::{Cause, Key, Limits, Outcome, Status, Stream, Timers, Window};
use nvx::host::instance::generate_capability;
use nvx::host::launch::LaunchSpec;
use nvx::host::nvxs::HostConnectionError;
use nvx::host::session;
use nvx::host::store::{LaunchId, SandboxStore};
use nvx::host::supervisor::{self, VmmCommand};
use nvx::protocol::root::ImageFormat;
use runtime_adapter::exec::{GuestMessage, HostMessage, Start};
use runtime_adapter::frame::Message;
use runtime_adapter::host::{self as adapter_host, Client, ClientError};
use runtime_adapter::initramfs;
use runtime_adapter::layered::{LaunchRecord, LayeredLaunch};
use runtime_adapter::runtime::Runtime;
use runtime_adapter::staged::Staged;

const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const START_TIMEOUT: Duration = Duration::from_secs(60);
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const EXEC_CHUNK: u32 = 16 * 1024;
const EXEC_INPUT_FRAMES: u32 = 4;
const EXEC_OUTPUT_FRAMES: u32 = 8;
const EXEC_GRACE: Duration = Duration::from_secs(1);
const EXEC_SETTLEMENT: Duration = Duration::from_secs(5);
/// How long the serving thread waits for a guest message before it looks at its commands again.
const INITRAMFS_NAME: &str = "runtime-adapter.cpio.gz";
const WAKE: Duration = Duration::from_millis(20);

/// Everything a VM is launched with.
#[derive(Clone, Debug)]
pub struct VmConfig {
    /// NVX's artifacts: a release directory or a repository checkout.
    pub artifacts: PathBuf,
    /// The guest agent (static musl executable).
    pub guest_agent: PathBuf,
    /// The EROFS image of the root.
    pub distro: PathBuf,
    pub hypervisor: Hypervisor,
    /// The directory of the sandbox's store; created if needed.
    pub store: PathBuf,
    pub memory_mib: u32,
    /// Passed to OpenVMM as `--cpu-profile`.
    pub cpu_profile: String,
    pub guest_build: String,
}

/// A request for the serving thread.
pub enum Command {
    Exec {
        id: String,
        arguments: Vec<Vec<u8>>,
        working_directory: Option<Vec<u8>>,
        environment: Vec<Vec<u8>>,
        timeout: Option<Duration>,
        reply: Sender<Result<(), String>>,
    },
    /// Ends the VM.
    Stop,
}

/// What the serving thread reports about an execution.
pub enum Event {
    Output { id: String, stderr: bool, bytes: Vec<u8> },
    Exit { id: String, outcome: ExitOutcome },
}

/// How an execution ended, in the vocabulary of the sidecar's `exec.exit` event.
pub struct ExitOutcome {
    /// `exited`, `signaled`, `cancelled`, `timeout` or `lost`.
    pub kind: &'static str,
    pub code: Option<i64>,
    pub truncated: bool,
    /// Why the program did not start, if it did not.
    pub launch_failure: Option<String>,
}

/// A running VM: the channel to its serving thread and the thread.
pub struct Vm {
    commands: Sender<Command>,
    thread: Option<JoinHandle<()>>,
}

impl Vm {
    /// Launches the VM and waits until its guest is ready for executions. `events` is called, on
    /// the serving thread, for every event of every execution.
    pub fn launch(
        config: VmConfig,
        events: impl Fn(Event) -> bool + Send + 'static,
    ) -> Result<Vm, (String, String)> {
        let (commands, receiver) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("nvxd-vm".to_owned())
            .spawn(move || serve(config, receiver, ready_tx, events))
            .map_err(|error| ("E_BACKEND_START".to_owned(), error.to_string()))?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Vm {
                commands,
                thread: Some(thread),
            }),
            Ok(Err(failure)) => {
                let _ = thread.join();
                Err(failure)
            }
            Err(_) => Err((
                "E_BACKEND_START".to_owned(),
                "the VM thread ended before it reported".to_owned(),
            )),
        }
    }

    /// Starts an execution; returns once the guest has been sent the start.
    pub fn exec(
        &self,
        id: String,
        arguments: Vec<Vec<u8>>,
        working_directory: Option<Vec<u8>>,
        environment: Vec<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> Result<(), String> {
        let (reply, answer) = mpsc::channel();
        self.commands
            .send(Command::Exec {
                id,
                arguments,
                working_directory,
                environment,
                timeout,
                reply,
            })
            .map_err(|_| "the VM is gone".to_owned())?;
        answer
            .recv_timeout(SESSION_TIMEOUT)
            .map_err(|_| "the VM did not answer".to_owned())?
    }

    /// Ends the VM and waits for its thread.
    pub fn stop(&mut self) {
        let _ = self.commands.send(Command::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        self.stop();
    }
}

fn failure(code: &str, message: impl std::fmt::Display) -> (String, String) {
    (code.to_owned(), message.to_string())
}

/// Classifies a launch failure the way the sidecar's protocol names them.
fn classify(error: &nvx::Error) -> (String, String) {
    let message = error.to_string();
    let code = crate::protocol::classify_start_failure(Some(error.kind()), &message);
    (code.to_owned(), message)
}

fn serve(
    config: VmConfig,
    commands: Receiver<Command>,
    ready: Sender<Result<(), (String, String)>>,
    events: impl Fn(Event) -> bool,
) {
    // The launch holds the locked store and borrows it for the VM's whole life; dropping the
    // starting handle without committing ends the VM.
    let outcome = launch_and_serve(&config, &commands, &ready, &events);
    if let Err(problem) = outcome {
        let _ = ready.send(Err(problem));
    }
}

fn launch_and_serve(
    config: &VmConfig,
    commands: &Receiver<Command>,
    ready: &Sender<Result<(), (String, String)>>,
    events: &impl Fn(Event) -> bool,
) -> Result<(), (String, String)> {
    let runtime = Runtime::from_dir(&config.artifacts, &config.guest_build).map_err(|e| classify(&e))?;
    runtime.artifacts.probe().map_err(|e| classify(&e))?;
    let identity = erofs_uuid(&config.distro)?;
    let staged = Staged::stage(&config.distro, ImageFormat::Erofs, identity, None).map_err(|e| classify(&e))?;
    let mut layered = LayeredLaunch::new(&config.distro, ImageFormat::Erofs, identity, None, None)
        .map_err(|e| classify(&e))?;
    // The identity of every execution is the sandbox's: the start names none.
    layered.config.workload_identity = Some(nvx::host::sandbox::DEFAULT_WORKLOAD_IDENTITY);
    layered.check_command_line().map_err(|e| classify(&e))?;
    if let Some(parent) = config.store.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| failure("E_BACKEND_START", format!("cannot create {}: {e}", parent.display())))?;
    }
    let store = SandboxStore::create(&config.store).map_err(|e| classify(&e))?;
    let mut locked = store
        .lock(Some(Instant::now() + LOCK_TIMEOUT))
        .map_err(|e| classify(&e))?;
    staged.write(store.dir()).map_err(|e| classify(&e))?;
    if let Some(staged) = Staged::read(store.dir()).map_err(|e| classify(&e))? {
        layered.bindings = staged.bindings(&layered.plan);
    }
    let mut prepared = Some(layered.prepare().map_err(|e| classify(&e))?);
    let capability = generate_capability().map_err(|e| classify(&e))?;
    let initramfs_path = store.dir().join(INITRAMFS_NAME);
    let mut spec = LaunchSpec::new(runtime.artifacts.clone(), config.hypervisor);
    spec.memory_mib = config.memory_mib;
    spec.openvmm = runtime.artifacts.openvmm.clone();
    spec.initrd = initramfs_path.clone();
    let launch_id = LaunchId::generate().map_err(|e| classify(&e))?;
    let deadline = Instant::now() + START_TIMEOUT;
    let command = |endpoint: &str| -> nvx::Result<VmmCommand<'_>> {
        initramfs::write(&runtime.artifacts.initrd, &config.guest_agent, None, &initramfs_path).map_err(
            |error| nvx::Error::io("cannot write the initramfs of the guest agent").with_source(error),
        )?;
        let outcome = store.outcome_path();
        let held = prepared.as_ref().expect("the checked files are held until the root is assembled");
        let mut arguments = layered.openvmm_arguments(held, &spec.vmm_launch(endpoint, &outcome))?;
        arguments.push("--cpu-profile".into());
        arguments.push(config.cpu_profile.clone().into());
        let record = LaunchRecord {
            kernel_command_line: held.kernel_command_line(),
            layered: Some(&layered),
        };
        record.write(store.dir())?;
        let mut command = VmmCommand::new(&spec.openvmm, arguments, store.dir());
        command.inherit = held.inherited();
        Ok(command)
    };
    let starting = supervisor::launch(&mut locked, &launch_id, &runtime.identity, &capability, command)
        .map_err(|e| classify(&e))?;
    let process = starting.process().reference().clone();
    let transport = session::connect(starting.endpoint(), process.pid, process.start_time, deadline)
        .map_err(|e| failure("E_BACKEND_START_CONTROL", format!("cannot connect to the VM: {e}")))?;
    let mut client = Client::attach(transport, &capability, deadline)
        .map_err(|e| failure("E_BACKEND_START_CONTROL", format!("cannot attach to the VM: {e}")))?;
    adapter_host::ready(&mut client, &layered.config, &config.guest_build, deadline)
        .map_err(|e| failure("E_BACKEND_START_CONTROL", format!("the guest did not assemble the root: {e}")))?;
    if let Some(prepared) = prepared.take() {
        prepared
            .release(starting.process())
            .map_err(|e| failure("E_BACKEND_START", format!("cannot release the checked files: {e}")))?;
    }
    let table = layered.table();
    adapter_host::start_sandbox(&mut client, &table, deadline)
        .map_err(|e| failure("E_BACKEND_START_CONTROL", format!("the guest did not start the sandbox: {e}")))?;
    let _ = ready.send(Ok(()));
    pump(&mut client, commands, events);
    // The starting handle drops here, uncommitted, which ends the VM.
    drop(client);
    drop(starting);
    Ok(())
}

/// Reads the filesystem UUID of an EROFS image from its superblock (offset 1024 + 48).
fn erofs_uuid(path: &std::path::Path) -> Result<nvx::uuid::Uuid, (String, String)> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).map_err(|e| failure("E_BACKEND_START_ASSET", format!("cannot read {}: {e}", path.display())))?;
    file.seek(SeekFrom::Start(1024 + 48))
        .and_then(|_| {
            let mut bytes = [0u8; 16];
            file.read_exact(&mut bytes).map(|()| bytes)
        })
        .map(nvx::uuid::Uuid::from_bytes)
        .map_err(|e| failure("E_BACKEND_START_ASSET", format!("cannot read the UUID of {}: {e}", path.display())))
}

/// The host's side of one execution: NVX's peer, a streaming sink that hands output to the
/// caller as it arrives (and withholds the peer's credit while the caller cannot take it, which
/// is the backpressure), and the peer's events.
struct Running {
    name: String,
    key: Key,
    peer: Peer,
    finished: Option<Outcome>,
    chunk: usize,
}

impl Running {
    fn new(name: String, start: &Start, timers: Timers, now: Instant) -> Self {
        Self {
            name,
            key: start.key,
            peer: Peer::new(start.key, start.limits, timers, now),
            finished: None,
            chunk: start.limits.chunk(),
        }
    }

    /// Takes every step the sink and the peer can take at `now`; returns the peer's messages for
    /// the guest.
    fn serve(&mut self, now: Instant, events: &impl Fn(Event) -> bool) -> Vec<Message> {
        for stream in Stream::ALL {
            loop {
                let pending = self.peer.pending_output(stream);
                if pending.is_empty() {
                    break;
                }
                let length = pending.len();
                let taken = events(Event::Output {
                    id: self.name.clone(),
                    stderr: matches!(stream, Stream::Stderr),
                    bytes: pending.to_vec(),
                });
                if !taken {
                    // The caller is not reading: leave the bytes in the peer, which grants the
                    // guest no credit for them, and try again next round.
                    break;
                }
                self.peer.consumed(stream, length);
            }
        }
        self.peer.tick(now);
        let mut buffer = vec![0; self.chunk];
        let mut messages = Vec::new();
        while let Some(message) = self.peer.next_message(&mut buffer) {
            if let Some(message) = HostMessage::from_peer(self.key, message, &buffer) {
                messages.push(message.encode());
            }
        }
        while let Some(event) = self.peer.next_event() {
            if let PeerEvent::Finished(outcome) = event {
                self.finished = Some(outcome);
            }
        }
        messages
    }
}

fn limits() -> Limits {
    Limits::new(EXEC_CHUNK, Window::frames(EXEC_INPUT_FRAMES), Window::frames(EXEC_OUTPUT_FRAMES))
        .expect("limits with no empty window")
        .shared_output()
}

fn pump(client: &mut Client, commands: &Receiver<Command>, events: &impl Fn(Event) -> bool) {
    let identity = client.identity();
    let (base, _) = identity.instance_id.split_at(8);
    let base = u64::from_le_bytes(base.try_into().expect("an instance ID has 16 bytes"));
    let mut next = 1u64;
    let mut running: BTreeMap<u64, Running> = BTreeMap::new();
    loop {
        // New commands first.
        loop {
            match commands.try_recv() {
                Ok(Command::Stop) | Err(mpsc::TryRecvError::Disconnected) => return,
                Ok(Command::Exec { id, arguments, working_directory, environment, timeout, reply }) => {
                    let key = Key::new(base.wrapping_add(next), identity.epoch);
                    next += 1;
                    let mut timers = Timers::new(EXEC_GRACE, EXEC_SETTLEMENT);
                    if let Some(timeout) = timeout {
                        timers = timers.timeout(timeout);
                    }
                    let mut start = Start::new(key, limits(), timers, arguments);
                    if let Some(directory) = working_directory {
                        start = start.with_working_directory(directory);
                    }
                    if !environment.is_empty() {
                        start = start.with_environment(environment);
                    }
                    let answer = Start::decode(&start.encode())
                        .map_err(|e| e.problem().to_owned())
                        .and_then(|_| {
                            client
                                .send(&Message::ExecStart(start.encode()), Some(Instant::now() + SESSION_TIMEOUT))
                                .map_err(|e| e.to_string())
                        });
                    if answer.is_ok() {
                        running.insert(key.id(), Running::new(id, &start, timers, Instant::now()));
                    }
                    let _ = reply.send(answer);
                }
                Err(mpsc::TryRecvError::Empty) => break,
            }
        }
        // What each peer has to say to the guest.
        let now = Instant::now();
        let send_deadline = now + SESSION_TIMEOUT;
        for entry in running.values_mut() {
            for message in entry.serve(now, events) {
                if client.send(&message, Some(send_deadline)).is_err() {
                    lose_all(&mut running, events);
                    return;
                }
            }
        }
        report(&mut running, events);
        let wake = running
            .values()
            .filter_map(|entry| entry.peer.deadline())
            .fold(now + WAKE, Instant::min);
        match client.receive(Some(wake)) {
            Ok(message) => {
                if let Some(Ok(decoded)) = GuestMessage::decode(&message) {
                    if let Some(entry) = running.get_mut(&decoded.key().id()) {
                        let _ = decoded.deliver(&mut entry.peer, Instant::now());
                    }
                }
            }
            Err(ClientError::Session(HostConnectionError::TimedOut)) => {}
            Err(_) => {
                lose_all(&mut running, events);
                return;
            }
        }
    }
}

/// Reports the end of finished executions.
fn report(running: &mut BTreeMap<u64, Running>, events: &impl Fn(Event) -> bool) {
    let done: Vec<u64> = running
        .iter()
        .filter(|(_, entry)| entry.finished.is_some())
        .map(|(id, _)| *id)
        .collect();
    for id in done {
        if let Some(entry) = running.remove(&id) {
            if let Some(outcome) = entry.finished {
                events(Event::Exit { id: entry.name, outcome: describe(&outcome) });
            }
        }
    }
}

fn describe(outcome: &Outcome) -> ExitOutcome {
    let truncated = Stream::ALL.into_iter().any(|stream| outcome.is_truncated(stream));
    let launch_failure = outcome
        .launch_failure()
        .map(|failure| format!("{} {}", failure.stage(), failure.error()));
    let (kind, code) = match (outcome.status(), outcome.cause()) {
        (_, Some(Cause::TimedOut)) => ("timeout", None),
        (_, Some(Cause::Cancelled)) => ("cancelled", None),
        (Some(Status::Exited(code)), _) => ("exited", Some(i64::from(code))),
        (Some(Status::Signaled(signal)), _) => ("signaled", Some(i64::from(signal))),
        _ => ("lost", None),
    };
    ExitOutcome { kind, code, truncated, launch_failure }
}

fn lose_all(running: &mut BTreeMap<u64, Running>, events: &impl Fn(Event) -> bool) {
    for (_, entry) in std::mem::take(running) {
        let _ = events(Event::Exit {
            id: entry.name,
            outcome: ExitOutcome { kind: "lost", code: None, truncated: false, launch_failure: None },
        });
    }
}

#[allow(dead_code)]
fn _unused(_: RecvTimeoutError) {}
