//! Request handlers. Each request runs on its own thread so that a `signal` can overtake a
//! running `exec`.

use std::collections::HashMap;
use std::io::{Read, Stdout};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aci_edge_sandboxes::nvx::host::filesystem::resolve_guest_path;
use aci_edge_sandboxes::nvx::host::poc_live::LiveShare;
use aci_edge_sandboxes::openvmm::OpenVmmBackend;
use aci_edge_sandboxes::{
    AciEdgeSandbox, Canceller, ExecOutcome, ExecRequest, ProvisionRequest, SandboxId,
};
use serde_json::{Value, json};

use crate::frame::FrameWriter;
use crate::plan::{self, Mount, Share, Step};
use crate::protocol;
use crate::winmem::VmmMemory;

const SHARE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Failure {
    pub code: &'static str,
    pub message: String,
}

fn fail(code: &'static str, message: impl ToString) -> Failure {
    Failure {
        code,
        message: message.to_string(),
    }
}

struct SessionState {
    shares: Vec<Share>,
    /// Successful live adds so far; the guest numbers runtime mappings with it.
    next_sequence: usize,
    /// Never reused, so an export name is unique for the life of the VM.
    next_child: u64,
    busy: bool,
    /// When the session last started or finished a command.
    last_activity: Instant,
    /// The working set was trimmed since the last activity.
    trimmed: bool,
    /// Idle trims so far.
    trims: u64,
}

struct Session {
    sandbox: SandboxId,
    request_dir: PathBuf,
    memory: Option<VmmMemory>,
    state: Mutex<SessionState>,
}

pub type Writer = Arc<FrameWriter<Stdout>>;

pub struct Context {
    backend: Arc<OpenVmmBackend>,
    client: AciEdgeSandbox,
    request_root: PathBuf,
    writer: Writer,
    /// The VMM inherits `NVX_POC_LIVE_SHARE_DIR` when it starts, so starts are serialized.
    start_lock: Mutex<()>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    handles: Mutex<HashMap<String, Canceller>>,
    counter: Mutex<u64>,
}

impl Context {
    pub fn new(
        backend: Arc<OpenVmmBackend>,
        client: AciEdgeSandbox,
        request_root: PathBuf,
        writer: Writer,
    ) -> Self {
        Self {
            backend,
            client,
            request_root,
            writer,
            start_lock: Mutex::new(()),
            sessions: Mutex::new(HashMap::new()),
            handles: Mutex::new(HashMap::new()),
            counter: Mutex::new(0),
        }
    }

    fn next_id(&self) -> u64 {
        let mut counter = self.counter.lock().unwrap();
        *counter += 1;
        *counter
    }

    fn session(&self, name: &str) -> Result<Arc<Session>, Failure> {
        let known = self.sessions.lock().unwrap().get(name).cloned();
        known.ok_or_else(|| {
            fail(
                protocol::REASON_SESSION_UNKNOWN,
                format!("unknown session {name}"),
            )
        })
    }

    pub fn handle(self: &Arc<Self>, head: &Value) -> Result<Value, Failure> {
        let text = |key: &str| head.get(key).and_then(Value::as_str).unwrap_or("");
        match text("op") {
            protocol::OP_PROBE => self
                .client
                .probe()
                .map(|()| json!({"backend": "nvx-whp"}))
                .map_err(|error| fail(protocol::REASON_BACKEND_UNAVAILABLE, error)),
            protocol::OP_SESSION_OPEN => {
                let memory = match head.get("memoryMiB") {
                    None => protocol::DEFAULT_MEMORY_MIB,
                    Some(value) => number(Some(value)).ok_or_else(|| {
                        fail(
                            protocol::REASON_MEMORY_UNSUPPORTED,
                            "memoryMiB must be an unsigned integer",
                        )
                    })?,
                };
                protocol::validate_memory(memory).map_err(|(code, message)| fail(code, message))?;
                self.open(text("session"), text("workspace"), memory as u32)
            }
            protocol::OP_EXEC => {
                if let Some(limits) = head.get("limits").and_then(Value::as_object) {
                    protocol::validate_limits(limits)
                        .map_err(|(code, message)| fail(code, message))?;
                }
                self.exec(head)
            }
            protocol::OP_SIGNAL => self.signal(text("handle")),
            protocol::OP_SESSION_CLOSE => self.close(text("session")),
            protocol::OP_MEMORY_STATS => self.memory_stats(text("session")),
            protocol::OP_MEMORY_TRIM => self.memory_trim(text("session")),
            other => Err(fail(
                protocol::REASON_PROTOCOL,
                format!("unknown op {other:?}"),
            )),
        }
    }

    fn open(&self, name: &str, workspace: &str, memory_mib: u32) -> Result<Value, Failure> {
        if name.is_empty() || workspace.is_empty() {
            return Err(fail(
                "E_BACKEND_PROTOCOL",
                "session and workspace are required",
            ));
        }
        if self.sessions.lock().unwrap().contains_key(name) {
            return Err(fail("E_BACKEND_PROTOCOL", "session already open"));
        }
        let request: ProvisionRequest = serde_json::from_value(json!({
            "filesystem": { "readwritePaths": [workspace] },
            "microvm": { "provision": { "memoryMib": memory_mib } }
        }))
        .map_err(|error| fail("E_BACKEND_PROTOCOL", error))?;
        let request_dir = self.request_root.join(format!("s{}", self.next_id()));
        std::fs::create_dir_all(&request_dir).map_err(|error| fail("E_BACKEND_START", error))?;
        let sandbox = {
            let _serialized = self.start_lock.lock().unwrap();
            let sandbox = self
                .client
                .provision(&request)
                .map_err(|error| fail("E_BACKEND_START", error))?
                .sandbox_id;
            // SAFETY: starts are serialized by `start_lock`; nothing else reads the variable.
            unsafe { std::env::set_var("NVX_POC_LIVE_SHARE_DIR", &request_dir) };
            if let Err(error) = self.client.start(&sandbox) {
                let _ = self.client.deprovision(&sandbox);
                return Err(fail("E_BACKEND_START", error));
            }
            sandbox
        };
        let memory = match self.backend.vmm_process(&sandbox) {
            Ok((pid, start_time)) => Some(VmmMemory::new(pid, start_time)),
            Err(error) => {
                eprintln!(
                    "genflow-nvxd: no VMM process for {name}: {error}; idle trimming is off for it"
                );
                None
            }
        };
        let state = SessionState {
            shares: Vec::new(),
            next_sequence: 0,
            next_child: 0,
            busy: false,
            last_activity: Instant::now(),
            trimmed: false,
            trims: 0,
        };
        let session = Session {
            sandbox,
            request_dir,
            memory,
            state: Mutex::new(state),
        };
        self.sessions
            .lock()
            .unwrap()
            .insert(name.to_owned(), Arc::new(session));
        let guest = resolve_guest_path(std::path::Path::new(workspace)).unwrap_or_default();
        Ok(json!({"workspaceGuestPath": guest}))
    }

    fn reconcile(
        &self,
        session: &Session,
        state: &mut SessionState,
        desired: &[Mount],
    ) -> Result<(), Failure> {
        for step in plan::plan(&state.shares, desired) {
            match step {
                Step::Remove(share) => {
                    self.backend
                        .remove_share_poc(
                            &session.sandbox,
                            &session.request_dir,
                            &share.child,
                            &share.target,
                            SHARE_TIMEOUT,
                        )
                        .map_err(|error| fail("E_WORKSPACE_MOUNT_REMOVE_FAILED", error))?;
                    state.shares.retain(|other| other.child != share.child);
                }
                Step::Add(mount) => {
                    let child = format!("mount{}", state.next_child);
                    state.next_child += 1;
                    let target = plan::guest_target(&mount.id);
                    let host = PathBuf::from(&mount.host_path);
                    let live = LiveShare {
                        child: &child,
                        host_path: &host,
                        target: &target,
                        read_only: mount.read_only,
                    };
                    self.backend
                        .add_share_poc(
                            &session.sandbox,
                            &session.request_dir,
                            state.next_sequence,
                            &live,
                            SHARE_TIMEOUT,
                        )
                        .map_err(|error| {
                            let text = error.to_string();
                            let limit =
                                text.contains("mapping-limit") || text.contains("256 children");
                            fail(
                                if limit {
                                    "E_WORKSPACE_MOUNT_LIMIT"
                                } else {
                                    "E_WORKSPACE_MOUNT_FAILED"
                                },
                                text,
                            )
                        })?;
                    state.next_sequence += 1;
                    state.shares.push(Share {
                        mount,
                        child,
                        target,
                    });
                }
            }
        }
        Ok(())
    }

    fn exec(self: &Arc<Self>, head: &Value) -> Result<Value, Failure> {
        let session = self.session(head.get("session").and_then(Value::as_str).unwrap_or(""))?;
        if head.get("stdin").is_some() || head.get("input").is_some() {
            return Err(fail(
                protocol::REASON_STDIN_UNSUPPORTED,
                "NVX v1 does not support stdin or input payloads",
            ));
        }
        if let Some(limits) = head.get("limits").and_then(Value::as_object) {
            if limits.contains_key("cpuPercent") {
                return Err(fail(
                    protocol::REASON_CPU_LIMIT_UNSUPPORTED,
                    "NVX v1 does not support per-task CPU limits",
                ));
            }
            if limits.contains_key("memMb") {
                return Err(fail(
                    protocol::REASON_MEMORY_LIMIT_UNSUPPORTED,
                    "NVX v1 does not support per-task memory limits",
                ));
            }
            if let Some(value) = limits.get("hardTimeoutSec") {
                let timeout = signed_number(Some(value)).ok_or_else(|| {
                    fail(
                        protocol::REASON_INVALID_LIMIT,
                        "hardTimeoutSec must be an integer",
                    )
                })?;
                if timeout < 0 {
                    return Err(fail(
                        protocol::REASON_INVALID_LIMIT,
                        "hardTimeoutSec must not be negative",
                    ));
                }
            }
        }
        let argv: Vec<String> = strings(head.get("argv"));
        if argv.is_empty() {
            return Err(fail("E_BACKEND_PROTOCOL", "argv is required"));
        }
        let desired = mounts(head.get("mounts"));
        if desired
            .iter()
            .any(|mount| mount.id.is_empty() || mount.host_path.is_empty())
        {
            return Err(fail(
                "E_BACKEND_PROTOCOL",
                "a mount needs mountId and hostPath",
            ));
        }
        let mut state = session.state.lock().unwrap();
        if state.busy {
            return Err(fail(
                protocol::REASON_BACKEND_BUSY,
                "the session is already running a command",
            ));
        }
        self.reconcile(&session, &mut state, &desired)?;

        let mut request = ExecRequest::argv(absolute_program(argv));
        if let Some(cwd) = head
            .get("cwd")
            .and_then(Value::as_str)
            .filter(|cwd| !cwd.is_empty())
        {
            let guest = plan::translate_cwd(cwd, &desired, |path| {
                resolve_guest_path(std::path::Path::new(path))
            })
            .ok_or_else(|| fail("E_BACKEND_CWD", format!("no guest path for {cwd}")))?;
            request = request.with_cwd(guest);
        }
        if let Some(env) = head.get("env").and_then(Value::as_object) {
            let entries = env
                .iter()
                .filter_map(|(key, value)| Some(format!("{key}={}", value.as_str()?)));
            request = request.with_envs(entries);
        }
        let timeout_ms = match head.get("timeoutMs") {
            None => None,
            Some(value) => {
                let ms = number(Some(value)).ok_or_else(|| {
                    fail(
                        protocol::REASON_INVALID_LIMIT,
                        "timeoutMs must be a positive integer",
                    )
                })?;
                if ms == 0 {
                    return Err(fail(
                        protocol::REASON_INVALID_LIMIT,
                        "timeoutMs must be a positive integer",
                    ));
                }
                Some(ms)
            }
        };
        if let Some(ms) = timeout_ms {
            request = request.with_timeout(Duration::from_millis(ms));
        }
        let mut execution = self
            .client
            .exec(&session.sandbox, &request)
            .map_err(|error| fail("E_BACKEND_EXEC", error))?;
        state.busy = true;
        state.last_activity = Instant::now();
        state.trimmed = false;
        drop(state);

        let handle = format!("nvx-{}", self.next_id());
        self.handles
            .lock()
            .unwrap()
            .insert(handle.clone(), execution.canceller());
        let mut pumps = Vec::new();
        if let Some(pipe) = execution.take_stdout() {
            pumps.push(spawn_pump(
                protocol::EVENT_EXEC_STDOUT,
                pipe,
                &handle,
                &self.writer,
            ));
        }
        if let Some(pipe) = execution.take_stderr() {
            pumps.push(spawn_pump(
                protocol::EVENT_EXEC_STDERR,
                pipe,
                &handle,
                &self.writer,
            ));
        }
        let (this, waiting_handle) = (Arc::clone(self), handle.clone());
        std::thread::spawn(move || {
            let outcome = execution.wait();
            for pump in pumps {
                let _ = pump.join();
            }
            this.handles.lock().unwrap().remove(&waiting_handle);
            {
                let mut state = session.state.lock().unwrap();
                state.busy = false;
                state.last_activity = Instant::now();
                state.trimmed = false;
            }
            let _ = this.writer.send(&exit_event(&waiting_handle, outcome), &[]);
        });
        Ok(json!({"handle": handle}))
    }

    fn memory_stats(&self, name: &str) -> Result<Value, Failure> {
        let session = self.session(name)?;
        let memory = session
            .memory
            .ok_or_else(|| fail("E_BACKEND_MEMORY", "no VMM process is known"))?;
        let working_set = memory
            .working_set()
            .map_err(|error| fail("E_BACKEND_MEMORY", error))?;
        let state = session.state.lock().unwrap();
        Ok(json!({
            "workingSetMiB": working_set / (1 << 20),
            "trims": state.trims,
            "idleMs": state.last_activity.elapsed().as_millis() as u64,
            "busy": state.busy,
        }))
    }

    /// Trims the working set of an idle session now.
    fn memory_trim(&self, name: &str) -> Result<Value, Failure> {
        let session = self.session(name)?;
        let memory = session
            .memory
            .ok_or_else(|| fail("E_BACKEND_MEMORY", "no VMM process is known"))?;
        let mut state = session.state.lock().unwrap();
        if state.busy {
            return Err(fail("E_BACKEND_BUSY", "the session is running a command"));
        }
        let (before, after) = memory
            .trim()
            .map_err(|error| fail("E_BACKEND_MEMORY", error))?;
        state.trimmed = true;
        Ok(json!({"beforeMiB": before / (1 << 20), "afterMiB": after / (1 << 20)}))
    }

    /// Backstop for the missing balloon device: a session that has been idle for `idle` gets its
    /// VMM's working set trimmed once, so that its guest RAM becomes reclaimable by the host.
    /// Sessions that are busy, or whose lock is taken, are skipped and retried on the next pass.
    pub fn idle_trim_pass(&self, idle: Duration) {
        let sessions: Vec<(String, Arc<Session>)> = self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .map(|(name, session)| (name.clone(), session.clone()))
            .collect();
        for (name, session) in sessions {
            let Some(memory) = session.memory else {
                continue;
            };
            let Ok(mut state) = session.state.try_lock() else {
                continue;
            };
            if state.busy || state.trimmed || state.last_activity.elapsed() < idle {
                continue;
            }
            state.trimmed = true;
            match memory.trim() {
                Ok((before, after)) => {
                    state.trims += 1;
                    eprintln!(
                        "genflow-nvxd: trimmed idle session {name}: {} MiB -> {} MiB",
                        before >> 20,
                        after >> 20
                    );
                }
                Err(error) => eprintln!("genflow-nvxd: cannot trim session {name}: {error}"),
            }
        }
    }

    fn signal(&self, handle: &str) -> Result<Value, Failure> {
        let canceller = self.handles.lock().unwrap().get(handle).cloned();
        let canceller = canceller.ok_or_else(|| {
            fail(
                protocol::REASON_HANDLE_UNKNOWN,
                format!("unknown handle {handle}"),
            )
        })?;
        canceller
            .cancel()
            .map_err(|error| fail("E_BACKEND_SIGNAL", error))?;
        Ok(json!({"signalled": true}))
    }

    fn close(&self, name: &str) -> Result<Value, Failure> {
        let removed = self.sessions.lock().unwrap().remove(name);
        let session = removed.ok_or_else(|| {
            fail(
                protocol::REASON_SESSION_UNKNOWN,
                format!("unknown session {name}"),
            )
        })?;
        let _ = self.client.stop(&session.sandbox);
        let result = self.client.deprovision(&session.sandbox);
        let _ = std::fs::remove_dir_all(&session.request_dir);
        result
            .map(|_| json!({}))
            .map_err(|error| fail("E_BACKEND_CLOSE", error))
    }

    pub fn close_all(&self) {
        let names: Vec<String> = self.sessions.lock().unwrap().keys().cloned().collect();
        for name in names {
            let _ = self.close(&name);
        }
    }
}

/// NVX accepts only an absolute guest path as the program. GenFlow sends bare names such as
/// `python` or `node`, so those are resolved by the guest shell, which keeps `argv` exact.
fn absolute_program(argv: Vec<String>) -> Vec<String> {
    if argv.first().is_some_and(|program| program.starts_with('/')) {
        return argv;
    }
    let mut wrapped: Vec<String> = ["/bin/sh", "-c", "exec \"$@\"", "sh"]
        .map(str::to_owned)
        .into();
    wrapped.extend(argv);
    wrapped
}

/// The C++ side builds requests with property trees, which write every scalar as a string.
fn number(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    value
        .as_u64()
        .or_else(|| value.as_str()?.trim().parse().ok())
}

fn signed_number(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    value
        .as_i64()
        .or_else(|| value.as_str()?.trim().parse().ok())
}

fn strings(value: Option<&Value>) -> Vec<String> {
    let items = value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    items
        .iter()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect()
}

fn mounts(value: Option<&Value>) -> Vec<Mount> {
    let items = value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    items
        .iter()
        .map(|item| Mount {
            id: item["mountId"].as_str().unwrap_or("").to_owned(),
            host_path: item["hostPath"].as_str().unwrap_or("").to_owned(),
            read_only: item["mode"].as_str() != Some("rw"),
        })
        .collect()
}

fn spawn_pump(
    event: &'static str,
    mut pipe: impl Read + Send + 'static,
    handle: &str,
    writer: &Writer,
) -> std::thread::JoinHandle<()> {
    let (handle, writer) = (handle.to_owned(), Arc::clone(writer));
    std::thread::spawn(move || {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    let head = json!({"event": event, "handle": handle});
                    if writer.send(&head, &buffer[..count]).is_err() {
                        break;
                    }
                }
            }
        }
    })
}

fn exit_event(handle: &str, outcome: aci_edge_sandboxes::Result<ExecOutcome>) -> Value {
    let (kind, code, detail) = match outcome {
        Ok(ExecOutcome::Exited(code)) => ("exited", Some(code), String::new()),
        Ok(ExecOutcome::Signaled(signal)) => ("signaled", Some(signal), String::new()),
        Ok(ExecOutcome::TimedOut) => ("timedOut", None, String::new()),
        Ok(ExecOutcome::Cancelled) => ("cancelled", None, String::new()),
        Ok(other) => ("failed", None, other.to_string()),
        Err(error) => ("failed", None, error.to_string()),
    };
    json!({"event": protocol::EVENT_EXEC_EXIT, "handle": handle, "outcome": kind, "code": code, "detail": detail})
}
