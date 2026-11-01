//! Request handlers.
//!
//! One VM serves every logical session this sidecar was opened for, and each session holds a set
//! of executions. Three rules shape this file, all of them from the productization plan:
//!
//! * **Identity before execution.** The host names an execution before it sends it, and the id
//!   keeps working across a lost reply, a duplicate start and a cancel that overtakes its start.
//! * **Start reply before events.** A dispatched execution is *gated*: it starts only after its
//!   start reply has been written, so a caller never sees output for a request it has not been
//!   answered yet.
//! * **Closing is not killing the VM.** Closing a session takes away that session's work and
//!   leaves the other sessions running on the same VM; the VM is retired only when nothing refers
//!   to it any more.
//!
//! The VM itself is [`crate::vm`]: NVX's supervisor and execution engine with the sidecar's guest
//! agent. TODO (next steps of the migration): per-execution limits and OOM attribution, workspace
//! mounts, session isolation, network policy; their code is in `reference/server_old.rs`.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::capability::{Capability, Verdict};
use crate::outbound::Writer;
use crate::plan;
use crate::ports;
use crate::protocol;
use crate::registry::{Accept, Cancel, Closed, Registry, Terminal};
use crate::vm::{Event, ExitOutcome, Resources, Vm, VmConfig};
use crate::winmem::VmmMemory;

pub const NOT_YET_SUPPORTED: &str = "E_NVX_NOT_YET_SUPPORTED";
/// How long `probe` waits for the capability check unless the caller names a bound.
const PROBE_WAIT: Duration = Duration::from_secs(30);
/// How long a close waits for the session's running executions before it reports `closing`.
const CLOSE_WAIT: Duration = Duration::from_secs(5);
/// How long a dispatched execution may wait for its start reply before it runs anyway.
const RELEASE_WAIT: Duration = Duration::from_secs(10);

pub struct Failure {
    pub code: String,
    pub message: String,
}

fn fail(code: &str, message: impl ToString) -> Failure {
    Failure { code: code.to_owned(), message: message.to_string() }
}

/// The request's `protocol`: `tcp` (the default) or `udp`.
fn port_transport(head: &Value) -> Result<ports::Transport, Failure> {
    let name = match head.get("protocol") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_str().unwrap_or("")),
    };
    ports::Transport::parse(name).ok_or_else(|| {
        fail(protocol::REASON_PORT_PROTOCOL_UNSUPPORTED, "protocol must be \"tcp\" or \"udp\"")
    })
}

/// The start failure code a remembered verdict names, or the unclassified one.
fn known_start_code(code: &str) -> &'static str {
    [
        protocol::REASON_START_ASSET,
        protocol::REASON_START_VMM_EXIT,
        protocol::REASON_START_TIMEOUT,
        protocol::REASON_START_CONTROL,
        protocol::REASON_START_HYPERVISOR,
    ]
    .into_iter()
    .find(|known| *known == code)
    .unwrap_or(protocol::REASON_START)
}

/// The one VM this sidecar runs, named by a generation that changes whenever it is replaced.
struct VmEntry {
    vm: Vm,
    generation: u64,
    runtime_id: String,
    memory: VmmMemory,
    state: Mutex<VmState>,
}

struct VmState {
    last_activity: Instant,
    trimmed: bool,
    trims: u64,
}

impl VmEntry {
    fn touch(&self) {
        let mut state = self.state.lock().unwrap();
        state.last_activity = Instant::now();
        state.trimmed = false;
    }

    fn idle(&self) -> Duration {
        self.state.lock().unwrap().last_activity.elapsed()
    }
}

/// A logical session: routing unit inside the VM, not a VM of its own.
struct SessionInfo {
    workspace: PathBuf,
    last_activity: Instant,
    /// The session's name reduced to a safe alphabet, for guest paths.
    prefix: String,
    /// Where the workspace is mounted in the guest.
    workspace_guest: String,
    /// The workspace's live share, exported and mounted when the session opened.
    workspace_share: Option<plan::Share>,
    /// The mounts that are live for this session, as of its last applied snapshot.
    shares: Vec<plan::Share>,
}

/// An export that could not be taken back yet; retried in the maintenance pass.
struct Removal {
    session: String,
    mount_id: String,
    child: String,
    target: String,
    generation: u64,
}

/// What the worker needs to run an execution. Kept apart from the registry so the lifecycle state
/// machine stays free of VM types.
#[derive(Clone)]
struct Spec {
    argv: Vec<String>,
    cwd: Option<String>,
    env: Vec<(String, String)>,
    timeout: Option<Duration>,
    /// The limits of the execution: the deployment's, overridden field by field by the request's.
    resources: Resources,
    /// The mounts the request asked for, applied before the execution runs; `None` when the
    /// request carried none, which leaves the session's mounts as they are.
    mounts: Option<Vec<plan::Mount>>,
}

struct Inner {
    registry: Registry,
    sessions: HashMap<String, SessionInfo>,
    specs: HashMap<String, Spec>,
    /// The thread that runs an execution waits on this for the way it ended.
    waiters: HashMap<String, Sender<ExitOutcome>>,
    /// Set while a VM exists; executions are refused rather than queued behind a boot.
    vm_present: bool,
    /// Guest paths used in this VM's lifetime, including revoked ones: never reused.
    guest_targets: HashSet<String>,
    /// Counter for export names, which are never reused within a VM.
    next_child: u64,
    /// Exports whose removal failed and is retried.
    removals: Vec<Removal>,
}

/// Counters of what this sidecar has done since it started.
#[derive(Debug, Default)]
struct Stats {
    requests: u64,
    failures: u64,
    execs: u64,
    last_failure: Option<(String, String)>,
    shares_added: u64,
    shares_removed: u64,
    shares_remove_failed: u64,
    mounts_applied: u64,
    mounts_skipped: u64,
}

pub struct Context {
    config: VmConfig,
    provenance: Value,
    writer: Arc<Writer>,
    max_queue: usize,
    max_sessions: usize,
    max_running: usize,
    ingress_host_loopback: bool,
    /// Deployment limits of each execution (memory MiB, CPU percent, pids), 0 for none.
    exec_defaults: (u64, u64, u64),
    /// Ports `port.allocate` handed out lately, so concurrent callers do not get the same one.
    allocated_ports: Mutex<std::collections::VecDeque<u16>>,
    /// Whether this machine can boot the VM at all, learned by booting a small one once.
    capability: Capability,
    /// Serialises VM creation and retirement against session open and close.
    lifecycle: Mutex<()>,
    vm: Mutex<Option<Arc<VmEntry>>>,
    inner: Mutex<Inner>,
    /// Wakes the worker when there is work, when a gate opens, or when the VM changes.
    wake: Condvar,
    worker_running: AtomicBool,
    /// Set while one thread is stopping the VM, so a second one cannot stop it again.
    retiring: AtomicBool,
    stopping: AtomicBool,
    counter: Mutex<u64>,
    runtime_prefix: String,
    stats: Mutex<Stats>,
}

/// The settings of the control plane (the VM's own are in [`VmConfig`]).
pub struct Settings {
    pub max_queue: usize,
    pub max_sessions: usize,
    pub max_running: usize,
    pub ingress_host_loopback: bool,
    /// Deployment-wide limits of each execution, 0 for none: memory in MiB, CPU in percent of one
    /// core, and processes.
    pub exec_memory_mb: u64,
    pub exec_cpu_percent: u64,
    pub exec_pids: u64,
}

impl Context {
    pub fn new(
        config: VmConfig,
        provenance: Value,
        writer: Arc<Writer>,
        settings: Settings,
        capability: Capability,
    ) -> Self {
        let max_queue = settings.max_queue.max(1);
        let max_running = settings.max_running.max(1);
        Self {
            config,
            provenance,
            writer,
            max_queue,
            max_sessions: settings.max_sessions,
            max_running,
            ingress_host_loopback: settings.ingress_host_loopback,
            exec_defaults: (settings.exec_memory_mb, settings.exec_cpu_percent, settings.exec_pids),
            allocated_ports: Mutex::new(std::collections::VecDeque::new()),
            capability,
            lifecycle: Mutex::new(()),
            vm: Mutex::new(None),
            inner: Mutex::new(Inner {
                registry: Registry::new(max_queue, max_running, 0),
                sessions: HashMap::new(),
                specs: HashMap::new(),
                waiters: HashMap::new(),
                vm_present: false,
                guest_targets: HashSet::new(),
                next_child: 0,
                removals: Vec::new(),
            }),
            wake: Condvar::new(),
            worker_running: AtomicBool::new(false),
            retiring: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            counter: Mutex::new(0),
            runtime_prefix: {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                std::process::id().hash(&mut hasher);
                std::time::SystemTime::now().hash(&mut hasher);
                format!("{:016x}", hasher.finish())
            },
            stats: Mutex::new(Stats::default()),
        }
    }

    fn next_id(&self) -> u64 {
        let mut counter = self.counter.lock().unwrap();
        *counter += 1;
        *counter
    }

    fn vm_now(&self) -> Option<Arc<VmEntry>> {
        self.vm.lock().unwrap().clone()
    }

    /// What a port the guest serves on looks like from the host's loopback.
    fn port_check(&self, head: &Value) -> Result<Value, Failure> {
        self.port_session(head)?;
        let port = number(head.get("port"))
            .filter(|port| (1..=65535).contains(port))
            .ok_or_else(|| fail(protocol::REASON_PROTOCOL, "port must be an integer in 1..=65535"))?
            as u16;
        let transport = port_transport(head)?;
        // The guest announces its listeners every couple of seconds, so a server that was just
        // started is not there yet; give it a bounded moment before calling it unpublished.
        let default_wait = match transport {
            ports::Transport::Tcp => 3000,
            ports::Transport::Udp => 6000,
        };
        let wait = number(head.get("waitMs")).unwrap_or(default_wait).min(10_000);
        let vmm_pid = self
            .vm_now()
            .map(|vm| vm.memory.pid())
            .ok_or_else(|| fail("E_BACKEND_UNAVAILABLE", "no VMM process is known"))?;
        let deadline = Instant::now() + Duration::from_millis(wait);
        loop {
            let listeners = ports::listeners(transport, port).map_err(|e| fail("E_NVX_PORT_CHECK", e))?;
            match ports::classify(&listeners, vmm_pid) {
                ports::PortState::Published => {
                    return Ok(json!({
                        "port": port, "protocol": transport.as_str(), "state": "published",
                        "hostAddress": "127.0.0.1",
                    }));
                }
                ports::PortState::Conflict { pid } => {
                    let suggested = self.free_port(transport)?;
                    return Ok(json!({
                        "port": port, "protocol": transport.as_str(), "state": "conflict",
                        "owner": { "pid": pid, "name": ports::process_name(pid) },
                        "suggestedPort": suggested,
                    }));
                }
                ports::PortState::Unpublished if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(200));
                }
                ports::PortState::Unpublished => {
                    return Ok(json!({
                        "port": port, "protocol": transport.as_str(), "state": "unpublished",
                    }));
                }
            }
        }
    }

    /// A port that is free on the host's loopback right now, for a server about to be started.
    fn port_allocate(&self, head: &Value) -> Result<Value, Failure> {
        self.port_enabled()?;
        let transport = port_transport(head)?;
        Ok(json!({
            "port": self.free_port(transport)?,
            "protocol": transport.as_str(),
            "hostAddress": "127.0.0.1",
        }))
    }

    fn free_port(&self, transport: ports::Transport) -> Result<u16, Failure> {
        let mut recent = self.allocated_ports.lock().unwrap();
        let port = ports::free_port(transport, &recent).map_err(|e| fail("E_NVX_PORT_CHECK", e))?;
        recent.push_back(port);
        while recent.len() > 64 {
            recent.pop_front();
        }
        Ok(port)
    }

    fn port_enabled(&self) -> Result<(), Failure> {
        if !self.ingress_host_loopback {
            return Err(fail(
                protocol::REASON_INBOUND_DISABLED,
                "host-loopback ingress is off, so nothing the guest listens on is published",
            ));
        }
        Ok(())
    }

    /// Checking a port belongs to an open session and needs ingress to be on.
    fn port_session(&self, head: &Value) -> Result<(), Failure> {
        self.port_enabled()?;
        let name = head.get("session").and_then(Value::as_str).unwrap_or("");
        if !self.inner.lock().unwrap().sessions.contains_key(name) {
            return Err(fail(protocol::REASON_SESSION_UNKNOWN, format!("unknown session {name}")));
        }
        Ok(())
    }

    pub fn handle(self: &Arc<Self>, head: &Value) -> Result<Value, Failure> {
        let text = |key: &str| head.get(key).and_then(Value::as_str).unwrap_or("");
        match text("op") {
            protocol::OP_PROBE => self.probe(head),
            protocol::OP_SESSION_OPEN => {
                reject_unsupported_session_options(head)?;
                let memory = match head.get("memoryMiB") {
                    None => protocol::DEFAULT_MEMORY_MIB,
                    Some(value) => number(Some(value)).ok_or_else(|| {
                        fail(protocol::REASON_MEMORY_UNSUPPORTED, "memoryMiB must be an unsigned integer")
                    })?,
                };
                protocol::validate_memory(memory).map_err(|(code, message)| fail(code, message))?;
                self.open(text("session"), text("workspace"), memory as u32)
            }
            protocol::OP_EXEC => {
                if let Some(limits) = head.get("limits").and_then(Value::as_object) {
                    protocol::validate_limits(limits).map_err(|(code, message)| fail(code, message))?;
                }
                self.exec(head)
            }
            protocol::OP_SIGNAL => self.signal(head),
            protocol::OP_SESSION_CLOSE => self.close(text("session")),
            protocol::OP_EXEC_STATUS => self.status(text("execId"), text("handle")),
            protocol::OP_MEMORY_STATS => self.memory_stats(),
            protocol::OP_MEMORY_TRIM => self.memory_trim(),
            protocol::OP_DIAGNOSTICS => Ok(self.diagnostics()),
            protocol::OP_PORT_CHECK => self.port_check(head),
            protocol::OP_PORT_ALLOCATE => self.port_allocate(head),
            other => Err(fail(protocol::REASON_PROTOCOL, format!("unknown op {other:?}"))),
        }
    }

    /// Times, counts and logs one request, then returns whatever [`Self::handle`] decided.
    pub fn handle_logged(self: &Arc<Self>, head: &Value) -> Result<Value, Failure> {
        let started = Instant::now();
        let op = head.get("op").and_then(Value::as_str).unwrap_or("");
        let session = head.get("session").and_then(Value::as_str).unwrap_or("");
        let outcome = self.handle(head);
        let elapsed_ms = started.elapsed().as_millis() as u64;
        {
            let mut stats = self.stats.lock().unwrap();
            stats.requests += 1;
            if op == protocol::OP_EXEC {
                stats.execs += 1;
            }
            if let Err(failure) = &outcome {
                stats.failures += 1;
                stats.last_failure = Some((failure.code.clone(), failure.message.clone()));
            }
        }
        let verbose = std::env::var_os("NVXD_LOG_REQUESTS").is_some();
        match &outcome {
            Ok(_) if elapsed_ms < 1000 && !verbose => {}
            Ok(_) => eprintln!("nvxd: request op={op} session={session} result=ok durationMs={elapsed_ms}"),
            Err(failure) => eprintln!(
                "nvxd: request op={op} session={session} result=error reasonCode={} durationMs={elapsed_ms} message={}",
                failure.code, failure.message
            ),
        }
        outcome
    }

    /// Opens the start gate for a dispatched execution once its reply is on the wire.
    pub fn release(&self, exec_id: &str) {
        self.inner.lock().unwrap().registry.release(exec_id);
        self.wake.notify_all();
    }

    fn probe(&self, head: &Value) -> Result<Value, Failure> {
        let wait = number(head.get("waitMs")).map_or(PROBE_WAIT, Duration::from_millis);
        self.ensure_capable(Some(wait))?;
        let generation = self.inner.lock().unwrap().registry.generation();
        Ok(json!({
            "backend": "nvx-whp",
            "provenance": self.provenance,
            "vmGeneration": generation,
            "capabilities": {
                "sharedVm": true,
                "parallelExec": self.max_running > 1,
                "maxRunningPerVm": self.max_running,
                "maxRunningPerSession": self.max_running,
                "guestFeatures": 953,
                "sessionIsolation": false,
            },
        }))
    }

    fn diagnostics(&self) -> Value {
        let stats = self.stats.lock().unwrap();
        let inner = self.inner.lock().unwrap();
        let vm = self.vm.lock().unwrap();
        let views = inner.registry.views();
        let sessions: Vec<Value> = inner
            .sessions
            .iter()
            .map(|(name, info)| {
                json!({
                    "session": name,
                    "runtimeId": vm.as_ref().map(|vm| vm.runtime_id.clone()),
                    "generation": vm.as_ref().map(|vm| vm.generation),
                    "workspace": info.workspace.display().to_string(),
                    "idleMs": info.last_activity.elapsed().as_millis() as u64,
                    "execs": views.iter().filter(|view| view.session == *name).count(),
                    "running": inner.registry.running_for_session(name),
                    "queued": inner.registry.queued_for_session(name),
                    "busy": views.iter().any(|view| view.session == *name && view.phase == crate::registry::Phase::Running),
                })
            })
            .collect();
        let execs: Vec<Value> = views
            .iter()
            .map(|view| {
                json!({
                    "exec": view.id,
                    "session": view.session,
                    "phase": view.phase.as_str(),
                    "generation": view.generation,
                    "queuedMs": view.queued_ms,
                })
            })
            .collect();
        let writer = self.writer.stats();
        json!({
            "runtimePrefix": self.runtime_prefix,
            "maxSessions": self.max_sessions,
            "sessionCount": inner.registry.session_count(),
            "maxQueue": self.max_queue,
            "vm": vm.as_ref().map(|vm| json!({
                "runtimeId": vm.runtime_id,
                "generation": vm.generation,
                "idleMs": vm.idle().as_millis() as u64,
            })),
            "sessions": sessions,
            "execs": execs,
            "running": inner.registry.running_ids(),
            "maxRunning": inner.registry.max_running(),
            "maxRunningPerSession": inner.registry.max_running_per_session(),
            "queued": inner.registry.queued_len(),
            "cleanupPending": inner.removals.len(),
            "closingGuestSessions": 0,
            "cleanupOldestMs": 0,
            "outbound": {
                "frames": writer.frames(),
                "refused": writer.refused(),
                "deferred": writer.deferred(),
                "broken": self.writer.broken(),
            },
            "stats": {
                "requests": stats.requests,
                "failures": stats.failures,
                "execs": stats.execs,
                "sharesAdded": stats.shares_added,
                "sharesRemoved": stats.shares_removed,
                "sharesRemoveFailed": stats.shares_remove_failed,
                "mountsApplied": stats.mounts_applied,
                "mountsSkipped": stats.mounts_skipped,
                "lastFailure": stats.last_failure.as_ref().map(|(code, message)| json!({
                    "reasonCode": code,
                    "message": message,
                })),
            },
        })
    }


    fn open(self: &Arc<Self>, name: &str, workspace: &str, memory_mib: u32) -> Result<Value, Failure> {
        if name.is_empty() || workspace.is_empty() {
            return Err(fail(protocol::REASON_PROTOCOL, "session and workspace are required"));
        }
        let _lifecycle = self.lifecycle.lock().unwrap();
        {
            let inner = self.inner.lock().unwrap();
            if inner.sessions.contains_key(name) {
                return Err(fail(protocol::REASON_PROTOCOL, "session already open"));
            }
            if self.max_sessions > 0 && inner.sessions.len() >= self.max_sessions {
                return Err(fail(
                    protocol::REASON_BACKEND_BUSY,
                    format!("{} sessions are already open, the limit is {}", inner.sessions.len(), self.max_sessions),
                ));
            }
        }
        let vm = match self.vm_now() {
            Some(vm) => vm,
            None => self.boot_vm(memory_mib)?,
        };
        {
            let mut inner = self.inner.lock().unwrap();
            if !inner.registry.open_session(name) {
                return Err(fail(protocol::REASON_PROTOCOL, "session already open"));
            }
            let prefix = safe_name(name);
            let mut workspace_guest = format!("/sessions/{prefix}/workspace");
            let mut suffix = 1;
            while inner.guest_targets.contains(&workspace_guest) {
                suffix += 1;
                workspace_guest = format!("/sessions/{prefix}-{suffix}/workspace");
            }
            inner.guest_targets.insert(workspace_guest.clone());
            inner.sessions.insert(
                name.to_owned(),
                SessionInfo {
                    workspace: PathBuf::from(workspace),
                    last_activity: Instant::now(),
                    prefix,
                    workspace_guest,
                    workspace_share: None,
                    shares: Vec::new(),
                },
            );
        }
        if let Err(failure) = self.ensure_workspace_export(&vm, name) {
            return Err(failure);
        }
        self.spawn_worker();
        let workspace_guest = {
            let inner = self.inner.lock().unwrap();
            inner.sessions.get(name).map(|info| info.workspace_guest.clone()).unwrap_or_default()
        };
        Ok(json!({
            "workspaceGuestPath": workspace_guest,
            "runtimeId": vm.runtime_id,
            "vmGeneration": vm.generation,
            "sharedVm": true,
        }))
    }

    /// Exports the session's workspace and mounts it in the guest. A session that cannot reach its
    /// workspace is not a session, so a failure takes the registration back.
    fn ensure_workspace_export(&self, vm: &Arc<VmEntry>, name: &str) -> Result<(), Failure> {
        let (prefix, workspace, target, child) = {
            let mut inner = self.inner.lock().unwrap();
            inner.next_child += 1;
            let n = inner.next_child;
            let info = inner
                .sessions
                .get(name)
                .ok_or_else(|| fail(protocol::REASON_SESSION_UNKNOWN, format!("unknown session {name}")))?;
            (info.prefix.clone(), info.workspace.clone(), info.workspace_guest.clone(), format!("{}-ws{n}", info.prefix))
        };
        let host = workspace.display().to_string();
        let outcome = vm.vm.mount_add(name, "workspace", &child, &host, &target, false);
        match outcome {
            Ok(()) => {
                self.stats.lock().unwrap().shares_added += 1;
                let mut inner = self.inner.lock().unwrap();
                if let Some(info) = inner.sessions.get_mut(name) {
                    info.workspace_share = Some(plan::Share {
                        mount: plan::Mount { id: "workspace".to_owned(), host_path: host, read_only: false, guest_path: None },
                        child,
                        source_target: target.clone(),
                        target,
                    });
                }
                let _ = prefix;
                Ok(())
            }
            Err((code, message)) => {
                let lost = vm_is_gone(&message);
                let mut inner = self.inner.lock().unwrap();
                inner.sessions.remove(name);
                inner.registry.close_session(name);
                drop(inner);
                if lost {
                    self.mark_vm_lost(vm.generation, message.clone());
                    return Err(fail(protocol::REASON_BACKEND_UNAVAILABLE, message));
                }
                Err(fail(&code, message))
            }
        }
    }

    /// Applies a session's mount snapshot: removes what it no longer lists, adds what is new.
    fn apply_mounts(&self, vm: &Arc<VmEntry>, name: &str, desired: &[plan::Mount]) -> Result<(), Failure> {
        let (prefix, mut shares) = {
            let inner = self.inner.lock().unwrap();
            let info = inner
                .sessions
                .get(name)
                .ok_or_else(|| fail(protocol::REASON_SESSION_UNKNOWN, format!("unknown session {name}")))?;
            (info.prefix.clone(), info.shares.clone())
        };
        let mut outcome = Ok(());
        let steps = plan::plan(&shares, desired);
        {
            let mut stats = self.stats.lock().unwrap();
            if steps.is_empty() {
                stats.mounts_skipped += 1;
            } else {
                stats.mounts_applied += 1;
            }
        }
        for step in steps {
            match step {
                plan::Step::Remove(share) => {
                    match vm.vm.mount_remove(name, &share.mount.id, &share.child, &share.target) {
                        Ok(()) => self.stats.lock().unwrap().shares_removed += 1,
                        Err((_, message)) => {
                            self.stats.lock().unwrap().shares_remove_failed += 1;
                            if vm_is_gone(&message) {
                                outcome = Err(fail(protocol::REASON_BACKEND_UNAVAILABLE, message));
                                break;
                            }
                            // Revoking a path must not fail the command that triggered it, nor
                            // destroy a VM other sessions share: keep trying later.
                            eprintln!("nvxd: cannot remove export {} ({message}); registered for retry", share.child);
                            self.inner.lock().unwrap().removals.push(Removal {
                                session: name.to_owned(),
                                mount_id: share.mount.id.clone(),
                                child: share.child.clone(),
                                target: share.target.clone(),
                                generation: vm.generation,
                            });
                        }
                    }
                    shares.retain(|other| other.child != share.child);
                }
                plan::Step::Add(mount) => {
                    let (child, target) = {
                        let mut inner = self.inner.lock().unwrap();
                        inner.next_child += 1;
                        let child = format!("{prefix}-m{}", inner.next_child);
                        let preferred = plan::guest_target_for(&mount);
                        let target = if inner.guest_targets.contains(&preferred) {
                            format!("/sessions/{prefix}/mounts/{}", mount.id)
                        } else {
                            preferred
                        };
                        inner.guest_targets.insert(target.clone());
                        (child, target)
                    };
                    if let Err((code, message)) =
                        vm.vm.mount_add(name, &mount.id, &child, &mount.host_path, &target, mount.read_only)
                    {
                        outcome = Err(if vm_is_gone(&message) {
                            fail(protocol::REASON_BACKEND_UNAVAILABLE, message)
                        } else {
                            fail(&code, message)
                        });
                        break;
                    }
                    self.stats.lock().unwrap().shares_added += 1;
                    shares.push(plan::Share { mount, child, source_target: target.clone(), target });
                }
            }
        }
        if let Some(info) = self.inner.lock().unwrap().sessions.get_mut(name) {
            info.shares = shares;
        }
        outcome
    }

    /// Retries the exports whose removal failed earlier.
    fn try_removals(&self) {
        let Some(vm) = self.vm_now() else { return };
        let pending: Vec<Removal> = {
            let mut inner = self.inner.lock().unwrap();
            let (now, later): (Vec<Removal>, Vec<Removal>) =
                std::mem::take(&mut inner.removals).into_iter().partition(|r| r.generation == vm.generation);
            inner.removals = later;
            now
        };
        for removal in pending {
            if vm.vm.mount_remove(&removal.session, &removal.mount_id, &removal.child, &removal.target).is_err() {
                self.inner.lock().unwrap().removals.push(removal);
            }
        }
    }

    /// Boots the VM that every session will share. Called only with `lifecycle` held.
    fn boot_vm(self: &Arc<Self>, memory_mib: u32) -> Result<Arc<VmEntry>, Failure> {
        self.ensure_capable(None)?;
        let mut config = self.config.clone();
        config.memory_mib = memory_mib;
        config.store = self.config.store.join(format!("vm-{}", self.next_id()));
        let _ = std::fs::remove_dir_all(&config.store);
        let generation = self.inner.lock().unwrap().registry.generation() + 1;
        config.generation = generation;
        let weak: Weak<Context> = Arc::downgrade(self);
        let vm = Vm::launch(config, move |event| match weak.upgrade() {
            Some(context) => context.on_event(generation, event),
            None => false,
        })
        .map_err(|(code, message)| fail(&code, message))?;
        let process = vm.process();
        let runtime_id = format!("rt-{}-{:08x}", self.runtime_prefix, self.next_id());
        let entry = Arc::new(VmEntry {
            vm,
            generation,
            runtime_id,
            memory: VmmMemory::new(process.pid, process.start_time),
            state: Mutex::new(VmState { last_activity: Instant::now(), trimmed: false, trims: 0 }),
        });
        {
            let mut inner = self.inner.lock().unwrap();
            let assigned = inner.registry.new_generation();
            debug_assert_eq!(assigned, generation);
            inner.vm_present = true;
        }
        self.retiring.store(false, Ordering::SeqCst);
        *self.vm.lock().unwrap() = Some(Arc::clone(&entry));
        eprintln!("nvxd: booted shared VM generation={} runtimeId={}", entry.generation, entry.runtime_id);
        Ok(entry)
    }

    /// What the VM thread reports: output and ends of executions, and the loss of the VM.
    fn on_event(self: &Arc<Self>, generation: u64, event: Event) -> bool {
        match event {
            Event::Output { id, stderr, bytes } => {
                let session = {
                    let inner = self.inner.lock().unwrap();
                    inner.registry.session_of(&id).map(str::to_owned)
                };
                // Output of an execution that is already over, or of a replaced VM, has nobody
                // to receive it.
                let Some(session) = session else { return true };
                let name = if stderr { protocol::EVENT_EXEC_STDERR } else { protocol::EVENT_EXEC_STDOUT };
                let head = json!({
                    "event": name, "handle": id, "execId": id, "session": session, "generation": generation,
                });
                // A refusal is flow control: the VM thread keeps the bytes and offers them again.
                self.writer.send_output(&head, &bytes).is_ok()
            }
            Event::Exit { id, outcome } => {
                let waiter = self.inner.lock().unwrap().waiters.remove(&id);
                if let Some(waiter) = waiter {
                    let _ = waiter.send(outcome);
                }
                true
            }
            Event::Lost { detail } => {
                // Reported from the VM's own thread, which `mark_vm_lost` ends and joins.
                let context = Arc::clone(self);
                std::thread::spawn(move || context.mark_vm_lost(generation, detail));
                true
            }
        }
    }

    /// Terminates everything this VM instance owned and retires it.
    ///
    /// The next `session.open` boots a new generation. Old exec ids and sessions are not reused
    /// (plan 3.3: an old generation is never revived, and no command is replayed). The report
    /// names the VM that failed: a thread talking to an earlier VM can learn of its end after a
    /// new VM has replaced it, and must not condemn the new one.
    fn mark_vm_lost(&self, lost_generation: u64, detail: String) {
        let victims: Vec<(String, String, u64)> = {
            let inner = self.inner.lock().unwrap();
            let generation = inner.registry.generation();
            if generation != lost_generation {
                eprintln!(
                    "nvxd: ignoring a late report that generation {lost_generation} was lost ({detail}); generation {generation} is current"
                );
                return;
            }
            inner.registry.views().into_iter().map(|view| (view.id, view.session, generation)).collect()
        };
        for (id, session, generation) in victims {
            let terminal = Terminal::new("failed", None, detail.clone());
            {
                let mut inner = self.inner.lock().unwrap();
                inner.specs.remove(&id);
                if inner.registry.finish(&id, terminal.clone()).is_none() {
                    continue;
                }
            }
            let _ = self.writer.send(&exit_event(&id, &session, generation, &terminal), &[]);
        }
        {
            let mut inner = self.inner.lock().unwrap();
            inner.registry.new_generation();
            inner.sessions.clear();
            inner.specs.clear();
            inner.waiters.clear();
            inner.guest_targets.clear();
            inner.removals.clear();
            inner.next_child = 0;
        }
        eprintln!("nvxd: the VM was lost: {detail}");
        self.retire_if_idle();
    }

    /// Runs the capability check now; the answer is kept for `probe` and for the first boot.
    pub fn check_capability(&self) {
        if let Err(failure) = self.ensure_capable(None) {
            eprintln!("nvxd: capability check failed: {} {}", failure.code, failure.message);
        }
    }

    /// Whether this machine can boot the VM, found out once by booting a small one. `None` waits
    /// for an unfinished check; `Some` gives up after that long with `E_NVX_CAPABILITY_PENDING`.
    fn ensure_capable(&self, wait: Option<Duration>) -> Result<(), Failure> {
        match self.capability.resolve(wait, &|| self.boot_probe()) {
            Some(Verdict::Capable) => Ok(()),
            Some(Verdict::Incapable { code, message }) => Err(fail(
                known_start_code(&code),
                format!("this machine cannot boot the microVM: {message}"),
            )),
            None => Err(fail(protocol::REASON_CAPABILITY_PENDING, "the capability check is still running")),
        }
    }

    /// Boots the smallest VM and stops it again, with the same launch a session would use.
    fn boot_probe(&self) -> Result<(), (String, String)> {
        let mut config = self.config.clone();
        config.memory_mib = protocol::PROBE_MEMORY_MIB;
        config.store = self.config.store.join("probe");
        let _ = std::fs::remove_dir_all(&config.store);
        let vm = Vm::launch(config, |_| true)?;
        vm.stop();
        Ok(())
    }


    fn spawn_worker(self: &Arc<Self>) {
        if self.worker_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let this = Arc::clone(self);
        std::thread::spawn(move || this.worker_loop());
    }

    /// Fills the VM's free run slots, and runs each execution it hands out in its own thread: an
    /// execution waits for its end, so a single blocking loop could keep only one alive.
    fn worker_loop(self: Arc<Self>) {
        loop {
            let started = {
                let mut inner = self.inner.lock().unwrap();
                if !inner.vm_present {
                    self.worker_running.store(false, Ordering::SeqCst);
                    return;
                }
                inner.registry.dispatch()
            };
            if started.is_empty() {
                self.expire_queued();
                // With nothing left to run, a VM that no session refers to any more is retired.
                self.retire_if_idle();
                let inner = self.inner.lock().unwrap();
                if !inner.vm_present {
                    self.worker_running.store(false, Ordering::SeqCst);
                    return;
                }
                let _ = self.wake.wait_timeout(inner, Duration::from_millis(200)).unwrap();
                continue;
            }
            for id in started {
                let this = Arc::clone(&self);
                std::thread::spawn(move || this.run_dispatched(id));
            }
        }
    }

    /// Runs one execution that already holds a run slot.
    fn run_dispatched(self: Arc<Self>, id: String) {
        self.await_release(&id);
        let spec = self.inner.lock().unwrap().specs.get(&id).cloned();
        // Cancelled between dispatch and run: the cancel path already emitted the terminal state.
        let Some(spec) = spec else { return };
        match self.vm_now() {
            Some(vm) => self.run_one(&vm, &id, spec),
            None => self.finish_and_emit(
                &id,
                Terminal::new("failed", None, "the VM was replaced before the run started"),
            ),
        }
    }

    /// Holds an execution back until its start reply has been written.
    fn await_release(&self, id: &str) {
        let deadline = Instant::now() + RELEASE_WAIT;
        let mut inner = self.inner.lock().unwrap();
        while !inner.registry.is_released(id) {
            let now = Instant::now();
            if now >= deadline {
                inner.registry.release(id);
                break;
            }
            let (guard, _) = self.wake.wait_timeout(inner, deadline - now).unwrap();
            inner = guard;
        }
    }

    fn run_one(&self, vm: &Arc<VmEntry>, id: &str, spec: Spec) {
        // A session closed (or the caller cancelled) while this execution was being prepared:
        // nothing has been started yet, so it simply does not start.
        if self.inner.lock().unwrap().registry.cancel_requested(id) {
            self.finish_and_emit(id, Terminal::new("cancelled", None, "cancelled before it started"));
            return;
        }
        let session = self.inner.lock().unwrap().registry.session_of(id).map(str::to_owned).unwrap_or_default();
        // Mounts change in a gap where this session runs nothing, before the execution starts.
        if let Some(desired) = &spec.mounts {
            if let Err(failure) = self.apply_mounts(vm, &session, desired) {
                if failure.code == protocol::REASON_BACKEND_UNAVAILABLE {
                    self.mark_vm_lost(vm.generation, failure.message.clone());
                }
                self.finish_and_emit(id, Terminal::new("failed", None, failure.message));
                return;
            }
        }
        let (finished_tx, finished) = mpsc::channel::<ExitOutcome>();
        self.inner.lock().unwrap().waiters.insert(id.to_owned(), finished_tx);
        vm.touch();
        let (arguments, environment) = guest_command(spec.argv, spec.env);
        let cwd = self.guest_cwd(&session, spec.cwd.as_deref()).map(String::into_bytes);
        if let Err(message) = vm.vm.exec(id.to_owned(), arguments, cwd, environment, spec.timeout, spec.resources) {
            self.inner.lock().unwrap().waiters.remove(id);
            self.finish_and_emit(id, Terminal::new("failed", None, message.clone()));
            if vm_is_gone(&message) {
                self.mark_vm_lost(vm.generation, message);
            }
            return;
        }
        // A cancel that came before the guest knew the execution is in the registry's flag, not
        // in the VM: look again now that the VM has it, so it cannot be lost between the two.
        if self.inner.lock().unwrap().registry.cancel_requested(id) {
            vm.vm.cancel(id);
        }
        let outcome = finished.recv();
        vm.touch();
        let cancelled = self.inner.lock().unwrap().registry.cancel_requested(id);
        let terminal = match outcome {
            Ok(outcome) => terminal_of(outcome, cancelled),
            Err(_) => Terminal::new("failed", None, "the VM ended without reporting the execution"),
        };
        self.finish_and_emit(id, terminal);
    }

    /// Where an execution of `session` runs in the guest: a host working directory is placed under
    /// the live share that holds it (the longest match), an absolute guest path is kept, and
    /// anything else, or no directory, means the session's workspace.
    fn guest_cwd(&self, session: &str, cwd: Option<&str>) -> Option<String> {
        let inner = self.inner.lock().unwrap();
        let info = inner.sessions.get(session)?;
        let mut shares: Vec<plan::Share> = info.shares.clone();
        shares.extend(info.workspace_share.clone());
        if let Some(cwd) = cwd {
            if let Some(translated) = plan::translate_cwd_shares(cwd, &shares) {
                return Some(translated);
            }
            if cwd.starts_with('/') {
                return Some(cwd.to_owned());
            }
        }
        Some(info.workspace_guest.clone())
    }

    /// Marks an execution terminal and emits exactly one exit event for it.
    fn finish_and_emit(&self, id: &str, terminal: Terminal) {
        let emitted = {
            let mut inner = self.inner.lock().unwrap();
            inner.specs.remove(id);
            let session = inner.registry.finish(id, terminal.clone());
            session.map(|session| (session, inner.registry.generation()))
        };
        if let Some((session, generation)) = emitted {
            if let Some(info) = self.inner.lock().unwrap().sessions.get_mut(&session) {
                info.last_activity = Instant::now();
            }
            let _ = self.writer.send(&exit_event(id, &session, generation, &terminal), &[]);
        }
        self.wake.notify_all();
    }

    /// Reports queued executions whose deadline passed, so a caller parked behind somebody else's
    /// long task gets an answer instead of silence. Also run from the maintenance tick.
    pub fn expire_queued_pass(&self) {
        self.expire_queued();
        self.try_removals();
    }

    fn expire_queued(&self) {
        let expired = self.inner.lock().unwrap().registry.expire_queued(Instant::now());
        for (id, session) in expired {
            let generation = {
                let mut inner = self.inner.lock().unwrap();
                inner.specs.remove(&id);
                inner.registry.generation()
            };
            let terminal = Terminal::timed_out("queue deadline expired");
            let _ = self.writer.send(&exit_event(&id, &session, generation, &terminal), &[]);
            eprintln!("nvxd: exec {id} expired in the queue");
        }
    }


    fn exec(self: &Arc<Self>, head: &Value) -> Result<Value, Failure> {
        let name = head.get("session").and_then(Value::as_str).unwrap_or("");
        if head.get("stdin").is_some() || head.get("input").is_some() {
            return Err(fail(protocol::REASON_STDIN_UNSUPPORTED, "NVX v1 does not support stdin or input payloads"));
        }
        let argv = strings(head.get("argv"));
        if argv.is_empty() {
            return Err(fail(protocol::REASON_PROTOCOL, "argv is required"));
        }
        let mounts = parse_mounts(head.get("mounts"));
        if mounts.iter().any(|mount| mount.id.is_empty() || mount.host_path.is_empty()) {
            return Err(fail(protocol::REASON_PROTOCOL, "a mount needs mountId and hostPath"));
        }
        if mounts.iter().any(|mount| {
            !plan::valid_mount_id(&mount.id)
                || mount.guest_path.as_deref().is_some_and(|path| !plan::valid_guest_target(path))
        }) {
            return Err(fail(
                "E_WORKSPACE_MOUNT_INVALID",
                "mountId and guestPath must be one safe /workspace/mounts component",
            ));
        }
        // The engine sends the whole set with every start, and an empty set has no key: a request without
        // mounts is the empty snapshot, which revokes what the session had.
        let desired: Option<Vec<plan::Mount>> = Some(mounts.clone());
        if !mounts.is_empty() || desired.is_some() {
            // A mount may only export a location inside the session's own tree.
            let root = {
                let inner = self.inner.lock().unwrap();
                let info = inner
                    .sessions
                    .get(name)
                    .ok_or_else(|| fail(protocol::REASON_SESSION_UNKNOWN, format!("unknown session {name}")))?;
                info.workspace.parent().map(std::path::Path::to_path_buf).unwrap_or_else(|| info.workspace.clone())
            };
            let root = std::fs::canonicalize(&root).unwrap_or(root);
            for mount in &mounts {
                let candidate = std::fs::canonicalize(&mount.host_path).unwrap_or_else(|_| PathBuf::from(&mount.host_path));
                if !candidate.starts_with(&root) {
                    return Err(fail(
                        "E_WORKSPACE_MOUNT_DENIED",
                        format!("hostPath {} is outside the allowed root {}", candidate.display(), root.display()),
                    ));
                }
            }
        }
        let timeout = match head.get("timeoutMs") {
            None => None,
            Some(value) => match number(Some(value)) {
                Some(ms) if ms > 0 => Some(Duration::from_millis(ms)),
                _ => return Err(fail(protocol::REASON_INVALID_LIMIT, "timeoutMs must be a positive integer")),
            },
        };
        let queue_deadline = number(head.get("queueDeadlineMs"))
            .filter(|ms| *ms > 0)
            .map(|ms| Instant::now() + Duration::from_millis(ms));
        let cwd = head.get("cwd").and_then(Value::as_str).filter(|cwd| !cwd.is_empty()).map(str::to_owned);
        let env: Vec<(String, String)> = head
            .get("env")
            .and_then(Value::as_object)
            .map(|env| {
                env.iter()
                    .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        let exec_id = match head.get("execId").and_then(Value::as_str) {
            Some(id) if !id.is_empty() => id.to_owned(),
            _ => format!("ex-{}-{:08x}", self.runtime_prefix, self.next_id()),
        };
        // The deployment's limits apply to every execution; a nonzero field of the request's own
        // `limits` replaces the deployment's value for that field.
        let requested = head
            .get("limits")
            .and_then(Value::as_object)
            .and_then(protocol::request_exec_limits)
            .unwrap_or_default();
        let (default_memory_mb, default_cpu, default_pids) = self.exec_defaults;
        let memory_mb = if requested.mem_mb > 0 { u64::from(requested.mem_mb) } else { default_memory_mb };
        let resources = Resources {
            memory_bytes: memory_mb * 1024 * 1024,
            cpu_percent: if requested.cpu_percent > 0 { u64::from(requested.cpu_percent) } else { default_cpu },
            pids: if requested.pids_max > 0 { u64::from(requested.pids_max) } else { default_pids },
        };
        if let Some(desired) = &desired {
            let inner = self.inner.lock().unwrap();
            if let Some(info) = inner.sessions.get(name) {
                let current: Vec<&plan::Mount> = info.shares.iter().map(|share| &share.mount).collect();
                let changes = current.len() != desired.len() || current.iter().zip(desired).any(|(a, b)| *a != b);
                if changes && inner.registry.session_has_unfinished(name) {
                    return Err(fail(
                        protocol::REASON_BACKEND_BUSY,
                        "the session has unfinished work, so its mounts cannot change",
                    ));
                }
            }
        }
        let digest = digest_of(&argv, cwd.as_deref(), &env, timeout, &mounts);
        let generation = number(head.get("generation")).unwrap_or(0);
        let accepted = {
            let mut inner = self.inner.lock().unwrap();
            inner.registry.accept(name, &exec_id, digest, generation, queue_deadline)
        };
        match accepted {
            Accept::Queued { position } => {
                let mut inner = self.inner.lock().unwrap();
                inner.specs.insert(exec_id.clone(), Spec { argv, cwd, env, timeout, resources, mounts: desired });
                if let Some(info) = inner.sessions.get_mut(name) {
                    info.last_activity = Instant::now();
                }
                drop(inner);
                self.wake.notify_all();
                Ok(json!({"handle": exec_id, "execId": exec_id, "state": "queued", "queuePosition": position}))
            }
            Accept::Duplicate { phase, terminal } => {
                let mut body = json!({
                    "handle": exec_id, "execId": exec_id, "state": phase.as_str(), "deduplicated": true,
                });
                if let Some(terminal) = terminal {
                    body["state"] = json!("finished");
                    body["outcome"] = json!(terminal.outcome);
                    body["code"] = json!(terminal.code);
                    body["detail"] = json!(terminal.detail);
                }
                Ok(body)
            }
            Accept::Conflict => Err(fail(
                protocol::REASON_EXEC_CONFLICT,
                format!("exec {exec_id} was already used with different arguments"),
            )),
            Accept::Cancelled => Ok(json!({
                "handle": exec_id, "execId": exec_id, "state": "cancelled",
                "detail": "cancelled before it was accepted",
            })),
            Accept::QueueFull => Err(fail(protocol::REASON_QUEUE_FULL, "the execution queue is full")),
            Accept::SessionUnknown => Err(fail(protocol::REASON_SESSION_UNKNOWN, format!("unknown session {name}"))),
            Accept::SessionClosing => Err(fail(protocol::REASON_SESSION_CLOSING, format!("session {name} is closing"))),
            Accept::GenerationStale => Err(fail(
                protocol::REASON_GENERATION_STALE,
                "the request names a VM generation this sidecar no longer serves",
            )),
        }
    }

    fn status(&self, exec_id: &str, handle: &str) -> Result<Value, Failure> {
        let id = if exec_id.is_empty() { handle } else { exec_id };
        if id.is_empty() {
            return Err(fail(protocol::REASON_PROTOCOL, "execId is required"));
        }
        let inner = self.inner.lock().unwrap();
        if let Some(view) = inner.registry.views().into_iter().find(|view| view.id == id) {
            return Ok(json!({
                "execId": id, "state": view.phase.as_str(), "session": view.session,
                "generation": view.generation, "queuedMs": view.queued_ms,
            }));
        }
        match inner.registry.terminal_of(id) {
            Some(terminal) => Ok(json!({
                "execId": id, "state": "finished", "outcome": terminal.outcome,
                "code": terminal.code, "detail": terminal.detail,
            })),
            // A cancel that arrived first is remembered, and the start it overtook will be
            // refused, so the caller may stop waiting for it. A plain `unknown` is not that proof.
            None if inner.registry.cancelled_before_start(id) => {
                Ok(json!({"execId": id, "state": "unknown", "cancelledBeforeStart": true}))
            }
            None => Ok(json!({"execId": id, "state": "unknown"})),
        }
    }

    fn signal(&self, head: &Value) -> Result<Value, Failure> {
        let id = head
            .get("execId")
            .and_then(Value::as_str)
            .or_else(|| head.get("handle").and_then(Value::as_str))
            .unwrap_or("");
        if id.is_empty() {
            return Err(fail(protocol::REASON_PROTOCOL, "handle or execId is required"));
        }
        enum Action {
            Emit(Terminal, String, u64),
            Stop,
            Done(Value),
            /// Nothing is known under this name. Whether that is an error depends on which name
            /// was used: a handle can only exist after its start was accepted, but an exec id is
            /// chosen by the host before the start is sent.
            Unknown,
        }
        let action = {
            let mut inner = self.inner.lock().unwrap();
            // Captured before the cancel: cancelling a queued execution makes it terminal and
            // removes it from the registry, so afterwards there is no session left to ask.
            let session = inner.registry.session_of(id).unwrap_or_default().to_owned();
            let generation = inner.registry.generation();
            match inner.registry.cancel(id) {
                Cancel::Queued(terminal) => {
                    inner.specs.remove(id);
                    Action::Emit(terminal, session, generation)
                }
                Cancel::Running => Action::Stop,
                Cancel::Finished(terminal) => Action::Done(json!({
                    "signalled": false, "state": "finished",
                    "outcome": terminal.outcome, "code": terminal.code,
                })),
                // Recorded so a start that arrives later cannot run.
                Cancel::Unknown => Action::Unknown,
            }
        };
        let by_exec_id = head.get("execId").and_then(Value::as_str).is_some_and(|value| !value.is_empty());
        match action {
            Action::Emit(terminal, session, generation) => {
                let _ = self.writer.send(&exit_event(id, &session, generation, &terminal), &[]);
                self.wake.notify_all();
                Ok(json!({"signalled": true, "state": "cancelled"}))
            }
            Action::Stop => {
                // The registry's flag is set; the VM stops the execution if it already has it,
                // and `run_one` looks at the flag once the VM has it otherwise.
                if let Some(vm) = self.vm_now() {
                    vm.vm.cancel(id);
                }
                Ok(json!({"signalled": true, "state": "stopping"}))
            }
            Action::Done(body) => Ok(body),
            Action::Unknown if by_exec_id => Ok(json!({"signalled": true, "state": "recorded"})),
            Action::Unknown => Err(fail(protocol::REASON_HANDLE_UNKNOWN, format!("unknown handle {id}"))),
        }
    }


    fn close(&self, name: &str) -> Result<Value, Failure> {
        if name.is_empty() {
            return Err(fail(protocol::REASON_PROTOCOL, "session is required"));
        }
        let _lifecycle = self.lifecycle.lock().unwrap();
        let (closed, running, removed): (Closed, Vec<String>, Option<SessionInfo>) = {
            let mut inner = self.inner.lock().unwrap();
            if !inner.sessions.contains_key(name) {
                // Closing is idempotent (plan 3.3.2): a caller whose first close reply was lost
                // must be able to repeat it and learn that the session is gone.
                return Ok(json!({
                    "closed": true, "state": "closed", "cleanupPending": false, "alreadyClosed": true,
                }));
            }
            let closed = inner.registry.close_session(name);
            let running = closed.running.clone();
            let removed = inner.sessions.remove(name);
            for id in &closed.cancelled_queued {
                inner.specs.remove(id);
            }
            (closed, running, removed)
        };
        // Queued work is already terminal; report it once, here.
        let generation = self.inner.lock().unwrap().registry.generation();
        for id in &closed.cancelled_queued {
            let terminal = Terminal::cancelled("session closed before it ran");
            let _ = self.writer.send(&exit_event(id, name, generation, &terminal), &[]);
        }
        // Every running execution of the session is stopped and waited for, but a close never
        // blocks forever: past the deadline it reports `closing` and keeps the responsibility.
        let mut cleanup_pending = false;
        if !running.is_empty() {
            if let Some(vm) = self.vm_now() {
                for id in &running {
                    vm.vm.cancel(id);
                }
            }
            let deadline = Instant::now() + CLOSE_WAIT;
            loop {
                let still_running = {
                    let inner = self.inner.lock().unwrap();
                    inner.registry.running_ids().iter().any(|active| running.contains(active))
                };
                if !still_running {
                    break;
                }
                if Instant::now() >= deadline {
                    cleanup_pending = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        if let (Some(info), Some(vm)) = (removed, self.vm_now()) {
            let mut leftovers = info.shares;
            leftovers.extend(info.workspace_share);
            for share in leftovers {
                let gone = !cleanup_pending
                    && vm.vm.mount_remove(name, &share.mount.id, &share.child, &share.target).is_ok();
                if !gone {
                    cleanup_pending = true;
                    self.inner.lock().unwrap().removals.push(Removal {
                        session: name.to_owned(),
                        mount_id: share.mount.id.clone(),
                        child: share.child.clone(),
                        target: share.target.clone(),
                        generation: vm.generation,
                    });
                }
            }
        }
        self.retire_if_idle();
        Ok(json!({
            "closed": true,
            "state": if cleanup_pending { "closing" } else { "closed" },
            "cleanupPending": cleanup_pending,
        }))
    }

    /// Retires the VM once no session and no execution refers to it.
    fn retire_if_idle(&self) -> bool {
        let idle = {
            let inner = self.inner.lock().unwrap();
            inner.registry.is_idle() && inner.vm_present
        };
        if !idle {
            self.wake.notify_all();
            return false;
        }
        // Two threads can reach this at once (the worker going idle and the last close), and
        // stopping the same VM twice would deprovision it twice.
        if self.retiring.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return false;
        }
        // Take the VM out of the slot before stopping it: `diagnostics` reads that slot, and a
        // VM whose stop is still in flight must already look gone.
        let vm = {
            let mut inner = self.inner.lock().unwrap();
            inner.vm_present = false;
            inner.waiters.clear();
            self.vm.lock().unwrap().take()
        };
        let Some(vm) = vm else {
            self.retiring.store(false, Ordering::SeqCst);
            return false;
        };
        vm.vm.stop();
        eprintln!("nvxd: retired shared VM generation={} runtimeId={}", vm.generation, vm.runtime_id);
        self.wake.notify_all();
        true
    }

    fn memory_stats(&self) -> Result<Value, Failure> {
        let vm = self.vm_now().ok_or_else(|| fail("E_BACKEND_MEMORY", "no VM is running"))?;
        let working_set = vm.memory.working_set().map_err(|e| fail("E_BACKEND_MEMORY", e))?;
        let state = vm.state.lock().unwrap();
        let inner = self.inner.lock().unwrap();
        Ok(json!({
            "workingSetMiB": working_set / (1 << 20),
            "trims": state.trims,
            "idleMs": state.last_activity.elapsed().as_millis() as u64,
            "busy": !inner.registry.running_ids().is_empty(),
            "queued": inner.registry.queued_len(),
        }))
    }

    /// Trims the working set of the shared VM now, when it is genuinely idle.
    fn memory_trim(&self) -> Result<Value, Failure> {
        let vm = self.vm_now().ok_or_else(|| fail("E_BACKEND_MEMORY", "no VM is running"))?;
        if !self.inner.lock().unwrap().registry.running_ids().is_empty() {
            return Err(fail("E_BACKEND_BUSY", "the VM is running a command"));
        }
        let (before, after) = vm.memory.trim().map_err(|e| fail("E_BACKEND_MEMORY", e))?;
        vm.state.lock().unwrap().trimmed = true;
        Ok(json!({"beforeMiB": before / (1 << 20), "afterMiB": after / (1 << 20)}))
    }

    /// Closes sessions idle past `ttl`. A session with unfinished work is never expired.
    pub fn expire_idle_pass(&self, ttl: Duration) -> Vec<String> {
        let candidates: Vec<String> = {
            let inner = self.inner.lock().unwrap();
            inner
                .sessions
                .iter()
                .filter(|(name, info)| {
                    info.last_activity.elapsed() >= ttl && !inner.registry.session_has_unfinished(name)
                })
                .map(|(name, _)| name.clone())
                .collect()
        };
        let mut expired = Vec::new();
        for name in candidates {
            if self.close(&name).is_ok() {
                eprintln!("nvxd: closed session {name}: idle past its TTL");
                expired.push(name);
            }
        }
        expired
    }

    /// Trims the VM's working set once it has been idle for `idle` and has nothing to run.
    pub fn idle_trim_pass(&self, idle: Duration) {
        let Some(vm) = self.vm_now() else { return };
        {
            let inner = self.inner.lock().unwrap();
            if !inner.registry.running_ids().is_empty() || inner.registry.queued_len() > 0 {
                return;
            }
        }
        let mut state = vm.state.lock().unwrap();
        if state.trimmed || state.last_activity.elapsed() < idle {
            return;
        }
        state.trimmed = true;
        match vm.memory.trim() {
            Ok((before, after)) => {
                state.trims += 1;
                eprintln!(
                    "nvxd: trimmed idle VM generation={}: {} MiB -> {} MiB",
                    vm.generation,
                    before >> 20,
                    after >> 20
                );
            }
            Err(error) => eprintln!("nvxd: cannot trim the VM: {error}"),
        }
    }

    /// Stops the time-based passes; they exit within one tick.
    pub fn stop_maintenance(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Drops everything because nobody is listening any more. Stopping the VM is what ends the
    /// work, so the sidecar's exit time does not depend on how long the caller's command runs;
    /// the bookkeeping is dropped first so nothing tries to report into a dead pipe.
    pub fn shutdown_now(&self) {
        self.stop_maintenance();
        let _lifecycle = self.lifecycle.lock().unwrap();
        {
            let mut inner = self.inner.lock().unwrap();
            inner.registry.new_generation();
            inner.sessions.clear();
            inner.specs.clear();
            inner.waiters.clear();
        }
        self.retire_if_idle();
    }
}


/// A request cannot change the mode selected for this sidecar's VM lifecycle. Validated before any
/// VM boot so a refused policy has no effects. This build serves the shared, non-isolated mode:
/// session isolation and a network policy are refused the way a sidecar started without them
/// refuses them.
fn reject_unsupported_session_options(head: &Value) -> Result<(), Failure> {
    // The C++ side writes scalar JSON values as strings.
    let boolean = |value: &Value| match value {
        Value::Bool(value) => Some(*value),
        Value::String(value) if value == "true" => Some(true),
        Value::String(value) if value == "false" => Some(false),
        _ => None,
    };
    if let Some(mode) = head.get("sessionIsolation") {
        if boolean(mode) != Some(false) {
            return Err(fail(
                "E_SESSION_MODE_MISMATCH",
                "sessionIsolation must match the startup mode; drain and recreate the backend to migrate",
            ));
        }
    }
    if head.get("networkPolicy").is_some() {
        return Err(fail(
            "E_SESSION_NETWORK_UNSUPPORTED",
            "isolated sessions here support only networkPolicy=deny",
        ));
    }
    if let Some(independent) = head.get("independentKernel") {
        if boolean(independent) != Some(false) {
            return Err(fail("E_SESSION_KERNEL_UNSUPPORTED", "sessions share the VM kernel"));
        }
    }
    Ok(())
}

/// Whether a failure to start an execution means the VM is gone rather than the execution bad.
fn vm_is_gone(message: &str) -> bool {
    message.contains("the VM is gone")
        || message.contains("control session ended")
        || message.contains("did not answer")
        || message.contains("is not running")
}

/// The guest takes the program as an absolute path and exactly the environment it is given: a bare
/// program name is resolved by the guest shell, which keeps `argv` exact, and PATH and HOME get
/// defaults the caller did not name.
fn guest_command(argv: Vec<String>, env: Vec<(String, String)>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut arguments: Vec<Vec<u8>> = Vec::new();
    if !argv.first().is_some_and(|program| program.starts_with('/')) {
        arguments.extend(["/bin/sh", "-c", "exec \"$@\"", "sh"].map(|part| part.as_bytes().to_vec()));
    }
    arguments.extend(argv.into_iter().map(String::into_bytes));
    let mut environment: Vec<Vec<u8>> =
        env.iter().map(|(name, value)| format!("{name}={value}").into_bytes()).collect();
    if !env.iter().any(|(name, _)| name == "PATH") {
        environment.push(b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_vec());
    }
    if !env.iter().any(|(name, _)| name == "HOME") {
        environment.push(b"HOME=/tmp".to_vec());
    }
    (arguments, environment)
}

/// How an execution ended, in the registry's vocabulary.
fn terminal_of(outcome: ExitOutcome, cancelled: bool) -> Terminal {
    if cancelled {
        return Terminal::new("cancelled", None, "cancelled by the caller");
    }
    if let Some(failure) = outcome.launch_failure {
        return Terminal::new("failed", None, failure);
    }
    match outcome.kind {
        "exited" => Terminal::new("exited", outcome.code.map(|code| code as i32), ""),
        "signaled" => Terminal::new("signaled", outcome.code.map(|code| code as i32), outcome.detail),
        "timeout" => Terminal::new("timedOut", None, ""),
        "cancelled" => Terminal::new("cancelled", None, ""),
        _ => Terminal::new("failed", None, "the execution was lost with its VM"),
    }
}

fn exit_event(handle: &str, session: &str, generation: u64, terminal: &Terminal) -> Value {
    json!({
        "event": protocol::EVENT_EXEC_EXIT,
        "handle": handle,
        "execId": handle,
        "session": session,
        "generation": generation,
        "outcome": terminal.outcome,
        "code": terminal.code,
        "detail": terminal.detail,
    })
}

/// The C++ side builds requests with property trees, which write every scalar as a string.
/// A caller-chosen name reduced to something safe to use in a guest path or an export name.
fn safe_name(session: &str) -> String {
    let safe: String = session
        .chars()
        .map(|character| if character.is_ascii_alphanumeric() || character == '-' || character == '_' { character } else { '_' })
        .collect();
    if safe.is_empty() { "session".to_owned() } else { safe }
}

fn parse_mounts(value: Option<&Value>) -> Vec<plan::Mount> {
    let items = value.and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    items
        .iter()
        .map(|item| plan::Mount {
            id: item["mountId"].as_str().unwrap_or("").to_owned(),
            host_path: item["hostPath"].as_str().unwrap_or("").to_owned(),
            read_only: item["mode"].as_str().is_some_and(|mode| mode.eq_ignore_ascii_case("ro")),
            guest_path: item["guestPath"].as_str().filter(|path| !path.is_empty()).map(str::to_owned),
        })
        .collect()
}

fn number(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    value.as_u64().or_else(|| value.as_str()?.trim().parse().ok())
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect()
}

/// Digest of everything that makes two requests the same command. Two requests that share an id
/// but differ here are a contract error, never a silent second run.
fn digest_of(
    argv: &[String],
    cwd: Option<&str>,
    env: &[(String, String)],
    timeout: Option<Duration>,
    mounts: &[plan::Mount],
) -> u64 {
    let mut parts: Vec<String> = argv.to_vec();
    for mount in mounts {
        parts.push(format!(
            "mount={}={}={}={}",
            mount.id,
            mount.host_path,
            mount.read_only,
            mount.guest_path.as_deref().unwrap_or("")
        ));
    }
    parts.push(format!("cwd={}", cwd.unwrap_or("")));
    for (key, value) in env {
        parts.push(format!("env={key}={value}"));
    }
    parts.push(format!("timeout={}", timeout.map(|value| value.as_millis() as u64).unwrap_or(0)));
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

