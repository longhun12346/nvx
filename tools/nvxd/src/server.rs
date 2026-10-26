//! Request handlers.
//!
//! One VM serves every logical session this sidecar was opened for, and each session holds
//! a *set* of executions. The VM still runs one execution at a time (the guest agent is
//! single-task until P6), so a second request is queued instead of being refused: capacity
//! answers "not yet", never "wrong session".
//!
//! Three rules shape this file, all of them from the productization plan:
//!
//! * **Identity before execution.** The host names an execution before it sends it, and the
//!   id keeps working across a lost reply, a duplicate start and a cancel that overtakes its
//!   start. Nothing here relies on a handle that only exists after the reply.
//! * **Start reply before events.** A dispatched execution is dispatched but *gated*: its
//!   events are emitted only after the reply has been written, so a caller never sees output
//!   for a request it has not been answered yet.
//! * **Closing is not killing the VM.** Closing a session takes away that session's work and
//!   leaves the other sessions running on the same VM; the VM is retired only when nothing
//!   refers to it any more.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use aci_edge_sandboxes::nvx::host::filesystem::resolve_guest_path;
use aci_edge_sandboxes::nvx::host::poc_live::LiveShare;
use aci_edge_sandboxes::nvx::protocol::ExecLimits;
use aci_edge_sandboxes::openvmm::OpenVmmBackend;
use aci_edge_sandboxes::{
    AciEdgeSandbox, Canceller, ExecOutcome, ExecRequest, ProvisionRequest, SandboxId,
};
use serde_json::{Value, json};

use crate::plan::{self, Mount, Share, Step};
use crate::protocol;
use crate::registry::{Accept, Cancel, Closed, Registry, Terminal};
use crate::winmem::VmmMemory;

const SHARE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a close waits for the session's running execution to be cleaned up before it
/// reports `closing` and keeps the responsibility in the background.
const CLOSE_WAIT: Duration = Duration::from_secs(5);
/// How long a dispatched execution may wait for its start reply before it runs anyway. The
/// only way to reach this is a reply that could not be written, in which case stopping is
/// not an improvement over running the work the caller already asked for.
const RELEASE_WAIT: Duration = Duration::from_secs(10);
/// How long a requested export removal may wait for the guest to be free.
///
/// The contract is "wait for the guest to release the lease, then remove". A guest that stays
/// busy past this is not converging, and the contract's answer to that is to destroy the dirty
/// VM — not to keep a half-cleaned VM admissible.
const REMOVAL_DEADLINE: Duration = Duration::from_secs(30);

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

/// The one VM this sidecar runs, named by a generation that changes whenever it is replaced.
pub struct Vm {
    sandbox: SandboxId,
    generation: u64,
    runtime_id: String,
    memory: Option<VmmMemory>,
    state: Mutex<VmState>,
}

struct VmState {
    last_activity: Instant,
    trimmed: bool,
    trims: u64,
}

impl Vm {
    fn touch(&self) {
        let mut state = self.state.lock().unwrap();
        state.last_activity = Instant::now();
        state.trimmed = false;
    }

    fn idle(&self) -> Duration {
        self.state.lock().unwrap().last_activity.elapsed()
    }
}

/// A logical session: routing and authorisation unit inside the VM, not a VM of its own.
struct SessionInfo {
    guest_session: Option<u64>,
    workspace: PathBuf,
    /// Prefix of every export name this session owns. Export names live in one namespace for
    /// the whole VM, so they cannot simply count from zero per session.
    prefix: String,
    /// Where this session's workspace lives in the guest. Unique per session: on a shared VM
    /// there is no single `/workspace` that could mean two different directories.
    workspace_guest: String,
    /// The export behind `workspace_guest`, kept apart from `shares` so reconciling mounts
    /// can never remove the session's own workspace.
    workspace_export: Option<WorkspaceExport>,
    /// Exports this session registered for its mounts, and nothing else. Reconciling it must
    /// never touch another session's exports.
    shares: Vec<Share>,
    next_child: u64,
    last_activity: Instant,
    /// Digest of the mount set currently applied in the guest, so an execution that asks for the
    /// same set does not reconcile (and re-mount) everything again.
    applied_mounts: Option<u64>,
    /// Serialises "is this set already applied?" with the reconcile that applies it.
    ///
    /// The session lock cannot do this: reconciling talks to the export channel and to the guest,
    /// which must not happen under the lock that every request needs. Without it two executions
    /// that start together both find the set unapplied and both reconcile it.
    mount_lock: Arc<Mutex<()>>,
}

struct WorkspaceExport {
    child: String,
    target: String,
}

/// What the worker needs to run an execution. Kept apart from the registry so the lifecycle
/// state machine stays free of VM types and can be tested without one.
#[derive(Clone)]
struct Spec {
    argv: Vec<String>,
    /// The working directory as the caller named it, resolved against the live shares when the
    /// execution actually runs: a mount's guest path is only known once it has been exported.
    cwd_host: Option<String>,
    env: Vec<(String, String)>,
    timeout: Option<Duration>,
    /// Per-execution limits this request asked for, if any. Zero fields keep the deployment's
    /// configured value; a request that names none sends none.
    limits: Option<ExecLimits>,
    /// The mounts this execution asked for, applied in the idle gap just before it runs.
    mounts: Vec<Mount>,
}

/// An export whose removal is waiting for the guest to become free.
///
/// Waiting is part of the contract ("wait until the guest releases the lease, then remove");
/// it is not a place to park work that cannot be cleaned. A removal that actually fails, or
/// that cannot happen before [`REMOVAL_DEADLINE`], makes the VM dirty and it is destroyed.
struct Removal {
    child: String,
    source_target: String,
    target: String,
    session: String,
    guest_session: Option<u64>,
    since: Instant,
}

struct Inner {
    registry: Registry,
    sessions: HashMap<String, SessionInfo>,
    specs: HashMap<String, Spec>,
    cancels: HashMap<String, Canceller>,
    removals: Vec<Removal>,
    /// Guest paths this VM has ever exported, including the revoked ones.
    ///
    /// Revoked paths are tombstoned for the life of the VM: the protocol promises that a
    /// revoked share id is never reused within one VM lifetime, so a later session cannot be
    /// handed a path whose binding somebody else may still hold open.
    guest_targets: std::collections::HashSet<String>,
    /// How many runtime mappings the guest already knows. The guest numbers each bind, and
    /// that numbering is per VM — not per session — so it cannot live in `SessionInfo`.
    next_sequence: usize,
    /// Set while a fresh VM must be created; executions are refused rather than queued
    /// behind a boot that may fail.
    vm_present: bool,
    /// Control features the running guest advertised at boot (0 when no VM is up).
    ///
    /// Kept so `probe` can answer truthfully about concurrency and per-execution limits
    /// instead of having the caller assume what the image can do.
    guest_features: u64,
}

/// Counters of what this sidecar has done since it started.
#[derive(Debug, Default)]
struct Stats {
    requests: u64,
    failures: u64,
    execs: u64,
    shares_added: u64,
    shares_removed: u64,
    /// Revocations the guest refused for a real reason (not "already unmounted").
    ///
    /// Expected to stay at zero: unmounting is refused only while something in the guest still
    /// holds the path. Watching this instead of designing for it is the cheap way to find out
    /// whether that assumption holds in the field.
    shares_remove_failed: u64,
    /// Mount sets actually reconciled in the guest, and executions that reused the applied set.
    ///
    /// The pair is the evidence for "the same mount revision does not re-mount": a parallel run
    /// should show one apply and several skips, not one apply per execution.
    mounts_applied: u64,
    mounts_skipped: u64,
    last_failure: Option<(String, String)>,
}

pub type Writer = Arc<crate::outbound::Writer>;

/// Metadata key under which the backend reports the guest's control features.
const GUEST_FEATURES_KEY: &str = "guestFeatures";
/// Guest feature bit `EXEC_SLOTS`: the agent serves several executions at once
/// (`guest/common/nvx-managed-agent.c`, `FEATURE_EXEC_SLOTS`).
const GUEST_FEATURE_EXEC_SLOTS: u64 = 1 << 8;
/// Guest feature bit `EXEC_LIMITS`: the agent enforces per-execution memory/CPU/pids limits on
/// the execution's own cgroup, and refuses an execution whose limit it cannot write.
const GUEST_FEATURE_EXEC_LIMITS: u64 = 1 << 9;
const GUEST_FEATURE_SESSION_ISOLATION: u64 = 1 << 10;

pub struct Context {
    backend: Arc<OpenVmmBackend>,
    client: AciEdgeSandbox,
    provenance: Value,
    writer: Writer,
    max_queue: usize,
    max_sessions: usize,
    /// How many executions the VM may run at once. One keeps the serial behaviour; more is only
    /// announced to callers through `probe`, and only works with a guest image that advertises
    /// concurrent executions.
    max_running: usize,
    session_isolation: bool,
    /// Empty directory provisioned with every VM so the virtio-fs device (and therefore the
    /// export channel) exists before the first session's workspace is exported.
    export_anchor: PathBuf,
    /// Serialises VM creation and retirement against session open and close, so two opens
    /// cannot both decide to boot a VM.
    lifecycle: Mutex<()>,
    vm: Mutex<Option<Arc<Vm>>>,
    inner: Mutex<Inner>,
    /// Wakes the worker when there is work, when a gate opens, or when the VM changes.
    wake: Condvar,
    worker_running: AtomicBool,
    /// Set while one thread is stopping the VM, so a second one cannot stop it again.
    retiring: AtomicBool,
    /// Asked to stop the time-based passes. Without it the maintenance thread would keep the
    /// context (and its writer handle) alive past shutdown, and the output thread would never
    /// see the connection close.
    stopping: AtomicBool,
    counter: Mutex<u64>,
    guest_session_counter: Mutex<u64>,
    runtime_prefix: String,
    stats: Mutex<Stats>,
}

impl Context {
    pub fn new(
        backend: Arc<OpenVmmBackend>,
        client: AciEdgeSandbox,
        provenance: Value,
        writer: Writer,
        max_queue: usize,
        max_sessions: usize,
        max_running: usize,
        session_isolation: bool,
        export_anchor: PathBuf,
    ) -> Self {
        Self {
            backend,
            client,
            provenance,
            writer,
            max_queue: max_queue.max(1),
            max_sessions,
            max_running: max_running.max(1),
            session_isolation,
            export_anchor,
            lifecycle: Mutex::new(()),
            vm: Mutex::new(None),
            inner: Mutex::new(Inner {
                registry: Registry::new(max_queue.max(1), max_running.max(1), 0),
                sessions: HashMap::new(),
                guest_targets: std::collections::HashSet::new(),
                next_sequence: 0,
                specs: HashMap::new(),
                cancels: HashMap::new(),
                removals: Vec::new(),
                vm_present: false,
                guest_features: 0,
            }),
            wake: Condvar::new(),
            worker_running: AtomicBool::new(false),
            retiring: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            counter: Mutex::new(0),
            guest_session_counter: Mutex::new(0),
            runtime_prefix: {
                use std::hash::Hash;
                use std::hash::Hasher;
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

    /// The next guest-mapping index, which the guest numbers per VM rather than per session.
    fn take_sequence(&self) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let value = inner.next_sequence;
        inner.next_sequence += 1;
        value
    }

    fn vm_now(&self) -> Option<Arc<Vm>> {
        self.vm.lock().unwrap().clone()
    }

    pub fn handle(self: &Arc<Self>, head: &Value) -> Result<Value, Failure> {
        let text = |key: &str| head.get(key).and_then(Value::as_str).unwrap_or("");
        match text("op") {
            protocol::OP_PROBE => self
                .client
                .probe()
                .map(|()| {
                    let inner = self.inner.lock().unwrap();
                    let generation = inner.registry.generation();
                    let features = inner.guest_features;
                    json!({"backend": "nvx-whp", "provenance": self.provenance,
                           "vmGeneration": generation,
                           "capabilities": {
                               "sharedVm": true,
                               // Configured, not guessed: a guest without concurrent executions
                               // is refused at startup (E_NVX_GUEST_NO_SLOTS), so once a VM is
                               // up this claim is true. The caller reads maxRunningPerVm.
                               "parallelExec": self.max_running > 1,
                               "maxRunningPerVm": self.max_running,
                               // Slots are counted per VM: a single session may use every one
                               // of them while the other sessions are idle.
                               "maxRunningPerSession": self.max_running,
                               // Diagnostic, not a gate: the guest's own control feature bits, 0
                               // before the first session opens a VM. An image that cannot enforce
                               // per-execution limits refuses such an execution explicitly rather
                               // than accepting it and ignoring the limit.
                               "guestFeatures": features,
                               "sessionIsolation": self.session_isolation
                                   && features & GUEST_FEATURE_SESSION_ISOLATION != 0,
                           }})
                })
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
            protocol::OP_SIGNAL => self.signal(head),
            protocol::OP_SESSION_CLOSE => self.close(text("session")),
            protocol::OP_EXEC_STATUS => self.status(text("execId"), text("handle")),
            protocol::OP_MEMORY_STATS => self.memory_stats(),
            protocol::OP_MEMORY_TRIM => self.memory_trim(),
            protocol::OP_DIAGNOSTICS => Ok(self.diagnostics()),
            other => Err(fail(
                protocol::REASON_PROTOCOL,
                format!("unknown op {other:?}"),
            )),
        }
    }

    /// Times, counts and logs one request, then returns whatever [`Self::handle`] decided.
    pub fn handle_logged(self: &Arc<Self>, head: &Value) -> Result<Value, Failure> {
        let started = std::time::Instant::now();
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
                stats.last_failure = Some((failure.code.to_owned(), failure.message.clone()));
            }
        }
        let verbose = std::env::var_os("NVXD_LOG_REQUESTS").is_some();
        match &outcome {
            Ok(_) if elapsed_ms < 1000 && !verbose => {}
            Ok(_) => eprintln!(
                "nvxd: request op={op} session={session} result=ok durationMs={elapsed_ms}"
            ),
            Err(failure) => eprintln!(
                "nvxd: request op={op} session={session} result=error \
                 reasonCode={} durationMs={elapsed_ms} message={}",
                failure.code, failure.message
            ),
        }
        outcome
    }

    /// Opens the start gate for a dispatched execution once its reply is on the wire.
    pub fn release(&self, exec_id: &str) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.registry.release(exec_id);
        }
        self.wake.notify_all();
    }

    fn diagnostics(&self) -> Value {
        let stats = self.stats.lock().unwrap();
        let inner = self.inner.lock().unwrap();
        let vm = self.vm.lock().unwrap();
        let sessions: Vec<Value> = inner
            .sessions
            .iter()
            .map(|(name, info)| {
                json!({
                    "session": name,
                    // The same runtime id for every session is the point: they share one VM.
                    "runtimeId": vm.as_ref().map(|vm| vm.runtime_id.clone()),
                    "generation": vm.as_ref().map(|vm| vm.generation),
                    "workspace": info.workspace.display().to_string(),
                    "shares": info.shares.len(),
                    "mountedOnce": info.next_child,
                    "idleMs": info.last_activity.elapsed().as_millis() as u64,
                    "execs": inner
                        .registry
                        .views()
                        .into_iter()
                        .filter(|view| view.session == *name)
                        .count(),
                    // Per-session load. Slots are counted per VM and a session may hold all of
                    // them, so these two numbers plus maxRunning are the whole concurrency story.
                    "running": inner.registry.running_for_session(name),
                    "queued": inner.registry.queued_for_session(name),
                    "busy": inner
                        .registry
                        .views()
                        .into_iter()
                        .any(|view| view.session == *name && view.phase == crate::registry::Phase::Running),
                })
            })
            .collect();
        let execs: Vec<Value> = inner
            .registry
            .views()
            .into_iter()
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
            // How long the oldest unremoved export has been waiting. A number that keeps
            // growing is the signal that a directory somebody revoked is still bound in the
            // guest — support can see it without a debugger.
            "cleanupOldestMs": inner
                .removals
                .iter()
                .map(|removal| removal.since.elapsed().as_millis() as u64)
                .max()
                .unwrap_or(0),
            "outbound": {
                "frames": self.writer.stats().frames(),
                "refused": self.writer.stats().refused(),
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
            return Err(fail(
                protocol::REASON_PROTOCOL,
                "session and workspace are required",
            ));
        }
        // The VM is created once and shared; the lock only covers the decision, never a run.
        let _lifecycle = self.lifecycle.lock().unwrap();
        {
            let inner = self.inner.lock().unwrap();
            if inner.sessions.contains_key(name) {
                return Err(fail(protocol::REASON_PROTOCOL, "session already open"));
            }
            if self.max_sessions > 0 && inner.sessions.len() >= self.max_sessions {
                return Err(fail(
                    protocol::REASON_BACKEND_BUSY,
                    format!(
                        "{} sessions are already open, the limit is {}",
                        inner.sessions.len(),
                        self.max_sessions
                    ),
                ));
            }
        }
        let target = guest_workspace(name);
        let workspace_path = PathBuf::from(workspace);
        // A VM that goes away while its first session opens is replaced once: the workspace
        // export then fails against a machine that no longer answers, and making the caller
        // retry the boot would report a dead VM as an unusable workspace.
        let mut attempt = 0;
        loop {
            attempt += 1;
            let vm = match self.vm_now() {
                Some(vm) => vm,
                None => self.boot_vm(name, workspace, memory_mib)?,
            };
            {
                let mut inner = self.inner.lock().unwrap();
                if !inner.registry.open_session(name) {
                    return Err(fail(protocol::REASON_PROTOCOL, "session already open"));
                }
                inner.sessions.insert(
                    name.to_owned(),
                    SessionInfo {
                        guest_session: None,
                        workspace: workspace_path.clone(),
                        prefix: safe_name(name),
                        workspace_guest: target.clone(),
                        workspace_export: None,
                        shares: Vec::new(),
                        next_child: 0,
                        last_activity: Instant::now(),
                        applied_mounts: None,
                        mount_lock: Arc::new(Mutex::new(())),
                    },
                );
            }
            self.spawn_worker();
            // The session's own workspace is registered now: it is part of what opening a
            // session means, and a session whose files are not reachable cannot be used at all.
            // Mounts are added later, in an idle gap, because those are changes to a live
            // directory tree.
            match self.ensure_workspace_export(&vm, name) {
                Ok(()) => {
                    if self.session_isolation {
                        let features = self.inner.lock().unwrap().guest_features;
                        if features & GUEST_FEATURE_SESSION_ISOLATION == 0 {
                            self.rollback_open_session(&vm, name);
                            return Err(fail(
                                "E_NVX_GUEST_NO_SESSION_ISOLATION",
                                "the guest image does not advertise isolated guest sessions",
                            ));
                        }
                        let id = {
                            let mut counter = self.guest_session_counter.lock().unwrap();
                            *counter += 1;
                            *counter
                        };
                        let spec = aci_edge_sandboxes::nvx::protocol::GuestSessionSpec {
                            id,
                            workspace: target.clone(),
                            network: aci_edge_sandboxes::nvx::protocol::SessionNetwork::Deny,
                        };
                        if let Err(error) = self.backend.open_guest_session(&vm.sandbox, &spec) {
                            self.rollback_open_session(&vm, name);
                            return Err(fail("E_SESSION_OPEN_FAILED", error));
                        }
                        self.inner
                            .lock()
                            .unwrap()
                            .sessions
                            .get_mut(name)
                            .expect("session inserted before workspace export")
                            .guest_session = Some(id);
                    }
                    return Ok(json!({
                        "workspaceGuestPath": if self.session_isolation {
                            "/workspace"
                        } else {
                            target.as_str()
                        },
                        "runtimeId": vm.runtime_id,
                        "vmGeneration": vm.generation,
                        "sharedVm": true,
                    }));
                }
                Err(failure)
                    if attempt == 1
                        && failure.code == protocol::REASON_BACKEND_UNAVAILABLE =>
                {
                    // ensure_workspace_export already retired the VM and dropped the session, so
                    // the next round boots a new instance and registers the session again.
                    continue;
                }
                Err(failure) => return Err(failure),
            }
        }
    }

    fn rollback_open_session(&self, vm: &Arc<Vm>, name: &str) {
        let export = {
            let mut inner = self.inner.lock().unwrap();
            inner.registry.close_session(name);
            inner
                .sessions
                .remove(name)
                .and_then(|info| info.workspace_export)
        };
        if let Some(export) = export {
            if let Err(error) =
                self.backend.remove_share(&vm.sandbox, &export.child, &export.target, SHARE_TIMEOUT)
            {
                self.mark_vm_lost(format!("isolated session rollback failed: {error}"));
            }
        }
    }

    /// Exports the session's workspace at its own guest path, once.
    ///
    /// The session stays in the map while the export runs: exporting is a slow channel call,
    /// and a session that vanished for its duration would be invisible to `diagnostics`, to
    /// its own queued work and to any concurrent request.
    fn ensure_workspace_export(&self, vm: &Arc<Vm>, name: &str) -> Result<(), Failure> {
        let (prefix, workspace, workspace_guest, next_child, already) = {
            let inner = self.inner.lock().unwrap();
            let info = inner
                .sessions
                .get(name)
                .ok_or_else(|| fail(protocol::REASON_SESSION_UNKNOWN, format!("unknown session {name}")))?;
            (
                info.prefix.clone(),
                info.workspace.clone(),
                info.workspace_guest.clone(),
                info.next_child,
                info.workspace_export.is_some(),
            )
        };
        if already {
            return Ok(());
        }
        let child = format!("{prefix}-ws{next_child}");
        let target = workspace_guest;
        let live = LiveShare {
            child: &child,
            host_path: &workspace,
            target: &target,
            read_only: false,
        };
        let outcome = self
            .backend
            .add_share(&vm.sandbox, self.take_sequence(), &live, SHARE_TIMEOUT)
            .map_err(|error| {
                // A VM that has gone away cannot export anything; saying "mount failed" would
                // send the caller looking at paths instead of at a VM that needs rebuilding.
                let lost = self.vm_is_gone(&error);
                let failure = fail(
                    if lost {
                        protocol::REASON_BACKEND_UNAVAILABLE
                    } else {
                        "E_WORKSPACE_MOUNT_FAILED"
                    },
                    error,
                );
                if lost {
                    self.mark_vm_lost(failure.message.clone());
                }
                failure
            });
        if outcome.is_ok() {
            let mut inner = self.inner.lock().unwrap();
            if let Some(info) = inner.sessions.get_mut(name) {
                info.next_child += 1;
                info.workspace_export = Some(WorkspaceExport { child, target });
            }
            self.stats.lock().unwrap().shares_added += 1;
            return Ok(());
        }
        // Nothing half-open: a session that cannot reach its workspace is not a session.
        let mut inner = self.inner.lock().unwrap();
        inner.sessions.remove(name);
        inner.registry.close_session(name);
        outcome
    }

    /// Applies this session's mounts, in a gap where the VM runs nothing.
    fn apply_mounts(
        &self,
        vm: &Arc<Vm>,
        name: &str,
        desired: &[Mount],
    ) -> Result<(), Failure> {
        // Snapshot, export, write back: the session keeps its identity (and its old shares)
        // for anything that looks at it while the (slow) export channel is being used.
        let (prefix, guest_session, mut shares, mut next_child) = {
            let inner = self.inner.lock().unwrap();
            let info = inner
                .sessions
                .get(name)
                .ok_or_else(|| fail(protocol::REASON_SESSION_UNKNOWN, format!("unknown session {name}")))?;
            (
                info.prefix.clone(),
                info.guest_session,
                info.shares.clone(),
                info.next_child,
            )
        };
        let outcome =
            self.reconcile(vm, &prefix, guest_session, &mut shares, &mut next_child, desired);
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(info) = inner.sessions.get_mut(name) {
                info.shares = shares;
                info.next_child = next_child;
            }
        }
        outcome
    }

    /// Whether a backend failure means the VM itself is gone, rather than the request being
    /// refused. A dead VM must stop being admissible: leaving it "present" makes the next
    /// `session.open` export into a corpse (which takes the full export timeout) and then
    /// reports the failure as a mount problem.
    fn vm_is_gone(&self, error: &aci_edge_sandboxes::Error) -> bool {
        use aci_edge_sandboxes::ErrorCode;
        match error.code() {
            ErrorCode::NotStarted | ErrorCode::AlreadyStopped | ErrorCode::StaleId => true,
            // A control session that ends mid-command is how a killed VMM shows up through
            // the exec path, where the code is the generic backend error.
            ErrorCode::BackendError => {
                let message = error.message();
                message.contains("control session ended")
                    || message.contains("is not running")
                    || message.contains("VMM process is gone")
                    // The VMM's own export pipe is gone or stopped answering: nothing but a VM
                    // that went away produces that, and exporting into it only burns the
                    // timeout and reports a mount failure.
                    || message.contains("cannot reach the export channel")
                    || message.contains("the VMM refused to export")
            }
            _ => false,
        }
    }

    /// Terminates everything this VM instance owned and retires it.
    ///
    /// The next `session.open` boots a new generation. Old exec ids and sessions are not
    /// reused (plan 3.3: an old generation is never revived, and no command is replayed).
    fn mark_vm_lost(&self, detail: String) {
        let victims: Vec<(String, String, u64)> = {
            let inner = self.inner.lock().unwrap();
            let generation = inner.registry.generation();
            inner
                .registry
                .views()
                .into_iter()
                .map(|view| (view.id, view.session, generation))
                .collect()
        };
        for (id, session, generation) in victims {
            // Everyone waiting on this VM learns the same thing: it is gone.
            let terminal = Terminal::new("failed", None, detail.clone());
            {
                let mut inner = self.inner.lock().unwrap();
                inner.specs.remove(&id);
                if inner.registry.finish(&id, terminal.clone()).is_some() {
                    // fall through to emit below
                } else {
                    continue;
                }
            }
            let event = exit_event(&id, &session, generation, &terminal);
            let _ = self.writer.send(&event, &[]);
        }
        {
            let mut inner = self.inner.lock().unwrap();
            inner.registry.new_generation();
            inner.sessions.clear();
            inner.specs.clear();
            inner.cancels.clear();
            inner.removals.clear();
            inner.guest_targets.clear();
            inner.next_sequence = 0;
        }
        eprintln!("nvxd: the VM was lost: {detail}");
        self.retire_if_idle();
    }

    /// Boots the VM that every session will share. Called only with `lifecycle` held.
    ///
    /// No session's workspace is pinned here: the VM outlives whichever session opened it
    /// first, so a workspace is exported per session (see [`Self::prepare_exports`]). What is
    /// pinned is an empty anchor directory, because OpenVMM only creates the virtio-fs device
    /// — and with it the export channel those per-session exports need — when the sandbox is
    /// provisioned with at least one path. The anchor is empty on purpose: the guest may read
    /// it, so it must never hold the sidecar's state or capability.
    fn boot_vm(&self, name: &str, _workspace: &str, memory_mib: u32) -> Result<Arc<Vm>, Failure> {
        std::fs::create_dir_all(&self.export_anchor)
            .map_err(|error| fail(protocol::REASON_PROTOCOL, error))?;
        let anchor = self.export_anchor.display().to_string();
        // The anchor is *read-write* on purpose: the sandbox's aggregate root inherits its
        // mount mode, so a read-only anchor would make every session's workspace and every
        // mount read-only in the guest no matter what the request asked for. The directory
        // is empty and owned by this sidecar, so exposing it writable exposes nothing.
        let request: ProvisionRequest = serde_json::from_value(json!({
            "filesystem": { "readwritePaths": [anchor] },
            "microvm": { "provision": { "memoryMib": memory_mib } }
        }))
        .map_err(|error| fail(protocol::REASON_PROTOCOL, error))?;
        let sandbox = self
            .client
            .provision(&request)
            .map_err(|error| fail("E_BACKEND_START", error))?
            .sandbox_id;
        let started = match self.client.start(&sandbox) {
            Ok(started) => started,
            Err(error) => {
                let _ = self.client.deprovision(&sandbox);
                return Err(fail("E_BACKEND_START", error));
            }
        };
        // What this image can actually do, remembered for `probe`: a caller must not have to
        // guess whether concurrency and per-execution limits are enforced.
        let features = started
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get(GUEST_FEATURES_KEY))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        // Concurrent executions need a guest that serves them; an image without the feature
        // would queue every execution behind one anyway, so claiming parallelism would be a lie.
        if self.max_running > 1 && features & GUEST_FEATURE_EXEC_SLOTS == 0 {
            let _ = self.client.deprovision(&sandbox);
            return Err(fail(
                "E_NVX_GUEST_NO_SLOTS",
                format!(
                    "the guest image does not advertise concurrent executions, but \
                     --max-running is {}; install the matching runtime or lower the limit",
                    self.max_running
                ),
            ));
        }
        let memory = match self.backend.vmm_process(&sandbox) {
            Ok((pid, start_time)) => Some(VmmMemory::new(pid, start_time)),
            Err(error) => {
                eprintln!(
                    "nvxd: no VMM process for {name}: {error}; idle trimming is off for it"
                );
                None
            }
        };
        let mut inner = self.inner.lock().unwrap();
        let generation = inner.registry.new_generation();
        let runtime_id = format!("rt-{}-{:08x}", self.runtime_prefix, self.next_id());
        let vm = Arc::new(Vm {
            sandbox,
            generation,
            runtime_id,
            memory,
            state: Mutex::new(VmState {
                last_activity: Instant::now(),
                trimmed: false,
                trims: 0,
            }),
        });
        inner.vm_present = true;
        inner.guest_features = features;
        drop(inner);
        self.retiring.store(false, Ordering::SeqCst);
        *self.vm.lock().unwrap() = Some(Arc::clone(&vm));
        eprintln!(
            "nvxd: booted shared VM generation={} runtimeId={}",
            vm.generation, vm.runtime_id
        );
        Ok(vm)
    }

    fn spawn_worker(self: &Arc<Self>) {
        if self.worker_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let this = Arc::clone(self);
        std::thread::spawn(move || this.worker_loop());
    }

    /// Fills the VM's free run slots, and runs each execution it hands out in its own thread.
    ///
    /// `run_one` waits for its execution to end, so a single blocking loop could not keep more
    /// than one execution alive; the loop therefore only dispatches, and each execution gets a
    /// thread. Mount changes stay a per-session decision: the session that owns the work refuses
    /// them itself while it has unfinished executions.
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
                self.try_removals(true);
                // With nothing left to run, a VM that no session refers to any more is
                // retired here: closing the last session cannot always do it itself,
                // because its exports may still be waiting for an idle gap.
                self.retire_if_idle();
                let inner = self.inner.lock().unwrap();
                if !inner.vm_present {
                    self.worker_running.store(false, Ordering::SeqCst);
                    return;
                }
                let _ = self
                    .wake
                    .wait_timeout(inner, Duration::from_millis(200))
                    .unwrap();
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
        let spec = {
            let inner = self.inner.lock().unwrap();
            inner.specs.get(&id).cloned()
        };
        let Some(spec) = spec else {
            // Cancelled between dispatch and run: the cancel path already emitted the
            // terminal state, so there is nothing left to report.
            return;
        };
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

    fn run_one(&self, vm: &Arc<Vm>, id: &str, spec: Spec) {
        // The run slot is ours, so this is the idle gap: drop exports whose sessions are gone
        // (before adding anything, so their guest slots are reusable), then apply the mounts
        // this execution was submitted with, then resolve its working directory against the
        // shares that now exist. All of it belongs here rather than to the request, so a mount
        // can never change under a task that is already running.
        self.try_removals(false);
        let session = {
            let inner = self.inner.lock().unwrap();
            session_of(&inner, id)
        };
        // Mounts are per-request snapshots, and reconciling one rewrites the guest's bind mounts.
        // Executions that ask for the same set as the one already applied skip that work, which
        // is what lets several of them run without re-mounting each other's paths. The session's
        // mount lock covers the check, the reconcile and the record together: without it two
        // executions starting together both find the set unapplied and both reconcile it.
        let mount_lock = {
            let inner = self.inner.lock().unwrap();
            inner.sessions.get(&session).map(|info| Arc::clone(&info.mount_lock))
        };
        let Some(mount_lock) = mount_lock else {
            self.finish_and_emit(
                id,
                Terminal::new("failed", None, "the session was closed before the run started"),
            );
            return;
        };
        let digest = mounts_digest(&spec.mounts);
        {
            let _applying = mount_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let already_applied = {
                let inner = self.inner.lock().unwrap();
                inner
                    .sessions
                    .get(&session)
                    .is_some_and(|info| info.applied_mounts == Some(digest))
            };
            if already_applied {
                self.stats.lock().unwrap().mounts_skipped += 1;
            } else {
                if let Err(failure) = self.apply_mounts(vm, &session, &spec.mounts) {
                    self.finish_and_emit(
                        id,
                        Terminal::new(
                            "failed",
                            None,
                            format!("{}: {}", failure.code, failure.message),
                        ),
                    );
                    return;
                }
                {
                    let mut inner = self.inner.lock().unwrap();
                    if let Some(info) = inner.sessions.get_mut(&session) {
                        info.applied_mounts = Some(digest);
                    }
                }
                self.stats.lock().unwrap().mounts_applied += 1;
            }
        }
        let cwd = match spec.cwd_host {
            None => None,
            Some(host) => {
                let (guest, shares, workspace_host, workspace_guest) = {
                    let inner = self.inner.lock().unwrap();
                    match inner.sessions.get(&session) {
                        Some(info) => (
                            if info.guest_session.is_some() {
                                "/workspace".to_owned()
                            } else {
                                info.workspace_guest.clone()
                            },
                            info.shares.clone(),
                            info.workspace.display().to_string(),
                            if info.guest_session.is_some() {
                                "/workspace".to_owned()
                            } else {
                                info.workspace_guest.clone()
                            },
                        ),
                        None => (String::new(), Vec::new(), String::new(), String::new()),
                    }
                };
                let resolved = plan::translate_cwd_shares(&host, &shares)
                    .or_else(|| {
                        plan::relative_to(&host, &workspace_host)
                            .map(|tail| plan::join_guest(&workspace_guest, tail))
                    })
                    .or_else(|| resolve_guest_path(std::path::Path::new(&host)));
                match resolved {
                    Some(path) => Some(path),
                    None => {
                        self.finish_and_emit(
                            id,
                            Terminal::new("failed", None, format!("no guest path for {host}")),
                        );
                        let _ = guest;
                        return;
                    }
                }
            }
        };
        let mut request = ExecRequest::argv(absolute_program(spec.argv));
        if let Some(cwd) = cwd {
            request = request.with_cwd(cwd);
        }
        if !spec.env.is_empty() {
            request =
                request.with_envs(spec.env.iter().map(|(key, value)| format!("{key}={value}")));
        }
        if let Some(timeout) = spec.timeout {
            request = request.with_timeout(timeout);
        }
        // Per-execution limits travel with this request alone. The backend keeps its configured
        // values for whatever the caller left at zero, and the guest refuses an execution whose
        // limit it cannot write into the execution's own cgroup.
        if let Some(limits) = spec.limits {
            request = request.with_limits(limits);
        }
        if let Some(guest_session) = {
            self.inner
                .lock()
                .unwrap()
                .sessions
                .get(&session)
                .and_then(|info| info.guest_session)
        } {
            request = request.with_guest_session(guest_session);
        }
        vm.touch();
        let mut execution = match self.client.exec(&vm.sandbox, &request) {
            Ok(execution) => execution,
            Err(error) => {
                let lost = self.vm_is_gone(&error);
                self.finish_and_emit(id, Terminal::new("failed", None, error.to_string()));
                if lost {
                    self.mark_vm_lost(error.to_string());
                }
                return;
            }
        };
        {
            let mut inner = self.inner.lock().unwrap();
            inner.cancels.insert(id.to_owned(), execution.canceller());
        }
        // A cancel may have arrived while the process was being started; honour it now.
        let cancel_requested = {
            let inner = self.inner.lock().unwrap();
            inner.registry.cancel_requested(id)
        };
        if cancel_requested {
            let canceller = {
                let inner = self.inner.lock().unwrap();
                inner.cancels.get(id).cloned()
            };
            if let Some(canceller) = canceller {
                let _ = canceller.cancel();
            }
        }
        let (session, generation) = {
            let inner = self.inner.lock().unwrap();
            (session_of(&inner, id), inner.registry.generation())
        };
        let mut pumps = Vec::new();
        if let Some(pipe) = execution.take_stdout() {
            pumps.push(spawn_pump(
                protocol::EVENT_EXEC_STDOUT,
                pipe,
                id,
                &session,
                generation,
                &self.writer,
            ));
        }
        if let Some(pipe) = execution.take_stderr() {
            pumps.push(spawn_pump(
                protocol::EVENT_EXEC_STDERR,
                pipe,
                id,
                &session,
                generation,
                &self.writer,
            ));
        }
        let outcome = execution.wait();
        for pump in pumps {
            let _ = pump.join();
        }
        {
            let mut inner = self.inner.lock().unwrap();
            inner.cancels.remove(id);
        }
        let cancelled = {
            let inner = self.inner.lock().unwrap();
            inner.registry.cancel_requested(id)
        };
        // A VM that died mid-command ends the command *here*, not in `client.exec`: this is the
        // path that has to notice it, or the corpse stays admissible.
        let lost = match &outcome {
            Err(error) => {
                let gone = self.vm_is_gone(error);
                if gone {
                    Some(error.to_string())
                } else {
                    None
                }
            }
            Ok(_) => None,
        };
        self.finish_and_emit(id, terminal_of(outcome, cancelled));
        if let Some(detail) = lost {
            self.mark_vm_lost(detail);
        }
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
            let event = exit_event(id, &session, generation, &terminal);
            let _ = self.writer.send(&event, &[]);
        }
        self.wake.notify_all();
    }

    /// Reports queued executions whose deadline passed, so a caller parked behind somebody
    /// else's long task gets an answer instead of silence.
    ///
    /// Called from the maintenance tick as well as from the idle worker: while an execution
    /// runs, the worker is blocked in `wait`, so it cannot notice a queue that expired.
    pub fn expire_queued_pass(&self) {
        self.expire_queued();
    }

    fn expire_queued(&self) {
        let expired = {
            let mut inner = self.inner.lock().unwrap();
            inner.registry.expire_queued(Instant::now())
        };
        for (id, session) in expired {
            let generation = self.inner.lock().unwrap().registry.generation();
            {
                let mut inner = self.inner.lock().unwrap();
                inner.specs.remove(&id);
            }
            let event = exit_event(
                &id,
                &session,
                generation,
                &Terminal::timed_out("queue deadline expired"),
            );
            let _ = self.writer.send(&event, &[]);
            eprintln!("nvxd: exec {id} expired in the queue");
        }
    }

    /// Retries export removals that were deferred because the VM was busy.
    ///
    /// `slot_is_free` is false when the caller is the dispatcher: it already owns the run slot,
    /// so "nothing is running" cannot be its precondition — and waiting for a fully idle VM is
    /// exactly what let a revoked session's directory stay reachable while other sessions kept
    /// the queue busy.
    fn try_removals(&self, slot_is_free: bool) {
        if slot_is_free {
            let ready = {
                let inner = self.inner.lock().unwrap();
                inner.registry.running_ids().is_empty() && inner.registry.queued_len() == 0
            };
            if !ready {
                return;
            }
        }
        let Some(vm) = self.vm_now() else {
            return;
        };
        let pending: Vec<(String, String, String, String, Option<u64>)> = {
            let inner = self.inner.lock().unwrap();
            inner
                .removals
                .iter()
                .map(|removal| {
                    (
                        removal.child.clone(),
                        removal.source_target.clone(),
                        removal.target.clone(),
                        removal.session.clone(),
                        removal.guest_session,
                    )
                })
                .collect()
        };
        for (child, source_target, target, _session, guest_session) in pending {
            if let Some(id) = guest_session {
                if let Err(_error) = self.backend.unbind_guest_session(
                    &vm.sandbox, id, &target
                ) {
                    self.stats.lock().unwrap().shares_remove_failed += 1;
                    continue;
                }
            }
            match self
                .backend
                .remove_share(&vm.sandbox, &child, &source_target, SHARE_TIMEOUT)
            {
                Ok(()) => {
                    let mut inner = self.inner.lock().unwrap();
                    inner.removals.retain(|removal| removal.child != child);
                    self.stats.lock().unwrap().shares_removed += 1;
                    eprintln!("nvxd: deferred export {child} removed in an idle gap");
                }
                Err(error) => {
                    // Removal is two steps: unmount in the guest, then stop the VMM export.
                    // Only the first is observable by the caller, so "the guest no longer
                    // knows this path" means the revocation already took effect — a retry
                    // after a failed second step lands here, and it is a success, not a
                    // failure.
                    if is_already_unmounted(&error) {
                        let mut inner = self.inner.lock().unwrap();
                        inner.removals.retain(|removal| removal.child != child);
                        self.stats.lock().unwrap().shares_removed += 1;
                        continue;
                    }
                    // A real refusal (something in the guest still holds the path) is not a
                    // reason to destroy this VM: it is shared, so the blast radius would be
                    // every other session's work. The entry stays registered, is retried in
                    // every safe gap, and is visible in `diagnostics`; it dies with the group
                    // VM. `sharesRemoveFailed` is the number that says how often this happens.
                    self.stats.lock().unwrap().shares_remove_failed += 1;
                    let overdue = {
                        let inner = self.inner.lock().unwrap();
                        inner
                            .removals
                            .iter()
                            .find(|removal| removal.child == child)
                            .is_some_and(|removal| removal.since.elapsed() > REMOVAL_DEADLINE)
                    };
                    if overdue {
                        eprintln!(
                            "nvxd: export {child} is still not removed after {}s \
                             ({error}); it stays registered until the group VM retires",
                            REMOVAL_DEADLINE.as_secs()
                        );
                        if guest_session.is_some() {
                            self.mark_vm_lost(format!(
                                "isolated session mapping {} could not be revoked: {error}",
                                target
                            ));
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Makes the guest's mounts match `desired` for one session.
    ///
    /// Only this session's exports are considered: on a shared VM another session's
    /// directories are not ours to drop, and the guest paths it chose stay in use.
    fn reconcile(
        &self,
        vm: &Arc<Vm>,
        prefix: &str,
        guest_session: Option<u64>,
        shares: &mut Vec<Share>,
        next_child: &mut u64,
        desired: &[Mount],
    ) -> Result<(), Failure> {
        for step in plan::plan(shares, desired) {
            match step {
                Step::Remove(share) => {
                    if let Some(id) = guest_session {
                        self.backend
                            .unbind_guest_session(
                                &vm.sandbox,
                                id,
                                &share.target,
                            )
                            .map_err(|error| {
                                self.mark_vm_lost(format!(
                                    "isolated session unmount failed for {}: {error}",
                                    share.target
                                ));
                                fail("E_SESSION_UNMOUNT_FAILED", error)
                            })?;
                    }
                    match self.backend.remove_share(
                        &vm.sandbox,
                        &share.child,
                        &share.source_target,
                        SHARE_TIMEOUT,
                    ) {
                        Ok(()) => {
                            self.stats.lock().unwrap().shares_removed += 1;
                        }
                        Err(error) => {
                            // Revoking a path must not fail the command that happened to
                            // trigger the reconcile, and it must not destroy the VM: the VM is
                            // shared, so destroying it would end every other session's work
                            // over one session's cleanup problem. The entry is registered, the
                            // path is out of this session's desired set (so it will not be
                            // re-added), and `try_removals` keeps trying in safe gaps.
                            if is_already_unmounted(&error) {
                                self.stats.lock().unwrap().shares_removed += 1;
                            } else {
                                eprintln!(
                                    "nvxd: cannot remove export {} ({error}); \
                                     registered for retry",
                                    share.child
                                );
                                let mut inner = self.inner.lock().unwrap();
                                inner.removals.push(Removal {
                                    child: share.child.clone(),
                                    source_target: share.source_target.clone(),
                                    target: share.target.clone(),
                                    session: prefix.to_owned(),
                                    guest_session,
                                    since: Instant::now(),
                                });
                                drop(inner);
                                self.stats.lock().unwrap().shares_remove_failed += 1;
                            }
                        }
                    }
                    shares.retain(|other| other.child != share.child);
                    // The path stays in `guest_targets` on purpose: a revoked share id is
                    // never reused within this VM's lifetime (protocol 3.2).
                }
                Step::Add(mount) => {
                    let child = format!("{prefix}-m{}", *next_child);
                    *next_child += 1;
                    // The caller may name the guest path (the engine always does); it only
                    // gets it if no other session in this VM already owns it, so a colliding
                    // mount id cannot silently re-point somebody else's directory.
                    let preferred = plan::guest_target_for(&mount);
                    let taken = {
                        let inner = self.inner.lock().unwrap();
                        inner.guest_targets.contains(&preferred)
                    };
                    let target = if taken {
                        format!("/sessions/{prefix}/mounts/{}", mount.id)
                    } else {
                        preferred
                    };
                    let source_target = guest_session
                        .map(|_| format!("/sessions/{prefix}/mounts/{}", mount.id))
                        .unwrap_or_else(|| target.clone());
                    let host = PathBuf::from(&mount.host_path);
                    let live = LiveShare {
                        child: &child,
                        host_path: &host,
                        target: &source_target,
                        read_only: mount.read_only,
                    };
                    self.backend
                        .add_share(&vm.sandbox, self.take_sequence(), &live, SHARE_TIMEOUT)
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
                    if let Some(id) = guest_session {
                        self.backend
                            .bind_guest_session(
                                &vm.sandbox,
                                id,
                                &aci_edge_sandboxes::nvx::protocol::SessionMount {
                                    source: source_target.clone(),
                                    target: target.clone(),
                                    read_only: mount.read_only,
                                },
                            )
                            .map_err(|error| fail("E_SESSION_MOUNT_FAILED", error))?;
                    }
                    self.stats.lock().unwrap().shares_added += 1;
                    self.inner
                        .lock()
                        .unwrap()
                        .guest_targets
                        .insert(target.clone());
                    shares.push(Share {
                        mount,
                        child,
                        source_target,
                        target,
                    });
                }
            }
        }
        Ok(())
    }

    fn exec(self: &Arc<Self>, head: &Value) -> Result<Value, Failure> {
        let name = head.get("session").and_then(Value::as_str).unwrap_or("");
        if head.get("stdin").is_some() || head.get("input").is_some() {
            return Err(fail(
                protocol::REASON_STDIN_UNSUPPORTED,
                "NVX v1 does not support stdin or input payloads",
            ));
        }
        let argv: Vec<String> = strings(head.get("argv"));
        if argv.is_empty() {
            return Err(fail(protocol::REASON_PROTOCOL, "argv is required"));
        }
        let desired = mounts(head.get("mounts"));
        if std::env::var_os("NVXD_LOG_MOUNTS").is_some() {
            for mount in &desired {
                eprintln!(
                    "nvxd: exec mounts session={name} id={} host={} guest={} mode={}",
                    mount.id,
                    mount.host_path,
                    plan::guest_target_for(mount),
                    if mount.read_only { "ro" } else { "rw" }
                );
            }
        }
        if desired
            .iter()
            .any(|mount| mount.id.is_empty() || mount.host_path.is_empty())
        {
            return Err(fail(
                protocol::REASON_PROTOCOL,
                "a mount needs mountId and hostPath",
            ));
        }
        if desired.iter().any(|mount| {
            !plan::valid_mount_id(&mount.id)
                || mount
                    .guest_path
                    .as_deref()
                    .is_some_and(|path| !plan::valid_guest_target(path))
        }) {
            return Err(fail(
                "E_WORKSPACE_MOUNT_INVALID",
                "mountId and guestPath must be one safe /workspace/mounts component",
            ));
        }
        // A mount change rewrites the guest's bind mounts, which cannot happen under a task that
        // is already running. The parallel-mode barrier below is checked in the same critical
        // section as admission: checking it here, in an earlier one, would let two concurrent
        // requests both find the session idle, both be admitted, and both reconcile.

        let timeout = match head.get("timeoutMs") {
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
                Some(Duration::from_millis(ms))
            }
        };
        let queue_deadline = match head.get("queueDeadlineMs") {
            None => None,
            Some(value) => number(Some(value)).filter(|ms| *ms > 0).map(|ms| {
                Instant::now() + Duration::from_millis(ms)
            }),
        };

        // Everything below decides admission before anything is registered.
        let workspace_root = {
            let inner = self.inner.lock().unwrap();
            let info = inner
                .sessions
                .get(name)
                .ok_or_else(|| fail(protocol::REASON_SESSION_UNKNOWN, format!("unknown session {name}")))?;
            info.workspace
                .parent()
                .map(std::path::Path::to_path_buf)
                .unwrap_or_else(|| info.workspace.clone())
        };
        // A mount may only export a location inside the session's own tree.
        let root = std::fs::canonicalize(&workspace_root).unwrap_or(workspace_root);
        for mount in &desired {
            let candidate = std::fs::canonicalize(&mount.host_path)
                .unwrap_or_else(|_| PathBuf::from(&mount.host_path));
            if !candidate.starts_with(&root) {
                return Err(fail(
                    "E_WORKSPACE_MOUNT_DENIED",
                    format!(
                        "hostPath {} is outside the allowed root {}",
                        candidate.display(),
                        root.display()
                    ),
                ));
            }
        }
        // Mounts are applied when this execution is about to run, not now: on a shared VM the
        // gap in which nothing runs belongs to the dispatcher, and a mount change under a
        // running task would move a path under it. Waiting here would also make one session's
        // long task refuse another session's command, which is exactly the coupling a queue
        // is meant to remove.
        let cwd_host = head
            .get("cwd")
            .and_then(Value::as_str)
            .filter(|cwd| !cwd.is_empty())
            .map(str::to_owned);

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
        // What this execution may charge, taken from the request. Validated at the entry point,
        // so anything non-zero here is inside what the guest agent can enforce. An image that
        // cannot enforce limits is refused here, not left to run without them.
        let exec_limits = head
            .get("limits")
            .and_then(Value::as_object)
            .and_then(protocol::request_exec_limits);
        if exec_limits.is_some() {
            let features = self.inner.lock().unwrap().guest_features;
            if features & GUEST_FEATURE_EXEC_LIMITS == 0 {
                return Err(fail(
                    protocol::REASON_GUEST_NO_LIMITS,
                    "the guest image does not enforce per-execution limits; install the \
                     matching runtime or drop the limits from this request",
                ));
            }
        }
        let digest = digest_of(&argv, cwd_host.as_deref(), &env, timeout, exec_limits, &desired);
        let generation = head.get("generation").and_then(|value| number(Some(value))).unwrap_or(0);
        let accepted = {
            let mut inner = self.inner.lock().unwrap();
            // Parallel-mode barrier, decided together with admission so that two requests cannot
            // both see the session idle and then both change its mounts.
            if self.max_running > 1 {
                let Some(info) = inner.sessions.get(name) else {
                    return Err(fail(
                        protocol::REASON_SESSION_UNKNOWN,
                        format!("unknown session {name}"),
                    ));
                };
                let changed = info.applied_mounts != Some(mounts_digest(&desired));
                if changed && inner.registry.session_has_unfinished(name) {
                    return Err(fail(
                        protocol::REASON_BACKEND_BUSY,
                        "the session still has unfinished executions; a mount change applies \
                         once they finish",
                    ));
                }
            }
            inner
                .registry
                .accept(name, &exec_id, digest, generation, queue_deadline)
        };
        match accepted {
            Accept::Queued { position } => {
                let mut inner = self.inner.lock().unwrap();
                inner.specs.insert(
                    exec_id.clone(),
                    Spec {
                        argv,
                        cwd_host,
                        env,
                        timeout,
                        limits: exec_limits,
                        mounts: desired,
                    },
                );
                if let Some(info) = inner.sessions.get_mut(name) {
                    info.last_activity = Instant::now();
                }
                drop(inner);
                self.wake.notify_all();
                Ok(json!({
                    "handle": exec_id,
                    "execId": exec_id,
                    "state": "queued",
                    "queuePosition": position,
                }))
            }
            Accept::Duplicate { phase, terminal } => {
                let mut body = json!({
                    "handle": exec_id,
                    "execId": exec_id,
                    "state": phase.as_str(),
                    "deduplicated": true,
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
                "handle": exec_id,
                "execId": exec_id,
                "state": "cancelled",
                "detail": "cancelled before it was accepted",
            })),
            Accept::QueueFull => Err(fail(
                protocol::REASON_QUEUE_FULL,
                "the execution queue is full",
            )),
            Accept::SessionUnknown => Err(fail(
                protocol::REASON_SESSION_UNKNOWN,
                format!("unknown session {name}"),
            )),
            Accept::SessionClosing => Err(fail(
                protocol::REASON_SESSION_CLOSING,
                format!("session {name} is closing"),
            )),
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
                "execId": id,
                "state": view.phase.as_str(),
                "session": view.session,
                "generation": view.generation,
                "queuedMs": view.queued_ms,
            }));
        }
        match inner.registry.terminal_of(id) {
            Some(terminal) => Ok(json!({
                "execId": id,
                "state": "finished",
                "outcome": terminal.outcome,
                "code": terminal.code,
                "detail": terminal.detail,
            })),
            // Not found is not a proof that a late start will never arrive.
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
            Stop(Canceller),
            Done(Value),
            /// Nothing is known under this name. Whether that is an error depends on which
            /// name was used: a handle can only exist after its start was accepted, but an
            /// exec id is chosen by the host before the start is sent.
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
                Cancel::Running => match inner.cancels.get(id).cloned() {
                    Some(canceller) => Action::Stop(canceller),
                    None => Action::Done(json!({"signalled": true, "state": "stopping"})),
                },
                Cancel::Finished(terminal) => Action::Done(json!({
                    "signalled": false,
                    "state": "finished",
                    "outcome": terminal.outcome,
                    "code": terminal.code,
                })),
                // Recorded so a start that arrives later cannot run.
                Cancel::Unknown => Action::Unknown,
            }
        };
        let by_exec_id = head
            .get("execId")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty());
        match action {
            Action::Emit(terminal, session, generation) => {
                // The registry already made it terminal, so the event is written here rather
                // than through `finish_and_emit`, which would find nothing left to finish.
                let event = exit_event(id, &session, generation, &terminal);
                let _ = self.writer.send(&event, &[]);
                self.wake.notify_all();
                Ok(json!({"signalled": true, "state": "cancelled"}))
            }
            Action::Stop(canceller) => {
                canceller
                    .cancel()
                    .map_err(|error| fail("E_BACKEND_SIGNAL", error))?;
                Ok(json!({"signalled": true, "state": "stopping"}))
            }
            Action::Done(body) => Ok(body),
            Action::Unknown if by_exec_id => {
                Ok(json!({"signalled": true, "state": "recorded"}))
            }
            Action::Unknown => Err(fail(
                protocol::REASON_HANDLE_UNKNOWN,
                format!("unknown handle {id}"),
            )),
        }
    }

    fn close(&self, name: &str) -> Result<Value, Failure> {
        if name.is_empty() {
            return Err(fail(protocol::REASON_PROTOCOL, "session is required"));
        }
        let _lifecycle = self.lifecycle.lock().unwrap();
        let (closed, running) = {
            let mut inner = self.inner.lock().unwrap();
            if !inner.sessions.contains_key(name) {
                // Closing is idempotent (plan 3.3.2): a caller whose first close reply was lost
                // must be able to repeat it and learn that the session is gone, instead of
                // getting an error that says nothing about whether it was ever open.
                return Ok(json!({
                    "closed": true,
                    "state": "closed",
                    "cleanupPending": !inner.removals.is_empty(),
                    "alreadyClosed": true,
                }));
            }
            let closed: Closed = inner.registry.close_session(name);
            let running = closed.running.clone();
            let workspace_export = inner
                .sessions
                .get(name)
                .and_then(|info| info.workspace_export.as_ref())
                .map(|export| WorkspaceExport {
                    child: export.child.clone(),
                    target: export.target.clone(),
                });
            let guest_session = inner
                .sessions
                .get(name)
                .and_then(|info| info.guest_session);
            let shares = inner
                .sessions
                .remove(name)
                .map(|info| info.shares)
                .unwrap_or_default();
            for id in &closed.cancelled_queued {
                inner.specs.remove(id);
            }
            // Exports of a closed session cannot always be removed at once: another session's
            // command may be running. The contract is to wait for the guest, then remove — and
            // to destroy the VM if that does not converge (`try_removals`).
            let mut exports: Vec<(String, String, String)> = Vec::new();
            if let Some(export) = workspace_export {
                exports.push((export.child, export.target.clone(), export.target));
            }
            for share in shares {
                exports.push((share.child, share.source_target, share.target));
            }
            for (child, source_target, target) in exports {
                inner.removals.push(Removal {
                    child,
                    source_target,
                    target,
                    session: name.to_owned(),
                    guest_session,
                    since: Instant::now(),
                });
            }
            (closed, running)
        };
        // Queued work is already terminal; report it once, here.
        let generation = self.inner.lock().unwrap().registry.generation();
        for id in &closed.cancelled_queued {
            let event = exit_event(
                id,
                name,
                generation,
                &Terminal::cancelled("session closed before it ran"),
            );
            let _ = self.writer.send(&event, &[]);
        }
        // Every running execution of the session is stopped and waited for, but a close never
        // blocks forever: past the deadline it reports `closing` and keeps the responsibility.
        let mut cleanup_pending = false;
        if !running.is_empty() {
            for id in &running {
                let canceller = {
                    let inner = self.inner.lock().unwrap();
                    inner.cancels.get(id).cloned()
                };
                if let Some(canceller) = canceller {
                    let _ = canceller.cancel();
                }
                // Dispatched but not started yet: the worker sees the cancel request instead.
            }
            let deadline = Instant::now() + CLOSE_WAIT;
            loop {
                let still_running = {
                    let inner = self.inner.lock().unwrap();
                    inner
                        .registry
                        .running_ids()
                        .iter()
                        .any(|active| running.contains(active))
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
        // Removing exports is only possible in an idle gap; when this was the last session,
        // retiring the VM does the whole cleanup at once.
        self.try_removals(true);
        self.retire_if_idle();
        Ok(json!({
            "closed": true,
            "state": if cleanup_pending { "closing" } else { "closed" },
            "cleanupPending": cleanup_pending,
        }))
    }

    /// Retires the VM once no session and no execution refers to it.
    ///
    /// Pending export removals do not hold the VM back: destroying the VM is what completes
    /// the cleanup, and unmounting each export first is not even possible for a runtime
    /// export in this configuration.
    fn retire_if_idle(&self) -> bool {
        let idle = {
            let inner = self.inner.lock().unwrap();
            inner.registry.is_idle() && inner.vm_present
        };
        if !idle {
            self.wake.notify_all();
            return false;
        }
        // Two threads can reach this at once — the worker going idle and the last
        // `session.close` — and stopping the same VM twice would deprovision it twice.
        if self
            .retiring
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        // Take the VM out of the slot before stopping it: `diagnostics` reads that slot, and a
        // VM whose stop is still in flight must already look gone. Otherwise the caller is told
        // the VM survived the last session close, which is exactly the wrong answer.
        let vm = {
            let mut inner = self.inner.lock().unwrap();
            inner.vm_present = false;
            inner.guest_features = 0;
            inner.removals.clear();
            inner.guest_targets.clear();
            inner.next_sequence = 0;
            self.vm.lock().unwrap().take()
        };
        let Some(vm) = vm else {
            self.retiring.store(false, Ordering::SeqCst);
            return false;
        };
        let _ = self.client.stop(&vm.sandbox);
        let _ = self.client.deprovision(&vm.sandbox);
        eprintln!(
            "nvxd: retired shared VM generation={} runtimeId={}",
            vm.generation, vm.runtime_id
        );
        self.wake.notify_all();
        true
    }

    fn memory_stats(&self) -> Result<Value, Failure> {
        let vm = self
            .vm_now()
            .ok_or_else(|| fail("E_BACKEND_MEMORY", "no VM is running"))?;
        let memory = vm
            .memory
            .ok_or_else(|| fail("E_BACKEND_MEMORY", "no VMM process is known"))?;
        let working_set = memory
            .working_set()
            .map_err(|error| fail("E_BACKEND_MEMORY", error))?;
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
        let vm = self
            .vm_now()
            .ok_or_else(|| fail("E_BACKEND_MEMORY", "no VM is running"))?;
        let memory = vm
            .memory
            .ok_or_else(|| fail("E_BACKEND_MEMORY", "no VMM process is known"))?;
        {
            let inner = self.inner.lock().unwrap();
            if !inner.registry.running_ids().is_empty() {
                return Err(fail("E_BACKEND_BUSY", "the VM is running a command"));
            }
        }
        let (before, after) = memory
            .trim()
            .map_err(|error| fail("E_BACKEND_MEMORY", error))?;
        let mut state = vm.state.lock().unwrap();
        state.trimmed = true;
        Ok(json!({"beforeMiB": before / (1 << 20), "afterMiB": after / (1 << 20)}))
    }

    /// Closes sessions idle past `ttl`. A session with unfinished work is never expired: the
    /// caller asked for that work to finish.
    pub fn expire_idle_pass(&self, ttl: Duration) -> Vec<String> {
        let candidates: Vec<String> = {
            let inner = self.inner.lock().unwrap();
            inner
                .sessions
                .iter()
                .filter(|(name, info)| {
                    info.last_activity.elapsed() >= ttl
                        && !inner.registry.session_has_unfinished(name)
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
        let Some(vm) = self.vm_now() else {
            return;
        };
        let Some(memory) = vm.memory else {
            return;
        };
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
        match memory.trim() {
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

    /// Drops everything because nobody is listening any more.
    ///
    /// Used when the transport closes. Waiting for work whose output cannot be delivered would
    /// make the sidecar's exit time depend on how long the caller's command happens to run —
    /// observed as a 20 s shutdown for a 20 s `sleep`. Stopping the VM is what actually ends
    /// the work; the bookkeeping is dropped first so nothing tries to report into a dead pipe.
    pub fn shutdown_now(&self) {
        let _lifecycle = self.lifecycle.lock().unwrap();
        let cancellers: Vec<Canceller> = {
            let mut inner = self.inner.lock().unwrap();
            let cancellers = inner.cancels.values().cloned().collect();
            // Terminal state for work nobody can hear about: the VM is about to be destroyed,
            // so pending registrations must not keep it alive.
            inner.registry.new_generation();
            inner.sessions.clear();
            inner.specs.clear();
            inner.cancels.clear();
            inner.removals.clear();
            cancellers
        };
        for canceller in cancellers {
            let _ = canceller.cancel();
        }
        self.retire_if_idle();
    }
}

/// Whether the guest answered "I do not know that mapping" to an unmount.
///
/// Removal is unmount-then-unexport. A failed unexport leaves the caller to retry, and the retry
/// legitimately finds the guest path already gone — the observable part succeeded. Treating that
/// answer as a failure would keep the entry in the cleanup queue forever and, past the backlog
/// limit, drain a VM that is actually healthy.
fn is_already_unmounted(error: &aci_edge_sandboxes::Error) -> bool {
    error
        .message()
        .contains("did not unmount the host path: invalid-request")
}

fn session_of(inner: &Inner, id: &str) -> String {
    inner
        .registry
        .session_of(id)
        .unwrap_or_default()
        .to_owned()
}

/// Where a session's workspace lives inside the guest.
///
/// The session name is caller-chosen text that becomes a path, so it is reduced to a safe
/// alphabet; it stays stable, so a session's files are at the same place for its whole life.
fn guest_workspace(session: &str) -> String {
    format!("/sessions/{}/workspace", safe_name(session))
}

/// A caller-chosen name reduced to something safe to use in a guest path or an export name.
fn safe_name(session: &str) -> String {
    let safe: String = session
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() {
        "session".to_owned()
    } else {
        safe
    }
}

/// NVX accepts only an absolute guest path as the program. the host sends bare names such as
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

/// Identifies a mount snapshot: the same set in the same order has the same digest.
///
/// Order matters because the guest's runtime mapping table is indexed: a reordered set is a
/// different table even when it names the same directories.
fn mounts_digest(mounts: &[Mount]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    mounts.len().hash(&mut hasher);
    for mount in mounts {
        mount.id.hash(&mut hasher);
        mount.host_path.hash(&mut hasher);
        mount.read_only.hash(&mut hasher);
        mount.guest_path.hash(&mut hasher);
    }
    hasher.finish()
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
            // The caller may name the guest path; the engine has always sent one. Honouring it
            // keeps scripts that write to `/workspace/mounts/<id>` working on a session that
            // owns that path.
            guest_path: item["guestPath"]
                .as_str()
                .filter(|path| !path.is_empty())
                .map(str::to_owned),
        })
        .collect()
}

/// Digest of everything that makes two requests the same command. Two requests that share an
/// id but differ here are a contract error, never a silent second run.
fn digest_of(
    argv: &[String],
    cwd: Option<&str>,
    env: &[(String, String)],
    timeout: Option<Duration>,
    limits: Option<ExecLimits>,
    mounts: &[Mount],
) -> u64 {
    let mut parts: Vec<String> = argv.to_vec();
    parts.push(format!("cwd={}", cwd.unwrap_or("")));
    for (key, value) in env {
        parts.push(format!("env={key}={value}"));
    }
    parts.push(format!(
        "timeout={}",
        timeout.map(|value| value.as_millis() as u64).unwrap_or(0)
    ));
    // Limits belong to the request digest: reusing an exec id with a different memory or CPU
    // bound is a different command, and must be refused as a conflict rather than silently
    // keeping the first one's limits.
    if let Some(limits) = limits {
        parts.push(format!(
            "limits={}:{}:{}",
            limits.mem_mb, limits.cpu_percent, limits.pids_max
        ));
    }
    for mount in mounts {
        parts.push(format!(
            "mount={}:{}:{}:{}",
            mount.id,
            mount.host_path,
            if mount.read_only { "ro" } else { "rw" },
            mount.guest_path.as_deref().unwrap_or("")
        ));
    }
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

fn spawn_pump(
    event: &'static str,
    mut pipe: impl Read + Send + 'static,
    handle: &str,
    session: &str,
    generation: u64,
    writer: &Writer,
) -> std::thread::JoinHandle<()> {
    let (handle, session, writer) = (handle.to_owned(), session.to_owned(), Arc::clone(writer));
    std::thread::spawn(move || {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    let head = json!({
                        "event": event,
                        "handle": handle,
                        "execId": handle,
                        "session": session,
                        "generation": generation,
                    });
                    if writer.send(&head, &buffer[..count]).is_err() {
                        break;
                    }
                }
            }
        }
    })
}

fn terminal_of(outcome: aci_edge_sandboxes::Result<ExecOutcome>, cancelled: bool) -> Terminal {
    match outcome {
        _ if cancelled => Terminal::new("cancelled", None, "cancelled by the caller"),
        Ok(ExecOutcome::Exited(code)) => Terminal::new("exited", Some(code), ""),
        Ok(ExecOutcome::Signaled(signal)) => Terminal::new("signaled", Some(signal), ""),
        Ok(ExecOutcome::OutOfMemory { signal, vm_wide }) => Terminal::new(
            "signaled",
            Some(signal),
            // The outcome stays "signaled" so an existing caller keeps working; the reason is
            // what distinguishes an execution-local limit from VM-wide pressure. Neither
            // category promises that blindly retrying the execution will succeed.
            if vm_wide { "vmOom" } else { "oom" },
        ),
        Ok(ExecOutcome::TimedOut) => Terminal::new("timedOut", None, ""),
        Ok(ExecOutcome::Cancelled) => Terminal::new("cancelled", None, ""),
        Ok(other) => Terminal::new("failed", None, other.to_string()),
        Err(error) => Terminal::new("failed", None, error.to_string()),
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
