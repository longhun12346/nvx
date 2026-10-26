//! Supervision of one VM instance: its OpenVMM process, its control endpoint, and the files that
//! record them.
//!
//! An instance lives in a directory of its own, which the caller creates and keeps private to the
//! current user:
//!
//! ```text
//! <dir>/
//!   launch.json             endpoint and available process identity of a start in progress
//!   runtime.json            OpenVMM process identity and endpoint (running only)
//!   control.capability      launch capability (running only)
//!   control.sock            Linux control endpoint (running only)
//!   openvmm.log             OpenVMM output of the latest start
//!   outcome.json            OpenVMM outcome report of the latest run
//! ```
//!
//! - [`Instance::start`] launches a detached OpenVMM process with the managed lifecycle, passes it
//!   a fresh 32-byte capability through standard input, and waits until the guest agent answers
//!   on the authenticated control console. The agent must also advertise the control features in
//!   [`GuestFeatures::REQUIRED`]; a guest image that lacks one is terminated, because it would
//!   silently ignore the policy or request that needs the feature. Start then hands the agent the
//!   table of mapped host paths, and fails if the agent cannot mount them all.
//! - [`Instance::exec`] runs a workload through the control console, and [`Execution::pump`]
//!   streams its output live.
//! - [`Instance::stop`] asks the guest to shut down and falls back to terminating OpenVMM.
//! - [`Instance::reconcile`] compares the recorded OpenVMM process with the host, so that every
//!   operation can run in a different process. A VM that died leaves the instance stopped, and a
//!   start whose caller died before recording OpenVMM's identity is recovered through its launch
//!   marker.
//!
//! Callers serialize the lifecycle transitions of one instance, for example with [`lock`]. A
//! control session carries one execution at a time as far as [`Instance::exec`] is concerned: it
//! opens a session per execution. [`Instance::exec_shared`] instead shares one session between
//! several executions ([`SharedSession`]), which a guest that advertises concurrent executions
//! can serve; every other control operation of the instance still opens its own session, so a
//! caller that adopts the shared session must route them through it too.
//! Messages call the instance `sandbox NAME`, after the name that [`Instance::new`] gives it.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::artifacts::Artifacts;
use super::launch::{LaunchSpec, timeout_problem};
use super::report::{self, Report};
use super::session::{self, ControlSession, Delivery, ExecEvent, SessionError, SharedSession};
use super::{platform, process};
use crate::error::{Error, ErrorKind, Result};
use crate::protocol::{
    CAPABILITY_LEN, CWD_FAILED, ExitCategory, GuestFeatures, LAUNCH_FAILED, MAPPINGS_INCOMPLETE,
    MAX_OUTPUT_BYTES, Workload,
};

/// Version of the state files written by this crate: the launch marker and the runtime record,
/// and the [`ExportPlan`](super::filesystem::ExportPlan) that callers record beside them.
///
/// Version 1 described sandboxes assembled from image layers and a scratch disk, and version 2
/// exported the mapped host paths as one directory whose bind mounts the kernel command line
/// listed.
pub const STATE_FORMAT: u32 = 3;
/// Linux control socket name.
pub const SOCKET_NAME: &str = "control.sock";
/// Name of the launch marker.
pub const LAUNCH_NAME: &str = "launch.json";
/// Name of the runtime record.
pub const RUNTIME_NAME: &str = "runtime.json";
/// Name of the file that holds the launch capability.
pub const CAPABILITY_NAME: &str = "control.capability";
/// Name of OpenVMM's log.
pub const LOG_NAME: &str = "openvmm.log";
/// Name of OpenVMM's outcome report.
pub const REPORT_NAME: &str = "outcome.json";
/// Every file that an instance keeps in its directory.
pub const FILE_NAMES: [&str; 6] = [
    RUNTIME_NAME,
    LAUNCH_NAME,
    CAPABILITY_NAME,
    SOCKET_NAME,
    REPORT_NAME,
    LOG_NAME,
];

/// Longest delay between a cancellation request and its delivery to the guest.
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Identity of an OpenVMM process: its ID and start time, which together never repeat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessIdentity {
    /// Process ID.
    pub pid: u32,
    /// Start time, in the units of [`platform::process_start_time`].
    pub start_time: u64,
}

/// Identity of the OpenVMM process of a running instance, and its control endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeRecord {
    /// [`STATE_FORMAT`].
    pub format: u32,
    /// Process ID.
    pub pid: u32,
    /// Start time, in the units of [`platform::process_start_time`].
    pub start_time: u64,
    /// Control endpoint: a Unix socket path on Linux, and a named pipe on Windows.
    pub endpoint: String,
    /// Pipe on which the VMM serves virtio-fs export requests, when it was started
    /// with one. Absent in records written before the channel existed, so a
    /// half-upgraded state file still loads and simply has no export channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_pipe: Option<String>,
}

/// Marker written before OpenVMM is launched and replaced by the runtime record afterwards.
///
/// Process identity is added as soon as the child is identified, before writing runtime state.
/// A marker without identity is never expired: its child may be alive without an endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchRecord {
    /// [`STATE_FORMAT`].
    pub format: u32,
    /// Control endpoint that the launch chose.
    pub endpoint: String,
    /// Identity of the launched process, once known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessIdentity>,
}

/// Held advisory lock. Dropping it releases the lock.
#[derive(Debug)]
pub struct LockGuard {
    /// Open locked file whose lifetime holds the operating-system lock.
    _file: File,
}

/// Takes the exclusive advisory lock of the file at `path`, creating the file if needed, and
/// waits until no other holder has it.
pub fn lock(path: &Path) -> Result<LockGuard> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(io_error(format!("cannot open lock {}", path.display())))?;
    file.lock()
        .map_err(io_error(format!("cannot lock {}", path.display())))?;
    Ok(LockGuard { _file: file })
}

/// Creates the directory at `path` if needed and restricts it to the current user.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    platform::create_private_dir(path)
}

/// Builds an error mapper that preserves an I/O source under `context`.
fn io_error(context: String) -> impl FnOnce(io::Error) -> Error {
    move |error| Error::io(context).with_source(error)
}

/// Returns create-and-write options that request owner-only permissions on Unix.
fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
}

/// Atomically replaces `path` with `contents`, readable only by the current user.
pub fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix)
        .map_err(|error| Error::other("cannot name a temporary file").with_source(error))?;
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temporary = path.with_file_name(format!(".{name}.{}.tmp", u64::from_le_bytes(suffix)));
    let written = (|| -> io::Result<()> {
        let mut file = private_options().create_new(true).open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written.map_err(io_error(format!("cannot write {}", path.display())))
}

/// Atomically replaces `path` with `value` as pretty JSON and a newline, readable only by the
/// current user.
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut text = serde_json::to_vec_pretty(value)
        .map_err(|error| Error::other("cannot encode sandbox state").with_source(error))?;
    text.push(b'\n');
    write_private(path, &text)
}

/// Reads the JSON at `path`, or returns `None` if the file does not exist.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    let text = match fs::read(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(format!("cannot read {}", path.display()))(error)),
    };
    serde_json::from_slice(&text).map(Some).map_err(|error| {
        Error::io(format!("sandbox state {} is malformed", path.display())).with_source(error)
    })
}

/// Removes the file at `path` if it exists.
pub fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            Err(io_error(format!("cannot remove {}", path.display()))(error))
        }
        _ => Ok(()),
    }
}

/// Returns a fresh launch capability, which is never all zero.
pub fn generate_capability() -> Result<[u8; CAPABILITY_LEN]> {
    let mut capability = [0u8; CAPABILITY_LEN];
    while capability == [0; CAPABILITY_LEN] {
        getrandom::fill(&mut capability).map_err(|error| {
            Error::other("cannot generate a control capability").with_source(error)
        })?;
    }
    Ok(capability)
}

/// Classifies a session failure.
fn session_kind(error: &SessionError) -> ErrorKind {
    match error {
        SessionError::TimedOut => ErrorKind::TimedOut,
        SessionError::ProcessExited => ErrorKind::Exited,
        SessionError::Refused(_) | SessionError::Io(_) => ErrorKind::Io,
        SessionError::Closed
        | SessionError::Reset
        | SessionError::AuthenticationFailed
        | SessionError::Protocol(_) => ErrorKind::Protocol,
    }
}

/// Explains why a launch did not become ready.
fn readiness_failure(error: &SessionError, runs_as_host_user: bool) -> String {
    let mut reason = error.to_string();
    // An image that predates account creation ends its boot, before the guest agent starts, when
    // it finds no account for the host user that the workloads run as. The VM then vanishes, or
    // its control endpoint closes first.
    let vm_ended = matches!(error, SessionError::ProcessExited | SessionError::Closed);
    if runs_as_host_user && vm_ended {
        reason.push_str(
            "; a guest image that predates workload account creation exits during boot when \
             workloads run under the host user's IDs, so use an NVX release or build that \
             includes it",
        );
    }
    reason
}

/// A VM that [`Instance::start`] launched and the guest agent of which is ready.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Started {
    /// The recorded identity and endpoint of its OpenVMM process.
    pub runtime: RuntimeRecord,
    /// Time from launch to guest readiness.
    pub boot: Duration,
    /// Control features the guest advertised. A caller that needs more than the required set,
    /// such as concurrent executions, reads them here instead of assuming a build.
    pub features: GuestFeatures,
}

/// A VM that [`Instance::stop`] stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stopped {
    /// Whether OpenVMM had to be terminated because the guest did not shut down in time.
    pub forced: bool,
    /// Summary of OpenVMM's outcome report, if it wrote one.
    pub report: Option<Report>,
}

/// One VM instance in a directory of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// Private directory containing runtime state, logs, and the control endpoint.
    dir: PathBuf,
    /// Sandbox name used in diagnostics.
    name: String,
}

/// The control session of each running VM, keyed by control endpoint and boot time.
///
/// A VM serves one control session, and the guest demultiplexes requests over it by request id:
/// executions, host path mappings, feature queries, and the stop request all travel over the
/// session registered here. The boot time is part of the key, so a restarted VM is never reached
/// through the session of the boot it replaced; an entry whose reader has stopped is dropped when
/// it is next looked up.
fn sessions() -> &'static Mutex<HashMap<(String, u64), Arc<SharedSession>>> {
    static SESSIONS: OnceLock<Mutex<HashMap<(String, u64), Arc<SharedSession>>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// One lock per VM, held while its session is being attached.
///
/// Attaching means connecting to the endpoint (with retries) and a handshake, which can take the
/// whole control timeout. That must not happen under the map's lock: it would stall every other
/// VM's control path, including their stops. Two callers of the same VM still serialise here, so
/// only one of them opens the session the broker serves.
fn opening_locks() -> &'static Mutex<HashMap<(String, u64), Arc<Mutex<()>>>> {
    static OPENING: OnceLock<Mutex<HashMap<(String, u64), Arc<Mutex<()>>>>> = OnceLock::new();
    OPENING.get_or_init(|| Mutex::new(HashMap::new()))
}

impl Instance {
    /// Returns the control session of `runtime`, attaching it on first use.
    ///
    /// Every control operation of a running VM must go through the session this returns: opening
    /// a second one would wait for the first to finish and then fail, because the broker issues a
    /// single host slot per VM.
    pub fn control_session(
        &self,
        runtime: &RuntimeRecord,
        capability: &[u8; CAPABILITY_LEN],
        control_timeout: Duration,
    ) -> Result<Arc<SharedSession>> {
        check_timeout("control timeout", control_timeout, true)?;
        let key = (runtime.endpoint.clone(), runtime.start_time);
        {
            let mut sessions = sessions().lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(session) = sessions.get(&key) {
                if session.is_running() {
                    return Ok(Arc::clone(session));
                }
                sessions.remove(&key);
            }
        }
        // Only this VM's callers serialise below; every other VM keeps using its own session.
        let opening = {
            let mut locks = opening_locks().lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(
                locks
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let _opening = opening.lock().unwrap_or_else(PoisonError::into_inner);
        // Another caller may have attached it while this one waited for the lock.
        {
            let mut sessions = sessions().lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(session) = sessions.get(&key) {
                if session.is_running() {
                    return Ok(Arc::clone(session));
                }
                sessions.remove(&key);
            }
        }
        let deadline = Instant::now() + control_timeout;
        let transport =
            session::connect(&runtime.endpoint, runtime.pid, runtime.start_time, deadline)
                .map_err(|error| self.session_error(error, control_timeout))?;
        let opened = SharedSession::open(transport, capability, deadline)
            .map_err(|error| self.session_error(error, control_timeout))?;
        sessions()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, Arc::clone(&opened));
        Ok(opened)
    }

    /// Forgets the control session of `runtime`, so a later call attaches a new one.
    pub fn forget_control_session(&self, runtime: &RuntimeRecord) {
        let key = (runtime.endpoint.clone(), runtime.start_time);
        sessions()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key);
        opening_locks()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key);
    }
}

impl Instance {
    /// Supervises the instance in `dir`, which messages call `sandbox NAME`.
    pub fn new(dir: impl Into<PathBuf>, name: impl Into<String>) -> Self {
        Self {
            dir: dir.into(),
            name: name.into(),
        }
    }

    /// Returns the instance's directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Returns the pipe on which this instance's VMM serves virtio-fs export requests.
    ///
    /// Derived from the directory rather than stored, so it is stable across processes
    /// and needs no state file field: a share added later by a different `Instance` for
    /// the same directory reaches the same pipe.
    pub fn export_pipe(&self) -> String {
        use std::hash::Hash;
        use std::hash::Hasher;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.dir.hash(&mut hasher);
        crate::host::live_control::pipe_name(hasher.finish())
    }

    /// Returns the instance's name in messages.
    pub fn name(&self) -> &str {        &self.name
    }

    /// Returns the path of the OpenVMM log of the latest start.
    pub fn log_path(&self) -> PathBuf {
        self.dir.join(LOG_NAME)
    }

    /// Returns the path of OpenVMM's outcome report of the latest run.
    pub fn report_path(&self) -> PathBuf {
        self.dir.join(REPORT_NAME)
    }

    /// Returns the path of the Linux control socket.
    pub fn socket_path(&self) -> PathBuf {
        self.dir.join(SOCKET_NAME)
    }

    /// Returns a control endpoint for the instance: its socket on Linux, and a fresh named pipe,
    /// whose name always has the same length, on Windows.
    fn endpoint(&self) -> Result<String> {
        platform::control_endpoint(&self.socket_path())
            .map_err(|error| Error::io("cannot choose a control endpoint").with_source(error))
    }

    /// Reads the runtime record, if the instance runs.
    pub fn runtime(&self) -> Result<Option<RuntimeRecord>> {
        let path = self.dir.join(RUNTIME_NAME);
        let runtime: Option<RuntimeRecord> = read_json(&path)?;
        match runtime {
            Some(runtime) if runtime.format != STATE_FORMAT => Err(Error::io(format!(
                "sandbox runtime state {} has an unsupported format",
                path.display()
            ))),
            runtime => Ok(runtime),
        }
    }

    /// Records the OpenVMM process of a running instance.
    pub fn write_runtime(&self, runtime: &RuntimeRecord) -> Result<()> {
        write_json(&self.dir.join(RUNTIME_NAME), runtime)
    }

    /// Records a launch in progress.
    pub fn write_launch(&self, launch: &LaunchRecord) -> Result<()> {
        write_json(&self.dir.join(LAUNCH_NAME), launch)
    }

    /// Reads the marker of a launch in progress, if any.
    pub fn launch(&self) -> Result<Option<LaunchRecord>> {
        let path = self.dir.join(LAUNCH_NAME);
        let Some(launch) = read_json::<LaunchRecord>(&path)? else {
            return Ok(None);
        };
        if launch.format != STATE_FORMAT {
            return Err(Error::io(format!(
                "sandbox launch marker {} has an unsupported format",
                path.display()
            )));
        }
        Ok(Some(launch))
    }

    /// Removes the launch marker once the runtime record replaces it.
    pub fn remove_launch(&self) {
        let _ = fs::remove_file(self.dir.join(LAUNCH_NAME));
    }

    /// Stores the launch capability, readable only by the current user.
    pub fn write_capability(&self, capability: &[u8; CAPABILITY_LEN]) -> Result<()> {
        write_private(&self.dir.join(CAPABILITY_NAME), capability)
    }

    /// Reads the launch capability of a running instance.
    pub fn read_capability(&self) -> Result<[u8; CAPABILITY_LEN]> {
        let path = self.dir.join(CAPABILITY_NAME);
        let bytes = fs::read(&path).map_err(io_error(format!(
            "cannot read the sandbox control capability {}",
            path.display()
        )))?;
        match <[u8; CAPABILITY_LEN]>::try_from(bytes.as_slice()) {
            Ok(capability) if capability != [0; CAPABILITY_LEN] => Ok(capability),
            _ => Err(Error::io(format!(
                "sandbox control capability {} is invalid",
                path.display()
            ))),
        }
    }

    /// Removes the files that exist only while the instance starts or runs.
    pub fn clear_runtime(&self) -> Result<()> {
        for name in [RUNTIME_NAME, LAUNCH_NAME, CAPABILITY_NAME, SOCKET_NAME] {
            remove_if_present(&self.dir.join(name))?;
        }
        Ok(())
    }

    /// Opens a fresh OpenVMM log, replacing the previous one.
    pub fn create_log(&self) -> Result<File> {
        let path = self.log_path();
        private_options()
            .truncate(true)
            .open(&path)
            .map_err(io_error(format!("cannot create {}", path.display())))
    }

    /// Fails with [`ErrorKind::Unsupported`] if OpenVMM's command line for `spec` would not fit
    /// the limit of a Windows process command line; see
    /// [`LaunchSpec::check_process_command_line`].
    pub fn check_launch(&self, spec: &LaunchSpec) -> Result<()> {
        spec.check_process_command_line(&self.endpoint()?, &self.report_path())
    }

    /// Returns the runtime record of the instance's OpenVMM process if it still runs, clearing
    /// stale runtime state otherwise.
    ///
    /// State is cleared only when the process is definitely gone; an inconclusive check fails
    /// instead, so a live VM is never forgotten. A start whose caller died before recording
    /// OpenVMM's identity is recovered through its launch marker. Callers hold the instance's
    /// lifecycle lock.
    pub fn reconcile(&self) -> Result<Option<RuntimeRecord>> {
        if let Some(runtime) = self.runtime()? {
            let current = platform::process_start_time(runtime.pid).map_err(|error| {
                Error::io(format!(
                    "cannot determine whether OpenVMM process {} of sandbox {} is running",
                    runtime.pid, self.name
                ))
                .with_source(error)
            })?;
            if current == Some(runtime.start_time) {
                self.remove_launch();
                return Ok(Some(runtime));
            }
            self.clear_runtime()?;
            return Ok(None);
        }
        if let Some(launch) = self.launch()? {
            self.recover_launch(&launch)?;
            self.clear_runtime()?;
        }
        Ok(None)
    }

    /// Terminates the OpenVMM process of a start whose caller died before recording it.
    ///
    /// Lifecycle locks serialize starts, so a launch marker seen under the lock always belongs
    /// to an interrupted start. Recorded identity is authoritative even before an endpoint
    /// exists; legacy markers can be recovered only when their endpoint identifies the child.
    fn recover_launch(&self, launch: &LaunchRecord) -> Result<()> {
        let interrupted = |kind: ErrorKind, detail: &str| {
            Error::new(
                kind,
                format!("an interrupted start of sandbox {} {detail}", self.name),
            )
        };
        let identity = match &launch.process {
            Some(identity) => identity.clone(),
            None => {
                let pid = platform::endpoint_server_pid(&launch.endpoint).map_err(|error| {
                    interrupted(ErrorKind::Io, "cannot be recovered yet").with_source(error)
                })?;
                let Some(pid) = pid else {
                    return Err(interrupted(
                        ErrorKind::Other,
                        "has no recorded process identity or observable endpoint; cannot verify \
                         that OpenVMM exited, so the launch marker is retained",
                    ));
                };
                let Some(start_time) = platform::process_start_time(pid).map_err(|error| {
                    interrupted(ErrorKind::Io, "cannot be recovered yet").with_source(error)
                })?
                else {
                    return Ok(());
                };
                ProcessIdentity { pid, start_time }
            }
        };
        match process::kill(identity.pid, identity.start_time) {
            Ok(true) => Ok(()),
            Ok(false) => Err(interrupted(
                ErrorKind::Other,
                &format!(
                    "left OpenVMM process {} running, and it did not exit",
                    identity.pid
                ),
            )),
            Err(error) => Err(interrupted(
                ErrorKind::Io,
                &format!(
                    "left OpenVMM process {} running, and it could not be terminated",
                    identity.pid
                ),
            )
            .with_source(error)),
        }
    }

    /// Describes why this instance did not start and points the caller to its log.
    fn start_failure(&self, kind: ErrorKind, reason: &str) -> Error {
        Error::new(
            kind,
            format!(
                "sandbox {} failed to start: {reason}; see {}",
                self.name,
                self.log_path().display()
            ),
        )
    }

    /// Terminates a launch that did not become ready.
    ///
    /// Runtime state is cleared only once the process has exited. Otherwise the instance stays
    /// marked as running so that a stop can retry instead of a second VM being started.
    fn abort_start(&self, runtime: &RuntimeRecord, kind: ErrorKind, reason: &str) -> Error {
        let cleanup = match process::kill(runtime.pid, runtime.start_time) {
            Ok(true) => {
                let _ = self.clear_runtime();
                return self.start_failure(kind, reason);
            }
            Ok(false) => "it did not exit".to_owned(),
            Err(error) => error.to_string(),
        };
        self.start_failure(
            kind,
            &format!(
                "{reason}; OpenVMM process {} could not be terminated ({cleanup}), so the \
                 sandbox stays marked as running until it is stopped",
                runtime.pid
            ),
        )
    }

    /// Terminates a launch whose guest image lacks control features that NVX needs.
    ///
    /// An older image would boot and answer, but it would silently ignore host path mappings and
    /// cancellation requests, so the VM must not run at all.
    fn reject_guest(&self, runtime: &RuntimeRecord, missing: &[&str]) -> Error {
        let reason = format!(
            "the guest image lacks control features that the openvmm backend needs ({}); use an \
             NVX release or build that includes them, for example through {}",
            missing.join(", "),
            Artifacts::ENV_DIR
        );
        self.abort_start(runtime, ErrorKind::Unavailable, &reason)
    }

    /// Launches the VM that `spec` describes and waits up to `timeout` until its guest is ready.
    ///
    /// The instance's directory must exist, and the caller holds its lifecycle lock and has found
    /// it stopped with [`reconcile`](Self::reconcile). Start first checks that the mapped host
    /// paths still name the objects they named when they were planned; see
    /// [`ExportPlan::verify`](super::filesystem::ExportPlan::verify).
    ///
    /// The capability travels through OpenVMM's standard-input pipe, which is closed before
    /// OpenVMM starts, and never appears in arguments, the environment, or the log. Before
    /// launching OpenVMM, start records the control endpoint in the launch marker, so that
    /// [`reconcile`](Self::reconcile) can terminate an OpenVMM whose start was interrupted.
    ///
    /// Fails with [`ErrorKind::Unavailable`] when the guest image lacks a feature in
    /// [`GuestFeatures::REQUIRED`], and with [`ErrorKind::Unsupported`] when `timeout` is zero or
    /// longer than [`MAX_TIMEOUT`](super::launch::MAX_TIMEOUT), when the specification fails
    /// [`LaunchSpec::check`] or exceeds a limit, or when OpenVMM's command line would not fit
    /// [`PROCESS_COMMAND_LINE_LIMIT`](super::launch::PROCESS_COMMAND_LINE_LIMIT), which holds on
    /// every host. Unlike [`check_launch`](Self::check_launch), start keeps no reserve. A launch
    /// that does not become ready is terminated; if it cannot be, the instance stays marked as
    /// running until it is stopped.
    pub fn start(&self, spec: &LaunchSpec, timeout: Duration) -> Result<Started> {
        check_timeout("start timeout", timeout, true)?;
        if let Some(plan) = &spec.filesystem {
            plan.verify()?;
        }
        let capability = generate_capability()?;
        let socket = self.socket_path();
        remove_if_present(&socket)?;
        let endpoint = self.endpoint()?;
        let report = self.report_path();
        remove_if_present(&report)?;
        // The export channel stays off by default: enabling it was observed to keep the
        // guest from becoming ready on a real VM, so it is opt-in until that is fixed.
        // The name derivation below is kept so a later round can flip this on.
        let _export_spec = crate::host::live_control::spec(
            &crate::host::live_control::Endpoint::Named(self.export_pipe()),
        );
        let arguments =
            spec.openvmm_arguments_with_control(&endpoint, &report, Some(&_export_spec))?;
        spec.fit_process_command_line(&arguments, 0)?;

        self.write_capability(&capability)?;
        let log = self.create_log()?;
        // Until the child is identified, recovery must retain this marker unless the endpoint
        // identifies the child. An absent endpoint never proves that a launch has exited.
        self.write_launch(&LaunchRecord {
            format: STATE_FORMAT,
            endpoint: endpoint.clone(),
            process: None,
        })?;
        let started = Instant::now();
        let child = match process::spawn(
            &spec.openvmm,
            spec.breakaway_from_job,
            &arguments,
            &capability,
            log,
            &self.dir,
        ) {
            Ok(child) => child,
            Err(error) => {
                let _ = self.clear_runtime();
                return Err(
                    Error::io(format!("cannot launch {}", spec.openvmm.display()))
                        .with_source(error),
                );
            }
        };
        let pid = child.id();
        let start_time = match platform::process_start_time(pid) {
            Ok(Some(start_time)) => start_time,
            outcome => {
                // Keep the launch marker unless OpenVMM is gone, so recovery can retry.
                if process::kill_child(child) {
                    let _ = self.clear_runtime();
                }
                let (kind, reason) = match outcome {
                    Err(error) => (
                        ErrorKind::Io,
                        format!("cannot identify the OpenVMM process: {error}"),
                    ),
                    _ => (
                        ErrorKind::Exited,
                        "OpenVMM exited during startup".to_owned(),
                    ),
                };
                return Err(self.start_failure(kind, &reason));
            }
        };
        let runtime = RuntimeRecord {
            format: STATE_FORMAT,
            pid,
            start_time,
            endpoint: endpoint.clone(),
            export_pipe: Some(self.export_pipe()),
        };
        let identified = LaunchRecord {
            format: STATE_FORMAT,
            endpoint: endpoint.clone(),
            process: Some(ProcessIdentity { pid, start_time }),
        };
        if let Err(error) = self
            .write_launch(&identified)
            .and_then(|()| self.write_runtime(&runtime))
        {
            if process::kill_child(child) {
                let _ = self.clear_runtime();
            }
            return Err(error);
        }
        process::detach_child(child);
        self.remove_launch();
        let deadline = started + timeout;
        let ready = session::connect(&endpoint, pid, start_time, deadline)
            .and_then(|transport| ControlSession::attach(transport, &capability, deadline))
            .and_then(|mut session| {
                session.ping(deadline)?;
                let features = session.features(deadline)?;
                Ok((session, features))
            });
        let (mut session, features) = match ready {
            Ok(ready) => ready,
            Err(error) => {
                let reason = readiness_failure(&error, spec.identity.create_account);
                return Err(self.abort_start(&runtime, session_kind(&error), &reason));
            }
        };
        let missing = features.missing(GuestFeatures::REQUIRED);
        if !missing.is_empty() {
            return Err(self.reject_guest(&runtime, &missing));
        }
        // Workloads run only once the guest has mounted every mapped host path.
        if let Some(plan) = &spec.filesystem
            && let Err(error) = session.map_host_paths(&plan.guest_table(), deadline)
        {
            let reason = format!("the host paths were not mapped: {error}");
            return Err(self.abort_start(&runtime, session_kind(&error), &reason));
        }
        Ok(Started {
            runtime,
            boot: started.elapsed(),
            features,
        })
    }

    /// Maps a control-session failure onto an instance-facing error and message.
    fn session_error(&self, error: SessionError, control_timeout: Duration) -> Error {
        match error {
            SessionError::ProcessExited => {
                Error::exited(format!("sandbox {} stopped unexpectedly", self.name))
            }
            SessionError::TimedOut => Error::timed_out(format!(
                "sandbox {} did not accept a control session within {} s; another exec may \
                 still be running",
                self.name,
                control_timeout.as_secs()
            )),
            other => Error::new(
                session_kind(&other),
                format!(
                    "the control session with sandbox {} failed: {other}",
                    self.name
                ),
            )
            .with_source(other),
        }
    }

    /// Starts `workload` in the running instance whose OpenVMM process `runtime` records, with
    /// the `capability` that it was launched with.
    ///
    /// It waits up to `control_timeout` for the control session, which the guest grants one
    /// execution at a time. [`Execution::pump`] then waits for the outcome up to the workload's
    /// own timeout plus `response_grace`, and without a limit when the workload has no timeout.
    /// Fails with [`ErrorKind::Exited`] when the VM is gone, and with
    /// [`ErrorKind::Unsupported`] when `control_timeout` is zero or either duration is longer
    /// than [`MAX_TIMEOUT`](super::launch::MAX_TIMEOUT).
    pub fn exec(
        &self,
        runtime: &RuntimeRecord,
        capability: &[u8; CAPABILITY_LEN],
        workload: &Workload<'_>,
        control_timeout: Duration,
        response_grace: Duration,
    ) -> Result<Execution> {
        // One path for every caller: the session this VM serves, shared with its other
        // executions. A caller that had its own session per execution would wait for the first
        // one to finish, because the broker issues a single host slot per VM.
        let shared = self.control_session(runtime, capability, control_timeout)?;
        self.exec_shared(&shared, workload, control_timeout, response_grace)
    }

    /// Starts one workload on a shared session and returns the handle that pumps its events.
    pub fn exec_shared(
        &self,
        shared: &Arc<SharedSession>,
        workload: &Workload<'_>,
        control_timeout: Duration,
        response_grace: Duration,
    ) -> Result<SharedExecution> {
        self.exec_shared_in_session(shared, None, workload, control_timeout, response_grace)
    }

    /// Start in an isolated guest context when `guest_session` is present.
    /// Absence keeps the legacy trusted-shared mode, never an automatic fallback.
    pub fn exec_shared_in_session(
        &self,
        shared: &Arc<SharedSession>,
        guest_session: Option<u64>,
        workload: &Workload<'_>,
        control_timeout: Duration,
        response_grace: Duration,
    ) -> Result<SharedExecution> {
        check_timeout("control timeout", control_timeout, true)?;
        check_timeout("response grace", response_grace, false)?;
        let deadline = Instant::now() + control_timeout;
        let (request_id, events) = shared
            .start_scoped_exec(guest_session, workload, deadline)
            .map_err(|error| self.session_error(error, control_timeout))?;
        let timeout_ms = workload.timeout_ms;
        let response_deadline = (timeout_ms > 0)
            .then(|| Instant::now() + Duration::from_millis(timeout_ms.into()) + response_grace);
        Ok(SharedExecution {
            shared: Arc::clone(shared),
            request_id,
            events,
            deadline: response_deadline,
            control_timeout,
        })
    }

    /// Asks the guest of the running instance that `runtime` records to shut down, and
    /// terminates OpenVMM if it has not exited within `timeout`.
    ///
    /// A running execution keeps the control session until it ends, so a stop that cannot reach
    /// the guest in time terminates the VM, and the execution then fails. Stop reads OpenVMM's
    /// outcome report and clears the runtime state. Fails with [`ErrorKind::Unsupported`] when
    /// `timeout` is zero or longer than [`MAX_TIMEOUT`](super::launch::MAX_TIMEOUT).
    pub fn stop(&self, runtime: &RuntimeRecord, timeout: Duration) -> Result<Stopped> {
        check_timeout("stop timeout", timeout, true)?;
        let deadline = Instant::now() + timeout;
        // The stop must travel over the VM's one control session: opening its own would wait for
        // that session to end instead of reaching the guest.
        let graceful = (|| -> std::result::Result<(), SessionError> {
            let capability = self
                .read_capability()
                .map_err(|error| SessionError::Protocol(error.to_string()))?;
            let shared = match self.control_session(runtime, &capability, timeout) {
                Ok(shared) => shared,
                // A VM that has already exited must stay distinguishable here: `finish_stop`
                // reports `forced` only for a stop that had to terminate it.
                Err(error) if error.kind() == ErrorKind::Exited => {
                    return Err(SessionError::ProcessExited);
                }
                Err(error) => return Err(SessionError::Protocol(error.to_string())),
            };
            shared.stop(deadline)?;
            if process::wait_for_exit(runtime.pid, runtime.start_time, deadline) {
                Ok(())
            } else {
                Err(SessionError::TimedOut)
            }
        })();
        self.forget_control_session(runtime);
        self.finish_stop(runtime, graceful)
    }

    /// Terminates OpenVMM when the guest did not shut down, then clears the runtime record.
    fn finish_stop(
        &self,
        runtime: &RuntimeRecord,
        graceful: std::result::Result<(), SessionError>,
    ) -> Result<Stopped> {
        let forced = !matches!(graceful, Ok(()) | Err(SessionError::ProcessExited));
        if forced {
            let exited = process::kill(runtime.pid, runtime.start_time).map_err(|error| {
                Error::io(format!("cannot terminate OpenVMM process {}", runtime.pid))
                    .with_source(error)
            })?;
            if !exited {
                return Err(Error::other(format!(
                    "OpenVMM process {} did not terminate",
                    runtime.pid
                )));
            }
        }
        let report = report::read(&self.report_path());
        self.clear_runtime()?;
        Ok(Stopped { forced, report })
    }
}

/// Fails with [`ErrorKind::Unsupported`] when the duration that `name` describes is longer than
/// [`MAX_TIMEOUT`](super::launch::MAX_TIMEOUT), or zero while it must be `positive`, so that no
/// deadline derived from it overflows.
fn check_timeout(name: &str, value: Duration, positive: bool) -> Result<()> {
    match timeout_problem(value, positive) {
        Some(problem) => Err(Error::unsupported(format!("the {name} {problem}"))),
        None => Ok(()),
    }
}

/// Receives a workload's output.
pub trait OutputSink {
    /// Writes one chunk. After an error, the chunks of this stream are discarded, and the
    /// workload continues.
    fn write(&mut self, chunk: &[u8]) -> io::Result<()>;
}

impl<F: FnMut(&[u8]) -> io::Result<()>> OutputSink for F {
    fn write(&mut self, chunk: &[u8]) -> io::Result<()> {
        self(chunk)
    }
}

/// How a workload ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadOutcome {
    /// The workload exited with this code.
    Exited(i32),
    /// A signal with this number ended the workload.
    Signaled(i32),
    /// The workload's own memory limit killed it. `signal` is the signal number, and
    /// `vm_wide` says whether the pressure was the whole VM's (the workload was collateral)
    /// or only this execution's.
    OutOfMemory {
        /// The signal that ended the workload.
        signal: i32,
        /// True when the VM ran out of memory; false when the execution's own limit did.
        vm_wide: bool,
    },
    /// The workload's timeout elapsed, and the guest agent killed it.
    TimedOut,
    /// The workload exceeded [`MAX_OUTPUT_BYTES`], and the guest agent killed it.
    OutputLimitExceeded,
    /// The guest agent could not supervise the workload.
    Failed,
    /// A cancellation request ended the workload.
    Cancelled,
    /// The guest agent could not launch the workload.
    LaunchFailed,
    /// The workload could not enter its working directory, so nothing of it ran. The guest agent
    /// wrote a diagnostic that names the directory to its standard error.
    WorkingDirectory,
}

/// The outcome the guest reported for an execution.
fn workload_outcome(category: ExitCategory, status: i32) -> WorkloadOutcome {
    match category {
        ExitCategory::Exit => WorkloadOutcome::Exited(status),
        ExitCategory::Signal => WorkloadOutcome::Signaled(if status > 128 {
            status - 128
        } else {
            status
        }),
        ExitCategory::Oom => WorkloadOutcome::OutOfMemory {
            signal: if status > 128 { status - 128 } else { status },
            vm_wide: false,
        },
        ExitCategory::VmOom => WorkloadOutcome::OutOfMemory {
            signal: if status > 128 { status - 128 } else { status },
            vm_wide: true,
        },
        ExitCategory::Timeout => WorkloadOutcome::TimedOut,
        ExitCategory::OutputLimit => WorkloadOutcome::OutputLimitExceeded,
        ExitCategory::Failed => WorkloadOutcome::Failed,
        ExitCategory::Cancelled => WorkloadOutcome::Cancelled,
    }
}

/// The outcome of a workload that the guest refused before it ran.
fn rejected_outcome(category: &str, status: i32) -> Result<WorkloadOutcome> {
    match category {
        LAUNCH_FAILED => Ok(WorkloadOutcome::LaunchFailed),
        // The guest already wrote a diagnostic that names the directory to stderr.
        CWD_FAILED => Ok(WorkloadOutcome::WorkingDirectory),
        // Only a start that was interrupted leaves a guest without its mappings.
        MAPPINGS_INCOMPLETE => Err(Error::protocol(
            "the guest has not mounted every mapped host path, because its start did not \
             complete; stop the sandbox and start it again",
        )),
        _ => Err(Error::protocol(format!(
            "the guest agent rejected the workload: {category} (status {status})"
        ))),
    }
}

/// A workload that [`Instance::exec_shared`] started on a [`SharedSession`].
pub struct SharedExecution {
    /// The session the workload runs on, which other executions also use.
    shared: Arc<SharedSession>,
    /// Identifier correlating requests, output, cancellation, and the final outcome.
    request_id: u64,
    /// Events of this execution, in the order the guest sent them.
    events: Receiver<Delivery>,
    /// Workload response deadline, absent for a workload without a timeout.
    deadline: Option<Instant>,
    /// Maximum time allowed for control traffic after cancellation or failure.
    control_timeout: Duration,
}

impl SharedExecution {
    /// Relays the workload's output to `stdout` and `stderr` and returns its outcome.
    ///
    /// Behaves like [`Execution::pump`], except that the events arrive from a session that other
    /// executions share: the reader thread of that session hands over the frames whose request id
    /// is this execution's, and a cancellation names only this execution.
    pub fn pump(
        self,
        stdout: &mut dyn OutputSink,
        stderr: &mut dyn OutputSink,
        cancel: &AtomicBool,
    ) -> Result<WorkloadOutcome> {
        let mut deadline = self.deadline;
        let mut forwarded = 0usize;
        let mut stdout_open = true;
        let mut stderr_open = true;
        let mut cancel_sent = false;
        loop {
            if !cancel_sent && cancel.load(Ordering::Acquire) {
                let cancellation_deadline = Instant::now() + self.control_timeout;
                self.shared
                    .cancel_exec(self.request_id, cancellation_deadline)
                    .map_err(|error| {
                        Error::new(
                            session_kind(&error),
                            format!("cannot deliver the cancellation request: {error}"),
                        )
                        .with_source(error)
                    })?;
                deadline = Some(deadline.map_or(cancellation_deadline, |deadline| {
                    deadline.min(cancellation_deadline)
                }));
                cancel_sent = true;
            }
            if let Some(deadline) = deadline
                && Instant::now() >= deadline
            {
                return Err(Error::timed_out(
                    "timed out waiting for the workload outcome",
                ));
            }
            let slice = Instant::now() + CANCEL_POLL_INTERVAL;
            let until = deadline.map_or(slice, |deadline| deadline.min(slice));
            let delivery = match self
                .events
                .recv_timeout(until.saturating_duration_since(Instant::now()))
            {
                Ok(delivery) => delivery,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(Error::protocol(
                        "the control session ended before the workload finished; the sandbox VM \
                         may have stopped",
                    ));
                }
            };
            let event = match delivery {
                Delivery::Event(event) => event,
                Delivery::Rejected { status, category } => {
                    return rejected_outcome(&category, status);
                }
                Delivery::Failed(message) => return Err(Error::protocol(message)),
                Delivery::Stopped => {
                    return Err(Error::protocol(
                        "the guest stopped before the workload finished",
                    ));
                }
                Delivery::Reply { .. } => {
                    return Err(Error::protocol(
                        "the guest acknowledged a request this execution did not send",
                    ));
                }
            };
            let (chunk, sink, open): (Vec<u8>, &mut dyn OutputSink, &mut bool) = match event {
                ExecEvent::Stdout(chunk) => (chunk, &mut *stdout, &mut stdout_open),
                ExecEvent::Stderr(chunk) => (chunk, &mut *stderr, &mut stderr_open),
                ExecEvent::Exit { category, status } => {
                    return Ok(workload_outcome(category, status));
                }
                ExecEvent::Rejected { status, category } => {
                    return rejected_outcome(&category, status);
                }
            };
            forwarded = forwarded.saturating_add(chunk.len());
            if forwarded > MAX_OUTPUT_BYTES {
                return Err(Error::protocol(
                    "the guest exceeded the output limit of the control protocol",
                ));
            }
            if *open && sink.write(&chunk).is_err() {
                *open = false;
            }
        }
    }
}

/// The handle of one execution, as earlier callers named it.
///
/// Executions share the VM's one control session now, so every caller receives a
/// [`SharedExecution`]; the name stays so existing code compiles unchanged.
pub type Execution = SharedExecution;

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    /// A process ID that fits every platform's type and that no process has.
    const GONE_PID: u32 = 0x7fff_fff0;

    fn instance() -> (tempfile::TempDir, Instance) {
        let directory = tempfile::tempdir().unwrap();
        let instance = Instance::new(directory.path(), "aci-edge-sandboxes:0123");
        (directory, instance)
    }

    #[test]
    fn readiness_failures_explain_images_without_workload_accounts() {
        let hint = "predates workload account creation";
        for ended in [SessionError::ProcessExited, SessionError::Closed] {
            assert!(readiness_failure(&ended, true).contains(hint));
            // Only a sandbox that needs the account suggests it.
            assert!(!readiness_failure(&ended, false).contains(hint));
        }
        for other in [
            SessionError::TimedOut,
            SessionError::Protocol("invalid record".to_owned()),
        ] {
            assert_eq!(readiness_failure(&other, true), other.to_string());
        }
    }

    #[test]
    fn runtime_files_round_trip_and_are_cleared() {
        let (_directory, instance) = instance();
        assert!(instance.launch().unwrap().is_none());
        assert!(instance.runtime().unwrap().is_none());
        let launch = LaunchRecord {
            format: STATE_FORMAT,
            endpoint: "endpoint".to_owned(),
            process: None,
        };
        instance.write_launch(&launch).unwrap();
        assert_eq!(instance.launch().unwrap(), Some(launch.clone()));
        let identified = LaunchRecord {
            process: Some(ProcessIdentity {
                pid: 1,
                start_time: 2,
            }),
            ..launch.clone()
        };
        instance.write_launch(&identified).unwrap();
        assert_eq!(instance.launch().unwrap(), Some(identified));
        instance.remove_launch();
        assert!(instance.launch().unwrap().is_none());
        instance.write_launch(&launch).unwrap();
        let runtime = RuntimeRecord {
            format: STATE_FORMAT,
            pid: 1,
            start_time: 2,
            endpoint: "endpoint".to_owned(),
            export_pipe: None,
        };
        instance.write_runtime(&runtime).unwrap();
        instance.write_capability(&[9; CAPABILITY_LEN]).unwrap();
        assert_eq!(instance.runtime().unwrap(), Some(runtime));
        assert_eq!(instance.read_capability().unwrap(), [9; CAPABILITY_LEN]);
        drop(instance.create_log().unwrap());
        instance.clear_runtime().unwrap();
        assert!(instance.runtime().unwrap().is_none());
        assert!(instance.launch().unwrap().is_none());
        assert!(instance.read_capability().is_err());
        // The log and the report outlive the run.
        assert!(instance.log_path().is_file());
    }

    #[test]
    fn records_keep_their_json_form() {
        let launch = LaunchRecord {
            format: STATE_FORMAT,
            endpoint: "/state/t/control.sock".to_owned(),
            process: Some(ProcessIdentity {
                pid: 7,
                start_time: 8,
            }),
        };
        assert_eq!(
            serde_json::to_value(&launch).unwrap(),
            serde_json::json!({
                "format": 3,
                "endpoint": "/state/t/control.sock",
                "process": { "pid": 7, "startTime": 8 },
            })
        );
        let runtime: RuntimeRecord = serde_json::from_value(serde_json::json!({
            "format": 3, "pid": 7, "startTime": 8, "endpoint": "e",
        }))
        .unwrap();
        assert_eq!(runtime.start_time, 8);
        // A marker of an interrupted start that predates process identities has none.
        let legacy: LaunchRecord =
            serde_json::from_value(serde_json::json!({ "format": 3, "endpoint": "e" })).unwrap();
        assert_eq!(legacy.process, None);
    }

    #[test]
    fn records_of_other_formats_are_rejected() {
        let (directory, instance) = instance();
        let write = |name: &str, value: serde_json::Value| {
            fs::write(directory.path().join(name), value.to_string()).unwrap();
        };
        write(
            RUNTIME_NAME,
            serde_json::json!({ "format": 2, "pid": 1, "startTime": 2, "endpoint": "e" }),
        );
        let error = instance.runtime().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Io);
        assert!(error.message().contains("unsupported format"), "{error}");
        write(
            LAUNCH_NAME,
            serde_json::json!({ "format": 2, "endpoint": "e" }),
        );
        assert!(instance.launch().is_err());
        fs::write(directory.path().join(RUNTIME_NAME), b"{ truncated").unwrap();
        assert!(
            instance
                .runtime()
                .unwrap_err()
                .message()
                .contains("malformed")
        );
        fs::write(directory.path().join(CAPABILITY_NAME), [0; CAPABILITY_LEN]).unwrap();
        assert!(instance.read_capability().is_err());
    }

    #[test]
    fn reconciliation_forgets_vms_that_are_gone() {
        let (_directory, instance) = instance();
        let runtime = RuntimeRecord {
            format: STATE_FORMAT,
            pid: GONE_PID,
            start_time: 0,
            endpoint: "endpoint".to_owned(),
            export_pipe: None,
        };
        instance.write_runtime(&runtime).unwrap();
        instance.write_capability(&[1; CAPABILITY_LEN]).unwrap();
        assert_eq!(instance.reconcile().unwrap(), None);
        assert!(instance.runtime().unwrap().is_none());
        assert!(instance.read_capability().is_err());
        // The marker of an interrupted start whose process is gone is cleared too.
        instance
            .write_launch(&LaunchRecord {
                format: STATE_FORMAT,
                endpoint: "endpoint".to_owned(),
                process: Some(ProcessIdentity {
                    pid: GONE_PID,
                    start_time: 0,
                }),
            })
            .unwrap();
        assert_eq!(instance.reconcile().unwrap(), None);
        assert!(instance.launch().unwrap().is_none());
    }

    #[test]
    fn capabilities_are_never_all_zero() {
        let first = generate_capability().unwrap();
        assert_ne!(first, [0; CAPABILITY_LEN]);
        assert_ne!(first, generate_capability().unwrap());
    }

    #[test]
    fn locks_are_exclusive() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("instance.lock");
        let guard = lock(&path).unwrap();
        let contender = OpenOptions::new().write(true).open(&path).unwrap();
        assert!(contender.try_lock().is_err());
        drop(guard);
        contender.try_lock().unwrap();
        drop(contender);
        // A waiter takes the lock once the holder releases it.
        let guard = lock(&path).unwrap();
        let waiter = thread::spawn({
            let path = path.clone();
            move || lock(&path).map(drop)
        });
        thread::sleep(Duration::from_millis(50));
        drop(guard);
        waiter.join().unwrap().unwrap();
    }

    #[test]
    fn private_files_are_replaced_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("value.json");
        write_json(&path, &serde_json::json!({ "a": 1 })).unwrap();
        write_json(&path, &serde_json::json!({ "a": 2 })).unwrap();
        assert_eq!(
            read_json::<serde_json::Value>(&path).unwrap(),
            Some(serde_json::json!({ "a": 2 }))
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\n  \"a\": 2\n}\n");
        // Nothing but the file remains, and a missing file reads as absent.
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        assert!(
            read_json::<serde_json::Value>(&directory.path().join("missing"))
                .unwrap()
                .is_none()
        );
        remove_if_present(&path).unwrap();
        remove_if_present(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            write_private(&path, b"secret").unwrap();
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
