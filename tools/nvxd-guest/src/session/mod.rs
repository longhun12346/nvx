//! In-VM session isolation: one keeper per session, scoped mounts, and the helper that starts a
//! program inside a session. See `ISOLATION.md` for the contract.
//!
//! The agent itself stays single threaded and never changes its own namespaces. Everything that
//! needs a namespace of its own is a short-lived helper: this binary started again with a hidden
//! command (see [`HELPER_COMMANDS`]).
#![allow(unsafe_code)]

mod enter;
mod keeper;
mod mountctl;
#[cfg(feature = "fault-observer")]
mod observer;
mod sys;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::os::fd::AsFd;
use std::path::Path;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Most sessions resident at one time.
pub const MAX_SESSIONS: usize = 64;
/// Most scoped mounts of one session.
pub const MAX_MOUNTS: usize = 256;
/// The first user ID of a session; every session gets the next.
const FIRST_UID: u32 = 100_000;
/// How long a keeper may take to become ready, and a mount change to finish.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
/// Where each session's private directory is made, in the agent's namespace.
const STORE: &str = "/run/nvxd-sessions";

/// The hidden commands of this binary that act as session helpers.
pub const HELPER_COMMANDS: [&str; 5] =
    ["__session-keeper", "__session-enter", "__session-bind", "__session-unbind", "__p8-observer"];

/// Runs the helper named `command` with `arguments`, if it is one, and returns its exit status.
pub fn run_helper(command: &str, arguments: &[String]) -> Option<i32> {
    Some(match command {
        "__session-keeper" => keeper::helper_main(arguments),
        "__session-enter" => enter::helper_main(arguments),
        "__session-bind" => mountctl::bind_main(arguments),
        "__session-unbind" => mountctl::unbind_main(arguments),
        #[cfg(feature = "fault-observer")]
        "__p8-observer" => observer::run(arguments),
        _ => return None,
    })
}

/// A session the agent keeps.
pub struct Session {
    launcher: Child,
    /// The keeper's process ID, in the agent's PID namespace.
    keeper: i32,
    uid: u32,
    share_network: bool,
    /// The agent-visible parent of the session's workspace and mounts, `/sessions/<name>`.
    source_parent: String,
    mounts: Vec<String>,
    directory: String,
}

/// The fields of a session open request, `id`, `network` (`0` private, `1` the VM's own) and the
/// agent-visible `workspace`, as the host sends them. Any other network value is refused: a policy
/// the agent does not know is never granted as a default.
pub fn decode_open<'a>(fields: &[&'a str]) -> Result<(u64, bool, &'a str), String> {
    let [id, network, workspace] = fields else {
        return Err("session open needs id, network and workspace".to_owned());
    };
    let id = id.parse().map_err(|_| "bad session id".to_owned())?;
    let share_network = match *network {
        "0" => false,
        "1" => true,
        other => return Err(errno_text(libc::EINVAL, &format!("unknown network policy {other:?}"))),
    };
    Ok((id, share_network, workspace))
}

/// The sessions of one VM.
#[derive(Default)]
pub struct Sessions {
    table: BTreeMap<u64, Session>,
    highest: u64,
    next_uid: u32,
    /// Set by any fault that leaves the isolation unproven; every later request is refused.
    broken: bool,
    /// Set once a program ran outside a session; private sessions then need a new VM.
    legacy_used: bool,
    capacity: usize,
    storage_mib: u64,
    /// The fault observer of a diagnostic agent, started with the first session.
    #[cfg(feature = "fault-observer")]
    observer: Option<Child>,
}

impl Sessions {
    /// Returns no sessions.
    pub fn new() -> Self {
        Self { next_uid: FIRST_UID, capacity: MAX_SESSIONS, storage_mib: 64, ..Self::default() }
    }

    /// Configures the shared per-session filesystem quota before the first session.
    pub fn configure_storage(&mut self, capacity: u64, memory_bytes: u64) -> Result<(), String> {
        if self.ever_used() || !(1..=MAX_SESSIONS as u64).contains(&capacity) {
            return Err("invalid session storage configuration".to_owned());
        }
        let storage_mib = memory_bytes / (2 * 1024 * 1024) / capacity;
        if storage_mib == 0 {
            return Err("session storage budget is below 1 MiB".to_owned());
        }
        self.capacity = capacity as usize;
        self.storage_mib = storage_mib;
        Ok(())
    }

    /// Whether an isolation fault was seen.
    pub fn is_broken(&self) -> bool {
        self.broken
    }

    /// Whether any session was ever created in this VM.
    pub fn ever_used(&self) -> bool {
        self.highest != 0
    }

    /// The process ID of session `id`'s keeper in the agent's PID namespace, for diagnostics.
    pub fn keeper_pid(&self, id: u64) -> Option<i32> {
        self.table.get(&id).map(|session| session.keeper)
    }

    /// Whether any session is resident.
    pub fn has_sessions(&self) -> bool {
        !self.table.is_empty()
    }

    /// Fails once a resident session's keeper went away.
    pub fn health(&mut self) -> Result<(), String> {
        for (id, session) in &mut self.table {
            if !matches!(session.launcher.try_wait(), Ok(None)) {
                self.broken = true;
                return Err(format!("the keeper of session {id} ended; its isolation is unproven"));
            }
        }
        Ok(())
    }

    /// Records that a program ran outside every session.
    pub fn note_unscoped_exec(&mut self) {
        self.legacy_used = true;
    }

    /// The command line that runs `program` in session `id`, or why it cannot.
    pub fn enter_arguments(&mut self, id: u64, directory: &str) -> Result<Vec<String>, i32> {
        if self.broken {
            return Err(libc::EIO);
        }
        let Some(session) = self.table.get_mut(&id) else { return Err(libc::ENOENT) };
        // A keeper that is gone means the isolation can no longer be vouched for.
        if !matches!(session.launcher.try_wait(), Ok(None)) {
            self.broken = true;
            return Err(libc::EIO);
        }
        Ok(vec![
            "__session-enter".to_owned(),
            session.keeper.to_string(),
            session.uid.to_string(),
            u8::from(session.share_network).to_string(),
            directory.to_owned(),
            "--".to_owned(),
        ])
    }

    /// Creates session `id` whose workspace is the agent-visible `workspace` below the sandbox
    /// `root`, i.e. `/sessions/<name>/workspace`.
    pub fn open(&mut self, root: &Path, id: u64, workspace: &str, share_network: bool) -> Result<(), String> {
        if self.broken || self.legacy_used {
            return Err(errno_text(libc::EXDEV, "a program already ran outside a session, or isolation failed"));
        }
        if id == 0 || id <= self.highest {
            return Err(errno_text(libc::ESTALE, "session identity not newer than the last"));
        }
        if self.table.len() >= self.capacity || self.next_uid == u32::MAX {
            return Err(errno_text(libc::ENOSPC, "no free session slot"));
        }
        let source_parent = workspace
            .rsplit_once('/')
            .map(|(parent, _)| parent.to_owned())
            .filter(|parent| parent.starts_with("/sessions/"))
            .ok_or_else(|| errno_text(libc::EINVAL, "bad workspace path"))?;
        #[cfg(feature = "fault-observer")]
        if self.observer.is_none() {
            self.observer = std::env::current_exe().ok().and_then(|executable| {
                Command::new(executable).arg0("nvxd-guest").arg("__p8-observer").arg(root).stdin(Stdio::null()).spawn().ok()
            });
        }
        let uid = self.next_uid;
        self.next_uid += 1;
        // A failed attempt cannot reuse the identity.
        self.highest = id;
        std::fs::create_dir_all(STORE).map_err(|error| format!("cannot create {STORE}: {error}"))?;
        let directory = format!("{STORE}/{id}");
        std::fs::create_dir(&directory).map_err(|error| format!("cannot create {directory}: {error}"))?;
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        // The spawner unshares the namespaces; the keeper it forks is PID 1 of the new one.
        let mut launcher = Command::new(&executable)
            .arg0("nvxd-guest")
            .args(["__session-keeper", &id.to_string(), &uid.to_string(), if share_network { "1" } else { "0" }])
            .arg(root)
            .arg(workspace)
            .arg(&directory)
            .arg(self.storage_mib.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|error| format!("cannot start the session keeper: {error}"))?;
        let outcome = (|| -> Result<i32, String> {
            let stdout = launcher.stdout.take().ok_or("no keeper output")?;
            let mut lines = LineReader::new(stdout);
            // The launcher's pid line and the keeper's status line may come in either order.
            let mut keeper = None;
            let mut status = None;
            while keeper.is_none() || status.is_none() {
                let line = lines
                    .read_line(CONTROL_TIMEOUT)
                    .ok_or_else(|| errno_text(libc::ETIMEDOUT, "the session keeper did not become ready"))?;
                if let Some(pid) = line.strip_prefix('P') {
                    keeper = pid.parse().ok();
                } else if line.starts_with('R') {
                    status = Some(line);
                } else {
                    return Err(format!("unexpected keeper output {line:?}"));
                }
            }
            match status.as_deref() {
                Some("R0") => keeper.ok_or_else(|| "no keeper pid".to_owned()),
                other => Err(format!("the session root failed: {}", other.unwrap_or(""))),
            }
        })();
        match outcome {
            Ok(keeper) => {
                self.table.insert(
                    id,
                    Session { launcher, keeper, uid, share_network, source_parent, mounts: Vec::new(), directory },
                );
                Ok(())
            }
            Err(problem) => {
                let _ = launcher.kill();
                let _ = launcher.wait();
                let _ = std::fs::remove_dir(&directory);
                // The keeper may have been forked before the failure: its namespace is torn down
                // with the launcher's group, but a leftover is an isolation fault.
                Err(problem)
            }
        }
    }

    /// Destroys session `id`: kills its keeper and waits for the kernel to tear the namespace down.
    pub fn close(&mut self, id: u64) -> Result<(), String> {
        let Some(mut session) = self.table.remove(&id) else {
            return Err(errno_text(libc::ENOENT, "unknown session"));
        };
        let result = destroy(&mut session);
        if result.is_err() {
            self.broken = true;
        }
        result
    }

    /// Destroys every session; a fault marks the agent broken.
    pub fn destroy_all(&mut self) {
        for (_, mut session) in std::mem::take(&mut self.table) {
            if destroy(&mut session).is_err() {
                self.broken = true;
            }
        }
    }

    /// Attaches a clone of the agent mount `source` (`/sessions/<name>/mounts/<leaf>`) at the
    /// session path `target` (`/workspace/mounts/<leaf>`).
    pub fn bind(&mut self, root: &Path, id: u64, source: &str, target: &str, read_only: bool) -> Result<(), String> {
        if self.broken {
            return Err(errno_text(libc::EIO, "session isolation failed earlier"));
        }
        let session = self.table.get_mut(&id).ok_or_else(|| errno_text(libc::ENOENT, "unknown session"))?;
        let prefix = format!("{}/mounts/", session.source_parent);
        if !source.starts_with(&prefix) || source.contains("..") {
            return Err(errno_text(libc::EACCES, "source outside the session's authorized mounts"));
        }
        if session.mounts.iter().any(|existing| existing == target) {
            return Err(errno_text(libc::EEXIST, "target already mounted"));
        }
        if session.mounts.len() >= MAX_MOUNTS {
            return Err(errno_text(libc::ENOSPC, "too many scoped mounts"));
        }
        let keeper = session.keeper.to_string();
        let mut arguments = vec![
            "__session-bind".to_owned(),
            keeper,
            root.display().to_string(),
            source.to_owned(),
            target.to_owned(),
            if read_only { "1" } else { "0" }.to_owned(),
        ];
        let outcome = run_control(&mut arguments);
        match outcome {
            Ok(()) => {
                session.mounts.push(target.to_owned());
                Ok(())
            }
            Err(problem) => {
                // A timed-out change has an unknown outcome.
                if problem.contains("timed out") {
                    self.broken = true;
                }
                Err(problem)
            }
        }
    }

    /// Strictly detaches the scoped mount at `target`.
    pub fn unbind(&mut self, id: u64, target: &str) -> Result<(), String> {
        let session = self.table.get_mut(&id).ok_or_else(|| errno_text(libc::ENOENT, "unknown session"))?;
        let Some(position) = session.mounts.iter().position(|existing| existing == target) else {
            return Err(errno_text(libc::ENOENT, "target not mounted"));
        };
        let mut arguments = vec!["__session-unbind".to_owned(), session.keeper.to_string(), target.to_owned()];
        match run_control(&mut arguments) {
            Ok(()) => {
                session.mounts.remove(position);
                Ok(())
            }
            Err(problem) => {
                // An unmount that cannot be proven complete is an isolation fault.
                self.broken = true;
                Err(problem)
            }
        }
    }
}

fn errno_text(errno: i32, what: &str) -> String {
    format!("{what} (errno {errno}: {})", std::io::Error::from_raw_os_error(errno))
}

/// Kills the keeper and waits for the launcher: a keeper that stays is an isolation fault.
fn destroy(session: &mut Session) -> Result<(), String> {
    let _ = sys::kill(session.keeper, libc::SIGKILL);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match session.launcher.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => return Err(errno_text(libc::EBUSY, "the session keeper did not go away")),
        }
    }
    std::fs::remove_dir(&session.directory)
        .or_else(|error| if error.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(error) })
        .map_err(|error| format!("cannot remove {}: {error}", session.directory))
}

/// Runs a control helper to its end within [`CONTROL_TIMEOUT`].
fn run_control(arguments: &mut Vec<String>) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let command = arguments.remove(0);
    let mut child = Command::new(executable)
        .arg0("nvxd-guest")
        .arg(&command)
        .args(arguments.iter())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot start {command}: {error}"))?;
    let deadline = Instant::now() + CONTROL_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                let mut text = String::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut text);
                }
                let errno: i32 = text.trim().parse().unwrap_or(libc::EIO);
                let mut detail = String::new();
                if let Some(mut err) = child.stderr.take() {
                    let _ = err.read_to_string(&mut detail);
                }
                return Err(errno_text(errno, &format!("{command} failed: {}", detail.trim())));
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(errno_text(libc::ETIMEDOUT, &format!("{command} timed out")));
            }
        }
    }
}

/// Reads whole lines from a pipe with a deadline.
struct LineReader {
    reader: BufReader<std::process::ChildStdout>,
}

impl LineReader {
    fn new(stdout: std::process::ChildStdout) -> Self {
        Self { reader: BufReader::new(stdout) }
    }

    fn read_line(&mut self, timeout: Duration) -> Option<String> {
        use nix::poll::{PollFd, PollFlags, PollTimeout};
        if self.reader.buffer().is_empty() {
            let mut fds = [PollFd::new(self.reader.get_ref().as_fd(), PollFlags::POLLIN)];
            let millis = u16::try_from(timeout.as_millis().min(u128::from(u16::MAX))).unwrap_or(u16::MAX);
            match nix::poll::poll(&mut fds, PollTimeout::from(millis)) {
                Ok(count) if count > 0 => {}
                _ => return None,
            }
        }
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line.trim_end().to_owned()),
        }
    }
}
