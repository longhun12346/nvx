//! The P8 guest probe: a privileged integration probe of the session isolation, run in a disposable
//! boot of the guest (see `tools/nvxd/tests/guest_probe_report.py`). It drives the production
//! [`Sessions`] type with real namespaces and mounts, and prints `P8-PROBE-PASS <check>` for every
//! check that held. A check that fails prints `P8-PROBE-FAIL <check>` on standard error and ends
//! the probe with status 1. Nothing is mocked: the session helpers are this binary started again.
//!
//! - `p8-session-probe` runs the probe as root in the guest's initramfs.
//! - `p8-session-probe __in-session CHECK...` runs one check inside a session, started by the
//!   session's own enter helper, so it has the identity and the view of a workload.
//! - Any other `__` command is a session helper of the agent (keeper, enter, bind, unbind).
//!
//! The list of checks and what each proves is in `ISOLATION.md`, section "Probe".
#![allow(unsafe_code)]
#![allow(missing_docs)]

use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use nvx::guest::cgroup::{ExecutionCgroup, Layout, Scope};
use runtime_adapter::session::{decode_open, Sessions};

const PROBE: &str = "/p8-session-probe";
const LOOPBACK_PORT: u16 = 35181;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let Some(command) = arguments.first().filter(|command| command.starts_with("__")) {
        if command == "__in-session" {
            return ExitCode::from(u8::from(!in_session(&arguments[1..])));
        }
        if let Some(status) = runtime_adapter::session::run_helper(command, &arguments[1..]) {
            return ExitCode::from(u8::try_from(status).unwrap_or(1));
        }
    }
    match probe() {
        Ok(()) => {
            println!("P8-PROBE-COMPLETE");
            ExitCode::SUCCESS
        }
        Err(label) => {
            eprintln!("P8-PROBE-FAIL {label} errno={}", std::io::Error::last_os_error());
            ExitCode::FAILURE
        }
    }
}

/// Records a check: prints its pass line or returns its label as the failure.
macro_rules! check {
    ($condition:expr, $label:expr) => {{
        if !($condition) {
            return Err($label);
        }
        println!("P8-PROBE-PASS {}", $label);
    }};
}

/// Whether `result` is an error that mentions `errno N`, as the session errors do.
fn refused_with(result: Result<(), String>, errno: i32) -> bool {
    matches!(result, Err(text) if text.contains(&format!("errno {errno}")))
}

fn make_directory(path: &str, mode: u32) -> bool {
    fs::create_dir_all(path).is_ok() && fs::set_permissions(path, fs::Permissions::from_mode(mode)).is_ok()
}

fn mount_tmpfs(target: &str, options: &str) -> bool {
    let (source, kind, options) = (
        CString::new("tmpfs").unwrap(),
        CString::new("tmpfs").unwrap(),
        CString::new(options).unwrap(),
    );
    let target = CString::new(target).unwrap();
    // SAFETY: all strings are valid and outlive the call.
    unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            kind.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            options.as_ptr().cast(),
        ) == 0
    }
}

/// Runs the in-session check `arguments` as session `id`; returns its exit status, or -1.
fn run_in_session(sessions: &mut Sessions, id: u64, arguments: &[&str]) -> i32 {
    let Ok(mut enter) = sessions.enter_arguments(id, "/workspace") else { return -1 };
    enter.push(PROBE.to_owned());
    enter.push("__in-session".to_owned());
    enter.extend(arguments.iter().map(|argument| (*argument).to_owned()));
    let Ok(executable) = std::env::current_exe() else { return -1 };
    match Command::new(executable)
        .arg0("p8-session-probe")
        .args(&enter)
        .stdin(Stdio::null())
        .status()
    {
        Ok(status) => status.code().unwrap_or(-1),
        Err(_) => -1,
    }
}

fn probe() -> Result<(), &'static str> {
    // SAFETY: geteuid has no preconditions.
    check!(unsafe { libc::geteuid() } == 0, "requires-root");
    check!(
        make_directory("/run/nvxd-sessions", 0o700)
            && mount_tmpfs("/run/nvxd-sessions", "size=2m")
            && make_directory("/sessions", 0o755)
            && mount_tmpfs("/sessions", "size=8m"),
        "disposable-agent-state"
    );
    let (workspace_a, workspace_b) = ("/sessions/a/workspace", "/sessions/b/workspace");
    check!(
        make_directory(workspace_a, 0o777) && make_directory(workspace_b, 0o777),
        "workspace-fixtures"
    );

    // The request the host sends for a session: id, network policy and workspace.
    check!(
        decode_open(&["1", "0", workspace_a]) == Ok((1, false, workspace_a)),
        "session-wire"
    );
    check!(
        decode_open(&["1", "1", workspace_a]) == Ok((1, true, workspace_a)),
        "shared-network-policy-decoded"
    );
    check!(
        decode_open(&["1", "2", workspace_a]).is_err() && decode_open(&["1", "", workspace_a]).is_err(),
        "unknown-network-policy-refused"
    );

    // A workspace that is a symbolic link is refused, and leaves nothing behind.
    {
        let mut linked = Sessions::new();
        let _ = fs::create_dir_all("/sessions/linked");
        let symlink_made = std::os::unix::fs::symlink("/etc", "/sessions/linked/workspace").is_ok();
        let refused = linked.open(Path::new("/"), 30, "/sessions/linked/workspace", false).is_err();
        check!(
            symlink_made && refused && !linked.has_sessions() && !Path::new("/run/nvxd-sessions/30").exists(),
            "workspace-symlink-refused"
        );
    }

    // A descriptor without close-on-exec stands for the agent's own: no session may inherit it.
    // SAFETY: the path is a valid C string; the descriptor is closed at the end.
    let sentinel = unsafe { libc::open(c"/etc/passwd".as_ptr(), libc::O_RDONLY) };
    let before = fs::metadata("/etc/passwd").map_err(|_| "agent-secret-fd")?;
    check!(sentinel >= 0, "agent-secret-fd");

    let root = Path::new("/");
    let mut sessions = Sessions::new();
    check!(sessions.open(root, 1, workspace_a, false).is_ok(), "create-a");
    check!(sessions.open(root, 2, workspace_b, false).is_ok(), "create-b");

    check!(scheduler(&mut sessions).is_ok(), "production-scheduler-two-by-two-cgroups");

    check!(run_in_session(&mut sessions, 1, &["identity", "100000"]) == 0, "identity-proc-capabilities-fds");
    check!(run_in_session(&mut sessions, 1, &["write-private"]) == 0, "a-private-state");
    check!(run_in_session(&mut sessions, 1, &["same-state"]) == 0, "same-session-state");
    check!(run_in_session(&mut sessions, 2, &["cross-state", "100001"]) == 0, "cross-session-state");
    check!(run_in_session(&mut sessions, 1, &["ipc-create"]) == 0, "same-session-sysv-ipc");
    check!(run_in_session(&mut sessions, 2, &["ipc-denied"]) == 0, "cross-session-sysv-ipc-denied");

    scoped_mounts(&mut sessions)?;
    check!(true, "scoped-mount-matrix");

    // A daemon survives between calls in this direct lifecycle probe. The production execution
    // cgroup additionally removes such descendants when an execution ends.
    check!(run_in_session(&mut sessions, 1, &["daemon"]) == 0, "a-loopback-server");
    check!(run_in_session(&mut sessions, 2, &["connect-fails"]) == 0, "cross-session-loopback-denied");
    check!(run_in_session(&mut sessions, 1, &["connect-ok"]) == 0, "same-session-loopback");

    let after = fs::metadata("/etc/passwd").map_err(|_| "agent-descriptors-preserved")?;
    let mut descriptor_state = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the descriptor is open and the buffer is valid.
    let still_open = unsafe { libc::fstat(sentinel, descriptor_state.as_mut_ptr()) } == 0;
    check!(
        still_open && std::os::unix::fs::MetadataExt::ino(&before) == std::os::unix::fs::MetadataExt::ino(&after),
        "agent-descriptors-preserved"
    );
    // SAFETY: the descriptor is ours.
    unsafe { libc::close(sentinel) };

    check!(sessions.close(1).is_ok(), "close-a");
    check!(
        run_in_session(&mut sessions, 2, &["temp-alive"]) == 0,
        "b-survives-a-close"
    );
    check!(
        refused_with(sessions.open(root, 1, workspace_a, false), libc::ESTALE),
        "id-reuse-refused"
    );
    check!(sessions.open(root, 3, workspace_a, false).is_ok(), "reopen-new-id");
    check!(run_in_session(&mut sessions, 3, &["reset-state"]) == 0, "private-state-reset-authorized-workspace-persists");
    check!(
        sessions.close(2).is_ok() && sessions.close(3).is_ok() && !sessions.is_broken(),
        "cleanup-all"
    );
    check!(!Path::new("/run/nvxd-sessions/1").exists(), "session-directories-removed");

    // A session created with a shared network never leaves the VM's own namespace.
    {
        let agent_net = fs::read_link("/proc/self/ns/net").map_err(|_| "agent-net-namespace")?;
        let agent_net = agent_net.to_string_lossy().into_owned();
        check!(!agent_net.is_empty(), "agent-net-namespace");
        let mut shared = Sessions::new();
        check!(shared.open(root, 10, workspace_a, true).is_ok(), "create-shared-network");
        check!(
            run_in_session(&mut shared, 10, &["net-ns", &agent_net]) == 0,
            "shared-network-is-the-vm-namespace"
        );
        check!(shared.close(10).is_ok() && !shared.is_broken(), "cleanup-shared-network");
    }

    // After a program ran outside every session, private sessions need a new VM.
    {
        let mut legacy = Sessions::new();
        legacy.note_unscoped_exec();
        check!(
            refused_with(legacy.open(root, 11, workspace_a, false), libc::EXDEV) && !Path::new("/run/nvxd-sessions/11").exists(),
            "legacy-migration-refused"
        );
    }

    // A keeper that dies on its own leaves the isolation unproven: the agent is broken.
    {
        let mut faulted = Sessions::new();
        check!(faulted.open(root, 12, workspace_a, false).is_ok(), "fault-injection-session");
        let keeper = faulted.keeper_pid(12).ok_or("fault-injection-kill-keeper")?;
        // SAFETY: the process ID is the keeper's.
        check!(unsafe { libc::kill(keeper, libc::SIGKILL) } == 0, "fault-injection-kill-keeper");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut lost = false;
        while Instant::now() < deadline {
            if faulted.health().is_err() {
                lost = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        check!(lost, "fault-injection-reap-keeper");
        check!(faulted.is_broken(), "keeper-loss-escalates-group-failure");
        faulted.destroy_all();
    }
    Ok(())
}

/// Two sessions with two programs each, in cgroup leaves of their own: the programs of a session
/// meet in its private `/tmp`, so they ran at the same time, and the leaves are gone afterwards.
fn scheduler(sessions: &mut Sessions) -> Result<(), String> {
    let cgroup_root = Path::new("/sys/fs/cgroup");
    if !cgroup_root.join("cgroup.controllers").exists() {
        fs::create_dir_all(cgroup_root).map_err(|error| error.to_string())?;
        let (kind, target) = (CString::new("cgroup2").unwrap(), CString::new("/sys/fs/cgroup").unwrap());
        // SAFETY: valid strings.
        let mounted = unsafe { libc::mount(kind.as_ptr(), target.as_ptr(), kind.as_ptr(), 0, std::ptr::null()) };
        if mounted != 0 {
            return Err(format!("cannot mount cgroup2: {}", std::io::Error::last_os_error()));
        }
    }
    let layout = Layout::new("/sys/fs/cgroup/agent", "/sys/fs/cgroup/workload").map_err(|error| error.to_string())?;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let mut running = Vec::new();
    for slot in 0..4u64 {
        let session = 1 + slot / 2;
        let own = (slot % 2).to_string();
        let other = (1 - slot % 2).to_string();
        let name = format!("probe-{slot}");
        let cgroup = ExecutionCgroup::prepare(
            &layout,
            Some(&name),
            &[("pids.max", "64"), ("memory.max", "67108864")],
        )
        .map_err(|error| format!("cgroup {name}: {error}"))?;
        let mut enter = sessions.enter_arguments(session, "/workspace").map_err(|errno| format!("enter: errno {errno}"))?;
        enter.extend([PROBE.to_owned(), "__in-session".to_owned(), "parallel".to_owned(), own, other]);
        let procs = fs::OpenOptions::new()
            .write(true)
            .open(cgroup.path().join("cgroup.procs"))
            .map_err(|error| error.to_string())?;
        let descriptor = procs.as_raw_fd();
        let mut command = Command::new(&executable);
        command.arg0("p8-session-probe").args(&enter).stdin(Stdio::null());
        // SAFETY: only async-signal-safe calls: the child joins its cgroup before the program runs.
        unsafe {
            command.pre_exec(move || {
                let line = b"0\n";
                if libc::write(descriptor, line.as_ptr().cast(), line.len()) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().map_err(|error| error.to_string())?;
        running.push((child, cgroup, procs));
    }
    // While they run, each program is in the leaf of its own.
    let mut occupied = 0;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && occupied < 4 {
        occupied = running
            .iter()
            .filter(|(_, cgroup, _)| cgroup.is_occupied(Scope::Execution).unwrap_or(false))
            .count();
        std::thread::sleep(Duration::from_millis(5));
    }
    if occupied < 4 {
        return Err(format!("only {occupied} of 4 cgroup leaves were occupied"));
    }
    for (index, (child, cgroup, _)) in running.iter_mut().enumerate() {
        let status = child.wait().map_err(|error| error.to_string())?;
        if !status.success() {
            return Err(format!("slot {index} ended with {status}"));
        }
        let path: PathBuf = cgroup.path().to_path_buf();
        cgroup
            .settle(Scope::Execution, Duration::from_secs(2), || Ok(()))
            .map_err(|error| format!("settle {index}: {error}"))?;
        cgroup.remove().map_err(|error| format!("remove {index}: {error}"))?;
        if path.exists() {
            return Err(format!("the leaf of slot {index} is still there"));
        }
    }
    Ok(())
}

/// The scoped mount matrix on sessions 1 and 2, then the busy revocation on a session of its own.
fn scoped_mounts(sessions: &mut Sessions) -> Result<(), &'static str> {
    let root = Path::new("/");
    check!(
        make_directory("/sessions/a/mounts/data", 0o777) && make_directory("/sessions/b/mounts/data", 0o777),
        "late-mount-fixtures"
    );
    check!(
        sessions.bind(root, 1, "/sessions/a/mounts/data", "/workspace/mounts/data", false).is_ok()
            && sessions.bind(root, 2, "/sessions/b/mounts/data", "/workspace/mounts/data", false).is_ok(),
        "same-target-in-independent-sessions"
    );
    check!(
        run_in_session(sessions, 1, &["write", "/workspace/mounts/data/marker", "authorized\n"]) == 0
            && run_in_session(sessions, 2, &["absent", "/workspace/mounts/data/marker"]) == 0,
        "late-mount-write-isolated"
    );
    check!(
        refused_with(
            sessions.bind(root, 1, "/sessions/b/mounts/data", "/workspace/mounts/foreign", false),
            libc::EACCES
        ),
        "foreign-source-denied"
    );
    check!(
        refused_with(
            sessions.bind(root, 1, "/sessions/a/mounts/data", "/workspace/mounts/../escape", false),
            libc::EINVAL
        ),
        "mount-traversal-denied"
    );
    check!(
        sessions.bind(root, 1, "/sessions/a/mounts/data", "/workspace/mounts/readonly", true).is_ok()
            && run_in_session(sessions, 1, &["content", "/workspace/mounts/readonly/marker", "authorized"]) == 0
            && run_in_session(sessions, 1, &["create-fails", "/workspace/mounts/readonly/forbidden"]) == 0,
        "recursive-readonly-enforced"
    );
    check!(
        sessions.unbind(1, "/workspace/mounts/data").is_ok()
            && run_in_session(sessions, 1, &["absent", "/workspace/mounts/data/marker"]) == 0
            && run_in_session(sessions, 1, &["present", "/workspace/mounts/readonly/marker"]) == 0,
        "private-unmount-preserves-other-authorized-view"
    );
    check!(
        run_in_session(sessions, 2, &["write", "/workspace/mounts/data/b", "alive\n"]) == 0,
        "b-mount-survives-a-unmount"
    );
    check!(
        sessions.unbind(1, "/workspace/mounts/readonly").is_ok() && sessions.unbind(2, "/workspace/mounts/data").is_ok(),
        "all-private-directory-mounts-revoked"
    );
    let file_made = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open("/sessions/a/mounts/file")
        .and_then(|mut file| file.write_all(b"file\n"))
        .is_ok();
    check!(file_made, "file-source");
    check!(
        sessions.bind(root, 1, "/sessions/a/mounts/file", "/workspace/mounts/file", true).is_ok()
            && run_in_session(sessions, 1, &["content", "/workspace/mounts/file", "file"]) == 0
            && sessions.unbind(1, "/workspace/mounts/file").is_ok(),
        "file-bind-and-strict-unmount"
    );

    // A mount that a process still holds cannot be proven revoked: the agent must become broken.
    // It runs on a table of its own, because a broken table refuses everything afterwards.
    let mut busy = Sessions::new();
    check!(
        make_directory("/sessions/c/workspace", 0o777)
            && make_directory("/sessions/c/mounts/data", 0o777)
            && busy.open(root, 20, "/sessions/c/workspace", false).is_ok()
            && busy.bind(root, 20, "/sessions/c/mounts/data", "/workspace/mounts/busy", false).is_ok(),
        "busy-revoke-fixture"
    );
    let keeper = busy.keeper_pid(20).ok_or("busy-revoke-holder")?;
    let holder = hold_session_mount(keeper, "/workspace/mounts/busy");
    let mut status = 0;
    // SAFETY: the process ID is our child's; the buffer is valid.
    let stopped = holder > 0
        && unsafe { libc::waitpid(holder, &mut status, libc::WUNTRACED) } == holder
        && libc::WIFSTOPPED(status);
    check!(stopped, "busy-revoke-holder");
    let refused = busy.unbind(20, "/workspace/mounts/busy").is_err();
    check!(refused && busy.is_broken(), "busy-revoke-escalates-group-failure");
    // SAFETY: the process ID is our child's.
    unsafe {
        libc::kill(holder, libc::SIGKILL);
        libc::waitpid(holder, &mut status, 0);
    }
    busy.destroy_all();
    Ok(())
}

/// A child that stands in the session's mount at `target` and stops: the mount is busy.
fn hold_session_mount(keeper: i32, target: &str) -> i32 {
    let open = |path: String, flags: i32| {
        let path = CString::new(path).unwrap();
        // SAFETY: valid string.
        unsafe { libc::open(path.as_ptr(), flags) }
    };
    let root = open(format!("/proc/{keeper}/root"), libc::O_PATH | libc::O_DIRECTORY);
    let namespace = open(format!("/proc/{keeper}/ns/mnt"), libc::O_RDONLY);
    if root < 0 || namespace < 0 {
        return -1;
    }
    let target = CString::new(target).unwrap();
    // SAFETY: the child only calls async-signal-safe functions before it stops or exits.
    unsafe {
        let child = libc::fork();
        if child == 0 {
            if libc::setns(namespace, libc::CLONE_NEWNS) != 0
                || libc::fchdir(root) != 0
                || libc::chroot(c".".as_ptr()) != 0
                || libc::chdir(target.as_ptr()) != 0
            {
                libc::_exit(125);
            }
            libc::raise(libc::SIGSTOP);
            libc::_exit(0);
        }
        libc::close(root);
        libc::close(namespace);
        child
    }
}

/// One check inside a session, as a workload sees it. Returns whether it held.
fn in_session(arguments: &[String]) -> bool {
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let held = match arguments.as_slice() {
        ["identity", uid] => identity(uid.parse().unwrap_or(0)),
        ["write-private"] => write_private(),
        ["same-state"] => same_state(),
        ["cross-state", uid] => cross_state(uid.parse().unwrap_or(0)),
        ["reset-state"] => reset_state(),
        ["ipc-create"] => ipc(true),
        ["ipc-denied"] => ipc(false),
        ["write", path, content] => fs::write(path, content).is_ok(),
        ["absent", path] => !Path::new(path).exists(),
        ["present", path] => Path::new(path).exists(),
        ["content", path, expected] => fs::read_to_string(path).is_ok_and(|text| text.trim() == *expected),
        ["create-fails", path] => fs::File::create(path).is_err(),
        ["daemon"] => daemon(),
        ["connect-fails"] => connect().is_err(),
        ["connect-ok"] => connect().is_ok(),
        ["temp-alive"] => fs::write("/tmp/alive", "b\n").is_ok() && fs::read_to_string("/tmp/alive").is_ok_and(|text| text == "b\n"),
        ["net-ns", expected] => fs::read_link("/proc/self/ns/net").is_ok_and(|link| link.to_string_lossy() == *expected),
        ["parallel", own, other] => parallel(own, other),
        _ => false,
    };
    if !held {
        eprintln!("in-session check failed: {arguments:?}");
    }
    held
}

fn status_field(name: &str) -> Option<String> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| line.strip_prefix(name)).map(|rest| rest.trim().to_owned())
}

fn is_empty_directory(path: &str) -> bool {
    fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_none())
}

/// Own identity, hidden agent state, no capabilities, a PID namespace of its own and no inherited
/// descriptors.
fn identity(uid: u32) -> bool {
    // SAFETY: plain system calls without preconditions.
    let (real, effective, gid, groups) = unsafe {
        (libc::getuid(), libc::geteuid(), libc::getgid(), libc::getgroups(0, std::ptr::null_mut()))
    };
    let namespaced_pids = status_field("NSpid:").is_some_and(|pids| pids.split_whitespace().count() == 1);
    // SAFETY: signalling PID 1, the keeper, which an unprivileged process may not do.
    let cannot_signal_init = unsafe { libc::kill(1, libc::SIGTERM) } != 0;
    let descriptors = fs::read_dir("/proc/self/fd").map_or(usize::MAX, Iterator::count);
    let facts = [
        ("uid", real == uid && effective == uid),
        ("gid", gid == uid),
        ("groups", groups == 0),
        ("sessions-empty", is_empty_directory("/sessions")),
        ("run-empty", is_empty_directory("/run")),
        ("sys-empty", is_empty_directory("/sys")),
        ("agent-state-hidden", !Path::new("/proc/1/root/run/nvxd-sessions").exists()),
        ("no-capabilities", status_field("CapEff:").is_some_and(|caps| caps.chars().all(|digit| digit == '0'))),
        ("pid-namespace", namespaced_pids),
        ("cannot-signal-init", cannot_signal_init),
        ("descriptors", descriptors <= 4),
    ];
    for (name, held) in facts {
        if !held {
            let open: Vec<String> = fs::read_dir("/proc/self/fd")
                .map(|entries| {
                    entries
                        .flatten()
                        .map(|entry| format!("{}->{}", entry.file_name().to_string_lossy(), fs::read_link(entry.path()).map(|link| link.display().to_string()).unwrap_or_default()))
                        .collect()
                })
                .unwrap_or_default();
            eprintln!("identity fact failed: {name} (uid {real}/{effective}, gid {gid}, descriptors {descriptors}: {open:?})");
        }
    }
    facts.iter().all(|(_, held)| *held)
}

fn write_private() -> bool {
    let writable = |path: &str| {
        let path = CString::new(path).unwrap();
        // SAFETY: valid string.
        unsafe { libc::access(path.as_ptr(), libc::W_OK) == 0 }
    };
    fs::write("/tmp/private", "a\n").is_ok()
        && fs::write("/home/session/credentials", "credentials\n").is_ok()
        && fs::write("/dev/shm/private", "ipc\n").is_ok()
        && fs::write("/workspace/owner", "workspace\n").is_ok()
        && Path::new("/etc/passwd").exists()
        && ["/usr/bin", "/bin", "/etc/passwd"].iter().all(|path| !Path::new(path).exists() || !writable(path))
}

fn same_state() -> bool {
    let read = |path: &str| fs::read_to_string(path).unwrap_or_default();
    read("/tmp/private") == "a\n"
        && read("/home/session/credentials") == "credentials\n"
        && read("/dev/shm/private") == "ipc\n"
        && read("/workspace/owner") == "workspace\n"
}

fn cross_state(uid: u32) -> bool {
    // SAFETY: no preconditions.
    let own = unsafe { libc::getuid() } == uid;
    own && ["/tmp/private", "/home/session/credentials", "/dev/shm/private", "/workspace/owner", "/workspace/../a/workspace/owner"]
        .iter()
        .all(|path| !Path::new(path).exists())
}

fn reset_state() -> bool {
    ["/tmp/private", "/home/session/credentials", "/dev/shm/private"].iter().all(|path| !Path::new(path).exists())
        && fs::read_to_string("/workspace/owner").is_ok_and(|text| text == "workspace\n")
}

/// Creates the SysV objects of keys `0x4e5658xx` (`create`), or looks for them and must not find them.
fn ipc(create: bool) -> bool {
    let flags = if create { 0o600 | 0o1000 } else { 0o600 };
    // SAFETY: plain system calls with integer arguments.
    let results = unsafe {
        [
            libc::syscall(libc::SYS_shmget, 0x4e56_5841_i64, 1_i64, i64::from(flags)),
            libc::syscall(libc::SYS_semget, 0x4e56_5842_i64, 1_i64, i64::from(flags)),
            libc::syscall(libc::SYS_msgget, 0x4e56_5843_i64, i64::from(flags)),
        ]
    };
    if create {
        results.iter().all(|result| *result >= 0)
    } else {
        results.iter().all(|result| *result < 0) && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
    }
}

/// Listens on the session's loopback and leaves a child that keeps the socket after the call ends.
fn daemon() -> bool {
    let Ok(listener) = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, LOOPBACK_PORT)) else { return false };
    // SAFETY: the parent ends right away, the child only accepts.
    match unsafe { libc::fork() } {
        0 => {
            // SAFETY: closing the standard descriptors the caller waits on.
            unsafe {
                libc::close(0);
                libc::close(1);
                libc::close(2);
            }
            loop {
                let mut sink = [0u8; 16];
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.read(&mut sink);
                }
            }
        }
        pid if pid > 0 => true,
        _ => false,
    }
}

fn connect() -> std::io::Result<TcpStream> {
    TcpStream::connect_timeout(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, LOOPBACK_PORT).into(), Duration::from_secs(1))
}

/// Meets the other program of the session in the private `/tmp`, then holds for a moment so the
/// controller can see the cgroup leaf occupied.
fn parallel(own: &str, other: &str) -> bool {
    if fs::write(format!("/tmp/parallel{own}"), "ready\n").is_err() {
        return false;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while !Path::new(&format!("/tmp/parallel{other}")).exists() {
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(400));
    !Path::new("/sys/fs/cgroup").exists() && is_empty_directory("/sys")
}
