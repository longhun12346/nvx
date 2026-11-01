//! The helper that starts a program inside a session.
//!
//! `nvxd-guest __session-enter KEEPER UID SHARE_NET CWD -- PROGRAM ARGUMENT...` is started by the
//! ordinary execution path, so it already sits in the execution's cgroup, process group and pipes. It
//! joins the keeper's namespaces, enters the session's root, drops to the session's user, and runs
//! the program as its child (born in the session's PID namespace). It ends as the program ended.

use super::sys;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Command;

struct Joined {
    root: OwnedFd,
    namespaces: Vec<(OwnedFd, i32)>,
}

fn open_session(keeper: i32, share_network: bool) -> std::io::Result<Joined> {
    let mut names: Vec<(&str, i32)> = vec![("mnt", libc::CLONE_NEWNS), ("ipc", libc::CLONE_NEWIPC), ("uts", libc::CLONE_NEWUTS)];
    if !share_network {
        names.push(("net", libc::CLONE_NEWNET));
    }
    names.push(("pid", libc::CLONE_NEWPID));
    let root = sys::open_path(
        std::path::Path::new(&format!("/proc/{keeper}/root")),
        libc::O_PATH | libc::O_DIRECTORY,
    )?;
    let mut namespaces = Vec::new();
    for (name, flag) in names {
        let fd = sys::open_path(std::path::Path::new(&format!("/proc/{keeper}/ns/{name}")), libc::O_RDONLY)?;
        namespaces.push((fd, flag));
    }
    Ok(Joined { root, namespaces })
}

pub(super) fn helper_main(arguments: &[String]) -> i32 {
    let [keeper, uid, share, directory, separator, program @ ..] = arguments else {
        eprintln!("usage: __session-enter KEEPER UID SHARE_NET CWD -- PROGRAM ARGUMENT...");
        return 2;
    };
    let (Ok(keeper), Ok(uid)) = (keeper.parse::<i32>(), uid.parse::<u32>()) else { return 2 };
    if separator != "--" || program.is_empty() {
        return 2;
    }
    match run(keeper, uid, share == "1", directory, program) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("nvxd-guest: cannot enter the session: {error}");
            125
        }
    }
}

fn step<T>(name: &str, result: std::io::Result<T>) -> std::io::Result<T> {
    result.map_err(|error| std::io::Error::new(error.kind(), format!("{name}: {error}")))
}

fn run(keeper: i32, uid: u32, share_network: bool, directory: &str, program: &[String]) -> std::io::Result<i32> {
    // Nothing the caller left open reaches the program: the agent's own descriptors stay out of the
    // session. This is before the chroot, while this process still sees its own /proc.
    sys::close_other_descriptors(&[0, 1, 2]);
    let joined = step("open session", open_session(keeper, share_network))?;
    for (fd, flag) in &joined.namespaces {
        step(&format!("setns {flag:#x}"), sys::setns(fd, *flag))?;
    }
    step("fchdir", sys::fchdir(joined.root.as_raw_fd()))?;
    step("chroot", sys::chroot_dot())?;
    drop(joined);
    step("restrict privileges", sys::restrict_privileges())?;
    step("become user", sys::become_user(uid))?;
    step("clear capabilities", sys::clear_capabilities())?;
    // The program is this process's child, so it is born in the session's PID namespace.
    let mut child = Command::new(&program[0]);
    child.arg0(&program[0]).args(&program[1..]).current_dir(directory);
    let mut child = step("spawn", child.spawn())?;
    let status = child.wait()?;
    if let Some(signal) = status.signal() {
        // Die the way the program died, so the execution reports the same signal.
        let _ = sys::kill(std::process::id() as i32, signal);
        std::thread::sleep(std::time::Duration::from_millis(100));
        return Ok(128 + signal);
    }
    Ok(status.code().unwrap_or(1))
}
