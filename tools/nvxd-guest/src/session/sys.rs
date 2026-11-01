//! Thin wrappers over the system calls the session helpers need. Every `unsafe` block of the
//! session code is here, with the argument checks it relies on in its comment.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

pub(super) fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

fn check(result: libc::c_long) -> io::Result<libc::c_long> {
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result) }
}

pub(super) fn cstr(text: &str) -> io::Result<CString> {
    CString::new(text).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn owned(fd: libc::c_long) -> io::Result<OwnedFd> {
    let fd = check(fd)?;
    // SAFETY: the kernel returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

/// Opens `relative` below `base` without following a symlink anywhere on the way, and without
/// leaving `base`. `flags` are the usual open flags.
pub(super) fn open_beneath(base: RawFd, relative: &str, flags: i32) -> io::Result<OwnedFd> {
    let path = cstr(relative.trim_start_matches('/'))?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `path` is NUL terminated, `how` is a live struct of the size passed, and the kernel
    // reads both only for the duration of the call.
    owned(unsafe {
        libc::syscall(libc::SYS_openat2, base, path.as_ptr(), &how, std::mem::size_of::<OpenHow>())
    })
}

pub(super) fn open_path(path: &Path, flags: i32) -> io::Result<OwnedFd> {
    let path = cstr(&path.to_string_lossy())?;
    // SAFETY: `path` is NUL terminated.
    owned(unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) } as libc::c_long)
}

pub(super) fn mount(
    source: &str,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let source = cstr(source)?;
    let target = cstr(target)?;
    let fstype = fstype.map(cstr).transpose()?;
    let data = data.map(cstr).transpose()?;
    // SAFETY: every pointer is NUL terminated and lives past the call, or is null.
    check(unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ref().map_or(std::ptr::null(), |text| text.as_ptr()),
            flags,
            data.as_ref().map_or(std::ptr::null(), |text| text.as_ptr().cast()),
        )
    } as libc::c_long)
    .map(|_| ())
}

pub(super) fn umount(target: &str) -> io::Result<()> {
    let target = cstr(target)?;
    // SAFETY: `target` is NUL terminated.
    check(unsafe { libc::umount2(target.as_ptr(), 0) } as libc::c_long).map(|_| ())
}

pub(super) fn chroot_dot() -> io::Result<()> {
    let dot = cstr(".")?;
    let slash = cstr("/")?;
    // SAFETY: both strings are NUL terminated.
    check(unsafe { libc::chroot(dot.as_ptr()) } as libc::c_long)?;
    check(unsafe { libc::chdir(slash.as_ptr()) } as libc::c_long).map(|_| ())
}

pub(super) fn fchdir(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a descriptor the caller holds.
    check(unsafe { libc::fchdir(fd) } as libc::c_long).map(|_| ())
}

pub(super) fn setns(fd: &OwnedFd, flag: i32) -> io::Result<()> {
    // SAFETY: `fd` is an open namespace descriptor.
    check(unsafe { libc::setns(fd.as_raw_fd(), flag) } as libc::c_long).map(|_| ())
}

pub(super) fn unshare(flags: i32) -> io::Result<()> {
    // SAFETY: only changes the caller's namespaces.
    check(unsafe { libc::unshare(flags) } as libc::c_long).map(|_| ())
}

/// Forks. The caller is single threaded, so the child may allocate.
pub(super) fn fork() -> io::Result<libc::pid_t> {
    // SAFETY: the session helpers run no other thread, so the child's copy of the process is whole.
    check(unsafe { libc::fork() } as libc::c_long).map(|pid| pid as libc::pid_t)
}

pub(super) fn waitpid(pid: libc::pid_t, nohang: bool) -> io::Result<Option<i32>> {
    let mut status = 0;
    let options = if nohang { libc::WNOHANG } else { 0 };
    loop {
        // SAFETY: `status` is a live integer.
        let result = unsafe { libc::waitpid(pid, &mut status, options) };
        if result > 0 {
            return Ok(Some(status));
        }
        if result == 0 {
            return Ok(None);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
}

pub(super) fn kill(pid: libc::pid_t, signal: i32) -> io::Result<()> {
    // SAFETY: plain signal delivery.
    check(unsafe { libc::kill(pid, signal) } as libc::c_long).map(|_| ())
}

pub(super) fn sethostname(name: &str) -> io::Result<()> {
    // SAFETY: the pointer and length describe `name`.
    check(unsafe { libc::sethostname(name.as_ptr().cast(), name.len()) } as libc::c_long).map(|_| ())
}

pub(super) fn chown(path: &str, uid: u32) -> io::Result<()> {
    let path = cstr(path)?;
    // SAFETY: `path` is NUL terminated.
    check(unsafe { libc::chown(path.as_ptr(), uid, uid) } as libc::c_long).map(|_| ())
}

/// Brings the loopback interface of the current network namespace up.
pub(super) fn loopback_up() -> io::Result<()> {
    // SAFETY: a datagram socket for the ioctl; closed by `OwnedFd`.
    let socket = owned(unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) } as libc::c_long)?;
    // SAFETY: an all-zero `ifreq` is a valid value.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name[..2].copy_from_slice(&[b'l' as libc::c_char, b'o' as libc::c_char]);
    request.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_LOOPBACK) as libc::c_short;
    // SAFETY: `request` is a live `ifreq`, which `SIOCSIFFLAGS` reads.
    check(unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS as _, &request) } as libc::c_long).map(|_| ())
}

/// Refuses new privileges for the rest of the process's life and empties its bounding set. Needs
/// the privilege it removes, so it comes before a switch to an unprivileged user.
pub(super) fn restrict_privileges() -> io::Result<()> {
    // SAFETY: prctl takes plain integers.
    unsafe {
        check(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) as libc::c_long)?;
        check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) as libc::c_long)?;
        for capability in 0..=63 {
            if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 && errno() != libc::EINVAL {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Empties the effective, permitted and inheritable capability sets.
pub(super) fn clear_capabilities() -> io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header { version: 0x2008_0522, pid: 0 };
    let data = [Data { effective: 0, permitted: 0, inheritable: 0 }, Data { effective: 0, permitted: 0, inheritable: 0 }];
    // SAFETY: capset reads a header and two data records, which are live and correctly sized.
    check(unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) }).map(|_| ())
}

/// Removes every capability and refuses new privileges for the rest of the process's life.
pub(super) fn drop_privileges_for_good() -> io::Result<()> {
    restrict_privileges()?;
    clear_capabilities()
}

/// Switches to `uid`/`gid` with no supplementary groups.
pub(super) fn become_user(uid: u32) -> io::Result<()> {
    // SAFETY: plain credential calls.
    unsafe {
        check(libc::setgroups(0, std::ptr::null()) as libc::c_long)?;
        check(libc::setresgid(uid, uid, uid) as libc::c_long)?;
        check(libc::setresuid(uid, uid, uid) as libc::c_long).map(|_| ())
    }
}

/// Closes every descriptor above 2 except those listed.
pub(super) fn close_other_descriptors(keep: &[RawFd]) {
    let Ok(directory) = std::fs::read_dir("/proc/self/fd") else { return };
    let open: Vec<RawFd> = directory
        .flatten()
        .filter_map(|entry| entry.file_name().to_str().and_then(|name| name.parse().ok()))
        .collect();
    for fd in open {
        if fd > 2 && !keep.contains(&fd) {
            // SAFETY: closing a descriptor of this process; a failure for the listing's own is harmless.
            unsafe { libc::close(fd) };
        }
    }
}

const SYS_OPEN_TREE: libc::c_long = 428;
const SYS_MOVE_MOUNT: libc::c_long = 429;
const SYS_MOUNT_SETATTR: libc::c_long = 442;

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// A detached recursive clone of the mount `source` names, nosuid and nodev, read-only on request.
pub(super) fn clone_tree(source: &OwnedFd, read_only: bool) -> io::Result<OwnedFd> {
    let empty = cstr("")?;
    const OPEN_TREE_CLONE: u32 = 1;
    const AT_EMPTY_PATH: i32 = 0x1000;
    const AT_RECURSIVE: i32 = 0x8000;
    // SAFETY: `empty` is NUL terminated and the descriptor is open.
    let tree = owned(unsafe {
        libc::syscall(
            SYS_OPEN_TREE,
            source.as_raw_fd(),
            empty.as_ptr(),
            OPEN_TREE_CLONE | libc::O_CLOEXEC as u32 | AT_EMPTY_PATH as u32 | AT_RECURSIVE as u32,
        )
    })?;
    let attributes = MountAttr {
        attr_set: 0x2 | 0x4 | if read_only { 0x1 } else { 0 },
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: `attributes` is live and its size is passed; the tree is an open descriptor.
    check(unsafe {
        libc::syscall(
            SYS_MOUNT_SETATTR,
            tree.as_raw_fd(),
            empty.as_ptr(),
            AT_EMPTY_PATH | AT_RECURSIVE,
            &attributes,
            std::mem::size_of::<MountAttr>(),
        )
    })?;
    Ok(tree)
}

/// Attaches the detached mount `tree`, or an existing mount, at the object `target` names.
pub(super) fn move_mount(tree: &OwnedFd, target: &OwnedFd) -> io::Result<()> {
    let empty = cstr("")?;
    const MOVE_MOUNT_F_EMPTY_PATH: u32 = 4;
    const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0x40;
    // SAFETY: `empty` is NUL terminated and both descriptors are open.
    check(unsafe {
        libc::syscall(
            SYS_MOVE_MOUNT,
            tree.as_raw_fd(),
            empty.as_ptr(),
            target.as_raw_fd(),
            empty.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        )
    })
    .map(|_| ())
}

/// Points the standard streams at `/dev/null`.
pub(super) fn redirect_stdio_to_null() {
    if let Ok(null) = open_path(Path::new("/dev/null"), libc::O_RDWR) {
        for target in 0..3 {
            // SAFETY: both descriptors are open in this process.
            unsafe { libc::dup2(null.as_raw_fd(), target) };
        }
    }
}

/// Reaps every child as it ends, for ever: what PID 1 of a PID namespace has to do.
pub(super) fn reap_forever() -> ! {
    extern "C" fn nothing(_: libc::c_int) {}
    // SAFETY: a handler that does nothing, a signal mask, and waiting for a signal.
    unsafe {
        libc::signal(libc::SIGCHLD, nothing as extern "C" fn(libc::c_int) as libc::sighandler_t);
        let mut blocked: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut blocked);
        libc::sigaddset(&mut blocked, libc::SIGCHLD);
        libc::sigprocmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut());
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        loop {
            while libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) > 0 {}
            libc::sigsuspend(&empty);
        }
    }
}

/// Whether the object `fd` names is a directory.
pub(super) fn is_dir(fd: &OwnedFd) -> io::Result<bool> {
    // SAFETY: an all-zero `stat` is a valid value, and `fstat` fills it for an open descriptor.
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    check(unsafe { libc::fstat(fd.as_raw_fd(), &mut status) } as libc::c_long)?;
    Ok(status.st_mode & libc::S_IFMT == libc::S_IFDIR)
}
