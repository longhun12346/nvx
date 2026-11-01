//! Scoped mounts: attaches a clone of an authorized agent mount to a session's mount namespace, or
//! strictly detaches one.
//!
//! `nvxd-guest __session-bind KEEPER ROOT SOURCE TARGET RO` and `__session-unbind KEEPER TARGET` run
//! as short-lived helpers of the agent: they need a mount namespace of their own to enter. A helper
//! ends with 0 on success, or prints the `errno` and ends with 1.

use super::sys;
use std::os::fd::{AsRawFd, OwnedFd};

fn open_keeper(keeper: i32) -> std::io::Result<(OwnedFd, OwnedFd)> {
    let namespace = sys::open_path(std::path::Path::new(&format!("/proc/{keeper}/ns/mnt")), libc::O_RDONLY)?;
    let root = sys::open_path(
        std::path::Path::new(&format!("/proc/{keeper}/root")),
        libc::O_PATH | libc::O_DIRECTORY,
    )?;
    Ok((namespace, root))
}

fn enter_mount_namespace(namespace: &OwnedFd, root: &OwnedFd) -> std::io::Result<()> {
    sys::setns(namespace, libc::CLONE_NEWNS)?;
    sys::fchdir(root.as_raw_fd())?;
    sys::chroot_dot()
}

fn leaf_ok(leaf: &str) -> bool {
    !leaf.is_empty()
        && leaf != "."
        && leaf != ".."
        && leaf.len() <= 255
        && leaf.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

/// The leaf of a `/workspace/mounts/<leaf>` target.
fn target_leaf(target: &str) -> std::io::Result<&str> {
    target
        .strip_prefix("/workspace/mounts/")
        .filter(|leaf| leaf_ok(leaf))
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))
}

fn step<T>(name: &str, result: std::io::Result<T>) -> std::io::Result<T> {
    result.map_err(|error| {
        eprintln!("nvxd-guest: scoped mount step {name}: {error}");
        error
    })
}

fn bind(arguments: &[String]) -> std::io::Result<()> {
    let [keeper, root, source, target, read_only] = arguments else {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    };
    let keeper: i32 = keeper.parse().map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let leaf = target_leaf(target)?;
    // The source is cloned before entering the target namespace: `move_mount` consumes a detached
    // mount, so no agent path is resolved inside the session's root.
    let base = step("open root", sys::open_path(std::path::Path::new(root), libc::O_PATH | libc::O_DIRECTORY))?;
    let source = step("open source", sys::open_beneath(base.as_raw_fd(), source, libc::O_PATH))?;
    let directory = step("stat source", sys::is_dir(&source))?;
    let tree = step("clone tree", sys::clone_tree(&source, read_only == "1"))?;
    drop((source, base));
    let (namespace, session_root) = step("open keeper", open_keeper(keeper))?;
    step("enter namespace", enter_mount_namespace(&namespace, &session_root))?;
    let workspace = step("open workspace", sys::open_path(std::path::Path::new("/workspace"), libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW))?;
    let mounts = std::ffi::CString::new("mounts").expect("no NUL");
    // SAFETY: `workspace` is open and `mounts` is NUL terminated.
    if unsafe { libc::mkdirat(workspace.as_raw_fd(), mounts.as_ptr(), 0o755) } != 0 && sys::errno() != libc::EEXIST {
        return Err(std::io::Error::last_os_error());
    }
    let mounts = step("open mounts", sys::open_beneath(workspace.as_raw_fd(), "mounts", libc::O_PATH | libc::O_DIRECTORY))?;
    let leaf_c = std::ffi::CString::new(leaf).expect("checked");
    if directory {
        // SAFETY: `mounts` is open and `leaf_c` is NUL terminated.
        if unsafe { libc::mkdirat(mounts.as_raw_fd(), leaf_c.as_ptr(), 0o755) } != 0 && sys::errno() != libc::EEXIST {
            return Err(std::io::Error::last_os_error());
        }
    } else {
        // SAFETY: as above; a regular file stands in for a file mount.
        let created = unsafe {
            libc::openat(mounts.as_raw_fd(), leaf_c.as_ptr(), libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW, 0o644)
        };
        if created >= 0 {
            // SAFETY: closing the descriptor just created.
            unsafe { libc::close(created) };
        } else if sys::errno() != libc::EEXIST {
            return Err(std::io::Error::last_os_error());
        }
    }
    let target_fd = step("open target", sys::open_beneath(mounts.as_raw_fd(), leaf, libc::O_PATH))?;
    let is_dir = step("stat target", sys::is_dir(&target_fd))?;
    if is_dir != directory {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    step("move mount", sys::move_mount(&tree, &target_fd))
}

fn unbind(arguments: &[String]) -> std::io::Result<()> {
    let [keeper, target] = arguments else {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    };
    let keeper: i32 = keeper.parse().map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    target_leaf(target)?;
    let (namespace, session_root) = open_keeper(keeper)?;
    enter_mount_namespace(&namespace, &session_root)?;
    // Move the mount to a root-only staging point, close the handle, and unmount strictly: a handle
    // that is still open makes the unmount fail, and no lazy unmount can hide it.
    let base = sys::open_path(std::path::Path::new("/"), libc::O_PATH | libc::O_DIRECTORY)?;
    let mount = sys::open_beneath(base.as_raw_fd(), target, libc::O_PATH)?;
    let directory = step("stat mount", sys::is_dir(&mount))?;
    let staging = "/run/nvx-revoke/mount";
    std::fs::create_dir_all("/run/nvx-revoke")?;
    if directory {
        std::fs::create_dir(staging)?;
    } else {
        std::fs::File::create(staging)?;
    }
    let staging_fd = sys::open_path(std::path::Path::new(staging), libc::O_PATH | libc::O_NOFOLLOW)?;
    sys::move_mount(&mount, &staging_fd)?;
    drop((mount, staging_fd));
    sys::umount(staging)?;
    if directory { std::fs::remove_dir(staging) } else { std::fs::remove_file(staging) }
}

pub(super) fn bind_main(arguments: &[String]) -> i32 {
    finish(bind(arguments))
}

pub(super) fn unbind_main(arguments: &[String]) -> i32 {
    finish(unbind(arguments))
}

fn finish(result: std::io::Result<()>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            println!("{}", error.raw_os_error().unwrap_or(libc::EIO));
            eprintln!("nvxd-guest: scoped mount failed: {error}");
            1
        }
    }
}
