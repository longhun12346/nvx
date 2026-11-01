//! The session keeper: PID 1 of a session's PID namespace, which builds the session's root.
//!
//! `nvxd-guest __session-keeper ID UID SHARE_NET ROOT WORKSPACE DIR` runs with the namespaces already
//! unshared by its spawner (see `Sessions::open`). It forks the keeper, which is PID 1 of the new PID
//! namespace, writes `P<pid>` on standard output, waits for the keeper, and then ends with its status.
//! The keeper writes `R0` once the root is ready or `R<errno> <stage>` if a stage failed.

use super::sys;
use std::io::Write;
use std::os::fd::AsRawFd;

struct Spec {
    id: u64,
    uid: u32,
    share_network: bool,
    root: String,
    workspace: String,
    directory: String,
}

fn parse(arguments: &[String]) -> Option<Spec> {
    let [id, uid, share, root, workspace, directory] = arguments else { return None };
    Some(Spec {
        id: id.parse().ok()?,
        uid: uid.parse().ok()?,
        share_network: share == "1",
        root: root.clone(),
        workspace: workspace.clone(),
        directory: directory.clone(),
    })
}

pub(super) fn helper_main(arguments: &[String]) -> i32 {
    let Some(spec) = parse(arguments) else {
        eprintln!("usage: __session-keeper ID UID SHARE_NET ROOT WORKSPACE DIR");
        return 2;
    };
    let mut flags = libc::CLONE_NEWNS | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS | libc::CLONE_NEWPID;
    if !spec.share_network {
        flags |= libc::CLONE_NEWNET;
    }
    if let Err(error) = sys::unshare(flags) {
        println!("R{} unshare", error.raw_os_error().unwrap_or(libc::EIO));
        return 1;
    }
    match sys::fork() {
        Err(error) => {
            println!("R{} fork", error.raw_os_error().unwrap_or(libc::EIO));
            1
        }
        Ok(0) => keeper(&spec),
        Ok(pid) => {
            println!("P{pid}");
            let _ = std::io::stdout().flush();
            match sys::waitpid(pid, false) {
                Ok(Some(status)) => libc::WEXITSTATUS(status),
                _ => 1,
            }
        }
    }
}

/// The keeper process. Never returns.
fn keeper(spec: &Spec) -> i32 {
    let mut stage = "descriptors";
    if let Err(error) = setup(spec, &mut stage) {
        let code = error.raw_os_error().unwrap_or(libc::EIO);
        println!("R{code} {stage}");
        let _ = std::io::stdout().flush();
        eprintln!("NVX-SESSION-ERROR stage={stage} errno={code}");
        return 125;
    }
    if sys::drop_privileges_for_good().is_err() {
        println!("R{} drop-privileges", sys::errno());
        let _ = std::io::stdout().flush();
        return 125;
    }
    println!("R0");
    let _ = std::io::stdout().flush();
    // Nothing of the keeper's standard streams may reach the agent's pipes again.
    sys::redirect_stdio_to_null();
    // PID 1 reaps every adopted descendant and runs no request-serving code.
    sys::reap_forever()
}

fn empty_mount(path: &str, options: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    sys::mount("tmpfs", path, Some("tmpfs"), libc::MS_NOSUID | libc::MS_NODEV, Some(options))
}

fn setup(spec: &Spec, stage: &mut &'static str) -> std::io::Result<()> {
    // The workspace is pinned before anything is hidden: the agent's mount of it is in this namespace.
    *stage = "workspace-open";
    let root_fd = sys::open_path(std::path::Path::new(&spec.root), libc::O_PATH | libc::O_DIRECTORY)?;
    let workspace = sys::open_beneath(root_fd.as_raw_fd(), &spec.workspace, libc::O_PATH | libc::O_DIRECTORY)?;
    let workspace_source = format!("/proc/self/fd/{}", workspace.as_raw_fd());
    sys::close_other_descriptors(&[0, 1, 2, root_fd.as_raw_fd(), workspace.as_raw_fd()]);

    *stage = "readonly-lower";
    sys::mount("", "/", None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    let dir = &spec.directory;
    sys::mount("tmpfs", dir, Some("tmpfs"), libc::MS_NOSUID | libc::MS_NODEV, Some("size=64m,nr_inodes=16384,mode=0700"))?;
    std::env::set_current_dir(dir)?;
    for (name, mode) in [("lower", 0o700), ("upper", 0o755), ("work", 0o700), ("root", 0o700)] {
        std::fs::create_dir(name)?;
        std::fs::set_permissions(name, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
    }
    sys::mount(&spec.root, "lower", None, libc::MS_BIND, None)?;
    sys::mount("", "lower", None, libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV, None)?;

    *stage = "overlay";
    let options = format!("lowerdir={dir}/lower,upperdir={dir}/upper,workdir={dir}/work");
    sys::mount("overlay", "root", Some("overlay"), libc::MS_NOSUID | libc::MS_NODEV, Some(&options))?;
    std::env::set_current_dir("root")?;

    *stage = "mask-agent-state";
    for hidden in ["run", "root", "sessions", "mnt", "sys"] {
        empty_mount(hidden, "size=1m,nr_inodes=256,mode=0755")?;
    }
    *stage = "private-writable-directories";
    empty_mount("tmp", "size=32m,nr_inodes=8192,mode=1777")?;
    empty_mount("home", "size=32m,nr_inodes=8192,mode=0755")?;
    std::fs::create_dir("home/session")?;
    std::fs::set_permissions("home/session", std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    sys::chown("home/session", spec.uid)?;
    empty_mount("dev", "size=1m,nr_inodes=256,mode=0755")?;

    *stage = "devices";
    for device in ["null", "zero", "random", "urandom"] {
        let target = format!("dev/{device}");
        std::fs::File::create(&target)?;
        sys::mount(&format!("/dev/{device}"), &target, None, libc::MS_BIND, None)?;
        sys::mount("", &target, None, libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NOEXEC, None)?;
    }
    for (link, to) in [("fd", "/proc/self/fd"), ("stdin", "/proc/self/fd/0"), ("stdout", "/proc/self/fd/1"), ("stderr", "/proc/self/fd/2")] {
        std::os::unix::fs::symlink(to, format!("dev/{link}"))?;
    }
    empty_mount("dev/shm", "size=16m,nr_inodes=4096,mode=1777")?;
    std::fs::create_dir_all("workspace")?;

    *stage = "workspace-proc";
    sys::mount(&workspace_source, "workspace", None, libc::MS_BIND | libc::MS_REC, None)?;
    std::fs::create_dir_all("proc")?;
    sys::mount("proc", "proc", Some("proc"), libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, None)?;

    *stage = "identity";
    sys::sethostname(&format!("nvx-session-{}", spec.id))?;
    std::fs::write("etc/passwd", format!("root:x:0:0:root:/root:/bin/false\nsession:x:{0}:{0}:session:/home/session:/bin/sh\n", spec.uid))?;
    std::fs::write("etc/group", format!("root:x:0:\nsession:x:{}:\n", spec.uid))?;

    *stage = "chroot-network";
    drop((root_fd, workspace));
    sys::chroot_dot()?;
    if !spec.share_network {
        sys::loopback_up()?;
    }
    Ok(())
}
