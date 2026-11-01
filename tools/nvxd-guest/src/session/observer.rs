//! Diagnostic fault injector, compiled into an agent built with the `fault-observer` feature only.
//!
//! The production agent has no observer and no trigger. The cleanup fault suite builds a separate,
//! disposable agent with this feature; the first session it opens starts
//! `nvxd-guest __p8-observer ROOT`, a privileged process outside every workload namespace and cgroup,
//! which waits for a workspace to ask for a fault (`p8-fire` holding the fault's name) and injects it.

use super::STORE;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn workspaces(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root.join("sessions")) else { return Vec::new() };
    entries.flatten().map(|entry| entry.path().join("workspace")).collect()
}

/// The keeper whose root holds the workspace marked `p8-target` with the same content as `workspace`.
fn keeper_for(workspace: &Path) -> Option<(i32, PathBuf)> {
    let identity = std::fs::read_to_string(workspace.join("p8-target")).ok()?;
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse::<i32>().ok()) else { continue };
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else { continue };
        let nested: Vec<&str> = match status.lines().find_map(|line| line.strip_prefix("NSpid:")) {
            Some(line) => line.split_whitespace().collect(),
            None => continue,
        };
        if nested.len() < 2 || nested.last() != Some(&"1") {
            continue;
        }
        let root = entry.path().join("root");
        if std::fs::read_to_string(root.join("workspace/p8-target")).ok().as_deref() == Some(identity.as_str()) {
            return Some((pid, root));
        }
    }
    None
}

pub(super) fn run(arguments: &[String]) -> i32 {
    let Some(root) = arguments.first().map(PathBuf::from) else { return 2 };
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut held: Vec<File> = Vec::new();
    while Instant::now() < deadline {
        for workspace in workspaces(&root) {
            let trigger = workspace.join("p8-fire");
            let Ok(mode) = std::fs::read_to_string(&trigger) else { continue };
            let mode = mode.trim().to_owned();
            let Some((pid, keeper_root)) = keeper_for(&workspace) else { continue };
            match mode.as_str() {
                "keeper" => {
                    // SAFETY: plain signal delivery to the session's PID 1.
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                }
                "strict-revoke" => {
                    if let Ok(file) = File::open(keeper_root.join("workspace/mounts/data/marker")) {
                        held.push(file);
                    }
                }
                "source-unmap" | "close-export" => {
                    let parent = workspace.parent().map(Path::to_path_buf).unwrap_or_default();
                    let sources: Vec<PathBuf> = std::fs::read_dir(parent.join("mounts"))
                        .into_iter()
                        .flatten()
                        .flatten()
                        .map(|entry| entry.path().join("marker"))
                        .filter(|marker| marker.exists())
                        .collect();
                    if sources.len() != 1 {
                        continue;
                    }
                    if let Ok(file) = File::open(&sources[0]) {
                        held.push(file);
                    }
                }
                "close-directory" => {
                    for directory in std::fs::read_dir(STORE).into_iter().flatten().flatten() {
                        let _ = std::fs::create_dir(directory.path().join("p8-injected-busy"));
                    }
                }
                _ => return 3,
            }
            let _ = std::fs::write(workspace.join("p8-injected"), format!("{mode} keeper={pid}"));
            // Hold the exact mount object until this diagnostic VM ends.
            while Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            return 0;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    1
}
