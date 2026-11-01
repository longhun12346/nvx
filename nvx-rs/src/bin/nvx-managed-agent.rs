//! The managed guest agent. It serves NVX's authenticated control session on the guest's control
//! TTY and runs one workload at a time, either as the guest's PID 1 or in a sandbox's root
//! filesystem.
//!
//! `nvx-managed-agent CONTROL_TTY ROOTFS HOSTNAME UID GID USER HOME` starts the agent, and
//! `nvx-managed-agent --exec-config-fd FD -- WORKLOAD...` is the direct agent's internal execution
//! helper. See `nvx::guest::managed_agent`.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    nvx::guest::managed_agent::main()
}

// The agent runs only in Linux guests. Elsewhere this stub fails, so that every target that CI
// checks with `--all-features` still builds.
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
