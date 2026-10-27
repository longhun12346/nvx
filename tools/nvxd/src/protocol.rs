pub const VERSION: u64 = 1;
pub const MAX_JSON_BYTES: usize = 1 << 20;
pub const MAX_PAYLOAD_BYTES: usize = 8 << 20;
pub const DEFAULT_MEMORY_MIB: u64 = 1024;
pub const MAX_HARD_TIMEOUT_SEC: i64 = 24 * 60 * 60;

pub const OP_PROBE: &str = "probe";
pub const OP_SESSION_OPEN: &str = "session.open";
pub const OP_EXEC: &str = "exec";
pub const OP_SIGNAL: &str = "signal";
pub const OP_SESSION_CLOSE: &str = "session.close";
pub const OP_MEMORY_STATS: &str = "memory.stats";
pub const OP_MEMORY_TRIM: &str = "memory.trim";
pub const OP_SHUTDOWN: &str = "shutdown";
/// Asks what became of one execution, by the id the host assigned before sending it.
///
/// Needed because a lost start reply says nothing about whether the work started: the host
/// asks instead of guessing, and "unknown" is a real answer rather than a retry signal.
pub const OP_EXEC_STATUS: &str = "exec.status";
/// Says whether a TCP server the guest started at `port` is reachable from the host on
/// 127.0.0.1: published, held by another host process (with a free port to use instead), or not
/// forwarded at all. Waits up to `waitMs` for the guest's announcement to arrive.
pub const OP_PORT_CHECK: &str = "port.check";
/// Hands out a TCP port that is free on the host's loopback, for a server the guest is about to
/// start, so the port it listens on is also the port the host can reach.
pub const OP_PORT_ALLOCATE: &str = "port.allocate";
/// Returns this sidecar's own counters and session summary. Read-only, so a diagnostic
/// run never changes what it is measuring.
pub const OP_DIAGNOSTICS: &str = "diagnostics";

pub const EVENT_READY: &str = "ready";
pub const EVENT_EXEC_STDOUT: &str = "exec.stdout";
pub const EVENT_EXEC_STDERR: &str = "exec.stderr";
pub const EVENT_EXEC_EXIT: &str = "exec.exit";

pub const REASON_PROTOCOL: &str = "E_BACKEND_PROTOCOL";
/// Host-loopback ingress is off, so nothing the guest listens on is published to the host.
pub const REASON_INBOUND_DISABLED: &str = "E_NVX_INBOUND_DISABLED";
/// A port question named a transport other than `tcp` or `udp`.
pub const REASON_PORT_PROTOCOL_UNSUPPORTED: &str = "E_NVX_PORT_PROTOCOL_UNSUPPORTED";
pub const REASON_MEMORY_LIMIT_UNSUPPORTED: &str = "E_NVX_MEMORY_LIMIT_UNSUPPORTED";
pub const REASON_CPU_LIMIT_UNSUPPORTED: &str = "E_NVX_CPU_LIMIT_UNSUPPORTED";
pub const REASON_MEMORY_UNSUPPORTED: &str = "E_NVX_MEMORY_UNSUPPORTED";
pub const REASON_STDIN_UNSUPPORTED: &str = "E_NVX_STDIN_UNSUPPORTED";
pub const REASON_INVALID_LIMIT: &str = "E_NVX_INVALID_LIMIT";
/// The guest image cannot enforce per-execution limits, so an execution that asks for one is
/// refused instead of running without the limit the caller asked for.
pub const REASON_GUEST_NO_LIMITS: &str = "E_NVX_GUEST_NO_LIMITS";
pub const REASON_BACKEND_UNAVAILABLE: &str = "E_BACKEND_UNAVAILABLE";
pub const REASON_BACKEND_BUSY: &str = "E_BACKEND_BUSY";
pub const REASON_SESSION_UNKNOWN: &str = "E_BACKEND_SESSION_UNKNOWN";
pub const REASON_HANDLE_UNKNOWN: &str = "E_BACKEND_HANDLE_UNKNOWN";
/// The same exec id was used with different arguments. Two commands must never share an id,
/// because a lost reply is resolved by resending that id and comparing it.
pub const REASON_EXEC_CONFLICT: &str = "E_BACKEND_EXEC_ID_CONFLICT";
/// The queue is full: refused before anything was registered.
pub const REASON_QUEUE_FULL: &str = "E_BACKEND_QUEUE_FULL";
/// The session is closing or closed and takes no new executions.
pub const REASON_SESSION_CLOSING: &str = "E_BACKEND_SESSION_CLOSING";
/// The request names a VM instance this sidecar no longer serves.
pub const REASON_GENERATION_STALE: &str = "E_BACKEND_GENERATION_STALE";

/// The sidecar's own request or output path is saturated: the request was refused before
/// anything was registered, so the caller may retry once the backlog drains.
pub const REASON_OVERLOAD: &str = "E_BACKEND_OVERLOAD";

/// The VM could not be brought up and the failure was not classified further.
pub const REASON_START: &str = "E_BACKEND_START";
/// A file the VM needs is missing or unreadable (OpenVMM, kernel, initramfs, distro layer), or
/// OpenVMM could not be launched at all.
pub const REASON_START_ASSET: &str = "E_BACKEND_START_ASSET";
/// OpenVMM exited before the guest was ready.
pub const REASON_START_VMM_EXIT: &str = "E_BACKEND_START_VMM_EXIT";
/// The guest did not become ready within the start timeout.
pub const REASON_START_TIMEOUT: &str = "E_BACKEND_START_TIMEOUT";
/// The VM booted but the control channel failed, or the guest image lacks control features.
pub const REASON_START_CONTROL: &str = "E_BACKEND_START_CONTROL";
/// The hypervisor (Windows Hypervisor Platform) is missing or reports that none is present.
pub const REASON_START_HYPERVISOR: &str = "E_BACKEND_START_HYPERVISOR";

/// Names the reason a VM did not come up. Every code it returns means the machine or the VM
/// image cannot boot, as opposed to one session's request being refused, so a caller may treat
/// the whole family (`E_BACKEND_START*`) as "do not keep retrying this VM".
///
/// `kind` is the NVX error kind when the failure came from NVX, and `message` its text. Kinds
/// that the NVX library folds together (several different causes of `Unavailable`) are told
/// apart by their message; anything that does not match stays `E_BACKEND_START`.
pub fn classify_start_failure(kind: Option<ErrorKind>, message: &str) -> &'static str {
    match kind {
        Some(ErrorKind::Exited) => REASON_START_VMM_EXIT,
        Some(ErrorKind::TimedOut) => REASON_START_TIMEOUT,
        Some(ErrorKind::Protocol) => REASON_START_CONTROL,
        Some(ErrorKind::Io) if message.starts_with("cannot launch") => REASON_START_ASSET,
        Some(ErrorKind::Unavailable) => {
            let lower = message.to_ascii_lowercase();
            if lower.contains("control features") {
                REASON_START_CONTROL
            } else if lower.contains(" not found: ")
                || lower.starts_with("cannot resolve")
                || lower.starts_with("cannot read")
                || lower.contains("is not valid json")
            {
                REASON_START_ASSET
            } else if lower.contains("hypervisor") || lower.contains("winhv") || lower.contains("whv")
            {
                REASON_START_HYPERVISOR
            } else {
                REASON_START
            }
        }
        _ => REASON_START,
    }
}

use aci_edge_sandboxes::nvx::ErrorKind;

use aci_edge_sandboxes::nvx::protocol::{ExecLimits, MAX_EXEC_CPU_PERCENT, MAX_EXEC_MEMORY_MIB};
use serde_json::Value;

/// Validates a request-level `limits` object.
///
/// `memMb` and `cpuPercent` are accepted up to what the guest agent can enforce: the guest
/// writes them into the execution's own cgroup and refuses an execution whose limit it cannot
/// apply, so an out-of-range request is refused here instead of becoming a silent no-op.
/// Zero keeps its v1 meaning: "inherit the deployment default, no extra limit from this field".
pub fn validate_limits(limits: &serde_json::Map<String, Value>) -> Result<(), (&'static str, String)> {
    for key in limits.keys() {
        if key != "memMb" && key != "cpuPercent" && key != "hardTimeoutSec" {
            return Err((REASON_INVALID_LIMIT, format!("unknown limits field {key}")));
        }
    }
    if let Some(value) = limits.get("memMb") {
        let memory = unsigned_number(Some(value)).ok_or((
            REASON_INVALID_LIMIT,
            "memMb must be an unsigned integer".to_owned(),
        ))?;
        if memory > u64::from(MAX_EXEC_MEMORY_MIB) {
            return Err((
                REASON_INVALID_LIMIT,
                format!("memMb must be at most {MAX_EXEC_MEMORY_MIB}"),
            ));
        }
    }
    if let Some(value) = limits.get("cpuPercent") {
        let cpu = unsigned_number(Some(value)).ok_or((
            REASON_INVALID_LIMIT,
            "cpuPercent must be an unsigned integer".to_owned(),
        ))?;
        if cpu > u64::from(MAX_EXEC_CPU_PERCENT) {
            return Err((
                REASON_INVALID_LIMIT,
                format!("cpuPercent must be at most {MAX_EXEC_CPU_PERCENT}"),
            ));
        }
    }
    if let Some(value) = limits.get("hardTimeoutSec") {
        let timeout = signed_number(Some(value)).ok_or((
            REASON_INVALID_LIMIT,
            "hardTimeoutSec must be an integer".to_owned(),
        ))?;
        if timeout < 0 || timeout > MAX_HARD_TIMEOUT_SEC {
            return Err((
                REASON_INVALID_LIMIT,
                format!("hardTimeoutSec must be in 0..{MAX_HARD_TIMEOUT_SEC}"),
            ));
        }
    }
    Ok(())
}

/// Turns a validated `limits` object into the per-execution limits to send to the guest.
///
/// Returns `None` when the request asks for nothing: the deployment-level limits then apply
/// unchanged. A field left at zero keeps that meaning per field, which is what the merge in the
/// backend does.
pub fn request_exec_limits(
    limits: &serde_json::Map<String, Value>,
) -> Option<ExecLimits> {
    let mem = limits
        .get("memMb")
        .and_then(|value| unsigned_number(Some(value)))
        .unwrap_or(0);
    let cpu = limits
        .get("cpuPercent")
        .and_then(|value| unsigned_number(Some(value)))
        .unwrap_or(0);
    if mem == 0 && cpu == 0 {
        return None;
    }
    Some(ExecLimits {
        mem_mb: u32::try_from(mem).unwrap_or(0),
        cpu_percent: u32::try_from(cpu).unwrap_or(0),
        pids_max: 0,
    })
}

/// Guest RAM accepted per session.
///
/// The floor is measured on the EROFS runtime (thin stage initramfs + read-only EROFS distro,
/// so the root filesystem is not held in RAM). Python and Node boot and run from 256 MiB; a
/// 192 MiB Node allocation needs 320 MiB; the eight-session workload (eight resident 32 MiB
/// tasks, plus 8 MiB private tmpfs each in isolated mode) fails at 320 MiB shared and 384 MiB
/// isolated, and passes from 448 MiB in both modes. The floor is the next size up, 512 MiB, so
/// it keeps a margin over the smallest size that passed. The sizes below 1024 MiB are
/// measured with that workload only; heavier work should ask for more. The older RAM-initramfs
/// numbers (253 MiB rootfs, 672 MiB first usable) no longer describe the shipped assets.
///
/// The ceiling matches the instance budget the host reserves by default, so one session can
/// never ask for more guest RAM than the host is willing to hold.
pub const MIN_MEMORY_MIB: u64 = 512;
pub const MAX_MEMORY_MIB: u64 = 4096;

pub fn validate_memory(memory_mib: u64) -> Result<(), (&'static str, String)> {
    if !(MIN_MEMORY_MIB..=MAX_MEMORY_MIB).contains(&memory_mib) {
        return Err((
            REASON_MEMORY_UNSUPPORTED,
            format!(
                "memoryMiB must be within {MIN_MEMORY_MIB}..={MAX_MEMORY_MIB}, got {memory_mib}"
            ),
        ));
    }
    Ok(())
}

fn unsigned_number(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    value
        .as_u64()
        .or_else(|| value.as_str()?.trim().parse().ok())
}

fn signed_number(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    value
        .as_i64()
        .or_else(|| value.as_str()?.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_stays_1024_and_the_floor_is_512_mib() {
        assert!(validate_memory(DEFAULT_MEMORY_MIB).is_ok());
        assert!(validate_memory(MIN_MEMORY_MIB).is_ok());
        let error = validate_memory(MIN_MEMORY_MIB - 1).unwrap_err();
        assert_eq!(error.0, REASON_MEMORY_UNSUPPORTED);
    }

    /// Messages are the ones NVX really produces (nvx-rs `Artifacts::probe`, `Instance::start`,
    /// `probe_hypervisor`); a reworded message degrades to the generic code, never to a wrong one.
    #[test]
    fn boot_failures_are_told_apart() {
        use ErrorKind::*;
        let cases = [
            (Some(Unavailable), "OpenVMM executable not found: D:/x/openvmm.exe", REASON_START_ASSET),
            (Some(Unavailable), "NVX guest kernel not found: D:/x/vmlinux", REASON_START_ASSET),
            (Some(Unavailable), "NVX EROFS distro layer not found: D:/x/d.erofs", REASON_START_ASSET),
            (Some(Io), "cannot launch D:/x/openvmm.exe", REASON_START_ASSET),
            (Some(Exited), "sandbox s failed to start: OpenVMM exited during startup; see log", REASON_START_VMM_EXIT),
            (Some(TimedOut), "sandbox s failed to start: timed out; see log", REASON_START_TIMEOUT),
            (Some(Protocol), "the control session was reset", REASON_START_CONTROL),
            (
                Some(Unavailable),
                "sandbox s failed to start: the guest image lacks control features that the openvmm backend needs (x)",
                REASON_START_CONTROL,
            ),
            (
                Some(Unavailable),
                "the Windows Hypervisor Platform is not installed (WinHvPlatform.dll is missing)",
                REASON_START_HYPERVISOR,
            ),
            (
                Some(Unavailable),
                "the Windows Hypervisor Platform reports that no hypervisor is present",
                REASON_START_HYPERVISOR,
            ),
            (Some(Io), "cannot write /state/runtime.json", REASON_START),
            (Some(Unsupported), "kernel command line too long", REASON_START),
            (Some(Other), "anything", REASON_START),
            (None, "not from NVX", REASON_START),
        ];
        for (kind, message, expected) in cases {
            assert_eq!(classify_start_failure(kind, message), expected, "{message}");
        }
    }

    /// A path that happens to contain the word hypervisor is still a missing file.
    #[test]
    fn a_missing_asset_under_a_hypervisor_directory_is_still_an_asset_failure() {
        assert_eq!(
            classify_start_failure(
                Some(ErrorKind::Unavailable),
                "OpenVMM executable not found: D:/hypervisor/openvmm.exe"
            ),
            REASON_START_ASSET
        );
    }

    #[test]
    fn every_boot_failure_code_is_in_the_start_family() {
        for code in [
            REASON_START,
            REASON_START_ASSET,
            REASON_START_VMM_EXIT,
            REASON_START_TIMEOUT,
            REASON_START_CONTROL,
            REASON_START_HYPERVISOR,
        ] {
            assert!(code.starts_with("E_BACKEND_START"), "{code}");
        }
    }

    /// The range is a correctness boundary, not a suggestion: a size below the floor boots
    /// nothing (or boots and then kills the runtimes), so it must be refused up front.
    #[test]
    fn only_sizes_inside_the_supported_range_are_accepted() {
        for mib in [MIN_MEMORY_MIB, DEFAULT_MEMORY_MIB, 2048, MAX_MEMORY_MIB] {
            assert!(validate_memory(mib).is_ok(), "{mib} MiB should be accepted");
        }
        for mib in [0, 256, MIN_MEMORY_MIB - 1, MAX_MEMORY_MIB + 1] {
            let error = validate_memory(mib).unwrap_err();
            assert_eq!(error.0, REASON_MEMORY_UNSUPPORTED, "{mib} MiB should be refused");
        }
    }

    #[test]
    fn stable_contract_codes_are_frozen() {
        assert_eq!(REASON_CPU_LIMIT_UNSUPPORTED, "E_NVX_CPU_LIMIT_UNSUPPORTED");
        assert_eq!(
            REASON_MEMORY_LIMIT_UNSUPPORTED,
            "E_NVX_MEMORY_LIMIT_UNSUPPORTED"
        );
        assert_eq!(REASON_INVALID_LIMIT, "E_NVX_INVALID_LIMIT");
        assert_eq!(REASON_STDIN_UNSUPPORTED, "E_NVX_STDIN_UNSUPPORTED");
    }

    /// A request may ask for its own per-execution limits, up to what the guest can enforce.
    #[test]
    fn request_limits_are_accepted_inside_the_guest_ceiling() {
        let zero = serde_json::json!({
            "memMb": 0, "cpuPercent": "0", "hardTimeoutSec": 0
        });
        assert!(validate_limits(zero.as_object().unwrap()).is_ok());
        assert!(
            request_exec_limits(zero.as_object().unwrap()).is_none(),
            "zero everywhere means the deployment default, nothing to send"
        );

        let inside = serde_json::json!({"memMb": 512, "cpuPercent": 150});
        assert!(validate_limits(inside.as_object().unwrap()).is_ok());
        let sent = request_exec_limits(inside.as_object().unwrap()).expect("limits to send");
        assert_eq!(sent.mem_mb, 512);
        assert_eq!(sent.cpu_percent, 150);

        // The ceiling is the guest's, checked here so an impossible request is refused by the
        // sidecar rather than surviving until the guest refuses the execution.
        let too_much_memory = serde_json::json!({"memMb": MAX_EXEC_MEMORY_MIB + 1});
        assert_eq!(
            validate_limits(too_much_memory.as_object().unwrap()).unwrap_err().0,
            REASON_INVALID_LIMIT
        );
        let too_much_cpu = serde_json::json!({"cpuPercent": MAX_EXEC_CPU_PERCENT + 1});
        assert_eq!(
            validate_limits(too_much_cpu.as_object().unwrap()).unwrap_err().0,
            REASON_INVALID_LIMIT
        );
    }

    #[test]
    fn unknown_and_out_of_range_limits_are_rejected() {
        let unknown = serde_json::json!({"pidsMax": 10});
        assert_eq!(
            validate_limits(unknown.as_object().unwrap()).unwrap_err().0,
            REASON_INVALID_LIMIT
        );
        let timeout = serde_json::json!({"hardTimeoutSec": -1});
        assert_eq!(
            validate_limits(timeout.as_object().unwrap()).unwrap_err().0,
            REASON_INVALID_LIMIT
        );
    }
}
