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
/// Returns this sidecar's own counters and session summary. Read-only, so a diagnostic
/// run never changes what it is measuring.
pub const OP_DIAGNOSTICS: &str = "diagnostics";

pub const EVENT_READY: &str = "ready";
pub const EVENT_EXEC_STDOUT: &str = "exec.stdout";
pub const EVENT_EXEC_STDERR: &str = "exec.stderr";
pub const EVENT_EXEC_EXIT: &str = "exec.exit";

pub const REASON_PROTOCOL: &str = "E_BACKEND_PROTOCOL";
pub const REASON_MEMORY_LIMIT_UNSUPPORTED: &str = "E_NVX_MEMORY_LIMIT_UNSUPPORTED";
pub const REASON_CPU_LIMIT_UNSUPPORTED: &str = "E_NVX_CPU_LIMIT_UNSUPPORTED";
pub const REASON_MEMORY_UNSUPPORTED: &str = "E_NVX_MEMORY_UNSUPPORTED";
pub const REASON_STDIN_UNSUPPORTED: &str = "E_NVX_STDIN_UNSUPPORTED";
pub const REASON_INVALID_LIMIT: &str = "E_NVX_INVALID_LIMIT";
pub const REASON_BACKEND_UNAVAILABLE: &str = "E_BACKEND_UNAVAILABLE";
pub const REASON_BACKEND_BUSY: &str = "E_BACKEND_BUSY";
pub const REASON_SESSION_UNKNOWN: &str = "E_BACKEND_SESSION_UNKNOWN";
pub const REASON_HANDLE_UNKNOWN: &str = "E_BACKEND_HANDLE_UNKNOWN";

use serde_json::Value;

pub fn validate_memory(memory_mib: u64) -> Result<(), (&'static str, String)> {
    if memory_mib != DEFAULT_MEMORY_MIB {
        return Err((
            REASON_MEMORY_UNSUPPORTED,
            format!("NVX v1 requires exactly {DEFAULT_MEMORY_MIB} MiB per session"),
        ));
    }
    Ok(())
}

pub fn validate_limits(
    limits: &serde_json::Map<String, Value>,
) -> Result<(), (&'static str, String)> {
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
        if memory > 0 {
            return Err((
                REASON_MEMORY_LIMIT_UNSUPPORTED,
                "NVX v1 does not support per-task memory limits".to_owned(),
            ));
        }
    }
    if let Some(value) = limits.get("cpuPercent") {
        let cpu = unsigned_number(Some(value)).ok_or((
            REASON_INVALID_LIMIT,
            "cpuPercent must be an unsigned integer".to_owned(),
        ))?;
        if cpu > 0 {
            return Err((
                REASON_CPU_LIMIT_UNSUPPORTED,
                "NVX v1 does not support per-task CPU limits".to_owned(),
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
    fn product_baseline_is_1024_mib() {
        assert!(validate_memory(DEFAULT_MEMORY_MIB).is_ok());
        let error = validate_memory(768).unwrap_err();
        assert_eq!(error.0, REASON_MEMORY_UNSUPPORTED);
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

    #[test]
    fn zero_limits_are_accepted_but_positive_vm_limits_are_rejected() {
        let zero = serde_json::json!({
            "memMb": 0, "cpuPercent": "0", "hardTimeoutSec": 0
        });
        assert!(validate_limits(zero.as_object().unwrap()).is_ok());

        let memory = serde_json::json!({"memMb": 512});
        assert_eq!(
            validate_limits(memory.as_object().unwrap()).unwrap_err().0,
            REASON_MEMORY_LIMIT_UNSUPPORTED
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
