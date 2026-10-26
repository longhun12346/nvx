//! Codec of the OpenVMM control-console protocol.
//!
//! OpenVMM brokers an authenticated stream of outer records (magic `NVXS`) between one host
//! client and the guest agent. Data records carry application frames (magic `NVXC`) that belong
//! to the guest agent in `guest/common/nvx-managed-agent.c`. All integers are little-endian.
//!
//! - Outer records: [`encode_outer`] and [`decode_outer_header`], and the `OUTER_*` record types.
//! - Application frames: [`encode_app`] and [`decode_app`], the `APP_*` request and response
//!   kinds, the error categories with which the guest agent refuses a request, and the
//!   [`ExitCategory`] of a workload.
//! - `EXEC` payloads: the [`Workload`] that the host encodes with [`encode_exec_payload`], and
//!   the [`ExecPayload`] that the guest agent decodes with [`decode_exec_payload`].
//! - `MAPS` payloads: the [`HostMap`] table that the host encodes with [`encode_maps_payloads`],
//!   and the [`MapsPayload`] that the guest agent decodes with [`decode_maps_payload`].
//! - [`GuestFeatures`]: the control features that a guest image advertises.
//! - The kernel command-line tokens through which the host configures the guest agent at boot,
//!   such as [`MAPS_TOKEN`].
//!
//! The module depends on nothing outside the standard library, so the host, the guest, and test
//! doubles share it. Its wire constants are those of the guest agent, which tests compare with
//! the agent's source, and golden byte fixtures pin every record that both sides exchange.

use std::fmt;

mod app;
mod boot;
mod exec;
mod features;
mod guest_session;
pub use guest_session::{
    APP_SESSION_BIND, APP_SESSION_UNBIND, SessionMount, encode_session_mount,
    encode_session_unmount, valid_session_mount_target,
};
mod maps;
mod outer;
#[cfg(test)]
mod tests;

pub use app::{
    APP_CANCEL, APP_ERROR, APP_EXEC, APP_EXIT, APP_FEATURES, APP_HEADER_LEN, APP_MAGIC, APP_MAPS,
    APP_UNMAP,
    APP_PING, APP_READY, APP_STDERR, APP_STDOUT, APP_STOP, APP_STOPPED, APP_VERSION, AppFrame,
    BUSY, CWD_FAILED, ExitCategory, INVALID_REQUEST, LAUNCH_FAILED, MAPPING_FAILED,
    MAPPING_LIMIT, MAPPINGS_INCOMPLETE, UNSUPPORTED_OPERATION, decode_app, encode_app,
};
pub use boot::{MAPS_TOKEN, WORKLOAD_ACCOUNT_TOKEN};
pub use exec::{
    EXEC_CWD_PRESENT, EXEC_ENVIRONMENT_PRESENT, EXEC_EXTENDED, EXEC_EXTENDED_V2,
    EXEC_INHERIT_DEFAULT_ENV, ExecLimits, ExecPayload, MAX_ARGUMENT_BYTES, MAX_ARGUMENTS,
    MAX_CWD_BYTES, MAX_ENVIRONMENT, MAX_EXEC_CPU_PERCENT, MAX_EXEC_MEMORY_MIB, MAX_EXEC_PIDS,
    MAX_OUTPUT_BYTES, MAX_TIMEOUT_MS, Workload, WorkloadEnvironment, decode_exec_payload,
    encode_exec_payload,
};
pub use features::GuestFeatures;
pub use guest_session::{
    APP_SESSION_CLOSE, APP_SESSION_EXEC, APP_SESSION_OPEN, GuestSessionSpec,
    MAX_GUEST_SESSIONS, MAX_SESSION_PATH, SESSION_VERSION, SessionNetwork,
    decode_session_open, encode_session_open, encode_session_request,
};
pub use maps::{
    HostMap, MAP_ENTRY_HEADER_LEN, MAP_READ_ONLY, MAPS_HEADER_LEN, MAX_HOST_MAPPINGS,
    MAX_MAP_PATH_BYTES, MapsPayload, decode_maps_payload, encode_maps_payloads,
    encode_maps_payloads_from,
};
pub use outer::{
    CAPABILITY_LEN, OUTER_DATA, OUTER_ERROR, OUTER_HEADER_LEN, OUTER_HOST_ATTACH, OUTER_MAGIC,
    OUTER_MAX_PAYLOAD, OUTER_READY, OUTER_RESET, OUTER_VERSION, OUTER_WAIT, OuterHeader,
    decode_outer_header, encode_outer,
};

/// Protocol violation detected while encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError(String);

impl ProtocolError {
    /// Returns the description of the violation.
    pub fn message(&self) -> &str {
        &self.0
    }

    /// Returns the description of the violation, consuming the error.
    pub fn into_message(self) -> String {
        self.0
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ProtocolError {}

/// Constructs a protocol error whose message describes the violated wire contract.
fn violation(message: impl Into<String>) -> ProtocolError {
    ProtocolError(message.into())
}

/// Copies an exactly `N`-byte wire field into an array for integer decoding.
fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut output = [0u8; N];
    output.copy_from_slice(bytes);
    output
}

/// Reads the little-endian `u16` at `offset`, or `None` past the end of `bytes`.
fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let field = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes(array(field)))
}

/// Reads the little-endian `u32` at `offset`, or `None` past the end of `bytes`.
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let field = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(array(field)))
}
