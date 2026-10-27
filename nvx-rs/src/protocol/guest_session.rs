//! Versioned identities for isolated guest sessions. Session ids are host allocated,
//! never derived from workload environment variables or guest paths.

use super::{ProtocolError, violation};

/// Create an isolated guest session and acknowledge it with APP_READY.
pub const APP_SESSION_OPEN: u8 = 8;
/// Close an isolated guest session after all its executions have been reaped.
pub const APP_SESSION_CLOSE: u8 = 9;
/// Run an ordinary EXEC payload prefixed by its isolated session id.
pub const APP_SESSION_EXEC: u8 = 10;
/// Clone an authorized agent mapping into one session's private mount namespace.
pub const APP_SESSION_BIND: u8 = 11;
/// Strictly unmount a session mapping before the host revokes its export.
pub const APP_SESSION_UNBIND: u8 = 12;
/// First session namespace control payload version.
pub const SESSION_VERSION: u16 = 1;
/// Maximum number of simultaneously resident isolated sessions.
pub const MAX_GUEST_SESSIONS: usize = 64;
/// Maximum length of an agent-owned source path.
pub const MAX_SESSION_PATH: usize = 4095;

/// Network policy applied inside the session's network namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionNetwork {
    /// Loopback within this session only; no device or route to another namespace.
    Deny,
    /// The session stays in the VM's own network namespace and uses whatever network the VM has.
    /// Sessions then share addresses and ports with each other; mount, PID, IPC and UTS
    /// isolation are unaffected.
    Shared,
}

impl SessionNetwork {
    fn wire(self) -> u16 {
        match self {
            SessionNetwork::Deny => 0,
            SessionNetwork::Shared => 1,
        }
    }
}

/// Host-owned creation request. The workspace names an already-authorized mount
/// in the agent namespace; user execution sees it only as /workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestSessionSpec {
    /// Nonzero, monotonically allocated within a VM generation; never reused.
    pub id: u64,
    /// Agent-visible, absolute workspace mount path.
    pub workspace: String,
    /// Explicit network policy; unsupported policies must be refused.
    pub network: SessionNetwork,
}

fn valid_workspace(path: &str) -> bool {
    path.starts_with("/sessions/")
        && path.len() <= MAX_SESSION_PATH
        && !path.contains('\0')
        && path.split('/').skip(1).all(|part| !part.is_empty() && part != "." && part != "..")
}

/// A session-visible attachment of an already authorized agent mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMount {
    /// Agent-visible mapping beneath this session's /sessions directory.
    pub source: String,
    /// Version 1 mount path, /workspace/mounts followed by one safe component.
    pub target: String,
    /// Require the private attachment and all submounts to be read-only.
    pub read_only: bool,
}

/// Whether a target follows the isolated workspace path contract.
pub fn valid_session_mount_target(path: &str) -> bool {
    path.strip_prefix("/workspace/mounts/").is_some_and(|leaf| {
        !leaf.is_empty() && leaf != "." && leaf != ".." && leaf.len() <= 255
            && leaf.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    })
}

/// Encode a scoped bind; flags and paths are validated before contacting the guest.
pub fn encode_session_mount(id: u64, mount: &SessionMount) -> Result<Vec<u8>, ProtocolError> {
    let source_ok = mount
        .source
        .strip_prefix("/sessions/")
        .and_then(|path| path.split_once("/mounts/"))
        .is_some_and(|(session, leaf)| {
            !session.is_empty()
                && !session.contains('/')
                && !leaf.is_empty()
                && !leaf.contains('/')
                && leaf.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        });
    if !source_ok || !valid_session_mount_target(&mount.target) {
        return Err(violation("invalid guest session mount path"));
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(&u16::from(mount.read_only).to_le_bytes());
    payload.extend_from_slice(&(mount.source.len() as u16).to_le_bytes());
    payload.extend_from_slice(&(mount.target.len() as u16).to_le_bytes());
    payload.extend_from_slice(mount.source.as_bytes());
    payload.extend_from_slice(mount.target.as_bytes());
    encode_session_request(id, &payload)
}

/// Encode a scoped unbind with the same strict target contract.
pub fn encode_session_unmount(id: u64, target: &str) -> Result<Vec<u8>, ProtocolError> {
    if !valid_session_mount_target(target) {
        return Err(violation("invalid guest session unmount path"));
    }
    encode_session_request(id, target.as_bytes())
}

/// Encode a session creation without silently normalizing path traversal.
pub fn encode_session_open(spec: &GuestSessionSpec) -> Result<Vec<u8>, ProtocolError> {
    let session = spec.workspace.strip_prefix("/sessions/")
        .and_then(|path| path.strip_suffix("/workspace"));
    if spec.id == 0 || !valid_workspace(&spec.workspace)
        || !session.is_some_and(|name| !name.is_empty() && !name.contains('/')) {
        return Err(violation("invalid guest session identity or workspace"));
    }
    let mut bytes = Vec::with_capacity(16 + spec.workspace.len());
    bytes.extend_from_slice(&SESSION_VERSION.to_le_bytes());
    bytes.extend_from_slice(&spec.network.wire().to_le_bytes());
    bytes.extend_from_slice(&spec.id.to_le_bytes());
    bytes.extend_from_slice(&(spec.workspace.len() as u32).to_le_bytes());
    bytes.extend_from_slice(spec.workspace.as_bytes());
    Ok(bytes)
}

/// Decode strictly so older guests never treat a newer policy as no-network.
pub fn decode_session_open(bytes: &[u8]) -> Result<GuestSessionSpec, ProtocolError> {
    if bytes.len() < 16 || u16::from_le_bytes(bytes[0..2].try_into().unwrap()) != SESSION_VERSION {
        return Err(violation("unsupported guest session header"));
    }
    let network = match u16::from_le_bytes(bytes[2..4].try_into().unwrap()) {
        0 => SessionNetwork::Deny,
        1 => SessionNetwork::Shared,
        _ => return Err(violation("unsupported guest session network policy")),
    };
    let id = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
    let length = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    if length != bytes.len() - 16 {
        return Err(violation("invalid guest session workspace length"));
    }
    let workspace = std::str::from_utf8(&bytes[16..])
        .map_err(|_| violation("guest session workspace is not UTF-8"))?;
    let spec = GuestSessionSpec { id, workspace: workspace.to_owned(), network };
    encode_session_open(&spec)?;
    Ok(spec)
}

/// Prefix session identity to an execution or mount-control payload.
pub fn encode_session_request(id: u64, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if id == 0 || payload.len() > super::OUTER_MAX_PAYLOAD - super::APP_HEADER_LEN - 8 {
        return Err(violation("invalid guest session request"));
    }
    let mut bytes = Vec::with_capacity(8 + payload.len());
    bytes.extend_from_slice(&id.to_le_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_creation_and_round_trip() {
        let spec = GuestSessionSpec {
            id: 7, workspace: "/sessions/a/workspace".into(), network: SessionNetwork::Deny,
        };
        let mut expected = vec![1, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0];
        expected.extend_from_slice(b"/sessions/a/workspace");
        assert_eq!(encode_session_open(&spec).unwrap(), expected);
        assert_eq!(decode_session_open(&expected).unwrap(), spec);
    }

    #[test]
    fn shared_network_policy_is_distinct_on_the_wire_and_round_trips() {
        let shared = GuestSessionSpec {
            id: 7, workspace: "/sessions/a/workspace".into(), network: SessionNetwork::Shared,
        };
        let bytes = encode_session_open(&shared).unwrap();
        assert_eq!(bytes[2..4], [1, 0]);
        assert_eq!(decode_session_open(&bytes).unwrap(), shared);
        let mut private = bytes.clone();
        private[2] = 0;
        assert_eq!(decode_session_open(&private).unwrap().network, SessionNetwork::Deny);
        let mut unknown = bytes;
        unknown[2] = 2;
        assert!(decode_session_open(&unknown).is_err());
    }

    #[test]
    fn rejects_ambiguous_paths_and_zero_identity() {
        for path in ["/", "/hostfs/root", "/sessions/../hostfs", "/sessions//a",
                     "/sessions/a/", "/sessions/./a", "/sessions/a\0b"] {
            assert!(encode_session_open(&GuestSessionSpec {
                id: 1, workspace: path.into(), network: SessionNetwork::Deny,
            }).is_err(), "{path:?}");
        }
        assert!(encode_session_request(0, &[]).is_err());
    }

    #[test]
    fn refuses_unknown_policy_versions_and_truncation() {
        let spec = GuestSessionSpec {
            id: 1, workspace: "/sessions/a/workspace".into(), network: SessionNetwork::Deny,
        };
        let bytes = encode_session_open(&spec).unwrap();
        for end in 0..bytes.len() {
            assert!(decode_session_open(&bytes[..end]).is_err());
        }
        for offset in [0, 2, 12] {
            let mut invalid = bytes.clone();
            invalid[offset] = 255;
            assert!(decode_session_open(&invalid).is_err());
        }
        assert_eq!(encode_session_request(7, &[2, 3]).unwrap(),
            [7, 0, 0, 0, 0, 0, 0, 0, 2, 3]);
    }

    #[test]
    fn scoped_mounts_have_strict_source_and_target_paths() {
        let mount = SessionMount {
            source: "/sessions/a/mounts/data".into(),
            target: "/workspace/mounts/data".into(),
            read_only: true,
        };
        let encoded = encode_session_mount(7, &mount).unwrap();
        assert_eq!(&encoded[..8], &7u64.to_le_bytes());
        assert_eq!(u16::from_le_bytes(encoded[8..10].try_into().unwrap()), 1);
        assert!(encode_session_mount(7, &SessionMount {
            source: "/sessions/b/mounts/data".into(),
            target: "/workspace/mounts/../escape".into(),
            read_only: false,
        }).is_err());
        assert!(encode_session_unmount(7, "/workspace/mounts/data").is_ok());
        assert!(encode_session_unmount(7, "/workspace/mounts/data/child").is_err());
    }
}
