//! Who listens on the host's loopback.
//!
//! With host-loopback ingress OpenVMM publishes each port the guest listens on at the same port
//! on the host's `127.0.0.1`, and silently skips a port a host process already holds. So a
//! server started in the guest can be unreachable from the host without anything failing. The
//! host's TCP table says which case it is: a listener owned by the VMM is the guest's server
//! published; one owned by anything else is a conflict; none means nothing is forwarded.

use std::collections::VecDeque;

/// One TCP listener on a port, on loopback or on every address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    pub pid: u32,
    /// Bound to every address, not only to loopback.
    pub wildcard: bool,
}

/// How a port looks from the host, given the VMM's process id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortState {
    /// The VMM listens on host loopback at this port: the guest's server is reachable.
    Published,
    /// Another process holds the port, so the guest's server is not forwarded.
    Conflict { pid: u32 },
    /// Nothing listens on the host at this port.
    Unpublished,
}

/// Decides from the listeners of one port. A listener of the VMM on loopback wins over a
/// wildcard listener of another process: the more specific address takes the connection.
pub fn classify(listeners: &[Listener], vmm_pid: u32) -> PortState {
    if listeners
        .iter()
        .any(|listener| listener.pid == vmm_pid && !listener.wildcard)
    {
        return PortState::Published;
    }
    match listeners.iter().find(|listener| listener.pid != vmm_pid) {
        Some(other) => PortState::Conflict { pid: other.pid },
        None => PortState::Unpublished,
    }
}

/// TCP listeners on `port` bound to loopback or to every address, IPv4 and IPv6.
pub fn tcp_listeners(port: u16) -> Result<Vec<Listener>, String> {
    imp::tcp_listeners(port)
}

/// Executable name of a process, when it can be read.
pub fn process_name(pid: u32) -> Option<String> {
    imp::process_name(pid)
}

/// A TCP port nobody holds on the host's loopback right now, avoiding `avoid`.
///
/// The port is not reserved at the OS: another process may take it before the caller does.
/// The ports this sidecar handed out recently are remembered by the caller and passed back in
/// so two callers asking at the same moment do not get the same one.
pub fn free_port(avoid: &VecDeque<u16>) -> Result<u16, String> {
    for _ in 0..32 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        drop(listener);
        if !avoid.contains(&port) && tcp_listeners(port)?.is_empty() {
            return Ok(port);
        }
    }
    Err("no free loopback port found".into())
}

#[cfg(windows)]
mod imp {
    use super::Listener;
    use std::ffi::c_void;

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetExtendedTcpTable(
            table: *mut c_void,
            size: *mut u32,
            order: i32,
            family: u32,
            class: u32,
            reserved: u32,
        ) -> u32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn QueryFullProcessImageNameW(
            process: *mut c_void,
            flags: u32,
            name: *mut u16,
            size: *mut u32,
        ) -> i32;
    }

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    /// `TCP_TABLE_OWNER_PID_LISTENER`: listening sockets with the owning process.
    const TCP_TABLE_OWNER_PID_LISTENER: u32 = 3;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    fn table(family: u32) -> Result<Vec<u8>, String> {
        let mut size = 0u32;
        let mut buffer: Vec<u8> = Vec::new();
        // The table can grow between the two calls, so ask again a few times.
        for _ in 0..8 {
            let pointer = if buffer.is_empty() {
                std::ptr::null_mut()
            } else {
                buffer.as_mut_ptr() as *mut c_void
            };
            // SAFETY: `pointer` is null or a writable buffer of at least `size` bytes.
            let status = unsafe {
                GetExtendedTcpTable(pointer, &mut size, 0, family, TCP_TABLE_OWNER_PID_LISTENER, 0)
            };
            match status {
                0 => return Ok(buffer),
                ERROR_INSUFFICIENT_BUFFER => buffer.resize(size as usize + 64, 0),
                other => return Err(format!("GetExtendedTcpTable failed ({other})")),
            }
        }
        Err("the TCP table kept changing".into())
    }

    fn read_u32(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    }

    /// The port of a row, stored in network byte order in the low 16 bits of a DWORD.
    fn read_port(bytes: &[u8], at: usize) -> u16 {
        u16::from_be_bytes([bytes[at], bytes[at + 1]])
    }

    pub fn tcp_listeners(port: u16) -> Result<Vec<Listener>, String> {
        let mut found = Vec::new();

        let v4 = table(AF_INET)?;
        if v4.len() >= 4 {
            // MIB_TCPTABLE_OWNER_PID: a count, then rows of state, local address, local port,
            // remote address, remote port, owning process (six DWORDs).
            let rows = read_u32(&v4, 0) as usize;
            for index in 0..rows {
                let base = 4 + index * 24;
                if base + 24 > v4.len() {
                    break;
                }
                let address = [v4[base + 4], v4[base + 5], v4[base + 6], v4[base + 7]];
                if read_port(&v4, base + 8) == port && (address[0] == 127 || address == [0; 4]) {
                    found.push(Listener {
                        pid: read_u32(&v4, base + 20),
                        wildcard: address == [0; 4],
                    });
                }
            }
        }

        let v6 = table(AF_INET6)?;
        if v6.len() >= 4 {
            // MIB_TCP6TABLE_OWNER_PID rows: local address (16 bytes), scope, local port, remote
            // address (16 bytes), scope, remote port, state, owning process.
            let rows = read_u32(&v6, 0) as usize;
            for index in 0..rows {
                let base = 4 + index * 56;
                if base + 56 > v6.len() {
                    break;
                }
                let address = &v6[base..base + 16];
                let loopback = address[..15].iter().all(|byte| *byte == 0) && address[15] == 1;
                let wildcard = address.iter().all(|byte| *byte == 0);
                if read_port(&v6, base + 20) == port && (loopback || wildcard) {
                    found.push(Listener {
                        pid: read_u32(&v6, base + 52),
                        wildcard,
                    });
                }
            }
        }
        Ok(found)
    }

    pub fn process_name(pid: u32) -> Option<String> {
        // SAFETY: plain Win32 calls; the handle is closed before returning.
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return None;
            }
            let mut buffer = [0u16; 1024];
            let mut size = buffer.len() as u32;
            let ok = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
            CloseHandle(handle);
            if ok == 0 {
                return None;
            }
            let path = String::from_utf16_lossy(&buffer[..size as usize]);
            path.rsplit(['\\', '/']).next().map(str::to_owned)
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::Listener;

    pub fn tcp_listeners(_port: u16) -> Result<Vec<Listener>, String> {
        Err("host port inspection is only implemented on Windows".into())
    }

    pub fn process_name(_pid: u32) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(pid: u32, wildcard: bool) -> Listener {
        Listener { pid, wildcard }
    }

    #[test]
    fn the_vmm_on_loopback_means_published() {
        assert_eq!(classify(&[listener(7, false)], 7), PortState::Published);
        // Another process on every address does not outrank the VMM's loopback listener.
        assert_eq!(
            classify(&[listener(9, true), listener(7, false)], 7),
            PortState::Published
        );
    }

    #[test]
    fn another_owner_without_the_vmm_is_a_conflict() {
        assert_eq!(classify(&[listener(9, false)], 7), PortState::Conflict { pid: 9 });
        assert_eq!(classify(&[listener(9, true)], 7), PortState::Conflict { pid: 9 });
        // The VMM on every address is not the loopback publication: the other owner stands.
        assert_eq!(
            classify(&[listener(7, true), listener(9, false)], 7),
            PortState::Conflict { pid: 9 }
        );
    }

    #[test]
    fn nothing_listening_is_unpublished() {
        assert_eq!(classify(&[], 7), PortState::Unpublished);
        assert_eq!(classify(&[listener(7, true)], 7), PortState::Unpublished);
    }

    #[cfg(windows)]
    #[test]
    fn a_listener_of_this_process_is_found_by_port_and_pid() {
        let socket = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        let found = tcp_listeners(port).unwrap();
        assert!(
            found.iter().any(|l| l.pid == std::process::id() && !l.wildcard),
            "{found:?}"
        );
        assert!(process_name(std::process::id()).is_some());
        drop(socket);
        assert!(tcp_listeners(port).unwrap().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn a_wildcard_listener_is_marked_as_such() {
        let socket = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        let found = tcp_listeners(port).unwrap();
        assert!(found.iter().any(|l| l.pid == std::process::id() && l.wildcard), "{found:?}");
    }

    #[cfg(windows)]
    #[test]
    fn a_free_port_is_free_and_not_one_that_was_just_handed_out() {
        let mut avoid = VecDeque::new();
        let first = free_port(&avoid).unwrap();
        avoid.push_back(first);
        let second = free_port(&avoid).unwrap();
        assert_ne!(first, second);
        assert!(tcp_listeners(second).unwrap().is_empty());
    }
}
