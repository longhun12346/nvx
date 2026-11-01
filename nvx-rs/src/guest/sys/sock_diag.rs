//! Socket diagnostics, `NETLINK_SOCK_DIAG`: the query for a dump of the kernel's IPv6 TCP
//! sockets in one state, and the decoding of the dump.
//!
//! musl lacks the kernel's netlink headers, `linux/netlink.h`, `linux/sock_diag.h`, and
//! `linux/inet_diag.h`, and `nix` does not model this protocol, so this module builds and decodes
//! its messages as those headers lay them out, in native byte order, without pointer casts. Test
//! snapshots replay recorded dumps through the same decoder.

use std::net::Ipv6Addr;
use std::os::fd::AsRawFd;
use std::time::Duration;

use nix::sys::socket::{AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType};
use nix::sys::time::TimeVal;

use super::Errno;

/// Length of a netlink message header, `struct nlmsghdr`: its 32-bit `nlmsg_len`, 16-bit
/// `nlmsg_type` and `nlmsg_flags`, and 32-bit `nlmsg_seq` and `nlmsg_pid`.
const NETLINK_HEADER_LENGTH: usize = 16;
/// Offset of `nlmsg_len`, the length of the message with its header, in `struct nlmsghdr`.
const NETLINK_LENGTH_OFFSET: usize = 0;
/// Offset of `nlmsg_type` in `struct nlmsghdr`.
const NETLINK_TYPE_OFFSET: usize = 4;
/// Offset of `nlmsg_flags` in `struct nlmsghdr`.
const NETLINK_FLAGS_OFFSET: usize = 6;
/// Alignment of netlink messages and attributes, `NLMSG_ALIGNTO` and `NLA_ALIGNTO`: each one
/// starts at the first multiple of 4 bytes after the end of the previous one.
const NETLINK_ALIGNMENT: usize = 4;
/// `NLM_F_REQUEST`, the flag of a message that asks the kernel for something.
const NLM_F_REQUEST: u16 = 0x001;
/// `NLM_F_DUMP`, `NLM_F_ROOT | NLM_F_MATCH`: the flags of a request for every matching object,
/// which the kernel answers with a multipart dump that `NLMSG_DONE` ends.
const NLM_F_DUMP: u16 = 0x100 | 0x200;
/// `NLMSG_ERROR`, the type of a message that reports an error, which ends a dump.
const NLMSG_ERROR: u16 = 2;
/// `NLMSG_DONE`, the type of the message that ends a multipart dump.
const NLMSG_DONE: u16 = 3;
/// `SOCK_DIAG_BY_FAMILY`, the type of a request for the sockets of one address family, and of
/// each message of its dump, which describes one socket.
const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// Netlink port ID of the kernel, to which the request goes.
const KERNEL_PORT_ID: u32 = 0;
/// Multicast groups of the request's destination: none, as it goes to the kernel alone.
const NO_MULTICAST_GROUPS: u32 = 0;

/// Length of a socket-diagnostics request, `struct inet_diag_req_v2`: its 8-bit `sdiag_family`,
/// `sdiag_protocol`, `idiag_ext`, and padding, its 32-bit `idiag_states`, and a 48-byte
/// `struct inet_diag_sockid`, which a dump of every socket leaves zero.
const INET_DIAG_REQUEST_LENGTH: usize = 56;
/// Offset of `sdiag_family`, the address family of the requested sockets, in the request.
const REQUEST_FAMILY_OFFSET: usize = 0;
/// Offset of `sdiag_protocol`, the IP protocol of the requested sockets, in the request.
const REQUEST_PROTOCOL_OFFSET: usize = 1;
/// Offset of `idiag_states`, the mask of the TCP states of the requested sockets with bit `n` for
/// state `n`, in the request.
const REQUEST_STATES_OFFSET: usize = 4;
/// Length of the whole query: a netlink header followed by the request.
const INET_DIAG_QUERY_LENGTH: usize = NETLINK_HEADER_LENGTH + INET_DIAG_REQUEST_LENGTH;

/// Length of `struct inet_diag_msg`, which describes one socket of the dump, and after which the
/// message's attributes follow: its 8-bit `idiag_family`, `idiag_state`, `idiag_timer`, and
/// `idiag_retrans`, a 48-byte `struct inet_diag_sockid`, and five 32-bit fields.
const INET_DIAG_MESSAGE_LENGTH: usize = 72;
/// Offset of `idiag_family`, the socket's address family, in `struct inet_diag_msg`.
const MESSAGE_FAMILY_OFFSET: usize = 0;
/// Offset of `idiag_state`, the socket's TCP state, in `struct inet_diag_msg`.
const MESSAGE_STATE_OFFSET: usize = 1;
/// Offset of `id.idiag_sport`, the socket's local port in network byte order, in
/// `struct inet_diag_msg`.
const MESSAGE_PORT_OFFSET: usize = 4;
/// Offset of `id.idiag_src`, the socket's local address, in `struct inet_diag_msg`.
const MESSAGE_ADDRESS_OFFSET: usize = 8;
/// Length of `idiag_src`, which holds an IPv6 address, or an IPv4 one in its first 4 bytes.
const ADDRESS_LENGTH: usize = 16;
/// Length of a netlink attribute header, `struct nlattr`: its 16-bit `nla_len`, which includes
/// the header, and `nla_type`. The attribute's value follows it.
const ATTRIBUTE_HEADER_LENGTH: usize = 4;
/// Offset of `nla_len` in `struct nlattr`.
const ATTRIBUTE_LENGTH_OFFSET: usize = 0;
/// Offset of `nla_type` in `struct nlattr`.
const ATTRIBUTE_TYPE_OFFSET: usize = 2;
/// `INET_DIAG_SKV6ONLY`, the type of the attribute whose 1-byte value is an IPv6 socket's
/// `IPV6_V6ONLY` option, which the kernel reports for listening sockets.
const INET_DIAG_SKV6ONLY: u16 = 11;

/// Length of the buffer that receives each part of a dump.
///
/// Linux packs each part of a dump into at most 32 KiB, the size at which `netlink_recvmsg` caps
/// the receive length from which it sizes later parts, so a receive of this size never truncates
/// a part. The C program's `diag_buffer` had this size, which also bounds a test snapshot's
/// recorded dump.
pub(crate) const INET_DIAG_BUFFER_LENGTH: usize = 32 * 1024;

/// One socket of a dump: the fields of its `struct inet_diag_msg` that NVX reads, and its
/// `INET_DIAG_SKV6ONLY` attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InetDiagMessage {
    /// Whether the socket is an IPv6 one, of `AF_INET6`.
    pub(crate) ipv6: bool,
    /// The socket's TCP state number.
    pub(crate) state: u8,
    /// The socket's local port.
    pub(crate) port: u16,
    /// The socket's local address, whose first 4 bytes hold an IPv4 socket's.
    pub(crate) address: Ipv6Addr,
    /// The value of the message's first `INET_DIAG_SKV6ONLY` attribute that has one, or `None`
    /// if the message ends, or an attribute is malformed, before it.
    pub(crate) ipv6_only: Option<bool>,
}

/// Asks the kernel for a dump of its IPv6 TCP sockets in `state`, a TCP state number, and
/// decodes each part of the dump with `visit` until the dump ends.
///
/// Each receive waits at most `timeout`, so a dump that never ends cannot stall the caller. It
/// returns the error of a system call that fails, including a receive that times out, `EINVAL`
/// for a `state` or `timeout` beyond the kernel's types, and `EIO` for a request that the kernel
/// accepts only in part.
pub(crate) fn dump_ipv6_tcp_sockets(
    state: u32,
    timeout: Duration,
    mut visit: impl FnMut(InetDiagMessage),
) -> Result<(), Errno> {
    let request = inet_diag_request(state).ok_or(Errno::EINVAL)?;
    let timeout = TimeVal::new(
        timeout.as_secs().try_into().map_err(|_| Errno::EINVAL)?,
        timeout.subsec_micros().into(),
    );
    let socket = nix::sys::socket::socket(
        AddressFamily::Netlink,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkSockDiag,
    )?;
    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::ReceiveTimeout, &timeout)?;
    let sent = nix::sys::socket::sendto(
        socket.as_raw_fd(),
        &request,
        &NetlinkAddr::new(KERNEL_PORT_ID, NO_MULTICAST_GROUPS),
        MsgFlags::empty(),
    )?;
    if sent != request.len() {
        return Err(Errno::EIO);
    }
    let mut buffer = [0_u8; INET_DIAG_BUFFER_LENGTH];
    loop {
        let received = nix::sys::socket::recv(socket.as_raw_fd(), &mut buffer, MsgFlags::empty())?;
        if received == 0 || !decode_inet_diag_dump(&buffer[..received], &mut visit) {
            return Ok(());
        }
    }
}

/// Decodes one received part of a dump, calling `visit` with each socket that it describes, and
/// returns whether the dump continues: false once `NLMSG_DONE` or `NLMSG_ERROR` ends it, or a
/// message's length is shorter than its header or overruns the part.
///
/// It skips messages of other types, and socket messages too short for a `struct inet_diag_msg`.
pub(crate) fn decode_inet_diag_dump(buffer: &[u8], mut visit: impl FnMut(InetDiagMessage)) -> bool {
    let mut offset = 0;
    while offset + NETLINK_HEADER_LENGTH <= buffer.len() {
        let header = &buffer[offset..];
        let length = native_u32(&header[NETLINK_LENGTH_OFFSET..]) as usize;
        let kind = native_u16(&header[NETLINK_TYPE_OFFSET..]);
        if length < NETLINK_HEADER_LENGTH
            || length > header.len()
            || kind == NLMSG_DONE
            || kind == NLMSG_ERROR
        {
            return false;
        }
        if kind == SOCK_DIAG_BY_FAMILY
            && let Some(message) = decode_message(&header[NETLINK_HEADER_LENGTH..length])
        {
            visit(message);
        }
        offset += align(length);
    }
    true
}

/// Returns the bytes of a query for the IPv6 TCP sockets in `state`: a netlink header and an
/// `inet_diag_req_v2`, in native byte order, or `None` for a `state` beyond the state mask.
fn inet_diag_request(state: u32) -> Option<[u8; INET_DIAG_QUERY_LENGTH]> {
    let states = 1_u32.checked_shl(state)?;
    let mut query = [0_u8; INET_DIAG_QUERY_LENGTH];
    query[NETLINK_LENGTH_OFFSET..][..size_of::<u32>()]
        .copy_from_slice(&(INET_DIAG_QUERY_LENGTH as u32).to_ne_bytes());
    query[NETLINK_TYPE_OFFSET..][..size_of::<u16>()]
        .copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    query[NETLINK_FLAGS_OFFSET..][..size_of::<u16>()]
        .copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    let request = &mut query[NETLINK_HEADER_LENGTH..];
    request[REQUEST_FAMILY_OFFSET] = AddressFamily::Inet6 as u8;
    request[REQUEST_PROTOCOL_OFFSET] = SockProtocol::Tcp as u8;
    request[REQUEST_STATES_OFFSET..][..size_of::<u32>()].copy_from_slice(&states.to_ne_bytes());
    Some(query)
}

/// Decodes the `struct inet_diag_msg` and attributes of one `SOCK_DIAG_BY_FAMILY` message, or
/// returns `None` if the message is too short for one.
fn decode_message(message: &[u8]) -> Option<InetDiagMessage> {
    let (fields, attributes) = message.split_at_checked(INET_DIAG_MESSAGE_LENGTH)?;
    let address: [u8; ADDRESS_LENGTH] = fields[MESSAGE_ADDRESS_OFFSET..][..ADDRESS_LENGTH]
        .try_into()
        .ok()?;
    Some(InetDiagMessage {
        ipv6: fields[MESSAGE_FAMILY_OFFSET] == AddressFamily::Inet6 as u8,
        state: fields[MESSAGE_STATE_OFFSET],
        port: u16::from_be_bytes([fields[MESSAGE_PORT_OFFSET], fields[MESSAGE_PORT_OFFSET + 1]]),
        address: Ipv6Addr::from(address),
        ipv6_only: decode_ipv6_only(attributes),
    })
}

/// Returns the value of the first `INET_DIAG_SKV6ONLY` attribute in `attributes` that has one, or
/// `None` if they end, or an attribute's length is shorter than its header or overruns them,
/// before it.
fn decode_ipv6_only(attributes: &[u8]) -> Option<bool> {
    let mut offset = 0;
    while offset + ATTRIBUTE_HEADER_LENGTH <= attributes.len() {
        let attribute = &attributes[offset..];
        let length = usize::from(native_u16(&attribute[ATTRIBUTE_LENGTH_OFFSET..]));
        let kind = native_u16(&attribute[ATTRIBUTE_TYPE_OFFSET..]);
        if length < ATTRIBUTE_HEADER_LENGTH || length > attribute.len() {
            return None;
        }
        if kind == INET_DIAG_SKV6ONLY && length > ATTRIBUTE_HEADER_LENGTH {
            return Some(attribute[ATTRIBUTE_HEADER_LENGTH] != 0);
        }
        offset += align(length);
    }
    None
}

/// Reads the native-endian 16-bit field with which `bytes` starts.
fn native_u16(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes([bytes[0], bytes[1]])
}

/// Reads the native-endian 32-bit field with which `bytes` starts.
fn native_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Rounds the length of a message or an attribute up to `NETLINK_ALIGNMENT`.
fn align(length: usize) -> usize {
    length.next_multiple_of(NETLINK_ALIGNMENT)
}

/// `NLM_F_MULTI`, the flag of each message of a multipart dump, which test dumps carry as the
/// kernel's do, although the decoder ignores it.
#[cfg(test)]
const NLM_F_MULTI: u16 = 0x002;

/// Encodes one netlink message of `kind` with `payload`, as the kernel writes a dump's messages.
#[cfg(test)]
fn encode_message(kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut message = vec![0_u8; NETLINK_HEADER_LENGTH];
    message[NETLINK_LENGTH_OFFSET..][..size_of::<u32>()]
        .copy_from_slice(&((NETLINK_HEADER_LENGTH + payload.len()) as u32).to_ne_bytes());
    message[NETLINK_TYPE_OFFSET..][..size_of::<u16>()].copy_from_slice(&kind.to_ne_bytes());
    message[NETLINK_FLAGS_OFFSET..][..size_of::<u16>()].copy_from_slice(&NLM_F_MULTI.to_ne_bytes());
    message.extend_from_slice(payload);
    message
}

/// Encodes the dump message of an IPv6 TCP socket in `state` on `address` and `port`, with an
/// `INET_DIAG_SKV6ONLY` attribute of `ipv6_only`, as the kernel writes it.
#[cfg(test)]
pub(crate) fn encode_inet_diag_socket(
    state: u8,
    address: Ipv6Addr,
    port: u16,
    ipv6_only: bool,
) -> Vec<u8> {
    let mut payload = vec![0_u8; INET_DIAG_MESSAGE_LENGTH];
    payload[MESSAGE_FAMILY_OFFSET] = AddressFamily::Inet6 as u8;
    payload[MESSAGE_STATE_OFFSET] = state;
    payload[MESSAGE_PORT_OFFSET..][..size_of::<u16>()].copy_from_slice(&port.to_be_bytes());
    payload[MESSAGE_ADDRESS_OFFSET..][..ADDRESS_LENGTH].copy_from_slice(&address.octets());
    let attribute_length = ATTRIBUTE_HEADER_LENGTH + size_of::<u8>();
    payload.extend_from_slice(&(attribute_length as u16).to_ne_bytes());
    payload.extend_from_slice(&INET_DIAG_SKV6ONLY.to_ne_bytes());
    payload.push(u8::from(ipv6_only));
    payload.resize(INET_DIAG_MESSAGE_LENGTH + align(attribute_length), 0);
    encode_message(SOCK_DIAG_BY_FAMILY, &payload)
}

/// Encodes the `NLMSG_DONE` message that ends a dump, whose payload is the dump's 32-bit status.
#[cfg(test)]
pub(crate) fn encode_inet_diag_done() -> Vec<u8> {
    encode_message(NLMSG_DONE, &0_i32.to_ne_bytes())
}

#[cfg(test)]
mod tests {
    //! Checks of the encoded query and the decoder against the kernel's layouts, which the tests
    //! spell out byte by byte, and of a live dump.

    use super::*;

    /// Linux's `TCP_LISTEN` state number.
    const TCP_LISTEN: u8 = 10;

    /// Returns the sockets that `dump` describes and whether the dump continues after it.
    fn decode(dump: &[u8]) -> (Vec<InetDiagMessage>, bool) {
        let mut messages = Vec::new();
        let continues = decode_inet_diag_dump(dump, |message| messages.push(message));
        (messages, continues)
    }

    /// Verifies the query's bytes against `linux/netlink.h` and `linux/inet_diag.h`, and the
    /// bound of the state mask.
    #[test]
    fn inet_diag_request_matches_the_linux_layout() {
        let request = inet_diag_request(10).unwrap();
        assert_eq!(request.len(), 72);
        assert_eq!(u32::from_ne_bytes(request[0..4].try_into().unwrap()), 72);
        assert_eq!(u16::from_ne_bytes(request[4..6].try_into().unwrap()), 20);
        assert_eq!(u16::from_ne_bytes(request[6..8].try_into().unwrap()), 0x301);
        // AF_INET6 and IPPROTO_TCP.
        assert_eq!(request[16], 10);
        assert_eq!(request[17], 6);
        assert_eq!(
            u32::from_ne_bytes(request[20..24].try_into().unwrap()),
            1 << 10
        );
        assert!(request[8..16].iter().all(|byte| *byte == 0));
        assert!(request[18..20].iter().all(|byte| *byte == 0));
        assert!(request[24..].iter().all(|byte| *byte == 0));
        assert_eq!(inet_diag_request(31).map(|_| ()), Some(()));
        assert_eq!(inet_diag_request(32), None);
    }

    /// Verifies the decoding of a message that the test lays out as `linux/inet_diag.h` does,
    /// independently of the module's offsets.
    #[test]
    fn messages_decode_from_the_linux_layout() {
        let mut dump = Vec::new();
        dump.extend_from_slice(&(16_u32 + 72 + 8 + 8).to_ne_bytes());
        dump.extend_from_slice(&20_u16.to_ne_bytes());
        dump.extend_from_slice(&[0; 10]);
        let mut message = [0_u8; 72];
        message[0] = 10;
        message[1] = 10;
        message[4..6].copy_from_slice(&8080_u16.to_be_bytes());
        message[8..24].copy_from_slice(&"fd00::a00:2".parse::<Ipv6Addr>().unwrap().octets());
        dump.extend_from_slice(&message);
        // An unrelated attribute, then `INET_DIAG_SKV6ONLY` with its value and padding.
        dump.extend_from_slice(&8_u16.to_ne_bytes());
        dump.extend_from_slice(&1_u16.to_ne_bytes());
        dump.extend_from_slice(&[7; 4]);
        dump.extend_from_slice(&5_u16.to_ne_bytes());
        dump.extend_from_slice(&11_u16.to_ne_bytes());
        dump.extend_from_slice(&[1, 0, 0, 0]);
        assert_eq!(
            decode(&dump),
            (
                vec![InetDiagMessage {
                    ipv6: true,
                    state: TCP_LISTEN,
                    port: 8080,
                    address: "fd00::a00:2".parse().unwrap(),
                    ipv6_only: Some(true),
                }],
                true
            )
        );
        message[0] = 2;
        let (messages, _) = decode(&[&dump[..16], &message, &dump[16 + 72..]].concat());
        assert!(!messages[0].ipv6);
    }

    /// Verifies that `NLMSG_DONE`, `NLMSG_ERROR`, and malformed framing end a dump.
    #[test]
    fn dumps_end_at_done_error_and_malformed_framing() {
        let socket = encode_inet_diag_socket(TCP_LISTEN, Ipv6Addr::UNSPECIFIED, 7001, true);
        let mut dump = socket.clone();
        dump.extend(encode_inet_diag_done());
        dump.extend(&socket);
        let (messages, continues) = decode(&dump);
        assert_eq!((messages.len(), continues), (1, false));

        let error = encode_message(NLMSG_ERROR, &(-(Errno::EINVAL as i32)).to_ne_bytes());
        let (messages, continues) = decode(&[&socket[..], &error, &socket].concat());
        assert_eq!((messages.len(), continues), (1, false));

        for length in [8_u32, 4096] {
            let mut malformed = socket.clone();
            malformed[..4].copy_from_slice(&length.to_ne_bytes());
            assert_eq!(decode(&malformed), (Vec::new(), false), "{length}");
        }
        assert_eq!(decode(&socket[..40]), (Vec::new(), false));
        assert_eq!(decode(&[0; 37]), (Vec::new(), false));
        let (messages, continues) = decode(&[&socket[..], &socket].concat());
        assert_eq!((messages.len(), continues), (2, true));
    }

    /// Verifies that short messages are skipped and malformed attributes leave `IPV6_V6ONLY`
    /// unknown, while a valueless one is passed over.
    #[test]
    fn short_messages_and_malformed_attributes_are_contained() {
        let socket = encode_inet_diag_socket(TCP_LISTEN, Ipv6Addr::UNSPECIFIED, 7101, true);
        let attribute = NETLINK_HEADER_LENGTH + INET_DIAG_MESSAGE_LENGTH;
        for length in [2_u16, 200] {
            let mut malformed = socket.clone();
            malformed[attribute..attribute + 2].copy_from_slice(&length.to_ne_bytes());
            let (messages, continues) = decode(&malformed);
            assert_eq!(messages[0].ipv6_only, None, "{length}");
            assert!(continues);
        }

        let short = encode_message(SOCK_DIAG_BY_FAMILY, &[0; 71]);
        assert_eq!(decode(&short), (Vec::new(), true));

        let mut valueless = socket[..attribute].to_vec();
        valueless.extend_from_slice(&4_u16.to_ne_bytes());
        valueless.extend_from_slice(&INET_DIAG_SKV6ONLY.to_ne_bytes());
        valueless.extend_from_slice(&socket[attribute..]);
        let length = valueless.len() as u32;
        valueless[..4].copy_from_slice(&length.to_ne_bytes());
        let (messages, _) = decode(&valueless);
        assert_eq!(messages[0].ipv6_only, Some(true));
    }

    /// Verifies a live dump against a listener on the unspecified IPv6 address, where the host
    /// has IPv6.
    #[test]
    fn the_kernel_reports_an_ipv6_wildcard_listener() {
        let Ok(listener) = std::net::TcpListener::bind("[::]:0") else {
            return;
        };
        let port = listener.local_addr().unwrap().port();
        let mut messages = Vec::new();
        dump_ipv6_tcp_sockets(u32::from(TCP_LISTEN), Duration::from_secs(5), |message| {
            messages.push(message);
        })
        .unwrap();
        let message = messages
            .iter()
            .find(|message| message.port == port)
            .expect("the dump reports the listener");
        assert!(message.ipv6);
        assert_eq!(message.state, TCP_LISTEN);
        assert!(message.address.is_unspecified());
        assert!(message.ipv6_only.is_some());
    }
}
