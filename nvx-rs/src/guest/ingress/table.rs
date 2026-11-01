//! Reads the kernel's TCP and UDP socket tables, row by row as the C program did, and parses each
//! row strictly, in the form in which the kernel prints it.

use std::io::{BufRead, BufReader, Read};

use super::address::AddressContext;
use super::encode::ListenerTable;
use super::{MAX_TRACKED, PROTOCOL_TCP, TCP_LISTEN, UDP_CONNECTED, UDP_UNCONNECTED, UdpSocket};
use crate::guest::parse;

/// Most bytes of a line that one row takes, as the C program's `fgets` read at most 511 bytes
/// into its `char line[512]`.
///
/// Every row that the kernel writes, at most about 200 bytes long for an IPv6 socket, fits, so
/// the limit only bounds the memory that a malformed snapshot's longer line takes; the rest of
/// that line is read as another row, as C read it.
const ROW_LENGTH_LIMIT: u64 = 511;

/// Text that ends a row's first column, the row's number, which the kernel prints with `"%4d:"`.
const ROW_NUMBER_END: &[u8] = b":";

/// Byte that separates an address from its port in a row's `ADDRESS:PORT` columns, which the
/// kernel prints with `"%08X:%04X"`, or with four address words for IPv6.
const PORT_SEPARATOR: u8 = b':';

/// Most bytes of a row's local or remote `ADDRESS:PORT` column, as the C program's `%63s` read at
/// most 63 bytes of one into its `char local[64]` or `char remote[64]`.
///
/// The kernel's longest such column, an IPv6 address and its port, takes 37 bytes. C read a
/// longer column as two, which shifted the columns after it, so a row with one is rejected rather
/// than read as C never read it.
const ADDRESS_COLUMN_LIMIT: usize = 63;

/// Bytes that the kernel never writes in its socket tables and that C's `sscanf` read differently
/// from the program's split at ASCII white space: a NUL byte, which ended C's string, and a
/// vertical tab, which C, unlike `u8::is_ascii_whitespace`, took for white space. A row that holds
/// one is rejected.
const REJECTED_BYTES: &[u8] = b"\0\x0b";

/// Number of columns between the state and the user ID that the program skips without reading
/// them, as C skipped them with `%*s`: `tx_queue:rx_queue`, `tr:tm->when`, and `retrnsmt`, none
/// of which bears on whether a socket listens.
const SKIPPED_COLUMNS: usize = 3;

/// Number of decimal columns before the inode that the program checks but does not use: `uid`
/// and `timeout`, which C read with `%*u`, so that a row that C rejected stays rejected.
const UNUSED_DECIMAL_COLUMNS: usize = 2;

/// The columns of a socket-table row that the program reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SocketTableRow<'a> {
    /// The local address and port, as the kernel renders them.
    local: &'a [u8],
    /// The remote address and port.
    remote: &'a [u8],
    /// The socket's TCP or UDP state number.
    state: u32,
    /// The socket's inode number.
    inode: u64,
}

/// Parses one row of a socket table, `"%4d: LOCAL REMOTE %02X ... %lu ..."`, whose columns any
/// ASCII white space separates, and returns the columns that the program reads, or `None` if a
/// column is missing or is not in the form in which the kernel prints it.
///
/// A row that holds any of `REJECTED_BYTES`, or an address column longer than
/// `ADDRESS_COLUMN_LIMIT`, whose columns C's `sscanf` read differently, is also rejected, so that
/// C read every row that the program reads alike. Columns after the inode, which kernels have
/// added over time, are ignored, as C ignored them.
fn parse_row(line: &[u8]) -> Option<SocketTableRow<'_>> {
    if line.iter().any(|byte| REJECTED_BYTES.contains(byte)) {
        return None;
    }
    let mut columns = line
        .split(u8::is_ascii_whitespace)
        .filter(|column| !column.is_empty());
    parse::parse_decimal(columns.next()?.strip_suffix(ROW_NUMBER_END)?)?;
    let local = columns
        .next()
        .filter(|column| column.len() <= ADDRESS_COLUMN_LIMIT)?;
    let remote = columns
        .next()
        .filter(|column| column.len() <= ADDRESS_COLUMN_LIMIT)?;
    let state = u32::try_from(parse::parse_hexadecimal(columns.next()?)?).ok()?;
    let mut columns = columns.skip(SKIPPED_COLUMNS);
    for _ in 0..UNUSED_DECIMAL_COLUMNS {
        parse::parse_decimal(columns.next()?)?;
    }
    let inode = parse::parse_decimal(columns.next()?)?;
    Some(SocketTableRow {
        local,
        remote,
        state,
        inode,
    })
}

/// Splits an `ADDRESS:PORT` column at its last separator, as the C program's `strrchr` did, into
/// the address's text and the port's.
fn split_port(column: &[u8]) -> Option<(&[u8], &[u8])> {
    let separator = column.iter().rposition(|byte| *byte == PORT_SEPARATOR)?;
    Some((&column[..separator], &column[separator + 1..]))
}

/// Reads the next row of a table into `line`, at most `ROW_LENGTH_LIMIT` bytes of it, and returns
/// whether it read one: false at the end of the table or after a read error, which also ended the
/// C program's `fgets` loop.
fn read_row(reader: &mut impl BufRead, line: &mut Vec<u8>) -> bool {
    line.clear();
    reader
        .take(ROW_LENGTH_LIMIT)
        .read_until(b'\n', line)
        .is_ok_and(|length| length != 0)
}

/// Scans one kernel table and appends reachable listener or UDP-socket records.
pub(super) fn scan(
    reader: impl Read,
    protocol: u8,
    ipv6: bool,
    own_port: u16,
    addresses: &AddressContext<'_>,
    listeners: &mut ListenerTable,
    udp_sockets: &mut Vec<UdpSocket>,
) {
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    // The first line is the table's header.
    if !read_row(&mut reader, &mut line) {
        return;
    }
    while read_row(&mut reader, &mut line) {
        let Some(row) = parse_row(&line) else {
            continue;
        };
        let (Some((local_address, local_port)), Some((remote_address, remote_port))) =
            (split_port(row.local), split_port(row.remote))
        else {
            continue;
        };
        let Some(port) = parse::parse_hexadecimal(local_port)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
        else {
            continue;
        };

        let connected = if protocol == PROTOCOL_TCP {
            if row.state != TCP_LISTEN {
                continue;
            }
            false
        } else if row.state == UDP_CONNECTED {
            true
        } else {
            if row.state != UDP_UNCONNECTED
                || parse::parse_hexadecimal(remote_port) != Some(0)
                || remote_address.iter().any(|byte| *byte != b'0')
                || port == own_port
            {
                continue;
            }
            false
        };
        let families = addresses.reachable_families(local_address, ipv6, protocol, port);
        if families == 0 {
            continue;
        }
        if protocol == PROTOCOL_TCP {
            listeners.add(protocol, port, families);
        } else if udp_sockets.len() < MAX_TRACKED {
            udp_sockets.push(UdpSocket {
                port,
                families,
                connected,
                inode: row.inode,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    //! Parser tests for kernel-format rows, bounded lines, and UDP classification.

    use super::*;
    use crate::guest::ingress::{FAMILY_IPV4, PROTOCOL_UDP, UDP_CONNECTED, UDP_UNCONNECTED};

    /// Minimal socket-table header skipped by every scan.
    const HEADER: &[u8] = b"header\n";

    /// Returns a dual-stack context with no diagnostic overrides.
    fn context() -> AddressContext<'static> {
        AddressContext {
            ipv6_dual_stack: true,
            wildcard_tcp: &[],
        }
    }

    /// Scans test rows and returns both output collections.
    fn scan_rows(
        rows: &[u8],
        protocol: u8,
        ipv6: bool,
        own_port: u16,
    ) -> (ListenerTable, Vec<UdpSocket>) {
        let mut input = HEADER.to_vec();
        input.extend_from_slice(rows);
        let mut listeners = ListenerTable::default();
        let mut udp = Vec::new();
        scan(
            input.as_slice(),
            protocol,
            ipv6,
            own_port,
            &context(),
            &mut listeners,
            &mut udp,
        );
        (listeners, udp)
    }

    /// Formats one socket-table row with the fields consumed by ingress.
    fn row(local: &str, remote: &str, state: u32, inode: &str) -> Vec<u8> {
        format!(
            "  7: {local} {remote} {state:02X} 00000000:00000000 00:00000000 \
             00000000 0 0 {inode} trailing\n"
        )
        .into_bytes()
    }

    /// Verifies that any ASCII white space separates columns and that later columns are ignored.
    #[test]
    fn parses_any_spacing_and_ignores_trailing_columns() {
        let mut input = b"\t7:  00000000:1F90\t00000000:0000 0a a b c 0 0 42 suffix\r\n".to_vec();
        input.extend_from_slice(b" 8: 00000000:1F91 00000000:0000 0A a b c 0 0 43\n");
        let (listeners, udp) = scan_rows(&input, PROTOCOL_TCP, false, 1023);
        assert!(udp.is_empty());
        assert_eq!(
            super::super::encode::encode(listeners),
            b"NVXL\x01\x00\x00\x02\x06\x01\x1f\x90\x06\x01\x1f\x91"
        );
    }

    /// Verifies rejection of malformed addresses, states, and port bounds.
    #[test]
    fn rejects_bad_states_zero_and_extreme_ports_and_addresses() {
        let mut input = Vec::new();
        input.extend(row("00000000:0000", "00000000:0000", TCP_LISTEN, "1"));
        input.extend(row("00000000:10000", "00000000:0000", TCP_LISTEN, "2"));
        input.extend(row("0000000G:1F90", "00000000:0000", TCP_LISTEN, "3"));
        input.extend(row("00000000:1F91", "00000000:0000", 1, "4"));
        let (listeners, udp) = scan_rows(&input, PROTOCOL_TCP, false, 1023);
        assert!(udp.is_empty());
        assert_eq!(
            super::super::encode::encode(listeners),
            b"NVXL\x01\x00\x00\x00"
        );
    }

    /// Verifies unconnected peer requirements, own-port filtering, and connected retention.
    #[test]
    fn udp_requires_an_unconnected_zero_peer_but_keeps_connected_rows() {
        let mut input = Vec::new();
        input.extend(row("00000000:1C21", "00000000:0000", UDP_UNCONNECTED, "10"));
        input.extend(row("00000000:1C22", "0100007F:0035", UDP_CONNECTED, "11"));
        input.extend(row("00000000:1C23", "00000000:0001", UDP_UNCONNECTED, "12"));
        input.extend(row("00000000:03FF", "00000000:0000", UDP_UNCONNECTED, "13"));
        let (_, udp) = scan_rows(&input, PROTOCOL_UDP, false, 1023);
        assert_eq!(
            udp,
            vec![
                UdpSocket {
                    port: 7201,
                    families: FAMILY_IPV4,
                    connected: false,
                    inode: 10,
                },
                UdpSocket {
                    port: 7202,
                    families: FAMILY_IPV4,
                    connected: true,
                    inode: 11,
                },
            ]
        );
    }

    /// Verifies that physical lines longer than the C buffer become separate parse chunks.
    #[test]
    fn an_overlong_physical_line_is_split_like_fgets() {
        let mut input = vec![b'x'; 511];
        input.push(b'\n');
        input.extend_from_slice(&row("00000000:1F90", "00000000:0000", TCP_LISTEN, "1"));
        let (listeners, _) = scan_rows(&input, PROTOCOL_TCP, false, 1023);
        assert_eq!(
            super::super::encode::encode(listeners),
            b"NVXL\x01\x00\x00\x01\x06\x01\x1f\x90"
        );
    }

    /// Verifies that an internal buffered-reader refill never truncates a short physical line.
    #[test]
    fn buffered_reader_boundaries_do_not_split_short_lines() {
        let mut input = Vec::new();
        for index in 0..100 {
            input.extend(row(
                &format!("00000000:{:04X}", 20_000 + index),
                "00000000:0000",
                UDP_UNCONNECTED,
                &index.to_string(),
            ));
        }
        assert!(input.len() > 8 * 1024);
        let (_, udp) = scan_rows(&input, PROTOCOL_UDP, false, 1023);
        assert_eq!(udp.len(), 100);
    }

    /// Verifies a kernel row, and that address columns are read whole up to the 63 bytes that C's
    /// `%63s` read.
    #[test]
    fn rows_parse_the_kernel_format() {
        let row = parse_row(
            b"   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0 \
              0 12345 1 0000000000000000 100 0 0 10 0\n",
        )
        .unwrap();
        assert_eq!(
            row,
            SocketTableRow {
                local: b"00000000:1F90",
                remote: b"00000000:0000",
                state: 0x0a,
                inode: 12345,
            }
        );
        let row = parse_row(b"0: a b 0 c d e 0 0 7").unwrap();
        assert_eq!((row.state, row.inode), (0, 7));
        let column = [b'a'; ADDRESS_COLUMN_LIMIT];
        let mut line = b"0: ".to_vec();
        line.extend(column);
        line.push(b' ');
        line.extend(column);
        line.extend(b" 0A c d e 0 0 1");
        let row = parse_row(&line).unwrap();
        assert_eq!((row.local, row.remote), (&column[..], &column[..]));
    }

    /// Verifies that numbers must fit their types rather than wrap or saturate as C stored them.
    #[test]
    fn row_numbers_must_fit_their_types() {
        assert_eq!(
            parse_row(b"0: a b A c d e 0 0 18446744073709551615").map(|row| row.inode),
            Some(u64::MAX)
        );
        for line in [
            &b"0: a b 1000000000A c d e 0 0 1"[..],
            b"0: a b 10000000000000000A c d e 0 0 1",
            b"0: a b A c d e 0 0 18446744073709551616",
        ] {
            assert_eq!(parse_row(line), None, "{}", line.escape_ascii());
        }
    }

    /// Verifies that rows that C's `sscanf` did not match, and the lenient forms that it did
    /// but the kernel never writes, are rejected.
    #[test]
    fn rows_reject_malformed_and_c_lenient_forms() {
        for line in [
            &b""[..],
            b"\n",
            b"0 : a b 0A c d e 0 0 1",
            b"0: a b 0x c d e 0 0 1",
            b"0: a b 0xg c d e 0 0 1",
            b"0: a b - c d e 0 0 1",
            b"0: a b g c d e 0 0 1",
            b"x: a b 0A c d e 0 0 1",
            b"0: a b 0A c d e 0 x 1",
            b"0: a b 0A c d e 0 0",
            b"0: a b 0A c d e 0 0 +",
            b"+7: a b 0A c d e 0 0 1",
            b"-1: a b 0A c d e 0 0 1",
            b"0:\x0ba b 0A c d e 0 0 1",
            b"0: a b 0x0a c d e 0 0 1",
            b"0: a b +A c d e 0 0 1",
            b"0: a b -0x0a c d e 0 0 1",
            b"0: a b 0A c d e +0 -0 1",
            b"0: a b 0A c d e 0 0 -1",
            b"0: a b 0A c d e 0 0 0x1",
            b"0: a b 0A c d e 0 0 1x",
        ] {
            assert_eq!(parse_row(line), None, "{}", line.escape_ascii());
        }
    }

    /// Verifies that rows whose columns C's `sscanf` read differently, which the kernel never
    /// writes, are rejected: an address column longer than C's `%63s`, which C split, and a NUL
    /// byte, which ended C's string, or a vertical tab, which C took for white space, anywhere in
    /// the row, even in a column that the program skips.
    #[test]
    fn rows_reject_columns_that_c_read_differently() {
        let column = [b'a'; ADDRESS_COLUMN_LIMIT + 1];
        let mut long_local = b"0: ".to_vec();
        long_local.extend(column);
        long_local.extend(b" b 0A c d e 0 0 1");
        let mut long_remote = b"0: a ".to_vec();
        long_remote.extend(column);
        long_remote.extend(b" 0A c d e 0 0 1");
        for line in [
            long_local.as_slice(),
            long_remote.as_slice(),
            b"0: a b 0A \0 d e 0 0 1",
            b"0: a b 0A c\x0bd e f 0 0 1",
            b"0: a b 0A c d e 0 0 1 \0",
            b"0: a b 0A c d e 0 0 1 \x0b",
        ] {
            assert_eq!(parse_row(line), None, "{}", line.escape_ascii());
        }
    }

    /// Verifies that rows that C split or cut short, and so skipped, announce nothing, though the
    /// program's split at ASCII white space alone would find a listener or UDP socket in each.
    #[test]
    fn rows_that_c_skipped_announce_nothing() {
        // A zero-padded port makes the local column 70 bytes long.
        let mut input = row(
            &format!("00000000:{:0>61}", "1F90"),
            "00000000:0000",
            TCP_LISTEN,
            "1",
        );
        input.extend_from_slice(b"  8: 00000000:1F91 00000000:0000 0A \0 b c 0 0 2\n");
        input.extend_from_slice(b"  9: 00000000:1F92 00000000:0000 0A a\x0bb c d 0 0 3\n");
        let (listeners, _) = scan_rows(&input, PROTOCOL_TCP, false, 1023);
        assert_eq!(
            super::super::encode::encode(listeners),
            b"NVXL\x01\x00\x00\x00"
        );
        let input = row(
            "00000000:1F90",
            &format!("{:0>64}:0000", ""),
            UDP_UNCONNECTED,
            "1",
        );
        let (_, udp) = scan_rows(&input, PROTOCOL_UDP, false, 1023);
        assert!(udp.is_empty());
    }

    /// Verifies that addresses and ports in forms that C's `strtoul` read but the kernel never
    /// writes announce nothing, as TCP listeners or UDP sockets, while their canonical form does.
    #[test]
    fn c_lenient_addresses_and_ports_announce_nothing() {
        let canonical = row("00000000:1F90", "00000000:0000", TCP_LISTEN, "1");
        let (listeners, _) = scan_rows(&canonical, PROTOCOL_TCP, false, 1023);
        assert_eq!(
            super::super::encode::encode(listeners),
            b"NVXL\x01\x00\x00\x01\x06\x01\x1f\x90"
        );
        let canonical = row("00000000:1F90", "00000000:0000", UDP_UNCONNECTED, "1");
        let (_, udp) = scan_rows(&canonical, PROTOCOL_UDP, false, 1023);
        assert_eq!(udp.len(), 1);
        for local in [
            "-0000001:1F90",
            "+0000001:1F90",
            "0000000\0:1F90",
            "00000000:+1F90",
            "00000000:0x1F90",
            "00000000:1F90x",
        ] {
            let input = row(local, "00000000:0000", TCP_LISTEN, "1");
            let (listeners, _) = scan_rows(&input, PROTOCOL_TCP, false, 1023);
            assert_eq!(
                super::super::encode::encode(listeners),
                b"NVXL\x01\x00\x00\x00",
                "{}",
                local.escape_debug()
            );
            let input = row(local, "00000000:0000", UDP_UNCONNECTED, "1");
            let (_, udp) = scan_rows(&input, PROTOCOL_UDP, false, 1023);
            assert!(udp.is_empty(), "{}", local.escape_debug());
        }
        // Only an unconnected UDP socket's remote port must be zero.
        for remote in ["00000000:+0", "00000000:0x0", "00000000:x"] {
            let input = row("00000000:1F90", remote, UDP_UNCONNECTED, "1");
            let (_, udp) = scan_rows(&input, PROTOCOL_UDP, false, 1023);
            assert!(udp.is_empty(), "{remote}");
        }
    }
}
