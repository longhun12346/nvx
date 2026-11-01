//! Launcher side of the virtio-fs export control channel.
//!
//! OpenVMM serves requests on an inherited pipe (see its
//! `vm/devices/virtio/virtiofs/src/microvm/control.rs`); this module is the other
//! end. The two crates cannot share code, so the wire format is pinned by
//! [`WIRE_VECTORS`]: the same literal frames are asserted here and in OpenVMM's
//! tests, which turns a silent divergence into a failing test on both sides.
//!
//! Format, one request per frame: `<4-byte LE length><payload>`, payload is one
//! line of space-separated `key=value` fields with percent-encoded values:
//! `gen= seq= session= mount= op= child= [mode= path=]`.
//! The reply is a single line: `ok` or `error: <reason>`.

use std::io::Read;
use std::io::Write;

/// Largest frame either side accepts, matching OpenVMM's limit.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Operations a launcher may request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Export one host path as a new aggregate child.
    Add,
    /// Stop exporting a child that was added.
    Remove,
}

/// Access mode of an export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    ReadOnly,
    ReadWrite,
}

/// One validated request, in the order the guest agent and the VMM see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Boot generation of the VM; a request for another generation is refused.
    pub generation: u64,
    /// Strictly increasing within a generation, so a replay is refused.
    pub sequence: u64,
    pub session: String,
    pub mount_id: String,
    pub child: String,
    pub operation: Operation,
    pub mode: Mode,
    /// Absolute host path; empty for [`Operation::Remove`].
    pub host_path: String,
}

/// Frames both sides must reproduce byte for byte.
///
/// Keeping them here means the encoders cannot drift: OpenVMM's receiver asserts
/// the same strings, so a change on one side fails the other side's test.
pub const WIRE_VECTORS: &[(&str, &str)] = &[
    (
        "gen=7 seq=1 session=session%20a mount=refs op=add child=mount0 mode=ro path=C:\\%20a",
        "add with a space in the session and path; ':' and '\\' stay literal",
    ),
    (
        "gen=7 seq=2 session=s mount=refs op=remove child=mount0",
        "remove carries neither mode nor path",
    ),
];

/// Percent-encodes a field value so spaces and newlines cannot forge fields.
pub fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'\\' | b':' | b'.' | b'-' | b'_' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Renders one request as its frame payload.
pub fn encode_request(request: &Request) -> String {
    let mut line = format!(
        "gen={} seq={} session={} mount={} op={} child={}",
        request.generation,
        request.sequence,
        encode(&request.session),
        encode(&request.mount_id),
        match request.operation {
            Operation::Add => "add",
            Operation::Remove => "remove",
        },
        encode(&request.child),
    );
    if request.operation == Operation::Add {
        line.push_str(&format!(
            " mode={} path={}",
            match request.mode {
                Mode::ReadOnly => "ro",
                Mode::ReadWrite => "rw",
            },
            encode(&request.host_path)
        ));
    }
    line
}

/// Interprets the VMM's reply line.
pub fn parse_reply(line: &str) -> Result<(), String> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line == "ok" {
        return Ok(());
    }
    match line.strip_prefix("error: ") {
        Some(reason) if !reason.is_empty() => Err(reason.to_owned()),
        _ => Err(format!("unexpected reply {line:?}")),
    }
}

/// Sends one request and waits for its reply on `pipe`.
///
/// The pipe is a single duplex handle: OpenVMM reads a frame and answers on the
/// same handle, so calls on one channel must not interleave.
pub fn exchange(pipe: &mut (impl Read + Write), request: &Request) -> Result<(), String> {
    let payload = encode_request(request);
    if payload.len() > MAX_FRAME_BYTES {
        return Err(format!("request is {} bytes, over the limit", payload.len()));
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload.as_bytes());
    pipe.write_all(&frame)
        .map_err(|error| format!("cannot send the request: {error}"))?;
    pipe.flush()
        .map_err(|error| format!("cannot flush the request: {error}"))?;

    let mut length = [0u8; 4];
    pipe.read_exact(&mut length)
        .map_err(|error| format!("cannot read the reply length: {error}"))?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(format!("reply length {length} is out of range"));
    }
    let mut reply = vec![0u8; length];
    pipe.read_exact(&mut reply)
        .map_err(|error| format!("cannot read the reply: {error}"))?;
    let text = String::from_utf8(reply).map_err(|_| "reply is not valid UTF-8".to_owned())?;
    parse_reply(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add() -> Request {
        Request {
            generation: 7,
            sequence: 1,
            session: "session a".to_owned(),
            mount_id: "refs".to_owned(),
            child: "mount0".to_owned(),
            operation: Operation::Add,
            mode: Mode::ReadOnly,
            host_path: "C:\\ a".to_owned(),
        }
    }

    #[test]
    fn the_wire_vectors_match_the_receiver() {
        assert_eq!(encode_request(&add()), WIRE_VECTORS[0].0);
        let mut remove = add();
        remove.operation = Operation::Remove;
        remove.sequence = 2;
        remove.session = "s".to_owned();
        remove.host_path.clear();
        assert_eq!(encode_request(&remove), WIRE_VECTORS[1].0);
    }

    #[test]
    fn replies_are_ok_or_an_error_reason() {
        assert_eq!(parse_reply("ok\n"), Ok(()));
        assert_eq!(parse_reply("error: child is missing"), Err("child is missing".to_owned()));
        assert!(parse_reply("").is_err());
        assert!(parse_reply("error: ").is_err());
        assert!(parse_reply("OK").is_err());
    }

    #[test]
    fn exchange_round_trips_a_frame_and_its_reply() {
        // A duplex stand-in: writes are dropped, reads return a canned reply.
        struct Pipe {
            reply: Vec<u8>,
            written: Vec<u8>,
        }
        impl Write for Pipe {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                self.written.extend_from_slice(buffer);
                Ok(buffer.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl Read for Pipe {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let take = buffer.len().min(self.reply.len());
                buffer[..take].copy_from_slice(&self.reply[..take]);
                self.reply.drain(..take);
                Ok(take)
            }
        }

        let reply = b"ok\n";
        let mut pipe = Pipe {
            reply: {
                let mut frame = (reply.len() as u32).to_le_bytes().to_vec();
                frame.extend_from_slice(reply);
                frame
            },
            written: Vec::new(),
        };
        assert_eq!(exchange(&mut pipe, &add()), Ok(()));

        let payload = encode_request(&add());
        let mut expected = (payload.len() as u32).to_le_bytes().to_vec();
        expected.extend_from_slice(payload.as_bytes());
        assert_eq!(pipe.written, expected);
    }
}
