//! The launcher's end of OpenVMM's virtio-fs export control channel (the fork's
//! `--microvm-virtiofs-control name=<pipe>`): the sidecar asks the VMM to export a host path as a
//! new child of the aggregate virtio-fs device, or to stop exporting one, while the VM runs.
//!
//! The VMM creates and serves the pipe; this side connects as a client and sends one frame per
//! request: `<4-byte LE length><payload>`, the payload one line of space-separated `key=value`
//! fields with percent-encoded values (`gen= seq= session= mount= op= child= [mode= path=]`), the
//! reply `ok` or `error: <reason>`. Every request carries the VM generation and a strictly
//! increasing sequence number, so a replayed request is refused. The wire format is pinned by
//! [`WIRE_VECTORS`], which OpenVMM's tests assert too.

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

/// Windows pipe-path prefix of this channel; the suffix is the VM's nonce.
pub const PIPE_PREFIX: &str = r"\\.\pipe\nvx-live-";

/// The pipe name for one VM from `nonce`, which must be unique per VM.
pub fn pipe_name(nonce: u64) -> String {
    format!("{PIPE_PREFIX}{nonce:016x}")
}

/// The value of OpenVMM's `--microvm-virtiofs-control` for the pipe `name`.
pub fn spec(name: &str) -> String {
    format!("name={name}")
}

/// Connects to the pipe the VMM serves, retrying until `deadline`: the VMM creates it while it starts.
pub fn connect(name: &str, deadline: std::time::Duration) -> std::io::Result<std::fs::File> {
    let until = std::time::Instant::now() + deadline;
    loop {
        match std::fs::OpenOptions::new().read(true).write(true).open(name) {
            Ok(pipe) => return Ok(pipe),
            Err(error) => {
                if std::time::Instant::now() >= until {
                    return Err(error);
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
}

/// One VM's export channel: a connection kept for the VM's life and the request counters.
pub struct Channel {
    name: String,
    generation: u64,
    state: std::sync::Mutex<ChannelState>,
}

struct ChannelState {
    pipe: Option<std::fs::File>,
    sequence: u64,
}

impl Channel {
    pub fn new(name: String, generation: u64) -> Self {
        Self { name, generation, state: std::sync::Mutex::new(ChannelState { pipe: None, sequence: 0 }) }
    }

    fn send(&self, mut request: Request) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        if state.pipe.is_none() {
            let pipe = connect(&self.name, std::time::Duration::from_secs(10))
                .map_err(|error| format!("cannot reach the export channel: {error}"))?;
            state.pipe = Some(pipe);
        }
        state.sequence += 1;
        request.generation = self.generation;
        request.sequence = state.sequence;
        let pipe = state.pipe.as_mut().expect("connected above");
        let outcome = exchange(pipe, &request);
        if outcome.as_ref().is_err_and(|reason| reason.starts_with("cannot ")) {
            // The connection broke: the next request connects again.
            state.pipe = None;
        }
        outcome
    }

    /// Asks the VMM to export the host path `host` as the aggregate child `child`.
    pub fn add(&self, session: &str, mount: &str, child: &str, host: &str, read_only: bool) -> Result<(), String> {
        self.send(Request {
            generation: 0,
            sequence: 0,
            session: session.to_owned(),
            mount_id: mount.to_owned(),
            child: child.to_owned(),
            operation: Operation::Add,
            mode: if read_only { Mode::ReadOnly } else { Mode::ReadWrite },
            host_path: host.to_owned(),
        })
    }

    /// Asks the VMM to stop exporting `child`.
    pub fn remove(&self, session: &str, mount: &str, child: &str) -> Result<(), String> {
        self.send(Request {
            generation: 0,
            sequence: 0,
            session: session.to_owned(),
            mount_id: mount.to_owned(),
            child: child.to_owned(),
            operation: Operation::Remove,
            mode: Mode::ReadOnly,
            host_path: String::new(),
        })
    }
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
