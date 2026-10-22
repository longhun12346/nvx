//! Export requests sent over the control channel instead of request files.
//!
//! [`crate::host::poc_live`] drives OpenVMM by writing a request file into a
//! directory the VMM polls, which nothing authenticates. This module speaks the same
//! operation over the inherited pipe that [`crate::host::control`] frames, so the
//! VMM can stop polling entirely once the launcher passes a handle.
//!
//! Only the VMM half of a share lives here. Binding the export inside the guest is a
//! separate control session and stays where it is: a share is only usable once both
//! halves succeed, so [`export_or_rollback`] undoes the VMM half when the guest
//! refuses the bind.

use std::io::Read;
use std::io::Write;

use crate::error::{Error, Result};
use crate::host::control::{self, Mode, Operation, Request};
use crate::host::poc_live::LiveShare;

/// Sequence numbers for one VM's channel.
///
/// Every request must carry a strictly greater sequence than the one before it, so
/// a recorded request replayed from an older transcript is refused by the VMM. The
/// guest's runtime mapping count is used as the sequence when it is known, because
/// it already grows by one per successful share; this counter is the fallback.
#[derive(Debug, Default)]
pub struct Sequences {
    next: u64,
}

impl Sequences {
    pub fn new(first: u64) -> Self {
        Self { next: first }
    }

    pub fn next(&mut self) -> u64 {
        let value = self.next;
        self.next += 1;
        value
    }
}

fn request_of(
    generation: u64,
    sequence: u64,
    session: &str,
    share: &LiveShare<'_>,
) -> Request {
    Request {
        generation,
        sequence,
        session: session.to_owned(),
        mount_id: share.target.to_owned(),
        child: share.child.to_owned(),
        operation: Operation::Add,
        mode: if share.read_only {
            Mode::ReadOnly
        } else {
            Mode::ReadWrite
        },
        host_path: share.host_path.display().to_string(),
    }
}

/// Asks the VMM to export `share` as a new aggregate child.
pub fn export(
    pipe: &mut (impl Read + Write),
    generation: u64,
    sequence: u64,
    session: &str,
    share: &LiveShare<'_>,
) -> Result<()> {
    control::exchange(pipe, &request_of(generation, sequence, session, share)).map_err(
        |reason| {
            Error::other(format!(
                "the VMM refused to export {:?}: {reason}",
                share.target
            ))
        },
    )
}

/// Asks the VMM to stop exporting `child`.
pub fn unexport(
    pipe: &mut (impl Read + Write),
    generation: u64,
    sequence: u64,
    session: &str,
    child: &str,
    target: &str,
) -> Result<()> {
    let request = Request {
        generation,
        sequence,
        session: session.to_owned(),
        mount_id: target.to_owned(),
        child: child.to_owned(),
        operation: Operation::Remove,
        mode: Mode::ReadOnly,
        host_path: String::new(),
    };
    control::exchange(pipe, &request).map_err(|reason| {
        Error::other(format!("the VMM refused to stop exporting {target:?}: {reason}"))
    })
}

/// Exports `share`, and takes the export back when `bind` fails.
///
/// The aggregate's child slots are a bounded resource, so a share the guest never
/// mounted must not keep one. The rollback uses the next sequence, because the VMM
/// would otherwise refuse it as a replay.
pub fn export_or_rollback(
    pipe: &mut (impl Read + Write),
    generation: u64,
    sequences: &mut Sequences,
    session: &str,
    share: &LiveShare<'_>,
    bind: impl FnOnce() -> Result<()>,
) -> Result<()> {
    export(pipe, generation, sequences.next(), session, share)?;
    match bind() {
        Ok(()) => Ok(()),
        Err(error) => {
            // Best effort: the original error is what the caller needs to see.
            let _ = unexport(
                pipe,
                generation,
                sequences.next(),
                session,
                share.child,
                share.target,
            );
            Err(error)
        }
    }
}

/// Where the VMM should serve export requests.
///
/// The launcher names the endpoint on OpenVMM's command line: `<digits>` is an
/// inherited handle, `name=<path>` is a pipe the VMM connects to. The named form
/// exists because an inherited handle must outlive the whole `Instance`, which its
/// `Clone`/`PartialEq` derives do not allow; a name is an ordinary string, and the
/// launcher can open it per request instead of holding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// A handle the child receives by inheritance; the value is the descriptor
    /// number the child sees.
    Inherited(u32),
    /// A pipe name the child connects to as a client.
    Named(String),
}

/// Windows pipe-path prefix for this channel.
pub const PIPE_PREFIX: &str = r"\\.\pipe\genflow-nvx-";

/// Builds the pipe name for one VM from `nonce`, which must be unique per VM.
///
/// The name is not a secret: the pipe's DACL limits connects to this user, the VMM
/// checks the connecting process, and every request carries a generation and a
/// monotonic sequence number. Uniqueness only keeps concurrent VMs apart.
pub fn pipe_name(nonce: u64) -> String {
    format!("{PIPE_PREFIX}{nonce:016x}")
}

/// Renders the value OpenVMM's `--microvm-virtiofs-control` expects for `endpoint`.
pub fn spec(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Inherited(handle) => handle.to_string(),
        Endpoint::Named(name) => format!("name={name}"),
    }
}

/// Parses that value back, on either side of the channel.
pub fn parse_spec(text: &str) -> Result<Endpoint, String> {
    let text = text.trim();
    if let Some(name) = text.strip_prefix("name=") {
        if !name.starts_with(PIPE_PREFIX) {
            return Err(format!("pipe name must start with {PIPE_PREFIX:?}"));
        }
        // The suffix is the VM's nonce; anything else would let two VMs collide.
        let suffix = &name[PIPE_PREFIX.len()..];
        if suffix.len() != 16 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("pipe name must end with 16 hexadecimal digits".to_owned());
        }
        return Ok(Endpoint::Named(name.to_owned()));
    }
    text.parse::<u32>()
        .map(Endpoint::Inherited)
        .map_err(|_| format!("endpoint {text:?} is neither a handle number nor name=..."))
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;

    #[test]
    fn names_are_unique_per_nonce_and_round_trip() {
        let first = pipe_name(0x1234_5678_9abc_def0);
        let second = pipe_name(1);
        assert_ne!(first, second);
        assert!(first.starts_with(PIPE_PREFIX));

        let endpoint = Endpoint::Named(first.clone());
        let spec = spec(&endpoint);
        assert_eq!(spec, format!("name={first}"));
        assert_eq!(parse_spec(&spec).unwrap(), endpoint);
    }

    #[test]
    fn inherited_handles_round_trip() {
        let endpoint = Endpoint::Inherited(0x1c);
        assert_eq!(spec(&endpoint), "28");
        assert_eq!(parse_spec("28").unwrap(), endpoint);
        assert_eq!(parse_spec(" 28 ").unwrap(), endpoint);
    }

    #[test]
    fn malformed_specs_are_refused() {
        for text in [
            "",
            "handle=28",
            "name=",
            "name=\\\\.\\pipe\\other",
            // Right prefix, wrong nonce shape: two VMs would collide.
            "name=\\\\.\\pipe\\genflow-nvx-abc",
            "name=\\\\.\\pipe\\genflow-nvx-00000000000000000",
            "name=\\\\.\\pipe\\genflow-nvx-zzzzzzzzzzzzzzzz",
            "-1",
            "0x1c",
            "1c",
        ] {
            assert!(parse_spec(text).is_err(), "{text:?} must be refused");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// A duplex stand-in that records what was sent and replays scripted replies.
    struct Channel {
        pending: Vec<u8>,
        written: Vec<u8>,
    }

    impl Channel {
        fn answering(replies: &[&str]) -> Self {
            // Pre-frame every reply into one byte stream: `read_exact` may ask for the
            // length and the payload separately, so a per-call frame would not do.
            let mut pending = Vec::new();
            for reply in replies {
                let line = format!("{reply}\n");
                pending.extend_from_slice(&(line.len() as u32).to_le_bytes());
                pending.extend_from_slice(line.as_bytes());
            }
            Self {
                pending,
                written: Vec::new(),
            }
        }

        fn frames(&self) -> Vec<String> {
            let mut frames = Vec::new();
            let mut offset = 0;
            while offset + 4 <= self.written.len() {
                let length =
                    u32::from_le_bytes(self.written[offset..offset + 4].try_into().unwrap())
                        as usize;
                offset += 4;
                frames.push(
                    String::from_utf8(self.written[offset..offset + length].to_vec()).unwrap(),
                );
                offset += length;
            }
            frames
        }
    }

    impl Write for Channel {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buffer);
            Ok(buffer.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Read for Channel {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let take = buffer.len().min(self.pending.len());
            buffer[..take].copy_from_slice(&self.pending[..take]);
            self.pending.drain(..take);
            Ok(take)
        }
    }

    fn share() -> LiveShare<'static> {
        LiveShare {
            child: "mount0",
            host_path: Path::new("C:\\refs"),
            target: "/workspace/mounts/refs",
            read_only: true,
        }
    }

    #[test]
    fn export_sends_an_add_frame() {
        let mut channel = Channel::answering(&["ok"]);
        export(&mut channel, 3, 1, "session-a", &share()).unwrap();
        assert_eq!(
            channel.frames(),
            vec![
                "gen=3 seq=1 session=session-a mount=/workspace/mounts/refs op=add child=mount0 \
                 mode=ro path=C:\\refs"
                    .to_owned()
            ]
        );
    }

    #[test]
    fn a_refusal_surfaces_the_vmm_reason() {
        let mut channel = Channel::answering(&["error: mapping-limit"]);
        let error = export(&mut channel, 3, 1, "s", &share()).unwrap_err();
        assert!(error.to_string().contains("mapping-limit"), "{error}");
    }

    #[test]
    fn a_failed_bind_takes_the_export_back() {
        let mut channel = Channel::answering(&["ok", "ok"]);
        let mut sequences = Sequences::new(1);
        let error = export_or_rollback(&mut channel, 3, &mut sequences, "s", &share(), || {
            Err(Error::other("the guest refused the bind"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("refused the bind"), "{error}");
        // Two frames: the add, then the compensating remove with a later sequence.
        let frames = channel.frames();
        assert_eq!(frames.len(), 2);
        assert!(frames[0].contains("op=add"), "{}", frames[0]);
        assert!(frames[1].contains("op=remove"), "{}", frames[1]);
        assert!(frames[1].contains("seq=2"), "{}", frames[1]);
    }

    #[test]
    fn a_successful_bind_keeps_the_export() {
        let mut channel = Channel::answering(&["ok"]);
        let mut sequences = Sequences::new(1);
        export_or_rollback(&mut channel, 3, &mut sequences, "s", &share(), || Ok(())).unwrap();
        assert_eq!(channel.frames().len(), 1);
    }
}
