//! The NVXS session through public APIs only: the host's and the guest's roles exchange messages of
//! an application framing of their own through a broker, and the host's and the guest's drivers
//! run them over their transports.
//!
//! The broker relays records between one host and the guest under protocol version 1, as
//! OpenVMM's broker does, so the roles meet the same sequencing, windows, and resets.

mod broker;
#[cfg(all(feature = "guest", target_os = "linux"))]
mod guest;
#[cfg(feature = "host")]
mod host;
mod session;

/// Application framing of the tests: each message is a little-endian `u32` length, then the
/// message, and a message may span DATA records.
fn framed(message: &[u8]) -> Vec<u8> {
    [&(message.len() as u32).to_le_bytes(), message].concat()
}

/// Receiver of the tests' application framing, which reassembles messages across DATA records.
#[derive(Default)]
struct Reassembler {
    /// Bytes of the message in progress.
    pending: Vec<u8>,
}

impl Reassembler {
    /// Appends the payload of a DATA record, and returns the messages that it completes.
    fn push(&mut self, payload: &[u8]) -> Vec<Vec<u8>> {
        self.pending.extend_from_slice(payload);
        let mut messages = Vec::new();
        while self.pending.len() >= 4 {
            let length = u32::from_le_bytes(self.pending[..4].try_into().unwrap()) as usize;
            if self.pending.len() < 4 + length {
                break;
            }
            messages.push(self.pending[4..4 + length].to_vec());
            self.pending.drain(..4 + length);
        }
        messages
    }

    /// Returns whether a message is in progress.
    fn is_partial(&self) -> bool {
        !self.pending.is_empty()
    }
}

/// Messages of 10 bytes, of the largest frame that fits one record, of one more byte, and of
/// about 300 KB, which spans five records.
fn messages() -> Vec<Vec<u8>> {
    let largest_in_one_record = nvx::protocol::OUTER_MAX_PAYLOAD - 4;
    [
        10,
        largest_in_one_record,
        largest_in_one_record + 1,
        300_000,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, length)| {
        (0..length)
            .map(|byte| (byte as u8).wrapping_mul(31).wrapping_add(index as u8))
            .collect()
    })
    .collect()
}
