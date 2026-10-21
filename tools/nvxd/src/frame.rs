//! Frame codec shared by both directions: `[u32 LE json_len][u32 LE payload_len][json][payload]`.

use std::io::{self, Read, Write};
use std::sync::Mutex;

use serde_json::Value;

use crate::protocol::{MAX_JSON_BYTES, MAX_PAYLOAD_BYTES};

pub fn read_frame(input: &mut impl Read) -> io::Result<Option<(Value, Vec<u8>)>> {
    let mut header = [0u8; 8];
    match input.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let json_len = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
    let payload_len = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
    if json_len > MAX_JSON_BYTES || payload_len > MAX_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized frame",
        ));
    }
    let mut json = vec![0u8; json_len];
    input.read_exact(&mut json)?;
    let mut payload = vec![0u8; payload_len];
    input.read_exact(&mut payload)?;
    let head = serde_json::from_slice(&json)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(Some((head, payload)))
}

/// Serializes writers so that frames from different threads never interleave.
pub struct FrameWriter<W: Write>(Mutex<W>);

impl<W: Write> FrameWriter<W> {
    pub fn new(output: W) -> Self {
        Self(Mutex::new(output))
    }

    pub fn send(&self, head: &Value, payload: &[u8]) -> io::Result<()> {
        let json = serde_json::to_vec(head).expect("a Value always serializes");
        let mut buffer = Vec::with_capacity(8 + json.len() + payload.len());
        buffer.extend_from_slice(&(json.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&json);
        buffer.extend_from_slice(payload);
        let mut output = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        output.write_all(&buffer)?;
        output.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn frames_round_trip_with_binary_payloads() {
        let writer = FrameWriter::new(Vec::new());
        writer
            .send(&json!({"id": 1, "op": "x"}), &[0, 255, 10, 13])
            .unwrap();
        writer.send(&json!({"id": 2}), &[]).unwrap();
        let bytes = writer.0.into_inner().unwrap();
        let mut input = bytes.as_slice();
        let (head, payload) = read_frame(&mut input).unwrap().unwrap();
        assert_eq!(head["op"], "x");
        assert_eq!(payload, [0, 255, 10, 13]);
        let (head, payload) = read_frame(&mut input).unwrap().unwrap();
        assert_eq!(head["id"], 2);
        assert!(payload.is_empty());
        assert!(read_frame(&mut input).unwrap().is_none());
    }

    #[test]
    fn oversized_frames_are_refused() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(u32::MAX).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert!(read_frame(&mut bytes.as_slice()).is_err());
    }
}
