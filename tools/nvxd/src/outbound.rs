//! Bounded outbound path.
//!
//! Every reply, every chunk of command output and every lifecycle event leaves through here.
//! Two things matter and neither is "write as fast as possible":
//!
//! * **Memory stays bounded.** The queue has a fixed capacity, so a caller that stops reading
//!   costs a fixed amount of memory instead of growing the sidecar until it dies. A full queue
//!   is reported to the sender, which is what lets the control plane notice that the connection
//!   is no longer usable instead of pretending the output was delivered.
//! * **Replies are not shed with output.** Command output is the only high-volume traffic, so
//!   only it is limited to `capacity` waiting frames. Replies and lifecycle events are small and
//!   one per request or state change; they have `RESERVE` more slots. Without that, a caller
//!   that stalled and then asked a question could find its reply dropped, with nothing to say
//!   the question had been answered at all.
//! * **Frames never interleave.** One thread owns the output, so the byte-level framing cannot
//!   be split by a concurrent writer — the reason the mutex around the writer existed before,
//!   replaced here because it also made a stalled reader block every producer.


use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;

use serde_json::Value;

/// Frames that may wait for the caller to read them.
///
/// Sized in frames rather than bytes because the per-frame size is already capped by the
/// protocol (`MAX_JSON_BYTES`, `MAX_PAYLOAD_BYTES`); capacity × frame size is the worst case.
pub const DEFAULT_CAPACITY: usize = 256;

/// Extra slots for replies and lifecycle events, on top of the output capacity. More than the
/// requests and events a caller can have outstanding, so a full output queue never costs a reply.
pub const RESERVE: usize = 256;

struct Frame {
    json: Vec<u8>,
    payload: Vec<u8>,
    /// Counted against the output limit and released by the writer thread once it is written.
    output: bool,
}

/// Counters a support case can read without attaching a debugger.
#[derive(Debug, Default)]
pub struct Stats {
    frames: AtomicU64,
    refused: AtomicU64,
    /// Set once a send was refused or the output thread failed: the connection is no longer
    /// able to carry everything that was produced.
    broken: AtomicBool,
}

impl Stats {
    pub fn frames(&self) -> u64 {
        self.frames.load(Ordering::Relaxed)
    }

    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    pub fn broken(&self) -> bool {
        self.broken.load(Ordering::Relaxed)
    }
}

pub struct Writer {
    sender: SyncSender<Frame>,
    stats: Arc<Stats>,
    output_limit: usize,
    queued_output: Arc<AtomicUsize>,
}

impl Writer {
    /// Queues a reply or event, or says why it could not be queued.
    ///
    /// Never blocks: a producer that cannot enqueue learns immediately, which is what keeps a
    /// slow reader from turning into an unbounded backlog or a deadlock between two producers.
    /// It is refused only when even the reserve is used up.
    pub fn send(&self, head: &Value, payload: &[u8]) -> io::Result<()> {
        self.enqueue(head, payload, false)
    }

    /// Queues a chunk of command output. Limited to the output capacity, so a caller that stops
    /// reading loses output, never replies.
    pub fn send_output(&self, head: &Value, payload: &[u8]) -> io::Result<()> {
        self.enqueue(head, payload, true)
    }

    fn enqueue(&self, head: &Value, payload: &[u8], output: bool) -> io::Result<()> {
        let json = serde_json::to_vec(head)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let frame = Frame {
            json,
            payload: payload.to_vec(),
            output,
        };
        if output && self.queued_output.fetch_add(1, Ordering::AcqRel) >= self.output_limit {
            self.queued_output.fetch_sub(1, Ordering::AcqRel);
            return Err(self.refuse_full());
        }
        match self.sender.try_send(frame) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                if output {
                    self.queued_output.fetch_sub(1, Ordering::AcqRel);
                }
                Err(self.refuse_full())
            }
            Err(TrySendError::Disconnected(_)) => {
                if output {
                    self.queued_output.fetch_sub(1, Ordering::AcqRel);
                }
                self.stats.refused.fetch_add(1, Ordering::Relaxed);
                self.stats.broken.store(true, Ordering::Relaxed);
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the outbound writer has stopped",
                ))
            }
        }
    }

    fn refuse_full(&self) -> io::Error {
        self.stats.refused.fetch_add(1, Ordering::Relaxed);
        self.stats.broken.store(true, Ordering::Relaxed);
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "the caller is not reading; the outbound queue is full",
        )
    }

    pub fn stats(&self) -> Arc<Stats> {
        Arc::clone(&self.stats)
    }

    /// Whether the connection can no longer carry everything that was produced.
    pub fn broken(&self) -> bool {
        self.stats.broken()
    }
}

/// Serialized writer with a bounded queue. Returns the handle and the thread that drains it.
pub fn spawn(output: Box<dyn Write + Send>, capacity: usize) -> (Writer, JoinHandle<()>) {
    let capacity = capacity.max(1);
    let (sender, receiver) = sync_channel(capacity + RESERVE);
    let stats = Arc::new(Stats::default());
    let queued_output = Arc::new(AtomicUsize::new(0));
    let writer = Writer {
        sender,
        stats: Arc::clone(&stats),
        output_limit: capacity,
        queued_output: Arc::clone(&queued_output),
    };
    let thread = std::thread::spawn(move || drain(output, receiver, stats, queued_output));
    (writer, thread)
}

fn drain(
    mut output: Box<dyn Write + Send>,
    receiver: Receiver<Frame>,
    stats: Arc<Stats>,
    queued_output: Arc<AtomicUsize>,
) {
    // Frames already accepted must be written even if the reader disappears: dropping them
    // here would make an accepted request look unanswered with nothing to point at.
    while let Ok(frame) = receiver.recv() {
        if frame.output {
            queued_output.fetch_sub(1, Ordering::AcqRel);
        }
        let mut buffer = Vec::with_capacity(8 + frame.json.len() + frame.payload.len());
        buffer.extend_from_slice(&(frame.json.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&(frame.payload.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&frame.json);
        buffer.extend_from_slice(&frame.payload);
        if let Err(error) = output.write_all(&buffer).and_then(|()| output.flush()) {
            // The caller is gone. Mark the connection broken and stop: staying here to drain
            // the queue would keep this thread alive for as long as any producer still holds
            // a handle, and shutdown would then wait for it forever.
            eprintln!("nvxd: cannot write to the caller: {error}");
            stats.broken.store(true, Ordering::Relaxed);
            return;
        }
        stats.frames.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex as StdMutex;
    use std::time::{Duration, Instant};

    #[derive(Clone, Default)]
    struct Sink(Arc<StdMutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn wait_for(sink: &Sink, at_least: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while sink.0.lock().unwrap().len() < at_least {
            assert!(Instant::now() < deadline, "the writer did not drain in time");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Frames leave in the order they were queued: a reply that overtook an earlier event
    /// would be indistinguishable from a lost one at the caller.
    #[test]
    fn frames_are_written_in_order() {
        let sink = Sink::default();
        let (writer, thread) = spawn(Box::new(sink.clone()), 16);
        for id in 0..5 {
            writer.send(&json!({"id": id}), &[]).unwrap();
        }
        wait_for(&sink, 5 * 8);
        drop(writer);
        thread.join().unwrap();
        let bytes = sink.0.lock().unwrap().clone();
        let mut input = bytes.as_slice();
        for id in 0..5 {
            let (head, _) = crate::frame::read_frame(&mut input).unwrap().unwrap();
            assert_eq!(head["id"], id);
        }
    }

    /// A caller that stops reading must cost bounded memory and a definite error, not an
    /// unbounded queue and a producer that quietly waits forever.
    #[test]
    fn a_stalled_reader_is_refused_rather_than_buffered_without_limit() {
        let gate = Gate::default();
        let (writer, thread) = spawn(Box::new(gate.clone()), 2);
        let mut refused = false;
        for id in 0..64 {
            if writer.send_output(&json!({"id": id}), b"x").is_err() {
                refused = true;
                break;
            }
        }
        assert!(refused, "a full queue must be reported");
        assert!(writer.broken(), "a refused send marks the connection broken");
        assert!(writer.stats().refused() >= 1);
        gate.open();
        drop(writer);
        let _ = thread.join();
    }

    /// The case that used to hang a caller: output has filled the queue, the caller asks a
    /// question, and the answer must not be shed with the output.
    #[test]
    fn a_reply_is_not_shed_while_output_is_refused() {
        let gate = Gate::default();
        let (writer, thread) = spawn(Box::new(gate.clone()), 2);
        let mut output_refused = false;
        for id in 0..64 {
            if writer.send_output(&json!({"id": id}), b"x").is_err() {
                output_refused = true;
                break;
            }
        }
        assert!(output_refused, "the output limit must be reached first");
        assert!(RESERVE >= 16, "the reserve must hold more than a few replies");
        for id in 0..16 {
            writer
                .send(&json!({"id": 1000 + id, "ok": true}), &[])
                .unwrap_or_else(|error| panic!("reply {id} was refused: {error}"));
        }
        // The reserve is itself bounded.
        let mut exhausted = false;
        for id in 0..(RESERVE + 8) {
            if writer.send(&json!({"id": 5000 + id}), &[]).is_err() {
                exhausted = true;
                break;
            }
        }
        assert!(exhausted, "replies must not grow the queue without limit");
        gate.open();
        drop(writer);
        thread.join().unwrap();
    }

    /// A sink that accepts nothing until it is opened, so the queue behind it can be filled
    /// deterministically.
    #[derive(Clone, Default)]
    struct Gate(Arc<(StdMutex<bool>, std::sync::Condvar)>);

    impl Gate {
        fn open(&self) {
            *self.0 .0.lock().unwrap() = true;
            self.0 .1.notify_all();
        }
    }

    impl Write for Gate {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut open = self.0 .0.lock().unwrap();
            while !*open {
                open = self.0 .1.wait(open).unwrap();
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
