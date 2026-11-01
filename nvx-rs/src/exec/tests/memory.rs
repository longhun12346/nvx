//! Bounded memory: streams far longer than their windows arrive whole while each side holds no
//! more than its bound, with byte windows and with a shared pool of frames.

use super::*;

/// Asserts that neither side of `pair` ever held more than its bound, and returns both
/// high-water marks.
fn assert_bounded(pair: &Pair) -> (usize, usize) {
    let runner = (pair.runner.high_water(), pair.runner.memory_bound());
    let peer = (pair.peer.high_water(), pair.peer.memory_bound());
    assert!(runner.0 <= runner.1, "the runner held {runner:?}");
    assert!(peer.0 <= peer.1, "the peer held {peer:?}");
    (runner.0, peer.0)
}

#[test]
fn a_stream_far_longer_than_its_window_arrives_whole_in_bounded_memory() {
    const STDOUT: usize = 64 << 20;
    const STDERR: usize = 1 << 20;
    const WINDOW: u32 = 64 * 1024;
    let limits = bytes(16 * 1024, WINDOW, WINDOW);
    let mut client = Client::new();
    client.rates = [48 * 1024, 5 * 1024];
    let mut pair = Pair::new(limits, timers(), Workload::new(STDOUT, STDERR), client);
    let outcome = pair.finish();
    // The client checked each byte against the workload's pattern as it took it.
    assert_eq!(pair.client.received, [STDOUT, STDERR]);
    assert!(!outcome.is_truncated(Stream::Stdout) && !outcome.is_truncated(Stream::Stderr));
    assert_eq!(outcome.status(), Some(Status::Exited(0)));
    let (runner, peer) = assert_bounded(&pair);
    // The runner held at most a chunk of each stream, and the peer at most both windows.
    assert!(runner <= 2 * limits.chunk(), "{runner}");
    assert!(peer <= 2 * WINDOW as usize, "{peer}");
    assert!(pair.in_flight_high_water <= 2 * WINDOW as usize);
}

#[test]
fn a_shared_pool_of_frames_carries_both_streams_whole_in_bounded_memory() {
    // Frames of up to 64 KiB less 256 bytes, in a pool of 64 frames that both streams share.
    const CHUNK: u32 = 64 * 1024 - 256;
    const LENGTH: usize = 16 << 20;
    let limits = Limits::new(CHUNK, Window::frames(64), Window::frames(64))
        .unwrap()
        .shared_output();
    let mut client = Client::new();
    client.rates = [100 * 1024, 30 * 1024];
    let mut pair = Pair::new(limits, timers(), Workload::new(LENGTH, LENGTH / 4), client);
    let outcome = pair.finish();
    assert_eq!(pair.client.received, [LENGTH, LENGTH / 4]);
    assert!(!outcome.is_truncated(Stream::Stdout) && !outcome.is_truncated(Stream::Stderr));
    let (runner, peer) = assert_bounded(&pair);
    assert!(runner <= 2 * CHUNK as usize, "{runner}");
    assert!(peer <= 64 * CHUNK as usize, "{peer}");
    // Each output message filled at most one frame.
    assert!(pair.sent_by_runner.iter().all(|message| match message {
        runner::Message::Output { length, .. } => *length <= CHUNK as usize,
        _ => true,
    }));
}

#[test]
fn input_longer_than_its_window_arrives_whole() {
    for limits in [
        bytes(4096, 16 * 1024, 16 * 1024),
        Limits::new(1000, Window::frames(4), Window::bytes(4096)).unwrap(),
    ] {
        let mut workload = Workload::new(0, 0);
        workload.reads_to_end = true;
        workload.input_rate = 5_000;
        let mut client = Client::new();
        client.input = (0..1usize << 20)
            .map(|index| (index * 7 + index / 251) as u8)
            .collect();
        let mut pair = Pair::new(limits, timers(), workload, client);
        let outcome = pair.finish();
        assert_eq!(pair.workload.input, pair.client.input, "{limits:?}");
        assert!(pair.workload.input_end);
        assert_eq!(outcome.status(), Some(Status::Exited(0)));
        assert!(outcome.is_reusable());
        let (runner, peer) = assert_bounded(&pair);
        // The runner held at most the input's window, and the peer at most a chunk of input.
        let window = match limits.input().unit() {
            Unit::Bytes => limits.input().size() as usize,
            Unit::Frames => limits.input().size() as usize * limits.chunk(),
        };
        assert!(runner <= window, "{runner}");
        assert!(peer <= limits.chunk(), "{peer}");
    }
}
