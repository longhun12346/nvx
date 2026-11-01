//! The credit arithmetic: initial grants, window edges, tiny and maximal chunks and frames, a
//! shared pool, invalid grants and over-credit, and partial consumption.

use super::*;

/// Returns a peer of `limits`, created now, whose first grants the runner took.
fn granted_peer(limits: Limits) -> (Peer, Vec<peer::Message>) {
    let mut peer = Peer::new(KEY, limits, timers(), Instant::now());
    let grants = std::iter::from_fn(|| peer.next_message(&mut [])).collect();
    (peer, grants)
}

/// Returns a runner of `limits`, created now, whose workload started.
fn started_runner(limits: Limits) -> Runner {
    let mut runner = Runner::new(KEY, limits, timers(), Instant::now());
    runner.launched(Ok(()));
    runner
}

/// Returns every message that `runner` returns now, with an output buffer of `capacity` bytes,
/// and each output's bytes.
fn drain(runner: &mut Runner, capacity: usize) -> Vec<ToPeer> {
    let mut buffer = vec![0; capacity];
    std::iter::from_fn(|| {
        runner
            .next_message(&mut buffer)
            .map(|message| to_peer(message, &buffer))
    })
    .collect()
}

#[test]
fn each_receiver_first_grants_its_whole_window_once() {
    let limits = bytes(4, 10, 8);
    let (_, grants) = granted_peer(limits);
    assert_eq!(
        grants,
        [
            peer::Message::Credit {
                pool: Pool::Stdout,
                units: 8
            },
            peer::Message::Credit {
                pool: Pool::Stderr,
                units: 8
            },
        ]
    );
    let (_, grants) = granted_peer(limits.shared_output());
    assert_eq!(
        grants,
        [peer::Message::Credit {
            pool: Pool::Output,
            units: 8
        }]
    );
    // The runner grants the input's window before the workload's launch, so that the peer may
    // send input with its request.
    let mut runner = Runner::new(KEY, limits, timers(), Instant::now());
    assert_eq!(drain(&mut runner, 0), [ToPeer::Credit(10)]);
    runner.launched(Ok(()));
    assert_eq!(drain(&mut runner, 0), [ToPeer::Started]);
}

#[test]
fn a_byte_window_admits_data_up_to_its_edge_and_no_further() {
    let limits = bytes(8, 8, 8);
    let mut peer = Peer::new(KEY, limits, timers(), Instant::now());
    // Before its first grant, the window admits nothing.
    assert_eq!(
        peer.output(KEY, Stream::Stdout, b"a"),
        Err(Violation::Window)
    );
    while peer.next_message(&mut []).is_some() {}
    assert_eq!(
        peer.output(KEY, Stream::Stdout, b"12345"),
        Ok(Receipt::Applied)
    );
    assert_eq!(
        peer.output(KEY, Stream::Stdout, b"6789"),
        Err(Violation::Window)
    );
    assert_eq!(
        peer.output(KEY, Stream::Stdout, b"678"),
        Ok(Receipt::Applied)
    );
    assert_eq!(
        peer.output(KEY, Stream::Stdout, b"9"),
        Err(Violation::Window)
    );
    // The other stream has a window of its own, and a refused message changed nothing.
    assert_eq!(
        peer.output(KEY, Stream::Stderr, b"abcdefgh"),
        Ok(Receipt::Applied)
    );
    assert_eq!(peer.pending_output(Stream::Stdout), b"12345678");
    // What the sink takes opens the window again, by as much.
    peer.consumed(Stream::Stdout, 1);
    assert_eq!(
        peer.next_message(&mut []),
        Some(peer::Message::Credit {
            pool: Pool::Stdout,
            units: 1
        })
    );
    assert_eq!(peer.output(KEY, Stream::Stdout, b"9"), Ok(Receipt::Applied));
    assert_eq!(
        peer.output(KEY, Stream::Stdout, b"0"),
        Err(Violation::Window)
    );
}

#[test]
fn data_messages_carry_at_least_a_byte_and_at_most_a_chunk() {
    let limits = bytes(4, 64, 64);
    let (mut peer, _) = granted_peer(limits);
    assert_eq!(peer.output(KEY, Stream::Stdout, b""), Err(Violation::Chunk));
    assert_eq!(
        peer.output(KEY, Stream::Stdout, b"12345"),
        Err(Violation::Chunk)
    );
    assert_eq!(
        peer.output(KEY, Stream::Stdout, b"1234"),
        Ok(Receipt::Applied)
    );
    let mut runner = Runner::new(KEY, limits, timers(), Instant::now());
    assert_eq!(runner.input(KEY, b""), Err(Violation::Chunk));
    while runner.next_message(&mut []).is_some() {}
    assert_eq!(runner.input(KEY, b"12345"), Err(Violation::Chunk));
    assert_eq!(runner.input(KEY, b"1234"), Ok(Receipt::Applied));
}

#[test]
fn the_runner_sends_the_most_that_its_credit_a_chunk_and_the_buffer_allow() {
    // A chunk of one byte sends each byte alone.
    let mut runner = started_runner(bytes(1, 8, 8));
    assert_eq!(runner.read_allowance(Stream::Stdout), 1);
    assert_eq!(runner.output(Stream::Stdout, b"ab"), 1);
    runner.credit(KEY, Pool::Stdout, 8).unwrap();
    assert_eq!(
        drain(&mut runner, 8),
        [
            ToPeer::Credit(8),
            ToPeer::Started,
            ToPeer::Output(Stream::Stdout, b"a".to_vec())
        ]
    );
    assert_eq!(runner.output(Stream::Stdout, b"b"), 1);
    assert_eq!(
        drain(&mut runner, 8),
        [ToPeer::Output(Stream::Stdout, b"b".to_vec())]
    );

    // A larger chunk sends what the credit allows, then the rest once credit returns.
    let mut runner = started_runner(bytes(6, 8, 8));
    assert_eq!(runner.output(Stream::Stdout, b"abcdef"), 6);
    assert_eq!(runner.read_allowance(Stream::Stdout), 0);
    runner.credit(KEY, Pool::Stdout, 4).unwrap();
    let messages = drain(&mut runner, 8);
    assert_eq!(
        messages[2..],
        [ToPeer::Output(Stream::Stdout, b"abcd".to_vec())]
    );
    // The queue has room again for what it sent, one chunk ahead of the credit.
    assert_eq!(runner.read_allowance(Stream::Stdout), 4);
    runner.credit(KEY, Pool::Stdout, 4).unwrap();
    // A small buffer bounds a message too.
    let mut small = [0u8; 1];
    assert_eq!(
        runner.next_message(&mut small),
        Some(runner::Message::Output {
            stream: Stream::Stdout,
            length: 1
        })
    );
    assert_eq!(&small, b"e");
    assert_eq!(
        drain(&mut runner, 8),
        [ToPeer::Output(Stream::Stdout, b"f".to_vec())]
    );
    // An empty buffer carries no output, but other messages still return.
    assert_eq!(runner.output(Stream::Stdout, b"g"), 1);
    runner.output_closed(Stream::Stderr);
    assert_eq!(drain(&mut runner, 0), [ToPeer::End(Stream::Stderr)]);
}

#[test]
fn a_frame_window_charges_one_unit_per_message_whatever_its_length() {
    let limits = Limits::new(16, Window::frames(2), Window::frames(2)).unwrap();
    let (mut peer, grants) = granted_peer(limits);
    assert_eq!(
        grants[0],
        peer::Message::Credit {
            pool: Pool::Stdout,
            units: 2
        }
    );
    assert_eq!(peer.output(KEY, Stream::Stdout, b"x"), Ok(Receipt::Applied));
    assert_eq!(
        peer.output(KEY, Stream::Stdout, &[7; 16]),
        Ok(Receipt::Applied)
    );
    assert_eq!(
        peer.output(KEY, Stream::Stdout, b"y"),
        Err(Violation::Window)
    );
    assert_eq!(
        peer.output(KEY, Stream::Stdout, &[7; 17]),
        Err(Violation::Chunk)
    );
    // A frame's unit returns only once the sink took its last byte.
    peer.consumed(Stream::Stdout, 1);
    assert_eq!(
        peer.next_message(&mut []),
        Some(peer::Message::Credit {
            pool: Pool::Stdout,
            units: 1
        })
    );
    peer.consumed(Stream::Stdout, 15);
    assert_eq!(peer.next_message(&mut []), None);
    peer.consumed(Stream::Stdout, 1);
    assert_eq!(
        peer.next_message(&mut []),
        Some(peer::Message::Credit {
            pool: Pool::Stdout,
            units: 1
        })
    );

    // The runner fills each frame with up to a chunk of what it read, whatever the reads.
    let mut runner = started_runner(limits);
    runner.credit(KEY, Pool::Stdout, 1).unwrap();
    for byte in b"abc" {
        assert_eq!(runner.output(Stream::Stdout, &[*byte]), 1);
    }
    let messages = drain(&mut runner, 16);
    assert_eq!(
        messages[2..],
        [ToPeer::Output(Stream::Stdout, b"abc".to_vec())]
    );
    // With no frame left, it reads one chunk ahead and holds it.
    assert_eq!(runner.output(Stream::Stdout, &[1; 20]), 16);
    assert!(drain(&mut runner, 16).is_empty());
    runner.credit(KEY, Pool::Stdout, 2).unwrap();
    assert_eq!(
        drain(&mut runner, 16),
        [ToPeer::Output(Stream::Stdout, vec![1; 16])]
    );
}

#[test]
fn a_shared_pool_charges_both_streams_and_answers_to_its_own_name() {
    let limits = Limits::new(8, Window::bytes(8), Window::frames(3))
        .unwrap()
        .shared_output();
    let (mut peer, _) = granted_peer(limits);
    assert_eq!(
        peer.output(KEY, Stream::Stdout, b"o1"),
        Ok(Receipt::Applied)
    );
    assert_eq!(
        peer.output(KEY, Stream::Stderr, b"e1"),
        Ok(Receipt::Applied)
    );
    assert_eq!(
        peer.output(KEY, Stream::Stdout, b"o2"),
        Ok(Receipt::Applied)
    );
    assert_eq!(
        peer.output(KEY, Stream::Stderr, b"e2"),
        Err(Violation::Window)
    );
    // A stalled standard output holds the pool that standard error shares.
    peer.consumed(Stream::Stderr, 2);
    assert_eq!(
        peer.next_message(&mut []),
        Some(peer::Message::Credit {
            pool: Pool::Output,
            units: 1
        })
    );
    assert_eq!(
        peer.output(KEY, Stream::Stderr, b"e2"),
        Ok(Receipt::Applied)
    );

    let mut runner = started_runner(limits);
    assert_eq!(runner.credit(KEY, Pool::Stdout, 1), Err(Violation::Pool));
    assert_eq!(runner.credit(KEY, Pool::Input, 1), Err(Violation::Pool));
    runner.credit(KEY, Pool::Output, 2).unwrap();
    // Each stream reads a chunk ahead, and both draw on the pool's two frames, in turns.
    assert_eq!(runner.output(Stream::Stdout, b"out"), 3);
    assert_eq!(runner.output(Stream::Stderr, b"err"), 3);
    let messages = drain(&mut runner, 8);
    assert_eq!(
        messages[2..],
        [
            ToPeer::Output(Stream::Stdout, b"out".to_vec()),
            ToPeer::Output(Stream::Stderr, b"err".to_vec()),
        ]
    );
    assert_eq!(runner.output(Stream::Stdout, b"more"), 4);
    assert!(drain(&mut runner, 8).is_empty());
    // Per-stream pools answer to their own names only.
    let mut runner = started_runner(bytes(8, 8, 8));
    assert_eq!(runner.credit(KEY, Pool::Output, 1), Err(Violation::Pool));
}

#[test]
fn invalid_grants_and_over_credit_are_refused_and_change_nothing() {
    let mut runner = started_runner(bytes(4, 8, 8));
    assert_eq!(runner.credit(KEY, Pool::Stdout, 0), Err(Violation::Credit));
    assert_eq!(runner.credit(KEY, Pool::Stdout, 9), Err(Violation::Credit));
    runner.credit(KEY, Pool::Stdout, 5).unwrap();
    // More than the units in flight would leave the runner more than the window.
    assert_eq!(runner.credit(KEY, Pool::Stdout, 4), Err(Violation::Credit));
    runner.credit(KEY, Pool::Stdout, 3).unwrap();
    assert_eq!(runner.credit(KEY, Pool::Stdout, 1), Err(Violation::Credit));
    // Eight bytes of credit send eight bytes, and no more, in chunks of four.
    let mut sent = 0;
    for _ in 0..4 {
        sent += runner.output(Stream::Stdout, b"abcd");
        for message in drain(&mut runner, 4) {
            if let ToPeer::Output(_, bytes) = message {
                assert!(bytes.len() <= 4);
            }
        }
    }
    assert_eq!(sent, 12);
    assert_eq!(runner.read_allowance(Stream::Stdout), 0);
    // Once the eight bytes are in flight, the peer may return them, and no more.
    assert_eq!(runner.credit(KEY, Pool::Stdout, 9), Err(Violation::Credit));
    runner.credit(KEY, Pool::Stdout, 8).unwrap();

    let mut peer = Peer::new(KEY, bytes(4, 8, 8), timers(), Instant::now());
    assert_eq!(peer.credit(KEY, 0), Err(Violation::Credit));
    assert_eq!(peer.credit(KEY, 9), Err(Violation::Credit));
    peer.credit(KEY, 8).unwrap();
    assert_eq!(peer.credit(KEY, 1), Err(Violation::Credit));
}

#[test]
fn maximal_windows_and_chunks_neither_overflow_nor_admit_more_than_the_window() {
    let limits = Limits::new(u32::MAX, Window::bytes(u32::MAX), Window::frames(u32::MAX)).unwrap();
    let mut runner = started_runner(limits);
    runner.credit(KEY, Pool::Stdout, u32::MAX).unwrap();
    assert_eq!(runner.credit(KEY, Pool::Stdout, 1), Err(Violation::Credit));
    runner.credit(KEY, Pool::Stderr, u32::MAX - 1).unwrap();
    runner.credit(KEY, Pool::Stderr, 1).unwrap();
    // Two chunks of output and the input's window, and two windows of maximal frames.
    assert_eq!(runner.memory_bound(), (u32::MAX as usize).saturating_mul(3));
    let peer = Peer::new(KEY, limits, timers(), Instant::now());
    assert_eq!(peer.memory_bound(), usize::MAX);
    // Empty chunks and windows are refused.
    assert!(Limits::new(0, Window::bytes(1), Window::bytes(1)).is_none());
    assert!(Limits::new(1, Window::bytes(0), Window::bytes(1)).is_none());
    assert!(Limits::new(1, Window::bytes(1), Window::frames(0)).is_none());
}

#[test]
fn partial_consumption_returns_only_what_the_sink_took() {
    let (mut peer, _) = granted_peer(bytes(8, 8, 8));
    peer.output(KEY, Stream::Stdout, b"abcdef").unwrap();
    assert_eq!(peer.pending_output(Stream::Stdout), b"abcdef");
    peer.consumed(Stream::Stdout, 2);
    assert_eq!(peer.pending_output(Stream::Stdout), b"cdef");
    assert_eq!(
        peer.next_message(&mut []),
        Some(peer::Message::Credit {
            pool: Pool::Stdout,
            units: 2
        })
    );
    // Credits coalesce until the adapter retrieves them.
    peer.consumed(Stream::Stdout, 1);
    peer.consumed(Stream::Stdout, 2);
    assert_eq!(
        peer.next_message(&mut []),
        Some(peer::Message::Credit {
            pool: Pool::Stdout,
            units: 3
        })
    );
    // Taking more than is pending takes what is pending.
    peer.consumed(Stream::Stdout, 100);
    assert_eq!(
        peer.next_message(&mut []),
        Some(peer::Message::Credit {
            pool: Pool::Stdout,
            units: 1
        })
    );
    assert_eq!(peer.next_message(&mut []), None);

    // The runner returns input credit for what the workload took, as it takes it.
    let mut runner = started_runner(bytes(8, 8, 8));
    drain(&mut runner, 0);
    runner.input(KEY, b"12345678").unwrap();
    assert_eq!(runner.input(KEY, b"9"), Err(Violation::Window));
    assert_eq!(runner.pending_input(), b"12345678");
    runner.input_written(3);
    assert_eq!(runner.pending_input(), b"45678");
    assert_eq!(drain(&mut runner, 0), [ToPeer::Credit(3)]);
    runner.input(KEY, b"9ab").unwrap();
    assert_eq!(runner.input(KEY, b"c"), Err(Violation::Window));
}

#[test]
fn the_peer_sends_input_within_the_runner_s_credit() {
    let limits = bytes(4, 6, 8);
    let mut peer = Peer::new(KEY, limits, timers(), Instant::now());
    let mut buffer = [0u8; 4];
    // The source may hand over one chunk ahead of the credit.
    assert_eq!(peer.write_allowance(), 4);
    assert_eq!(peer.input(b"abcdefgh"), 4);
    assert_eq!(peer.write_allowance(), 0);
    let messages = std::iter::from_fn(|| peer.next_message(&mut buffer)).collect::<Vec<_>>();
    assert!(
        messages
            .iter()
            .all(|message| matches!(message, peer::Message::Credit { .. })),
        "{messages:?}"
    );
    peer.credit(KEY, 6).unwrap();
    assert_eq!(
        peer.next_message(&mut buffer),
        Some(peer::Message::Input { length: 4 })
    );
    assert_eq!(&buffer, b"abcd");
    assert_eq!(peer.input(b"efgh"), 4);
    assert_eq!(
        peer.next_message(&mut buffer),
        Some(peer::Message::Input { length: 2 })
    );
    assert_eq!(&buffer[..2], b"ef");
    assert_eq!(peer.next_message(&mut buffer), None);
    // The end follows the last byte.
    peer.end_input();
    assert_eq!(peer.write_allowance(), 0);
    assert_eq!(peer.next_message(&mut buffer), None);
    peer.credit(KEY, 4).unwrap();
    assert_eq!(
        peer.next_message(&mut buffer),
        Some(peer::Message::Input { length: 2 })
    );
    assert_eq!(
        peer.next_message(&mut buffer),
        Some(peer::Message::InputEnd)
    );
    assert_eq!(peer.next_message(&mut buffer), None);
}
