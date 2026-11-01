//! Messages of an earlier generation, of another execution or a later generation, and messages
//! that arrive after the side no longer needs them.

use super::*;

/// The key of the same execution's earlier generation.
const EARLIER: Key = Key::new(KEY.id(), KEY.generation() - 1);
/// The key of the same execution's later generation.
const LATER: Key = Key::new(KEY.id(), KEY.generation() + 1);
/// The key of another execution.
const OTHER: Key = Key::new(KEY.id() + 1, KEY.generation());

#[test]
fn messages_of_an_earlier_generation_are_stale_and_change_nothing() {
    let now = Instant::now();
    let mut runner = Runner::new(KEY, bytes(8, 8, 8), timers(), now);
    runner.launched(Ok(()));
    while runner.next_message(&mut []).is_some() {}
    assert_eq!(runner.credit(EARLIER, Pool::Stdout, 8), Ok(Receipt::Stale));
    assert_eq!(runner.input(EARLIER, b"stale"), Ok(Receipt::Stale));
    assert_eq!(runner.end_input(EARLIER), Ok(Receipt::Stale));
    assert_eq!(
        runner.cancel(now, EARLIER, Cause::Cancelled),
        Ok(Receipt::Stale)
    );
    // No credit arrived, so the output waits; no input arrived; nothing ends the workload.
    runner.output(Stream::Stdout, b"out");
    assert_eq!(runner.next_message(&mut [0; 8]), None);
    assert_eq!(runner.pending_input(), b"");
    assert_eq!(runner.next_request(), None);
    assert_eq!(runner.input(KEY, b"12345678"), Ok(Receipt::Applied));

    let mut peer = Peer::new(KEY, bytes(8, 8, 8), timers(), now);
    while peer.next_message(&mut []).is_some() {}
    assert_eq!(peer.credit(EARLIER, 8), Ok(Receipt::Stale));
    assert_eq!(peer.started(EARLIER), Ok(Receipt::Stale));
    assert_eq!(
        peer.output(EARLIER, Stream::Stdout, b"stale"),
        Ok(Receipt::Stale)
    );
    assert_eq!(peer.end_output(EARLIER, Stream::Stdout), Ok(Receipt::Stale));
    assert_eq!(peer.input_closed(EARLIER), Ok(Receipt::Stale));
    let outcome = Outcome::new(Some(Status::Exited(0)));
    assert_eq!(peer.terminal(now, EARLIER, outcome), Ok(Receipt::Stale));
    assert_eq!(peer.pending_output(Stream::Stdout), b"");
    assert_eq!(peer.next_event(), None);
    assert!(!peer.has_started());
    assert_eq!(peer.input(b"in"), 2);
    assert_eq!(peer.next_message(&mut [0; 8]), None);
    // The window of the current generation is whole.
    assert_eq!(
        peer.output(KEY, Stream::Stdout, b"12345678"),
        Ok(Receipt::Applied)
    );
}

#[test]
fn messages_of_another_execution_or_a_later_generation_are_refused() {
    let now = Instant::now();
    let mut runner = Runner::new(KEY, bytes(8, 8, 8), timers(), now);
    let mut peer = Peer::new(KEY, bytes(8, 8, 8), timers(), now);
    for key in [LATER, OTHER] {
        assert_eq!(runner.credit(key, Pool::Stdout, 1), Err(Violation::Key));
        assert_eq!(runner.input(key, b"x"), Err(Violation::Key));
        assert_eq!(runner.end_input(key), Err(Violation::Key));
        assert_eq!(
            runner.cancel(now, key, Cause::Cancelled),
            Err(Violation::Key)
        );
        assert_eq!(peer.credit(key, 1), Err(Violation::Key));
        assert_eq!(peer.started(key), Err(Violation::Key));
        assert_eq!(peer.output(key, Stream::Stdout, b"x"), Err(Violation::Key));
        assert_eq!(peer.end_output(key, Stream::Stdout), Err(Violation::Key));
        assert_eq!(peer.input_closed(key), Err(Violation::Key));
        assert_eq!(
            peer.terminal(now, key, Outcome::new(None)),
            Err(Violation::Key)
        );
    }
    assert_eq!(runner.next_request(), None);
    assert!(!peer.has_started());
}

#[test]
fn messages_after_the_execution_ended_are_late() {
    let mut pair = Pair::new(
        bytes(64, 64, 64),
        timers(),
        Workload::new(100, 0),
        Client::new(),
    );
    pair.finish();
    let now = pair.now;
    let runner = &mut pair.runner;
    assert_eq!(runner.credit(KEY, Pool::Stdout, 1), Ok(Receipt::Late));
    assert_eq!(runner.input(KEY, b"late"), Ok(Receipt::Late));
    assert_eq!(runner.end_input(KEY), Ok(Receipt::Late));
    assert_eq!(runner.cancel(now, KEY, Cause::Cancelled), Ok(Receipt::Late));
    // A stale message stays stale, and a foreign one refused.
    assert_eq!(runner.credit(EARLIER, Pool::Stdout, 1), Ok(Receipt::Stale));
    assert_eq!(runner.credit(OTHER, Pool::Stdout, 1), Err(Violation::Key));
    assert_eq!(runner.next_message(&mut [0; 64]), None);
    assert_eq!(runner.next_request(), None);
    assert_eq!(runner.deadline(), None);

    let peer = &mut pair.peer;
    assert_eq!(peer.credit(KEY, 1), Ok(Receipt::Late));
    assert_eq!(peer.started(KEY), Ok(Receipt::Late));
    assert_eq!(peer.output(KEY, Stream::Stdout, b"late"), Ok(Receipt::Late));
    assert_eq!(peer.end_output(KEY, Stream::Stdout), Ok(Receipt::Late));
    assert_eq!(peer.input_closed(KEY), Ok(Receipt::Late));
    assert_eq!(
        peer.terminal(now, KEY, Outcome::new(None)),
        Ok(Receipt::Late)
    );
    assert_eq!(peer.next_message(&mut [0; 64]), None);
    assert_eq!(peer.next_event(), None);
    assert_eq!(peer.deadline(), None);
}

#[test]
fn a_cancellation_after_a_termination_began_is_late() {
    let now = Instant::now();
    let mut runner = Runner::new(KEY, bytes(8, 8, 8), timers(), now);
    runner.launched(Ok(()));
    assert_eq!(
        runner.cancel(now, KEY, Cause::TimedOut),
        Ok(Receipt::Applied)
    );
    assert_eq!(runner.cancel(now, KEY, Cause::Cancelled), Ok(Receipt::Late));
    assert_eq!(
        runner.next_request(),
        Some(runner::Request::Terminate(Cause::TimedOut))
    );
    assert_eq!(runner.next_request(), None);
}
