//! Liveness: a stalled sink, an exhausted window, or a full transport holds back only the bytes
//! that wait on it. Cancellations, timeouts, resets, and drops still end the execution by their
//! deadlines, and another execution keeps streaming meanwhile. Credit that frees up before every
//! message takes turns with each side's other messages, which still go out, and a stream's end
//! goes out while the other stream's output keeps flowing.

use super::*;

/// The limits of these executions.
fn limits() -> Limits {
    bytes(4096, 4096, 16 * 1024)
}

/// Returns an execution whose workload writes a mebibyte to each stream to a sink that takes
/// nothing.
fn stalled() -> Pair {
    let mut client = Client::new();
    client.rates = [0, 0];
    Pair::new(limits(), timers(), Workload::new(1 << 20, 1 << 20), client)
}

/// Returns an execution whose workload streams `length` bytes of standard output to a sink that
/// takes 8 KiB in each step.
fn streaming(length: usize) -> Pair {
    let mut client = Client::new();
    client.rates = [8 * 1024, 8 * 1024];
    Pair::new(limits(), timers(), Workload::new(length, 0), client)
}

/// Steps `first` and `second` in turns, `count` times, as one adapter's loop drives both.
fn step_both(first: &mut Pair, second: &mut Pair, count: usize) {
    for _ in 0..count {
        first.step();
        second.step();
    }
}

/// Moves both executions' clocks to `now`.
fn set_clock(first: &mut Pair, second: &mut Pair, now: Instant) {
    first.now = now;
    second.now = now;
}

/// Asserts that `pair`'s execution is stalled: the runner reads nothing, the workload still
/// runs, the sink took nothing, and the peer holds no more than its windows.
fn assert_stalled(pair: &Pair) {
    for stream in Stream::ALL {
        assert_eq!(pair.runner.read_allowance(stream), 0);
    }
    assert!(pair.workload.status.is_none());
    assert!(pair.peer.buffered() <= 2 * 16 * 1024);
    assert_eq!(pair.client.received, [0, 0]);
}

#[test]
fn a_stalled_sink_with_an_exhausted_window_stalls_only_its_own_execution() {
    let mut stalled = stalled();
    let mut other = streaming(8 << 20);
    for _ in 0..STEPS {
        if other.peer.is_finished() {
            break;
        }
        step_both(&mut stalled, &mut other, 1);
    }
    let outcome = other
        .client
        .outcome()
        .expect("the other execution finished");
    assert_eq!(other.client.received, [8 << 20, 0]);
    assert!(!outcome.is_truncated(Stream::Stdout));
    // The stalled execution waits for its sink, with no timer that would end it.
    assert_stalled(&stalled);
    assert!(!stalled.runner.is_finished() && !stalled.peer.is_finished());
    assert_eq!(stalled.runner.deadline(), None);
    assert_eq!(stalled.peer.deadline(), None);
}

/// How a liveness check ends the stalled execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ending {
    /// The peer's caller cancels it.
    Cancel,
    /// The runner's timeout passes.
    Timeout,
    /// The session is reset.
    Reset,
    /// The peer's caller drops its handle.
    Drop,
}

#[test]
fn endings_finish_by_their_deadlines_while_a_sink_is_stalled_and_another_execution_streams() {
    const TIMEOUT: Duration = Duration::from_secs(30);
    for ending in [Ending::Cancel, Ending::Timeout, Ending::Reset, Ending::Drop] {
        let mut stalled = stalled();
        if ending == Ending::Timeout {
            stalled.runner = Runner::new(KEY, limits(), timers().timeout(TIMEOUT), stalled.now);
        }
        let mut other = streaming(8 << 20);
        let start = stalled.now;
        other.now = start;
        step_both(&mut stalled, &mut other, 50);
        assert_stalled(&stalled);
        let ended = match ending {
            Ending::Timeout => start + TIMEOUT,
            _ => start + Duration::from_secs(1),
        };
        set_clock(&mut stalled, &mut other, ended);
        match ending {
            Ending::Cancel => stalled.peer.cancel(ended),
            Ending::Timeout => {}
            Ending::Reset => {
                stalled.runner.reset(ended);
                stalled.peer.reset(ended);
            }
            Ending::Drop => stalled.peer.dropped(ended),
        }
        let streamed = other.client.received[0];
        step_both(&mut stalled, &mut other, 50);
        // The workload ended at once, whatever its streams, and the other execution streamed on.
        assert_eq!(
            stalled.workload.status,
            Some(Status::Signaled(9)),
            "{ending:?}"
        );
        assert!(other.client.received[0] > streamed, "{ending:?}");
        // A cancellation and a timeout leave the pending output its grace, as the deadline shows.
        // A reset leaves no peer and a drop no sink to wait for, so their output goes at once.
        if matches!(ending, Ending::Cancel | Ending::Timeout) {
            assert!(!stalled.runner.is_finished(), "{ending:?}");
            assert_eq!(stalled.runner.deadline(), Some(ended + GRACE), "{ending:?}");
        }
        set_clock(&mut stalled, &mut other, ended + GRACE);
        let streamed = other.client.received[0];
        step_both(&mut stalled, &mut other, 10);
        assert!(stalled.runner.is_finished(), "{ending:?}");
        // The peer learns of the runner's timeout only from the terminal outcome, which leaves
        // its own sink a grace of its own.
        if ending == Ending::Timeout {
            assert!(!stalled.peer.is_finished());
            assert_eq!(stalled.peer.deadline(), Some(ended + GRACE + GRACE));
            set_clock(&mut stalled, &mut other, ended + GRACE + GRACE);
            step_both(&mut stalled, &mut other, 10);
        }
        assert!(stalled.peer.is_finished(), "{ending:?}");
        assert!(other.client.received[0] > streamed, "{ending:?}");
        let cause = match ending {
            Ending::Cancel => Cause::Cancelled,
            Ending::Timeout => Cause::TimedOut,
            Ending::Reset => Cause::Reset,
            Ending::Drop => Cause::Dropped,
        };
        let terminal = stalled.terminal();
        assert_eq!(terminal.cause(), Some(cause), "{ending:?}");
        assert_eq!(terminal.status(), Some(Status::Signaled(9)), "{ending:?}");
        assert!(terminal.is_reusable(), "{ending:?}");
        // A dropping peer takes and drops everything at once, so the runner discards nothing.
        assert_eq!(
            terminal.is_truncated(Stream::Stdout),
            ending != Ending::Drop,
            "{ending:?}"
        );
        let outcome = stalled.client.outcome().unwrap();
        assert_eq!(outcome.cause(), Some(cause), "{ending:?}");
        assert!(outcome.is_truncated(Stream::Stdout), "{ending:?}");
        // The peer knows the runner's settlement unless the reset kept it from hearing.
        assert_eq!(outcome.is_reusable(), ending != Ending::Reset, "{ending:?}");
        // The other execution still finishes whole.
        other.finish();
        assert_eq!(other.client.received, [8 << 20, 0]);
        assert!(!other.client.outcome().unwrap().is_truncated(Stream::Stdout));
    }
}

#[test]
fn a_full_transport_holds_back_only_the_messages_that_wait_for_it() {
    // The transport drains within the grace after the cancellation, or once the settlement time
    // after the grace has passed too: the runner's outcome tells how the execution's cleanup
    // went, however long the transport held it.
    for held in [GRACE, GRACE + SETTLEMENT] {
        let mut blocked = Pair::new(limits(), timers(), Workload::new(1 << 20, 0), Client::new());
        let mut other = streaming(8 << 20);
        // The transport from the runner to the peer stops carrying messages, and fills before
        // the credit runs out.
        blocked.delivers_to_peer = false;
        blocked.capacity = 3;
        step_both(&mut blocked, &mut other, 50);
        assert_eq!(blocked.to_peer.len(), 3);
        assert_eq!(blocked.runner.read_allowance(Stream::Stdout), 0);
        assert!(blocked.workload.status.is_none());
        let cancelled = blocked.now;
        blocked.peer.cancel(cancelled);
        let streamed = other.client.received[0];
        step_both(&mut blocked, &mut other, 50);
        // The cancellation went the other way, and the runner ended the workload and settled
        // it, though it could send nothing.
        assert_eq!(blocked.workload.status, Some(Status::Signaled(9)));
        assert!(blocked.workload.requests.contains(&runner::Request::Settle));
        assert!(other.client.received[0] > streamed);
        set_clock(&mut blocked, &mut other, cancelled + GRACE);
        step_both(&mut blocked, &mut other, 10);
        assert!(
            blocked
                .workload
                .requests
                .contains(&runner::Request::Discard(Stream::Stdout))
        );
        // The execution's cleanup is complete, so the runner has no timer left: only the
        // transport holds its last messages.
        assert_eq!(blocked.workload.closed, [true, true]);
        assert_eq!(blocked.runner.deadline(), None);
        set_clock(&mut blocked, &mut other, cancelled + held);
        step_both(&mut blocked, &mut other, 10);
        // Once the transport drains, the runner sends no stale output: only both ends and the
        // terminal outcome follow what the transport held.
        let sent = blocked.sent_by_runner.len();
        blocked.delivers_to_peer = true;
        blocked.capacity = usize::MAX;
        blocked.finish();
        let after = &blocked.sent_by_runner[sent..];
        assert!(
            after.iter().all(|message| matches!(
                message,
                runner::Message::End(_) | runner::Message::Terminal(_)
            )),
            "{after:?}"
        );
        let terminal = blocked.terminal();
        assert_eq!(terminal.cause(), Some(Cause::Cancelled), "{held:?}");
        assert!(terminal.is_truncated(Stream::Stdout), "{held:?}");
        assert!(terminal.is_reusable(), "{held:?}");
        // The peer takes the terminal outcome while it waits for it; once it gave up on it, its
        // own outcome stands, fenced.
        let outcome = blocked.client.outcome().unwrap();
        assert_eq!(outcome.cause(), Some(Cause::Cancelled), "{held:?}");
        assert!(outcome.is_truncated(Stream::Stdout), "{held:?}");
        assert_eq!(outcome.is_reusable(), held == GRACE, "{held:?}");
        other.finish();
        assert_eq!(other.client.received, [8 << 20, 0]);
    }
}

#[test]
fn input_credit_takes_turns_with_the_runner_s_other_messages() {
    // An adapter takes one message of the runner at a time, and before each, hands it the
    // workload's output as far as it reads ahead, and all the input that the peer's credit
    // allows, which the workload takes at once: credit of the input frees up before every
    // message.
    let mut runner = Runner::new(KEY, bytes(4, 4, 16), timers(), Instant::now());
    runner.launched(Ok(()));
    runner
        .credit(KEY, Pool::Stdout, 16)
        .expect("the runner takes the peer's grant");
    runner.output_closed(Stream::Stderr);
    let output = b"abcdefgh";
    let mut read = 0;
    let mut buffer = [0; 4];
    let mut credit = 0;
    let mut written = 0;
    let mut others = Vec::new();
    for _ in 0..16 {
        if read < output.len() {
            let length = runner
                .read_allowance(Stream::Stdout)
                .min(output.len() - read);
            read += runner.output(Stream::Stdout, &output[read..read + length]);
            if read == output.len() {
                runner.output_closed(Stream::Stdout);
            }
        }
        if credit > 0 {
            let input = vec![b'i'; credit];
            deliver_to_runner(&mut runner, Instant::now(), ToRunner::Input(input));
            runner.input_written(credit);
            written += credit;
            credit = 0;
        }
        match runner
            .next_message(&mut buffer)
            .map(|message| to_peer(message, &buffer))
        {
            Some(ToPeer::Credit(units)) => credit += units as usize,
            Some(message) => others.push(message),
            None => break,
        }
    }
    // The workload's start, the end of standard error, which closed with no byte, the output,
    // and the end of standard output went out, in turns with the credit, which kept the input
    // flowing.
    assert_eq!(
        others,
        [
            ToPeer::Started,
            ToPeer::End(Stream::Stderr),
            ToPeer::Output(Stream::Stdout, b"abcd".to_vec()),
            ToPeer::Output(Stream::Stdout, b"efgh".to_vec()),
            ToPeer::End(Stream::Stdout),
        ]
    );
    assert!(written >= 4 * 4, "{written}");
}

#[test]
fn a_stream_s_end_goes_out_while_the_other_stream_s_output_keeps_flowing() {
    // An adapter takes one message of the runner at a time, and before each, hands it as much of
    // one stream's output as it reads ahead, while the peer's sink takes each output message at
    // once and grants its credit back: that stream always has bytes and credit. The other stream
    // closed at once, with no byte.
    for flowing in Stream::ALL {
        let (closed, pool) = match flowing {
            Stream::Stdout => (Stream::Stderr, Pool::Stdout),
            Stream::Stderr => (Stream::Stdout, Pool::Stderr),
        };
        let now = Instant::now();
        let mut runner = Runner::new(KEY, bytes(4, 4, 16), timers(), now);
        runner.launched(Ok(()));
        deliver_to_runner(&mut runner, now, ToRunner::Credit(pool, 16));
        runner.output_closed(closed);
        let mut buffer = [0; 4];
        let mut others = Vec::new();
        for _ in 0..16 {
            let length = runner.read_allowance(flowing);
            assert_eq!(runner.output(flowing, &vec![b'x'; length]), length);
            let message = runner.next_message(&mut buffer).expect("output waits");
            match to_peer(message, &buffer) {
                ToPeer::Credit(_) => {}
                message => {
                    if let ToPeer::Output(_, bytes) = &message {
                        let units = u32::try_from(bytes.len()).unwrap();
                        deliver_to_runner(&mut runner, now, ToRunner::Credit(pool, units));
                    }
                    others.push(message);
                }
            }
        }
        // The closed stream's end went out right after the start, and the other stream's output
        // flowed on, a full chunk in each message.
        assert_eq!(
            others[..2],
            [ToPeer::Started, ToPeer::End(closed)],
            "{flowing:?}"
        );
        assert!(others.len() > 10, "{flowing:?}: {others:?}");
        assert!(
            others[2..]
                .iter()
                .all(|message| *message == ToPeer::Output(flowing, b"xxxx".to_vec())),
            "{flowing:?}: {others:?}"
        );
    }
}

#[test]
fn output_credit_takes_turns_with_the_peer_s_input_and_its_other_pool() {
    // An adapter takes one message of the peer at a time, and before each, its source hands over
    // as much input as the peer takes, and the runner sends a byte of standard output, which the
    // sink takes at once: that pool's credit frees up before every message.
    let mut peer = Peer::new(KEY, bytes(4, 16, 4), timers(), Instant::now());
    let mut buffer = [0; 4];
    while peer.next_message(&mut buffer).is_some() {}
    peer.credit(KEY, 16)
        .expect("the peer takes the runner's grant");
    peer.output(KEY, Stream::Stderr, b"zz")
        .expect("the peer takes standard error within its window");
    peer.consumed(Stream::Stderr, 2);
    let input = b"0123456789abcdef";
    let mut handed = 0;
    let mut sent = Vec::new();
    for _ in 0..16 {
        if handed < input.len() {
            handed += peer.input(&input[handed..]);
            if handed == input.len() {
                peer.end_input();
            }
        }
        peer.output(KEY, Stream::Stdout, b"x")
            .expect("the peer's credit keeps the runner's window open");
        peer.consumed(Stream::Stdout, 1);
        let message = peer.next_message(&mut buffer).expect("credit waits");
        sent.push(to_runner(message, &buffer));
    }
    // The input, its end, and the credit of standard error went out, in turns with the credit
    // of standard output.
    let others = sent
        .iter()
        .filter(|message| !matches!(message, ToRunner::Credit(Pool::Stdout, _)))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        others,
        [
            ToRunner::Input(b"0123".to_vec()),
            ToRunner::Credit(Pool::Stderr, 2),
            ToRunner::Input(b"4567".to_vec()),
            ToRunner::Input(b"89ab".to_vec()),
            ToRunner::Input(b"cdef".to_vec()),
            ToRunner::InputEnd,
        ]
    );
}
