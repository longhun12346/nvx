//! The abnormal paths and the normal one: a termination's grace and the truncation that follows
//! it, lossless normal completion, failed reads, failed and late settlements, the streams that an
//! execution that does not settle leaves open, and those that hung up, launch results that a
//! process holds back after the workload's end, and sides that give up and fence the execution.

use super::*;

/// Returns whether `outcome` marks either stream as truncated.
fn truncated(outcome: Outcome) -> bool {
    Stream::ALL
        .into_iter()
        .any(|stream| outcome.is_truncated(stream))
}

#[test]
fn a_workload_that_ends_on_its_own_loses_no_byte_however_slow_the_sink() {
    let mut client = Client::new();
    client.rates = [100, 37];
    let mut pair = Pair::new(
        bytes(1024, 1024, 4096),
        timers(),
        Workload::new(100_000, 50_000),
        client,
    );
    // Each step takes longer than the grace and the settlement time together.
    for _ in 0..STEPS {
        if pair.peer.is_finished() {
            break;
        }
        pair.advance(GRACE + SETTLEMENT);
        pair.step();
        // The runner's terminal outcome waits for the output that the sink has yet to take,
        // beyond what its windows hold.
        if pair.runner.is_finished() {
            assert!(pair.client.received[0] + 4096 >= 100_000);
            assert!(pair.client.received[1] + 4096 >= 50_000);
        }
    }
    let outcome = pair.client.outcome().unwrap();
    assert_eq!(pair.client.received, [100_000, 50_000]);
    assert_eq!(outcome, pair.terminal());
    assert_eq!(outcome.cause(), None);
    assert!(!truncated(outcome));
    assert!(outcome.is_reusable());
}

#[test]
fn a_termination_drains_pending_output_for_its_grace_then_marks_the_loss() {
    let mut client = Client::new();
    client.rates = [0, 0];
    let mut pair = Pair::new(
        bytes(4096, 4096, 16 * 1024),
        timers(),
        Workload::new(1 << 20, 100),
        client,
    );
    // The stalled sink exhausts both windows, and the workload blocks on its full pipe.
    pair.steps(20);
    assert_eq!(pair.runner.read_allowance(Stream::Stdout), 0);
    assert!(pair.workload.status.is_none());
    let cancelled = pair.now;
    pair.peer.cancel(cancelled);
    pair.steps(20);
    assert!(
        pair.workload.status.is_some(),
        "the cancellation ended the workload"
    );
    assert!(!pair.runner.is_finished() && !pair.peer.is_finished());
    pair.advance(GRACE);
    pair.steps(5);
    assert!(pair.runner.is_finished() && pair.peer.is_finished());
    let terminal = pair.terminal();
    assert_eq!(terminal.cause(), Some(Cause::Cancelled));
    assert_eq!(terminal.status(), Some(Status::Signaled(9)));
    assert!(terminal.is_truncated(Stream::Stdout));
    // Standard error's 100 bytes were in flight within its window, and the peer discarded them.
    assert!(!terminal.is_truncated(Stream::Stderr));
    let outcome = pair.client.outcome().unwrap();
    assert!(outcome.is_truncated(Stream::Stdout) && outcome.is_truncated(Stream::Stderr));
    assert_eq!(outcome.cause(), Some(Cause::Cancelled));
    assert!(outcome.is_reusable());
    assert!(
        pair.workload
            .requests
            .contains(&runner::Request::Discard(Stream::Stdout))
    );
    assert!(pair.workload.discarded[0] > 0);
}

#[test]
fn a_termination_whose_pending_output_drains_within_the_grace_loses_nothing() {
    let mut client = Client::new();
    client.rates = [0, 0];
    let mut pair = Pair::new(
        bytes(4096, 4096, 16 * 1024),
        timers(),
        Workload::new(1 << 20, 0),
        client,
    );
    pair.steps(20);
    pair.peer.cancel(pair.now);
    // The sink takes everything again within the grace: what the workload wrote before its end
    // all arrives, though the cancellation cut the workload short.
    pair.client.rates = [usize::MAX, usize::MAX];
    pair.finish();
    let outcome = pair.client.outcome().unwrap();
    assert_eq!(outcome.cause(), Some(Cause::Cancelled));
    assert!(!truncated(outcome), "{outcome:?}");
    assert_eq!(pair.client.received[0], pair.workload.written[0]);
    assert!(pair.workload.written[0] < 1 << 20);
}

#[test]
fn a_failed_read_truncates_its_stream_without_a_cause() {
    let now = Instant::now();
    let mut runner = Runner::new(KEY, bytes(8, 8, 8), timers(), now);
    runner.launched(Ok(()));
    runner.output_failed(Stream::Stdout);
    runner.output_closed(Stream::Stderr);
    runner.exited(now, Some(Status::Exited(0)));
    runner.settled(Settlement::Settled);
    let messages = std::iter::from_fn(|| runner.next_message(&mut [0; 8])).collect::<Vec<_>>();
    let Some(runner::Message::Terminal(outcome)) = messages.last() else {
        panic!("{messages:?}");
    };
    assert_eq!(outcome.cause(), None);
    assert!(outcome.is_truncated(Stream::Stdout));
    assert!(!outcome.is_truncated(Stream::Stderr));
    assert_eq!(runner.read_allowance(Stream::Stdout), 0);
}

#[test]
fn a_failed_or_late_settlement_fences_the_execution() {
    for settlement in [Some(Settlement::Failed), None] {
        let mut workload = Workload::new(10, 0);
        workload.settlement = settlement;
        let mut pair = Pair::new(bytes(64, 64, 64), timers(), workload, Client::new());
        pair.run_until(|pair| pair.workload.requests.contains(&runner::Request::Settle));
        pair.steps(3);
        if settlement.is_none() {
            // The runner waits for the settlement for its settlement time.
            assert!(!pair.runner.is_finished());
            assert!(pair.runner.awaits_settlement());
            assert!(pair.runner.deadline().is_some());
            pair.advance(SETTLEMENT);
        }
        let outcome = pair.finish();
        assert!(!pair.runner.awaits_settlement(), "{settlement:?}");
        assert!(!outcome.is_reusable(), "{settlement:?}");
        assert_eq!(outcome.status(), Some(Status::Exited(0)));
        assert!(!truncated(outcome));
        // A result after the settlement time changes nothing.
        pair.runner.settled(Settlement::Settled);
        assert!(!pair.terminal().is_reusable());
    }
}

#[test]
fn an_execution_that_does_not_settle_gives_up_on_the_streams_still_open_after_its_end() {
    // A process that the workload left behind holds standard output open, and the settlement
    // fails, or never comes. The runner leaves the stream the settlement time and then the
    // grace after the workload's end to close, then gives up on it: it sends what it read, and
    // marks only that stream truncated.
    for settlement in [Some(Settlement::Failed), None] {
        let mut workload = Workload::new(10_000, 100);
        workload.held = [true, false];
        workload.settlement = settlement;
        let mut pair = Pair::new(bytes(1024, 1024, 4096), timers(), workload, Client::new());
        pair.run_until(|pair| pair.workload.reported);
        let exited = pair.now;
        pair.run_until(|pair| {
            pair.client.received == [10_000, 100]
                && pair
                    .client
                    .events
                    .contains(&peer::Event::End(Stream::Stderr))
        });
        pair.steps(5);
        assert!(!pair.runner.is_finished(), "{settlement:?}");
        assert!(
            !pair
                .client
                .events
                .contains(&peer::Event::End(Stream::Stdout))
        );
        if settlement.is_none() {
            assert!(pair.runner.awaits_settlement());
            assert_eq!(pair.runner.deadline(), Some(exited + SETTLEMENT));
            pair.advance(SETTLEMENT);
            pair.steps(5);
            assert!(!pair.runner.awaits_settlement());
            assert!(!pair.runner.is_finished());
        }
        assert_eq!(
            pair.runner.deadline(),
            Some(exited + SETTLEMENT + GRACE),
            "{settlement:?}"
        );
        pair.now = exited + SETTLEMENT + GRACE - Duration::from_millis(1);
        pair.steps(5);
        assert!(!pair.runner.is_finished(), "{settlement:?}");
        pair.now = exited + SETTLEMENT + GRACE;
        let outcome = pair.finish();
        assert_eq!(outcome, pair.terminal());
        assert_eq!(outcome.status(), Some(Status::Exited(0)));
        assert_eq!(outcome.cause(), None);
        assert!(outcome.is_truncated(Stream::Stdout));
        assert!(!outcome.is_truncated(Stream::Stderr));
        assert!(!outcome.is_reusable());
        assert_eq!(pair.client.received, [10_000, 100]);
        assert_eq!(pair.runner.read_allowance(Stream::Stdout), 0);
        assert!(
            pair.sent_by_runner
                .contains(&runner::Message::End(Stream::Stdout))
        );
    }
}

#[test]
fn an_execution_that_does_not_settle_loses_nothing_of_the_streams_that_hung_up() {
    // No process holds the streams once the workload ended, but the settlement fails, or never
    // comes, and the sink takes nothing for long after the settlement time and the grace. The
    // streams hung up, so the runner never gives up on them: it waits for the sink, and loses
    // nothing, though the execution is fenced.
    for settlement in [Some(Settlement::Failed), None] {
        let mut workload = Workload::new(10_000, 5_000);
        workload.settlement = settlement;
        let mut client = Client::new();
        client.rates = [0, 0];
        let mut pair = Pair::new(bytes(1024, 1024, 4096), timers(), workload, client);
        pair.run_until(|pair| pair.workload.reported);
        pair.steps(5);
        pair.advance((SETTLEMENT + GRACE) * 10);
        pair.steps(5);
        assert!(!pair.runner.is_finished(), "{settlement:?}");
        assert_eq!(pair.runner.deadline(), None, "{settlement:?}");
        pair.client.rates = [usize::MAX, usize::MAX];
        let outcome = pair.finish();
        assert_eq!(pair.client.received, [10_000, 5_000], "{settlement:?}");
        assert_eq!(outcome.status(), Some(Status::Exited(0)));
        assert_eq!(outcome.cause(), None);
        assert!(!truncated(outcome), "{settlement:?}");
        assert!(!outcome.is_reusable(), "{settlement:?}");
    }
}

#[test]
fn a_settled_execution_waits_for_its_sink_however_long_its_streams_stay_open() {
    // The settlement ends the process that held standard output, and the stalled sink takes the
    // rest long after the settlement time and the grace: nothing is lost.
    let mut workload = Workload::new(10_000, 0);
    workload.held = [true, false];
    let mut client = Client::new();
    client.rates = [0, 0];
    let mut pair = Pair::new(bytes(1024, 1024, 4096), timers(), workload, client);
    pair.run_until(|pair| pair.workload.reported);
    pair.steps(5);
    assert!(!pair.runner.awaits_settlement());
    assert_eq!(pair.runner.deadline(), None);
    pair.advance((SETTLEMENT + GRACE) * 10);
    pair.steps(5);
    assert!(!pair.runner.is_finished());
    pair.client.rates = [usize::MAX, usize::MAX];
    let outcome = pair.finish();
    assert_eq!(pair.client.received, [10_000, 0]);
    assert!(!truncated(outcome));
    assert!(outcome.is_reusable());
}

#[test]
fn the_runner_gives_up_on_a_launch_result_that_a_process_holds_back_after_the_workload_s_end() {
    // A process holds back what reports the workload's launch, whether the execution settles,
    // its settlement fails, or never comes, and only the runner has a timeout, which the
    // workload's end disarmed before it passed. The runner leaves the launch result the
    // settlement time and then the grace after the workload's end to arrive, holding the start
    // and the output meanwhile, then gives up on it: it sends the output, which the streams that
    // hung up keep whole, and the outcome, without a start, with the workload's status and no
    // cause, and fences the execution. The result arrives once the runner sent output and an
    // end, but before the terminal outcome, and counts for nothing, so no start follows them.
    const TIMEOUT: Duration = Duration::from_secs(2);
    let limits = bytes(64, 64, 64);
    for settlement in [Some(Settlement::Settled), Some(Settlement::Failed), None] {
        let mut workload = Workload::new(100, 10);
        workload.launch_held = true;
        workload.settlement = settlement;
        let mut pair = Pair::new(limits, timers(), workload, Client::new());
        pair.runner = Runner::new(KEY, limits, timers().timeout(TIMEOUT), pair.now);
        pair.run_until(|pair| pair.workload.reported);
        let exited = pair.now;
        pair.steps(5);
        let held = |pair: &Pair| {
            !pair.runner.is_finished()
                && !pair.sent_by_runner.iter().any(|message| {
                    matches!(
                        message,
                        runner::Message::Started
                            | runner::Message::Output { .. }
                            | runner::Message::End(_)
                    )
                })
        };
        assert!(held(&pair), "{settlement:?}");
        if settlement.is_none() {
            assert_eq!(pair.runner.deadline(), Some(exited + SETTLEMENT));
            pair.advance(SETTLEMENT);
            pair.steps(5);
            assert!(!pair.runner.awaits_settlement());
            assert!(held(&pair));
        }
        assert_eq!(
            pair.runner.deadline(),
            Some(exited + SETTLEMENT + GRACE),
            "{settlement:?}"
        );
        pair.now = exited + SETTLEMENT + GRACE - Duration::from_millis(1);
        pair.steps(5);
        assert!(held(&pair), "{settlement:?}");
        pair.now = exited + SETTLEMENT + GRACE;
        pair.run_until(|pair| !held(pair));
        assert!(!pair.runner.is_finished(), "{settlement:?}");
        pair.workload.launch_held = false;
        let outcome = pair.finish();
        assert!(pair.workload.launched);
        assert_eq!(outcome, pair.terminal());
        assert_eq!(outcome.status(), Some(Status::Exited(0)), "{settlement:?}");
        assert_eq!(outcome.cause(), None, "{settlement:?}");
        assert_eq!(outcome.launch_failure(), None);
        assert!(!truncated(outcome), "{settlement:?}");
        assert!(!outcome.is_reusable(), "{settlement:?}");
        assert_eq!(pair.client.received, [100, 10]);
        assert!(!pair.sent_by_runner.contains(&runner::Message::Started));
        assert!(!pair.peer.has_started());
        // A launch result after the terminal outcome changes nothing.
        pair.runner.launched(Ok(()));
        assert_eq!(pair.runner.next_message(&mut []), None);
    }
}

#[test]
fn a_launch_result_after_a_termination_s_give_up_counts_for_nothing() {
    // A cancellation ends a workload whose launch result never arrives, and which never ends, so
    // the runner gives up on it once the grace and the settlement time have passed. The result
    // arrives once the runner sent a stream's end, but before the terminal outcome, and counts
    // for nothing: no start follows the end.
    let now = Instant::now();
    let mut runner = Runner::new(KEY, bytes(8, 8, 8), timers(), now);
    assert_eq!(
        runner.cancel(now, KEY, Cause::Cancelled),
        Ok(Receipt::Applied)
    );
    runner.tick(now + GRACE + SETTLEMENT);
    let mut sent = Vec::new();
    while let Some(message) = runner.next_message(&mut [0; 8]) {
        sent.push(message);
        if matches!(message, runner::Message::End(_)) {
            break;
        }
    }
    assert!(
        matches!(sent.last(), Some(runner::Message::End(_))),
        "{sent:?}"
    );
    runner.launched(Ok(()));
    sent.extend(std::iter::from_fn(|| runner.next_message(&mut [0; 8])));
    assert!(!sent.contains(&runner::Message::Started), "{sent:?}");
    let Some(runner::Message::Terminal(outcome)) = sent.last() else {
        panic!("{sent:?}");
    };
    assert_eq!(outcome.cause(), Some(Cause::Cancelled));
    assert_eq!(outcome.launch_failure(), None);
    assert!(!outcome.is_reusable());
}

#[test]
fn a_launch_result_that_arrives_after_the_workload_s_end_but_in_time_still_counts() {
    // A process holds back what reports the workload's launch until just before the runner would
    // give up on it: the runner sends the start first, the outcome is lossless, and the execution
    // is reusable.
    let mut workload = Workload::new(100, 10);
    workload.launch_held = true;
    let mut pair = Pair::new(bytes(64, 64, 64), timers(), workload, Client::new());
    pair.run_until(|pair| pair.workload.reported);
    pair.now += SETTLEMENT + GRACE - Duration::from_millis(1);
    pair.steps(5);
    assert!(!pair.runner.is_finished());
    assert!(!pair.sent_by_runner.contains(&runner::Message::Started));
    pair.workload.launch_held = false;
    let outcome = pair.finish();
    assert_eq!(outcome, pair.terminal());
    assert_eq!(outcome.status(), Some(Status::Exited(0)));
    assert_eq!(outcome.cause(), None);
    assert!(!truncated(outcome));
    assert!(outcome.is_reusable());
    assert_eq!(pair.client.received, [100, 10]);
    let started = pair
        .sent_by_runner
        .iter()
        .position(|message| *message == runner::Message::Started)
        .expect("the runner sent the start");
    assert!(
        pair.sent_by_runner[..started]
            .iter()
            .all(|message| matches!(
                message,
                runner::Message::Credit { .. } | runner::Message::InputClosed
            )),
        "{:?}",
        pair.sent_by_runner
    );
}

#[test]
fn a_settlement_that_the_runner_did_not_request_counts_for_nothing() {
    let now = Instant::now();
    let mut runner = Runner::new(KEY, bytes(8, 8, 8), timers(), now);
    runner.launched(Ok(()));
    runner.output_closed(Stream::Stdout);
    runner.output_closed(Stream::Stderr);
    // The workload still runs, so nothing settles it yet.
    runner.settled(Settlement::Settled);
    assert!(!runner.awaits_settlement());
    runner.exited(now, Some(Status::Exited(0)));
    assert!(runner.awaits_settlement());
    assert_eq!(runner.next_request(), Some(runner::Request::Settle));
    while let Some(message) = runner.next_message(&mut []) {
        assert!(
            !matches!(message, runner::Message::Terminal(_)),
            "{message:?}"
        );
    }
    runner.settled(Settlement::Failed);
    assert!(!runner.awaits_settlement());
    let Some(runner::Message::Terminal(outcome)) = runner.next_message(&mut []) else {
        panic!("the terminal outcome follows the settlement");
    };
    assert!(!outcome.is_reusable());
}

#[test]
fn the_runner_gives_up_on_a_workload_that_will_not_end_and_fences_it() {
    let mut workload = Workload::new(1 << 20, 0);
    workload.unkillable = true;
    let mut client = Client::new();
    client.rates = [0, 0];
    let mut pair = Pair::new(bytes(4096, 4096, 4096), timers(), workload, client);
    pair.steps(10);
    let cancelled = pair.now;
    pair.peer.cancel(cancelled);
    pair.steps(10);
    pair.advance(GRACE);
    pair.steps(10);
    // The workload still runs and holds its stream open, so the runner waits.
    assert!(!pair.runner.is_finished());
    assert_eq!(pair.runner.deadline(), Some(cancelled + GRACE + SETTLEMENT));
    pair.advance(SETTLEMENT);
    pair.steps(5);
    assert!(pair.runner.is_finished() && pair.peer.is_finished());
    let terminal = pair.terminal();
    assert_eq!(terminal.status(), None);
    assert_eq!(terminal.cause(), Some(Cause::Cancelled));
    assert!(terminal.is_truncated(Stream::Stdout));
    assert!(!terminal.is_reusable());
    // The runner still ended both streams before its terminal outcome.
    for stream in Stream::ALL {
        assert!(pair.sent_by_runner.contains(&runner::Message::End(stream)));
    }
    assert_eq!(pair.client.outcome(), Some(terminal));
    assert_eq!(pair.runner.read_allowance(Stream::Stdout), 0);
}

#[test]
fn a_peer_that_ended_the_execution_gives_up_on_a_silent_runner() {
    let mut pair = Pair::new(
        bytes(64, 64, 64),
        timers(),
        Workload::new(1 << 20, 0),
        Client::new(),
    );
    pair.steps(5);
    // The transport stops delivering the runner's messages.
    pair.delivers_to_peer = false;
    let cancelled = pair.now;
    pair.peer.cancel(cancelled);
    pair.steps(5);
    pair.advance(GRACE);
    pair.steps(5);
    assert!(!pair.peer.is_finished());
    assert_eq!(pair.peer.deadline(), Some(cancelled + GRACE + SETTLEMENT));
    pair.advance(SETTLEMENT);
    pair.steps(1);
    let outcome = pair.client.outcome().expect("the peer gave up");
    assert_eq!(outcome.status(), None);
    assert_eq!(outcome.cause(), Some(Cause::Cancelled));
    assert!(outcome.is_truncated(Stream::Stdout) && outcome.is_truncated(Stream::Stderr));
    assert!(!outcome.is_reusable());
}

#[test]
fn the_peer_s_own_timeout_cancels_and_names_itself() {
    let mut client = Client::new();
    client.rates = [0, 0];
    let mut pair = Pair::new(
        bytes(64, 64, 64),
        timers().timeout(Duration::from_secs(30)),
        Workload::new(1 << 20, 0),
        client,
    );
    // Only the peer's timer runs out: the runner's workload got the same timeout, but the
    // runner reports the peer's cause, which arrives first.
    pair.runner = Runner::new(KEY, bytes(64, 64, 64), timers(), pair.now);
    pair.steps(5);
    pair.advance(Duration::from_secs(30));
    pair.steps(5);
    let terminations = pair
        .workload
        .requests
        .iter()
        .filter(|request| matches!(request, runner::Request::Terminate(_)))
        .collect::<Vec<_>>();
    assert_eq!(terminations, [&runner::Request::Terminate(Cause::TimedOut)]);
    pair.advance(GRACE);
    let outcome = pair.finish();
    assert_eq!(outcome.cause(), Some(Cause::TimedOut));
    assert_eq!(pair.terminal().cause(), Some(Cause::TimedOut));
}
