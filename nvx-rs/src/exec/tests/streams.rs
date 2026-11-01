//! The order of each stream, the end of the input after every accepted byte, a workload that
//! closes its input early, and a launch that fails.

use super::*;

/// Returns the input bytes `0, 1, 2, ...` of `length` bytes.
fn counting(length: usize) -> Vec<u8> {
    (0..length).map(|index| index as u8).collect()
}

#[test]
fn each_stream_keeps_its_order_and_its_end_follows_its_last_byte() {
    let mut client = Client::new();
    client.rates = [700, 300];
    let mut pair = Pair::new(
        bytes(1000, 4096, 3000),
        timers(),
        Workload::new(10_000, 7_000),
        client,
    );
    let outcome = pair.finish();
    // The client checked every byte against the workload's pattern as it took it.
    assert_eq!(pair.client.received, [10_000, 7_000]);
    assert_eq!(outcome, pair.terminal());
    assert_eq!(outcome.status(), Some(Status::Exited(0)));
    assert_eq!(outcome.cause(), None);
    assert!(outcome.is_reusable());
    assert!(!outcome.is_truncated(Stream::Stdout) && !outcome.is_truncated(Stream::Stderr));

    let sent = &pair.sent_by_runner;
    let position = |wanted: runner::Message| sent.iter().position(|message| *message == wanted);
    let started = position(runner::Message::Started).unwrap();
    for stream in Stream::ALL {
        let end = position(runner::Message::End(stream)).unwrap();
        let outputs = sent
            .iter()
            .enumerate()
            .filter(|(_, message)| {
                matches!(message, runner::Message::Output { stream: of, .. } if *of == stream)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert!(outputs.iter().all(|&index| started < index && index < end));
    }
    assert!(matches!(sent.last(), Some(runner::Message::Terminal(_))));
    assert_eq!(
        sent.iter()
            .filter(|message| matches!(message, runner::Message::Terminal(_)))
            .count(),
        1
    );
    // The peer tells its caller in the same order.
    let events = &pair.client.events;
    assert_eq!(events.first(), Some(&peer::Event::Started));
    assert!(matches!(events.last(), Some(peer::Event::Finished(_))));
    for stream in Stream::ALL {
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == peer::Event::End(stream))
                .count(),
            1
        );
    }
}

#[test]
fn the_input_ends_only_after_every_accepted_byte() {
    let mut workload = Workload::new(0, 0);
    workload.reads_to_end = true;
    workload.input_rate = 3;
    let mut client = Client::new();
    client.input = counting(50);
    let mut pair = Pair::new(bytes(8, 16, 64), timers(), workload, client);
    let outcome = pair.finish();
    // The workload took every byte before its input closed, which ended the program.
    assert_eq!(pair.workload.input, counting(50));
    assert_eq!(
        pair.workload
            .requests
            .iter()
            .filter(|request| **request == runner::Request::CloseInput)
            .count(),
        1
    );
    assert!(pair.workload.input_end);
    // The peer ended the input, so the runner never said that it closed early.
    assert!(!pair.sent_by_runner.contains(&runner::Message::InputClosed));
    assert!(!pair.client.events.contains(&peer::Event::InputClosed));
    assert_eq!(outcome.status(), Some(Status::Exited(0)));
    assert!(outcome.is_reusable());
}

#[test]
fn a_workload_that_closes_its_input_early_never_leaves_the_source_waiting() {
    let mut workload = Workload::new(2_000, 0);
    workload.reads_to_end = true;
    workload.input_limit = Some(5);
    let mut client = Client::new();
    client.input = counting(100_000);
    let mut pair = Pair::new(bytes(512, 1024, 1024), timers(), workload, client);
    let outcome = pair.finish();
    assert_eq!(pair.workload.input, counting(5));
    assert!(pair.sent_by_runner.contains(&runner::Message::InputClosed));
    assert!(pair.client.events.contains(&peer::Event::InputClosed));
    // The source stopped once the input closed, short of its 100,000 bytes, and the output
    // still arrived whole.
    assert!(pair.client.sent < 100_000);
    assert_eq!(pair.peer.write_allowance(), 0);
    assert_eq!(pair.client.received, [2_000, 0]);
    assert_eq!(outcome.status(), Some(Status::Exited(0)));
    assert!(!outcome.is_truncated(Stream::Stdout));
    assert!(outcome.is_reusable());
}

#[test]
fn input_after_the_workload_s_input_closed_is_dropped_within_the_window() {
    let mut runner = Runner::new(KEY, bytes(4, 8, 8), timers(), Instant::now());
    runner.launched(Ok(()));
    while runner.next_message(&mut []).is_some() {}
    assert_eq!(runner.input(KEY, b"abcd"), Ok(Receipt::Applied));
    runner.input_closed();
    assert_eq!(runner.pending_input(), b"");
    assert_eq!(
        runner.next_message(&mut []),
        Some(runner::Message::InputClosed)
    );
    // The peer may still send what its credit allowed before it learned, and no more.
    assert_eq!(runner.input(KEY, b"efgh"), Ok(Receipt::Late));
    assert_eq!(runner.input(KEY, b"i"), Err(Violation::Window));
    assert_eq!(runner.end_input(KEY), Ok(Receipt::Late));
    assert_eq!(runner.end_input(KEY), Err(Violation::Ended));
    assert_eq!(runner.next_request(), None);
}

#[test]
fn closing_the_input_keeps_the_output_flowing() {
    let mut workload = Workload::new(50_000, 3_000);
    workload.reads_to_end = true;
    let mut client = Client::new();
    client.input = counting(10);
    client.rates = [1_000, 1_000];
    let mut pair = Pair::new(bytes(2048, 4096, 4096), timers(), workload, client);
    let outcome = pair.finish();
    assert_eq!(pair.workload.input, counting(10));
    assert_eq!(pair.client.received, [50_000, 3_000]);
    assert!(!outcome.is_truncated(Stream::Stdout));
}

#[test]
fn a_failed_launch_sends_no_start_and_reports_why() {
    let mut workload = Workload::new(0, 0);
    workload.launches = false;
    let mut pair = Pair::new(bytes(64, 64, 64), timers(), workload, Client::new());
    let outcome = pair.finish();
    assert!(!pair.sent_by_runner.contains(&runner::Message::Started));
    assert!(!pair.client.events.contains(&peer::Event::Started));
    assert!(!pair.peer.has_started());
    assert_eq!(outcome.launch_failure(), Some(LaunchFailure::new(5, 2)));
    assert_eq!(outcome.status(), Some(Status::Exited(125)));
    assert!(outcome.is_reusable());
}

#[test]
fn a_second_start_end_or_terminal_is_out_of_order() {
    let mut peer = Peer::new(KEY, bytes(8, 8, 8), timers(), Instant::now());
    let now = Instant::now();
    assert_eq!(peer.started(KEY), Ok(Receipt::Applied));
    assert_eq!(peer.started(KEY), Err(Violation::Order));
    let terminal = Outcome::new(Some(Status::Exited(0))).with_reusable();
    // The terminal outcome follows both streams' ends.
    assert_eq!(peer.terminal(now, KEY, terminal), Err(Violation::Order));
    assert_eq!(peer.end_output(KEY, Stream::Stdout), Ok(Receipt::Applied));
    assert_eq!(peer.end_output(KEY, Stream::Stdout), Err(Violation::Ended));
    while peer.next_message(&mut []).is_some() {}
    assert_eq!(
        peer.output(KEY, Stream::Stdout, b"x"),
        Err(Violation::Ended)
    );
    assert_eq!(peer.terminal(now, KEY, terminal), Err(Violation::Order));
    assert_eq!(peer.end_output(KEY, Stream::Stderr), Ok(Receipt::Applied));
    assert_eq!(peer.terminal(now, KEY, terminal), Ok(Receipt::Applied));
    assert_eq!(peer.terminal(now, KEY, terminal), Err(Violation::Ended));
    let events = std::iter::from_fn(|| peer.next_event()).collect::<Vec<_>>();
    assert_eq!(
        events,
        [
            peer::Event::Started,
            peer::Event::InputClosed,
            peer::Event::End(Stream::Stdout),
            peer::Event::End(Stream::Stderr),
            peer::Event::Finished(terminal),
        ]
    );
}

#[test]
fn a_start_after_the_terminal_outcome_of_a_failed_launch_is_out_of_order() {
    // The runner reported that the launch failed, so no start follows, even before the peer's
    // caller retrieved the outcome.
    let now = Instant::now();
    let mut peer = Peer::new(KEY, bytes(8, 8, 8), timers(), now);
    for stream in Stream::ALL {
        assert_eq!(peer.end_output(KEY, stream), Ok(Receipt::Applied));
    }
    let terminal = Outcome::new(Some(Status::Exited(125)))
        .with_launch_failure(LaunchFailure::new(5, 2))
        .with_reusable();
    assert_eq!(peer.terminal(now, KEY, terminal), Ok(Receipt::Applied));
    assert_eq!(peer.started(KEY), Err(Violation::Order));
    assert!(!peer.has_started());
    let events = std::iter::from_fn(|| peer.next_event()).collect::<Vec<_>>();
    assert_eq!(
        events,
        [
            peer::Event::InputClosed,
            peer::Event::End(Stream::Stdout),
            peer::Event::End(Stream::Stderr),
            peer::Event::Finished(terminal),
        ]
    );
}
