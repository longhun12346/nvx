//! Deterministic checks of the engine, with no operating-system calls: the credit arithmetic of
//! each side, the order of each stream, the completion rules, terminal races, bounded memory, and
//! liveness, with the sides connected by bounded queues, and a simulated workload and client.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::{
    Cause, Key, LaunchFailure, Limits, Outcome, Peer, Pool, Receipt, Runner, Settlement, Status,
    Stream, Timers, Unit, Violation, Window, peer, runner,
};

mod credit;
mod keys;
mod liveness;
mod memory;
mod races;
mod streams;
mod truncation;

/// The key of the executions in these tests.
const KEY: Key = Key::new(7, 3);
/// The grace of pending output in these tests.
const GRACE: Duration = Duration::from_secs(1);
/// The settlement time in these tests.
const SETTLEMENT: Duration = Duration::from_secs(5);
/// The capacity of each simulated pipe between the workload and the runner's adapter.
const PIPE: usize = 64 * 1024;
/// The most steps that a test drives a pair through before it fails.
const STEPS: usize = 1_000_000;

/// Returns limits with chunks of `chunk` bytes, an input window of `input` bytes, and an output
/// window of `output` bytes for each stream.
fn bytes(chunk: u32, input: u32, output: u32) -> Limits {
    Limits::new(chunk, Window::bytes(input), Window::bytes(output)).unwrap()
}

/// Returns the timers of these tests: a grace of [`GRACE`], a settlement time of
/// [`SETTLEMENT`], and no timeout.
fn timers() -> Timers {
    Timers::new(GRACE, SETTLEMENT)
}

/// Returns the byte at `position` of `stream`'s simulated output: a pattern that differs between
/// the streams and between nearby positions, so that a lost, repeated, or reordered byte shows.
fn pattern(stream: Stream, position: usize) -> u8 {
    let salt = match stream {
        Stream::Stdout => 0x5a,
        Stream::Stderr => 0xa5,
    };
    (position as u8)
        ^ ((position >> 8) as u8).rotate_left(3)
        ^ ((position >> 16) as u8).rotate_left(5)
        ^ ((position >> 24) as u8).rotate_left(7)
        ^ salt
}

/// Returns `length` bytes of `stream`'s pattern from `position`.
fn patterned(stream: Stream, position: usize, length: usize) -> Vec<u8> {
    (position..position + length)
        .map(|position| pattern(stream, position))
        .collect()
}

/// A message in flight from the peer to the runner, with its data.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ToRunner {
    /// A cancellation.
    Cancel(Cause),
    /// Credit of an output pool.
    Credit(Pool, u32),
    /// Input.
    Input(Vec<u8>),
    /// The input's end.
    InputEnd,
}

/// A message in flight from the runner to the peer, with its data.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ToPeer {
    /// Credit of the input.
    Credit(u32),
    /// The workload started.
    Started,
    /// Output.
    Output(Stream, Vec<u8>),
    /// A stream's end.
    End(Stream),
    /// The input closed early.
    InputClosed,
    /// The terminal outcome.
    Terminal(Outcome),
}

/// Returns the message that `message` describes, with the data that `buffer` holds.
fn to_runner(message: peer::Message, buffer: &[u8]) -> ToRunner {
    match message {
        peer::Message::Cancel(cause) => ToRunner::Cancel(cause),
        peer::Message::Credit { pool, units } => ToRunner::Credit(pool, units),
        peer::Message::Input { length } => ToRunner::Input(buffer[..length].to_vec()),
        peer::Message::InputEnd => ToRunner::InputEnd,
    }
}

/// Returns the message that `message` describes, with the data that `buffer` holds.
fn to_peer(message: runner::Message, buffer: &[u8]) -> ToPeer {
    match message {
        runner::Message::Credit { units } => ToPeer::Credit(units),
        runner::Message::Started => ToPeer::Started,
        runner::Message::Output { stream, length } => {
            ToPeer::Output(stream, buffer[..length].to_vec())
        }
        runner::Message::End(stream) => ToPeer::End(stream),
        runner::Message::InputClosed => ToPeer::InputClosed,
        runner::Message::Terminal(outcome) => ToPeer::Terminal(outcome),
    }
}

/// Hands `message` to `runner` at `now`, which must accept it.
fn deliver_to_runner(runner: &mut Runner, now: Instant, message: ToRunner) -> Receipt {
    let key = runner.key();
    match message {
        ToRunner::Cancel(cause) => runner.cancel(now, key, cause),
        ToRunner::Credit(pool, units) => runner.credit(key, pool, units),
        ToRunner::Input(bytes) => runner.input(key, &bytes),
        ToRunner::InputEnd => runner.end_input(key),
    }
    .expect("the runner accepts the peer's message")
}

/// Hands `message` to `peer` at `now`, which must accept it.
fn deliver_to_peer(peer: &mut Peer, now: Instant, message: ToPeer) -> Receipt {
    let key = peer.key();
    match message {
        ToPeer::Credit(units) => peer.credit(key, units),
        ToPeer::Started => peer.started(key),
        ToPeer::Output(stream, bytes) => peer.output(key, stream, &bytes),
        ToPeer::End(stream) => peer.end_output(key, stream),
        ToPeer::InputClosed => peer.input_closed(key),
        ToPeer::Terminal(outcome) => peer.terminal(now, key, outcome),
    }
    .expect("the peer accepts the runner's message")
}

/// A simulated workload, as the runner's adapter drives it: a program that writes its output
/// through pipes of [`PIPE`] bytes, takes its input at a rate, and exits once it wrote all of its
/// output, after its input's end if it reads to it.
#[derive(Debug)]
struct Workload {
    /// Whether the adapter reports a successful launch at the first step.
    launches: bool,
    /// Whether a process holds back what reports the launch, so that the adapter reports it only
    /// once this is false again.
    launch_held: bool,
    /// Whether the adapter reported the launch.
    launched: bool,
    /// The bytes of each stream that the program writes in all.
    lengths: [usize; 2],
    /// The bytes of each stream that the program wrote into its pipe.
    written: [usize; 2],
    /// The bytes of each stream that the adapter read from the pipe.
    read: [usize; 2],
    /// Whether the adapter reported each stream's close.
    closed: [bool; 2],
    /// Whether the adapter discards each stream.
    discarding: [bool; 2],
    /// The bytes of each stream that the adapter discarded.
    discarded: [usize; 2],
    /// The input that the program took.
    input: Vec<u8>,
    /// The most input bytes that the program takes in one step.
    input_rate: usize,
    /// The input bytes after which the program closes its input, if it does.
    input_limit: Option<usize>,
    /// Whether the program's input closed.
    input_closed: bool,
    /// Whether the program saw its input's end.
    input_end: bool,
    /// Whether the program exits only once its input closed: at its end, or because the
    /// program closed it.
    reads_to_end: bool,
    /// Whether the program exits once it has done its work; otherwise it runs until it is
    /// ended.
    exits: bool,
    /// The program's own exit code.
    code: i32,
    /// The program's status, once it ended.
    status: Option<Status>,
    /// Whether the adapter reported the status.
    reported: bool,
    /// Whether a termination fails to end the program.
    unkillable: bool,
    /// Whether a process that the program left behind holds each stream's pipe open once the
    /// program ended, until a settlement that succeeds ends it.
    held: [bool; 2],
    /// Whether the adapter reported that each stream hung up: no process holds its pipe any more.
    hung_up: [bool; 2],
    /// The settlement that the adapter reports once the runner requests it, if any.
    settlement: Option<Settlement>,
    /// Whether the runner requested the settlement and the adapter has not reported it.
    settling: bool,
    /// The requests that the runner made, in order.
    requests: Vec<runner::Request>,
}

impl Workload {
    /// Returns a workload that writes `stdout` and `stderr` bytes, takes all of its input at
    /// once, exits with 0 without waiting for its input's end, and settles.
    fn new(stdout: usize, stderr: usize) -> Self {
        Self {
            launches: true,
            launch_held: false,
            launched: false,
            lengths: [stdout, stderr],
            written: [0, 0],
            read: [0, 0],
            closed: [false, false],
            discarding: [false, false],
            discarded: [0, 0],
            input: Vec::new(),
            input_rate: usize::MAX,
            input_limit: None,
            input_closed: false,
            input_end: false,
            reads_to_end: false,
            exits: true,
            code: 0,
            status: None,
            reported: false,
            unkillable: false,
            held: [false, false],
            hung_up: [false, false],
            settlement: Some(Settlement::Settled),
            settling: false,
            requests: Vec::new(),
        }
    }

    /// Takes one step of the workload and of its adapter at `now`: applies the runner's
    /// requests, writes the program's output into its pipes, feeds it input, reads the pipes as
    /// the runner allows, reports what happened, and applies the requests that this makes.
    fn step(&mut self, runner: &mut Runner, now: Instant) {
        runner.tick(now);
        self.apply_requests(runner);
        if !self.launched && !self.launch_held {
            self.launched = true;
            if self.launches {
                runner.launched(Ok(()));
            } else {
                runner.launched(Err(LaunchFailure::new(5, 2)));
                self.status = Some(Status::Exited(125));
                self.lengths = [0, 0];
            }
        }
        if self.status.is_none() {
            for index in 0..2 {
                let room = PIPE - (self.written[index] - self.read[index]);
                self.written[index] += room.min(self.lengths[index] - self.written[index]);
            }
            self.take_input(runner);
            if self.exits
                && self.written == self.lengths
                && (!self.reads_to_end || self.input_closed)
            {
                self.status = Some(Status::Exited(self.code));
                self.input_closed = true;
            }
        }
        for stream in Stream::ALL {
            let index = stream.index();
            let held = self.written[index] - self.read[index];
            if self.discarding[index] {
                self.read[index] += held;
                self.discarded[index] += held;
                runner.discarded(stream, held);
            } else {
                let length = held.min(runner.read_allowance(stream));
                let bytes = patterned(stream, self.read[index], length);
                assert_eq!(runner.output(stream, &bytes), length);
                self.read[index] += length;
            }
            if !self.closed[index]
                && !self.held[index]
                && self.status.is_some()
                && self.written[index] == self.read[index]
            {
                self.closed[index] = true;
                runner.output_closed(stream);
            }
        }
        if self.status.is_some() && !self.reported {
            self.reported = true;
            runner.exited(now, self.status);
        }
        // Once the program ended, a stream that no process holds hung up, whatever its pipe
        // still holds.
        for stream in Stream::ALL {
            let index = stream.index();
            if self.status.is_some() && !self.held[index] && !self.hung_up[index] {
                self.hung_up[index] = true;
                runner.output_hung_up(stream);
            }
        }
        self.apply_requests(runner);
        if self.settling
            && let Some(settlement) = self.settlement
        {
            self.settling = false;
            if settlement == Settlement::Settled {
                self.held = [false, false];
            }
            runner.settled(settlement);
        }
    }

    /// Applies the requests that the runner makes.
    fn apply_requests(&mut self, runner: &mut Runner) {
        while let Some(request) = runner.next_request() {
            self.requests.push(request);
            match request {
                runner::Request::Terminate(_) => {
                    if !self.unkillable && self.status.is_none() {
                        self.status = Some(Status::Signaled(9));
                        self.input_closed = true;
                    }
                }
                runner::Request::Discard(stream) => self.discarding[stream.index()] = true,
                runner::Request::CloseInput => {
                    self.input_end = true;
                    self.input_closed = true;
                }
                runner::Request::Settle => self.settling = true,
            }
        }
    }

    /// Feeds the program the input that the runner holds, at the program's rate, until the
    /// program closes its input.
    fn take_input(&mut self, runner: &mut Runner) {
        let mut budget = self.input_rate;
        while budget > 0 && !self.input_closed {
            if self.input_limit == Some(self.input.len()) {
                self.input_closed = true;
                runner.input_closed();
                break;
            }
            let pending = runner.pending_input();
            let mut length = pending.len().min(budget);
            if let Some(limit) = self.input_limit {
                length = length.min(limit - self.input.len());
            }
            if length == 0 {
                break;
            }
            self.input.extend_from_slice(&pending[..length]);
            runner.input_written(length);
            budget -= length;
        }
    }
}

/// The peer's caller, as the peer's adapter drives it: a source of input and a sink for each
/// output stream, which takes at most a rate of bytes in each step, and checks each byte
/// against the workload's pattern.
#[derive(Debug)]
struct Client {
    /// The input that the source hands over in all.
    input: Vec<u8>,
    /// The bytes of input that the source handed over.
    sent: usize,
    /// Whether the source ends the input once it handed over everything.
    ends_input: bool,
    /// The most bytes that each sink takes in one step: zero stalls it.
    rates: [usize; 2],
    /// The bytes that each sink took.
    received: [usize; 2],
    /// The events, in order.
    events: Vec<peer::Event>,
}

impl Client {
    /// Returns a client that sends no input, ends it, and takes each stream at once.
    fn new() -> Self {
        Self {
            input: Vec::new(),
            sent: 0,
            ends_input: true,
            rates: [usize::MAX, usize::MAX],
            received: [0, 0],
            events: Vec::new(),
        }
    }

    /// Takes one step of the client and of the peer's adapter at `now`: hands the peer input as
    /// it allows, takes output at the sinks' rates, and collects the peer's events.
    fn step(&mut self, peer: &mut Peer, now: Instant) {
        peer.tick(now);
        if self.sent < self.input.len() {
            self.sent += peer.input(&self.input[self.sent..]);
        }
        if self.ends_input && self.sent == self.input.len() {
            peer.end_input();
        }
        for stream in Stream::ALL {
            let index = stream.index();
            let mut budget = self.rates[index];
            while budget > 0 {
                let pending = peer.pending_output(stream);
                let length = pending.len().min(budget);
                if length == 0 {
                    break;
                }
                for (offset, &byte) in pending[..length].iter().enumerate() {
                    let position = self.received[index] + offset;
                    assert_eq!(
                        byte,
                        pattern(stream, position),
                        "{stream:?} byte {position}"
                    );
                }
                self.received[index] += length;
                peer.consumed(stream, length);
                budget -= length;
            }
        }
        while let Some(event) = peer.next_event() {
            assert!(
                !matches!(self.events.last(), Some(peer::Event::Finished(_))),
                "the outcome is the last event"
            );
            self.events.push(event);
        }
    }

    /// Returns the execution's outcome, once the peer finished.
    fn outcome(&self) -> Option<Outcome> {
        self.events.iter().find_map(|event| match event {
            peer::Event::Finished(outcome) => Some(*outcome),
            _ => None,
        })
    }
}

/// A runner and a peer, with their workload and client, connected by a queue of messages in each
/// direction, as their adapters and a transport would connect them.
struct Pair {
    /// The current instant of the simulated clock.
    now: Instant,
    /// The runner.
    runner: Runner,
    /// The peer.
    peer: Peer,
    /// The runner's workload.
    workload: Workload,
    /// The peer's caller.
    client: Client,
    /// The messages in flight from the peer to the runner.
    to_runner: VecDeque<ToRunner>,
    /// The messages in flight from the runner to the peer.
    to_peer: VecDeque<ToPeer>,
    /// The most messages that each queue holds, after which its sender's adapter retrieves no
    /// more.
    capacity: usize,
    /// Whether the transport delivers the runner's messages to the peer.
    delivers_to_peer: bool,
    /// Every message that the runner returned, in order, without its data.
    sent_by_runner: Vec<runner::Message>,
    /// The terminal outcomes that the runner returned.
    terminals: Vec<Outcome>,
    /// The most data bytes in flight at once from the runner to the peer.
    in_flight_high_water: usize,
    /// The adapters' buffer.
    buffer: Vec<u8>,
}

impl Pair {
    /// Returns a pair of sides with `limits` and `timers`, created at `now`, around `workload`
    /// and `client`.
    fn new(limits: Limits, timers: Timers, workload: Workload, client: Client) -> Self {
        let now = Instant::now();
        Self {
            now,
            runner: Runner::new(KEY, limits, timers, now),
            peer: Peer::new(KEY, limits, timers, now),
            workload,
            client,
            to_runner: VecDeque::new(),
            to_peer: VecDeque::new(),
            capacity: usize::MAX,
            delivers_to_peer: true,
            sent_by_runner: Vec::new(),
            terminals: Vec::new(),
            in_flight_high_water: 0,
            buffer: vec![0; limits.chunk()],
        }
    }

    /// Takes one step: the workload, the client, both adapters' retrieval of messages while the
    /// queues have room, and the transport's delivery.
    fn step(&mut self) {
        self.workload.step(&mut self.runner, self.now);
        self.client.step(&mut self.peer, self.now);
        while self.to_runner.len() < self.capacity {
            let Some(message) = self.peer.next_message(&mut self.buffer) else {
                break;
            };
            self.to_runner.push_back(to_runner(message, &self.buffer));
        }
        while self.to_peer.len() < self.capacity {
            let Some(message) = self.runner.next_message(&mut self.buffer) else {
                break;
            };
            self.sent_by_runner.push(message);
            if let runner::Message::Terminal(outcome) = message {
                self.terminals.push(outcome);
                if self.runner.is_detached() {
                    continue;
                }
            }
            self.to_peer.push_back(to_peer(message, &self.buffer));
        }
        let in_flight = self
            .to_peer
            .iter()
            .map(|message| match message {
                ToPeer::Output(_, bytes) => bytes.len(),
                _ => 0,
            })
            .sum::<usize>();
        self.in_flight_high_water = self.in_flight_high_water.max(in_flight);
        while let Some(message) = self.to_runner.pop_front() {
            deliver_to_runner(&mut self.runner, self.now, message);
        }
        while self.delivers_to_peer
            && let Some(message) = self.to_peer.pop_front()
        {
            if !self.peer.is_detached() {
                deliver_to_peer(&mut self.peer, self.now, message);
            }
        }
    }

    /// Takes steps until `done` holds, and fails after [`STEPS`] steps.
    fn run_until(&mut self, mut done: impl FnMut(&Self) -> bool) {
        for _ in 0..STEPS {
            if done(self) {
                return;
            }
            self.step();
        }
        panic!("the pair did not get there in time");
    }

    /// Takes steps until both sides finished, and returns the peer's outcome.
    fn finish(&mut self) -> Outcome {
        self.run_until(|pair| pair.runner.is_finished() && pair.peer.is_finished());
        self.client.outcome().unwrap()
    }

    /// Takes `count` steps.
    fn steps(&mut self, count: usize) {
        for _ in 0..count {
            self.step();
        }
    }

    /// Moves the clock forward by `duration`.
    fn advance(&mut self, duration: Duration) {
        self.now += duration;
    }

    /// Returns the runner's terminal outcome, which it returned exactly once.
    fn terminal(&self) -> Outcome {
        assert_eq!(self.terminals.len(), 1, "one terminal outcome");
        self.terminals[0]
    }
}
