//! Shared-VM bookkeeping: one VM, several logical sessions, each holding a set of execs.
//!
//! Before P5 a session *was* a VM and carried a single `busy` flag, so a second `exec` on
//! the same session was refused. Here the two are separate: sessions are routing and
//! authorisation units inside one VM, and every execution has its own identity, phase,
//! output stream and terminal state. The VM still runs one execution at a time (the guest
//! agent is single-task until P6), so executions wait in a bounded queue instead of being
//! refused: `busy` is an answer about capacity, never about which session asked.
//!
//! This module is deliberately free of VM calls, threads and I/O so the whole lifecycle
//! can be tested as a state machine. `server` drives it: it resolves a session, computes the
//! request digest, calls [`Registry::accept`], and runs whatever [`Registry::dispatch`]
//! hands out.
//!
//! Two identities matter and are kept apart:
//!
//! * the **exec id** is chosen by the host before the request is sent, so a lost reply, a
//!   duplicate start or a cancel that overtakes its start can still be resolved;
//! * the **generation** names the VM instance those executions belong to, so an answer
//!   about a replaced VM can never be mistaken for an answer about the current one.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Executions that may wait for the VM's single run slot.
///
/// Bounded because the queue is admission control: once it is full the caller is refused
/// *before* anything is registered, rather than growing until the control plane stalls.
pub const DEFAULT_QUEUE_DEPTH: usize = 32;

/// Completed executions kept so a late status query can still be answered.
pub const DEFAULT_FINISHED_RETENTION: usize = 256;

/// How long a cancel that arrived before its start is remembered. A start that turns up
/// afterwards must not run, and one query that finds nothing proves nothing.
pub const CANCEL_TOMBSTONE_TTL: Duration = Duration::from_secs(600);

/// Bounded, so a caller cancelling invented ids cannot grow the sidecar without limit.
pub const MAX_CANCEL_TOMBSTONES: usize = 256;

/// Where an execution is. `Queued` owns no run slot; `Running` owns the VM's only one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Queued,
    Running,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Queued => "queued",
            Phase::Running => "running",
        }
    }
}

/// How an execution ended. Mirrors the public event vocabulary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terminal {
    pub outcome: &'static str,
    pub code: Option<i32>,
    pub detail: String,
}

impl Terminal {
    pub fn new(outcome: &'static str, code: Option<i32>, detail: impl Into<String>) -> Self {
        Self {
            outcome,
            code,
            detail: detail.into(),
        }
    }

    pub fn cancelled(detail: impl Into<String>) -> Self {
        Self::new("cancelled", None, detail)
    }

    pub fn timed_out(detail: impl Into<String>) -> Self {
        Self::new("timedOut", None, detail)
    }
}

/// The answer to [`Registry::accept`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Accept {
    /// Registered and waiting for its turn; `position` counts queued executions ahead of it.
    Queued { position: usize },
    /// The same id with the same arguments: the original execution is untouched.
    Duplicate { phase: Phase, terminal: Option<Terminal> },
    /// The same id with different arguments. Two different commands must never share an id.
    Conflict,
    /// A cancel for this id arrived before the start did.
    Cancelled,
    /// No capacity: refused before any registration.
    QueueFull,
    SessionUnknown,
    /// The session is closing or closed; a new execution may not join it.
    SessionClosing,
    /// The id belongs to a VM instance this sidecar no longer serves.
    GenerationStale,
}

/// The answer to [`Registry::cancel`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cancel {
    /// It was queued; it is now terminal and will never run.
    Queued(Terminal),
    /// It is running; the caller must stop the process and report its terminal state.
    Running,
    /// It had already finished; this is that terminal state again.
    Finished(Terminal),
    /// No such execution. The cancel is remembered so a late start cannot run.
    Unknown,
}

/// What closing a session took away.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Closed {
    /// Executions that never ran and are now cancelled.
    pub cancelled_queued: Vec<String>,
    /// Executions of this session that still hold a run slot.
    pub running: Vec<String>,
}

/// An execution as reported by `diagnostics`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecView {
    pub id: String,
    pub session: String,
    pub phase: Phase,
    pub generation: u64,
    pub queued_ms: u64,
}

struct Exec {
    session: String,
    generation: u64,
    phase: Phase,
    /// Digest of the request, so a repeated id with different arguments is caught.
    digest: u64,
    queued_at: Instant,
    queue_deadline: Option<Instant>,
    /// The caller asked to stop it; the process is being stopped.
    cancel_requested: bool,
    /// The start reply has been written, so events for it may now be emitted. Holding this
    /// closed is what keeps "start response before the execution's events" true no matter
    /// which thread wins the race.
    released: bool,
}

struct SessionEntry {
    closing: bool,
    /// Every id this session was given, so closing it can find them all.
    execs: Vec<String>,
    /// This session's own waiting executions, in submission order.
    ///
    /// Kept per session, not in one global FIFO: with several run slots a single session that
    /// queued a burst would otherwise fill every freed slot and starve the others. Dispatch
    /// walks the sessions in turn (see [`Registry::dispatch`]).
    queue: VecDeque<String>,
    /// Executions of this session holding a run slot right now.
    running: usize,
}

/// Lifecycle of one VM instance and everything registered against it.
pub struct Registry {
    generation: u64,
    max_queue: usize,
    /// How many executions may run at the same time. One until the guest image and the product
    /// configuration both accept more.
    max_running: usize,
    /// Total queued executions, across sessions. The admission ceiling is per VM, so one
    /// session's burst cannot push the VM past it either.
    queued: usize,
    /// Sessions with waiting work, in the order they are next to be served.
    rotation: VecDeque<String>,
    /// Executions that hold a run slot, in dispatch order.
    running: Vec<String>,
    execs: HashMap<String, Exec>,
    /// Terminal state and request digest of completed executions. The digest is kept so a
    /// repeated id with different arguments is still a conflict after the first one ended.
    finished: HashMap<String, (Terminal, u64)>,
    finished_order: VecDeque<String>,
    finished_limit: usize,
    /// Cancels that arrived before their start, with the time they were recorded.
    tombstones: HashMap<String, Instant>,
    tombstone_order: VecDeque<String>,
    sessions: HashMap<String, SessionEntry>,
}

impl Registry {
    pub fn new(max_queue: usize, max_running: usize, generation: u64) -> Self {
        Self {
            generation,
            max_queue: max_queue.max(1),
            max_running: max_running.max(1),
            queued: 0,
            rotation: VecDeque::new(),
            running: Vec::new(),
            execs: HashMap::new(),
            finished: HashMap::new(),
            finished_order: VecDeque::new(),
            finished_limit: DEFAULT_FINISHED_RETENTION,
            tombstones: HashMap::new(),
            tombstone_order: VecDeque::new(),
            sessions: HashMap::new(),
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Names a new VM instance. Everything registered against the old one is gone, and its
    /// ids must never resolve again.
    pub fn new_generation(&mut self) -> u64 {
        self.generation += 1;
        self.queued = 0;
        self.rotation.clear();
        self.running.clear();
        self.execs.clear();
        self.finished.clear();
        self.finished_order.clear();
        self.sessions.clear();
        self.generation
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn open_session(&mut self, name: &str) -> bool {
        if self.sessions.contains_key(name) {
            return false;
        }
        self.sessions.insert(
            name.to_owned(),
            SessionEntry {
                closing: false,
                execs: Vec::new(),
                queue: VecDeque::new(),
                running: 0,
            },
        );
        true
    }

    /// Registers `id` for `session`, or explains why it cannot be registered.
    ///
    /// Nothing is started here: the caller must answer the request first (the start reply
    /// precedes the events) and only then let [`Self::dispatch`] hand the work out.
    pub fn accept(
        &mut self,
        session: &str,
        id: &str,
        digest: u64,
        generation: u64,
        queue_deadline: Option<Instant>,
    ) -> Accept {
        if generation != 0 && generation != self.generation {
            return Accept::GenerationStale;
        }
        match self.sessions.get(session) {
            None => return Accept::SessionUnknown,
            Some(entry) if entry.closing => return Accept::SessionClosing,
            Some(_) => {}
        }
        // A repeat of an id we already know is not a new execution, whatever its phase.
        if let Some(existing) = self.execs.get(id) {
            if existing.digest != digest {
                return Accept::Conflict;
            }
            return Accept::Duplicate {
                phase: existing.phase,
                terminal: None,
            };
        }
        if let Some((terminal, known_digest)) = self.finished.get(id) {
            if *known_digest != digest {
                return Accept::Conflict;
            }
            return Accept::Duplicate {
                phase: Phase::Running,
                terminal: Some(terminal.clone()),
            };
        }
        if self.cancel_tombstone(id, Instant::now()) {
            return Accept::Cancelled;
        }
        if self.queued >= self.max_queue {
            return Accept::QueueFull;
        }
        let position = self.queued;
        self.execs.insert(
            id.to_owned(),
            Exec {
                session: session.to_owned(),
                generation: self.generation,
                phase: Phase::Queued,
                digest,
                queued_at: Instant::now(),
                queue_deadline,
                cancel_requested: false,
                released: false,
            },
        );
        if let Some(entry) = self.sessions.get_mut(session) {
            entry.execs.push(id.to_owned());
            entry.queue.push_back(id.to_owned());
        }
        self.queued += 1;
        if !self.rotation.iter().any(|known| known == session) {
            self.rotation.push_back(session.to_owned());
        }
        Accept::Queued { position }
    }

    /// Hands out the next executions that may start while run slots are free.
    ///
    /// Each returned id is now `Running` but not yet released: the caller answers its start
    /// request, then calls [`Self::release`], and only then may events be emitted. Sessions with
    /// waiting work are served in turn (round robin), so one session's burst cannot take every
    /// freed slot while another session waits; inside a session the order is submission order.
    /// The caller starts the returned executions concurrently.
    pub fn dispatch(&mut self) -> Vec<String> {
        let mut started = Vec::new();
        while self.running.len() < self.max_running {
            let Some(session) = self.next_ready_session() else {
                break;
            };
            let mut popped = None;
            if let Some(entry) = self.sessions.get_mut(&session) {
                popped = entry.queue.pop_front();
            }
            let Some(id) = popped else {
                break;
            };
            let Some(exec) = self.execs.get_mut(&id) else {
                self.queued = self.queued.saturating_sub(1);
                continue;
            };
            exec.phase = Phase::Running;
            if let Some(entry) = self.sessions.get_mut(&session) {
                entry.running += 1;
            }
            self.queued = self.queued.saturating_sub(1);
            self.running.push(id.clone());
            started.push(id);
        }
        started
    }

    /// Takes the next session with waiting work from the rotation, or `None` when none is left.
    fn next_ready_session(&mut self) -> Option<String> {
        for _ in 0..self.rotation.len() {
            let session = self.rotation.pop_front()?;
            let ready = self
                .sessions
                .get(&session)
                .is_some_and(|entry| !entry.queue.is_empty());
            if !ready {
                // Closed, or it has nothing left to run: it leaves the rotation until it
                // queues again.
                continue;
            }
            self.rotation.push_back(session.clone());
            return Some(session);
        }
        None
    }

    /// Opens the start gate for `id` once its reply has been written.
    pub fn release(&mut self, id: &str) {
        if let Some(exec) = self.execs.get_mut(id) {
            exec.released = true;
        }
    }

    pub fn is_released(&self, id: &str) -> bool {
        self.execs.get(id).is_some_and(|exec| exec.released)
    }

    pub fn session_of(&self, id: &str) -> Option<&str> {
        self.execs.get(id).map(|exec| exec.session.as_str())
    }

    pub fn cancel_requested(&self, id: &str) -> bool {
        self.execs.get(id).is_some_and(|exec| exec.cancel_requested)
    }

    pub fn running_ids(&self) -> &[String] {
        &self.running
    }

    /// The one execution a single-slot registry starts, for tests that predate concurrent runs.
    #[cfg(test)]
    pub fn dispatch_one(&mut self) -> Option<String> {
        self.dispatch().into_iter().next()
    }

    /// How many executions this VM may run at once.
    pub fn max_running(&self) -> usize {
        self.max_running
    }

    pub fn queued_len(&self) -> usize {
        self.queued
    }

    /// Executions of `session` holding a run slot right now.
    pub fn running_for_session(&self, session: &str) -> usize {
        self.sessions
            .get(session)
            .map(|entry| entry.running)
            .unwrap_or(0)
    }

    /// Executions of `session` waiting for a slot right now.
    pub fn queued_for_session(&self, session: &str) -> usize {
        self.sessions
            .get(session)
            .map(|entry| entry.queue.len())
            .unwrap_or(0)
    }

    /// The per-session ceiling this registry enforces.
    ///
    /// Slots are counted per VM, and a session may use all of them: concurrency is bounded by
    /// the VM's run slots, not by a separate per-session quota. A single active session is
    /// therefore never throttled below the VM's capacity while the other sessions are idle.
    pub fn max_running_per_session(&self) -> usize {
        self.max_running
    }

    /// Whether this session has an execution that has not finished yet.
    ///
    /// Mount changes ask this: on a shared VM a mount cannot be rewritten under a running
    /// execution, so the request is refused while the session still owns work.
    pub fn session_has_unfinished(&self, session: &str) -> bool {
        self.sessions
            .get(session)
            .map(|entry| {
                entry
                    .execs
                    .iter()
                    .any(|id| self.execs.contains_key(id))
            })
            .unwrap_or(false)
    }

    /// Marks `id` terminal and frees the run slot when it held it.
    pub fn finish(&mut self, id: &str, terminal: Terminal) -> Option<String> {
        let exec = self.execs.remove(id)?;
        let session = exec.session.clone();
        if let Some(entry) = self.sessions.get_mut(&session) {
            entry.execs.retain(|known| known != id);
        }
        if exec.phase == Phase::Running {
            if let Some(position) = self.running.iter().position(|running| running == id) {
                self.running.remove(position);
            }
            if let Some(entry) = self.sessions.get_mut(&session) {
                entry.running = entry.running.saturating_sub(1);
            }
        } else {
            // Queued: it never held a slot, so only its queue entry and the VM-wide count go.
            self.queued = self.queued.saturating_sub(1);
            if let Some(entry) = self.sessions.get_mut(&session) {
                entry.queue.retain(|queued| queued != id);
            }
        }
        self.remember_finished(id, terminal, exec.digest);
        Some(session)
    }

    fn remember_finished(&mut self, id: &str, terminal: Terminal, digest: u64) {
        self.finished.insert(id.to_owned(), (terminal, digest));
        self.finished_order.push_back(id.to_owned());
        while self.finished_order.len() > self.finished_limit {
            if let Some(oldest) = self.finished_order.pop_front() {
                self.finished.remove(&oldest);
            }
        }
    }

    /// Stops `id`, or remembers the request if the start has not arrived yet.
    ///
    /// A queued execution is cancelled here and now: it never runs, and its terminal state
    /// is returned so the caller can emit exactly one exit event. A running one must be
    /// stopped by the caller, which owns the process; this only records the request so the
    /// completion path reports `cancelled` rather than the signal it happens to observe.
    pub fn cancel(&mut self, id: &str) -> Cancel {
        let Some(phase) = self.execs.get(id).map(|exec| exec.phase) else {
            if let Some((terminal, _)) = self.finished.get(id) {
                return Cancel::Finished(terminal.clone());
            }
            self.remember_tombstone(id, Instant::now());
            return Cancel::Unknown;
        };
        match phase {
            Phase::Queued => {
                let terminal = Terminal::cancelled("cancelled while queued");
                let _ = self.finish(id, terminal.clone());
                Cancel::Queued(terminal)
            }
            Phase::Running => {
                if let Some(exec) = self.execs.get_mut(id) {
                    exec.cancel_requested = true;
                }
                Cancel::Running
            }
        }
    }

    /// Drops queued executions whose deadline passed, so a caller cannot be parked for an
    /// unbounded time behind somebody else's long task. Returns `(id, session)` pairs, so the
    /// caller can report each terminal state to the right stream.
    pub fn expire_queued(&mut self, now: Instant) -> Vec<(String, String)> {
        let mut expired: Vec<(String, String)> = Vec::new();
        for (session, entry) in self.sessions.iter() {
            for id in entry.queue.iter() {
                let due = self
                    .execs
                    .get(id)
                    .and_then(|exec| exec.queue_deadline)
                    .is_some_and(|deadline| deadline <= now);
                if due {
                    expired.push((id.clone(), session.clone()));
                }
            }
        }
        for (id, _) in &expired {
            let _ = self.finish(id, Terminal::timed_out("queue deadline expired"));
        }
        expired
    }

    /// Closes a session: refuses it new work and takes away everything it already owns.
    pub fn close_session(&mut self, name: &str) -> Closed {
        let Some(mut entry) = self.sessions.remove(name) else {
            return Closed::default();
        };
        entry.closing = true;
        let mut closed = Closed::default();
        for id in entry.execs {
            let Some(exec) = self.execs.get(&id) else {
                continue;
            };
            match exec.phase {
                Phase::Queued => {
                    let terminal = Terminal::cancelled("session closed before it ran");
                    let _ = self.finish(&id, terminal);
                    closed.cancelled_queued.push(id);
                }
                Phase::Running => closed.running.push(id),
            }
        }
        closed
    }

    /// Whether anything at all still refers to this VM instance.
    pub fn is_idle(&self) -> bool {
        self.sessions.is_empty()
            && self.running.is_empty()
            && self.queued == 0
            && self.execs.is_empty()
    }

    pub fn views(&self) -> Vec<ExecView> {
        let now = Instant::now();
        let mut views: Vec<ExecView> = self
            .execs
            .iter()
            .map(|(id, exec)| ExecView {
                id: id.clone(),
                session: exec.session.clone(),
                phase: exec.phase,
                generation: exec.generation,
                queued_ms: now.saturating_duration_since(exec.queued_at).as_millis() as u64,
            })
            .collect();
        views.sort_by(|left, right| left.id.cmp(&right.id));
        views
    }

    pub fn terminal_of(&self, id: &str) -> Option<&Terminal> {
        self.finished.get(id).map(|(terminal, _)| terminal)
    }

    fn remember_tombstone(&mut self, id: &str, now: Instant) {
        if self.tombstones.contains_key(id) {
            self.tombstones.insert(id.to_owned(), now);
            return;
        }
        self.tombstones.insert(id.to_owned(), now);
        self.tombstone_order.push_back(id.to_owned());
        while self.tombstone_order.len() > MAX_CANCEL_TOMBSTONES {
            if let Some(oldest) = self.tombstone_order.pop_front() {
                self.tombstones.remove(&oldest);
            }
        }
    }

    /// Whether a cancel for this id is still remembered. A hit consumes the record: the id
    /// must not become usable again after its one late start was refused.
    fn cancel_tombstone(&mut self, id: &str, now: Instant) -> bool {
        let Some(recorded) = self.tombstones.remove(id) else {
            return false;
        };
        self.tombstone_order.retain(|known| known != id);
        now.saturating_duration_since(recorded) <= CANCEL_TOMBSTONE_TTL
    }

    #[cfg(test)]
    fn set_finished_limit(&mut self, limit: usize) {
        self.finished_limit = limit;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: u64 = 0x5eed;

    fn registry() -> Registry {
        Registry::new(DEFAULT_QUEUE_DEPTH, 1, 1)
    }

    /// Registers a session and one queued execution; panics if either is refused.
    fn accept(registry: &mut Registry, session: &str, id: &str) -> Accept {
        let outcome = registry.accept(session, id, DIGEST, 0, None);
        assert!(
            matches!(outcome, Accept::Queued { .. }),
            "{id} should be accepted, got {outcome:?}"
        );
        outcome
    }

    fn open(registry: &mut Registry, session: &str) {
        assert!(registry.open_session(session), "{session} should open");
    }

    /// The delivery point of P5: two sessions, one VM, and a second execution on the first
    /// session is queued rather than refused.
    #[test]
    fn two_sessions_share_one_vm_and_a_session_holds_several_execs() {
        let mut registry = registry();
        open(&mut registry, "A");
        open(&mut registry, "B");

        accept(&mut registry, "A", "A1");
        let second = registry.accept("A", "A2", DIGEST, 0, None);
        assert_eq!(second, Accept::Queued { position: 1 });
        accept(&mut registry, "B", "B1");

        assert_eq!(registry.session_count(), 2, "one VM, two sessions");
        assert_eq!(registry.queued_len(), 3);
        assert_eq!(registry.generation(), 1, "no new VM was created for B");
    }

    /// One run slot: while an execution holds it, nothing else may be handed out.
    #[test]
    fn the_vm_runs_one_execution_at_a_time() {
        let mut registry = registry();
        open(&mut registry, "A");
        open(&mut registry, "B");
        accept(&mut registry, "A", "A1");
        accept(&mut registry, "B", "B1");

        assert_eq!(registry.dispatch_one().as_deref(), Some("A1"));
        assert_eq!(registry.running_ids(), ["A1"]);
        assert_eq!(registry.dispatch_one(), None, "the slot is taken");

        registry.finish("A1", Terminal::new("exited", Some(0), ""));
        assert_eq!(registry.dispatch_one().as_deref(), Some("B1"), "the slot moved on");
    }

    /// A start reply must be written before any event for that execution.
    #[test]
    fn events_stay_behind_the_start_gate() {
        let mut registry = registry();
        open(&mut registry, "A");
        accept(&mut registry, "A", "A1");

        let id = registry.dispatch_one().expect("dispatched");
        assert!(!registry.is_released(&id), "not released before the reply");
        registry.release(&id);
        assert!(registry.is_released(&id));
    }

    /// With more than one run slot, dispatch fills them in turn across sessions.
    #[test]
    fn several_executions_run_at_once_when_the_slots_allow_it() {
        let mut registry = Registry::new(DEFAULT_QUEUE_DEPTH, 2, 1);
        open(&mut registry, "A");
        open(&mut registry, "B");
        accept(&mut registry, "A", "A1");
        accept(&mut registry, "A", "A2");
        accept(&mut registry, "B", "B1");

        // One call fills both slots: two executions start together, the third waits. The two
        // slots go to different sessions, not both to the session that queued first.
        assert_eq!(registry.dispatch(), ["A1", "B1"]);
        assert_eq!(registry.running_ids(), ["A1", "B1"]);
        assert!(registry.dispatch().is_empty(), "both slots are taken");

        // Releasing one slot admits exactly one more, and leaves the other running.
        registry.finish("A1", Terminal::new("exited", Some(0), ""));
        assert_eq!(registry.running_ids(), ["B1"], "B1 is untouched");
        assert_eq!(registry.dispatch(), ["A2"]);
        assert_eq!(registry.running_ids(), ["B1", "A2"]);
    }

    /// A burst from one session must not take every slot while another session waits.
    #[test]
    fn a_burst_from_one_session_does_not_starve_another() {
        let mut registry = Registry::new(DEFAULT_QUEUE_DEPTH, 2, 1);
        open(&mut registry, "A");
        open(&mut registry, "B");
        accept(&mut registry, "A", "A1");
        accept(&mut registry, "A", "A2");
        accept(&mut registry, "A", "A3");
        accept(&mut registry, "B", "B1");

        assert_eq!(registry.dispatch(), ["A1", "B1"], "B is served before A2");
        assert_eq!(registry.running_for_session("A"), 1);
        assert_eq!(registry.running_for_session("B"), 1);
        assert_eq!(registry.queued_for_session("A"), 2);
        assert_eq!(registry.queued_for_session("B"), 0);

        // Slots are the only limit: one session may still hold both of them.
        registry.finish("B1", Terminal::new("exited", Some(0), ""));
        assert_eq!(registry.dispatch(), ["A2"]);
        registry.finish("A1", Terminal::new("exited", Some(0), ""));
        assert_eq!(registry.dispatch(), ["A3"]);
        assert_eq!(registry.running_for_session("A"), 2, "one session may use every slot");
        assert_eq!(registry.max_running_per_session(), 2, "counted per VM, not per session");
    }

    /// The real interleaving: accepts and dispatches alternate while four slots are in flight,
    /// then the slots are freed one at a time. This is the shape the session-fairness case in
    /// `tests/mixed_parallel.py` produces, and the one round robin has to survive.
    #[test]
    fn a_burst_queued_while_the_vm_is_full_is_served_in_turn() {
        let mut registry = Registry::new(DEFAULT_QUEUE_DEPTH, 4, 1);
        open(&mut registry, "A");
        open(&mut registry, "B");
        for index in 1..=6 {
            accept(&mut registry, "A", &format!("F{index}"));
            // The dispatcher runs between accepts, exactly as the worker does.
            let _ = registry.dispatch();
        }
        accept(&mut registry, "B", "FB1");
        let _ = registry.dispatch();
        assert_eq!(
            registry.running_ids(),
            ["F1", "F2", "F3", "F4"],
            "the first four fills of one session take the slots"
        );

        // Two slots free together: one each, not two for the session that queued first.
        registry.finish("F1", Terminal::new("exited", Some(0), ""));
        registry.finish("F2", Terminal::new("exited", Some(0), ""));
        let started = registry.dispatch();
        assert_eq!(started, ["F5", "FB1"], "the other session is served in the same wave");
    }

    /// Closing a session stops every execution of it that holds a slot, not just one.
    #[test]
    fn closing_a_session_frees_all_of_its_run_slots() {
        let mut registry = Registry::new(DEFAULT_QUEUE_DEPTH, 2, 1);
        open(&mut registry, "A");
        open(&mut registry, "B");
        accept(&mut registry, "A", "A1");
        accept(&mut registry, "A", "A2");
        assert_eq!(registry.dispatch(), ["A1", "A2"]);
        accept(&mut registry, "B", "B1");

        let closed = registry.close_session("A");

        assert_eq!(closed.running, ["A1", "A2"]);
        assert!(closed.cancelled_queued.is_empty());
        // A closed session's executions keep their slots until the caller has stopped them and
        // reported their terminal state; B still waits its turn and is not affected.
        assert_eq!(registry.running_ids(), ["A1", "A2"]);
        assert!(registry.dispatch().is_empty(), "no slot is free yet");
        registry.finish("A1", Terminal::new("cancelled", None, "session closed"));
        registry.finish("A2", Terminal::new("cancelled", None, "session closed"));
        assert_eq!(registry.dispatch(), ["B1"], "B runs once A's slots are gone");
    }

    /// Cancelling a queued execution must leave whatever is running alone.
    #[test]
    fn cancelling_a_queued_execution_does_not_touch_the_running_one() {
        let mut registry = registry();
        open(&mut registry, "A");
        open(&mut registry, "B");
        accept(&mut registry, "A", "A1");
        accept(&mut registry, "A", "A2");
        accept(&mut registry, "B", "B1");
        assert_eq!(registry.dispatch_one().as_deref(), Some("A1"));

        let cancelled = registry.cancel("A2");
        assert!(matches!(cancelled, Cancel::Queued(_)), "{cancelled:?}");
        assert_eq!(registry.running_ids(), ["A1"]);
        assert!(!registry.cancel_requested("A1"), "A1 was not cancelled");
        assert_eq!(registry.queued_len(), 1, "only B1 is still queued");
        assert_eq!(registry.terminal_of("A2").unwrap().outcome, "cancelled");

        registry.finish("A1", Terminal::new("exited", Some(0), ""));
        assert_eq!(registry.dispatch_one().as_deref(), Some("B1"), "B was not affected");
    }

    /// Cancelling the running execution records the request; the slot is released when the
    /// process is actually gone, not when the cancel is accepted.
    #[test]
    fn cancelling_the_running_execution_leaves_the_slot_until_cleanup_finishes() {
        let mut registry = registry();
        open(&mut registry, "A");
        open(&mut registry, "B");
        accept(&mut registry, "A", "A1");
        accept(&mut registry, "B", "B1");
        assert_eq!(registry.dispatch_one().as_deref(), Some("A1"));

        assert_eq!(registry.cancel("A1"), Cancel::Running);
        assert!(registry.cancel_requested("A1"));
        assert_eq!(registry.running_ids(), ["A1"], "cleanup still owns the slot");
        assert_eq!(registry.dispatch_one(), None, "no new work before cleanup is confirmed");

        registry.finish("A1", Terminal::cancelled("cancelled by the caller"));
        assert_eq!(registry.dispatch_one().as_deref(), Some("B1"));
    }

    /// Closing A takes A's work only: B keeps what it had, in the same VM.
    #[test]
    fn closing_one_session_keeps_the_other_sessions_work() {
        let mut registry = registry();
        open(&mut registry, "A");
        open(&mut registry, "B");
        accept(&mut registry, "A", "A1");
        accept(&mut registry, "A", "A2");
        accept(&mut registry, "B", "B1");
        assert_eq!(registry.dispatch_one().as_deref(), Some("A1"));
        assert_eq!(registry.dispatch_one(), None, "A1 holds the slot");

        let closed = registry.close_session("A");
        assert_eq!(closed.cancelled_queued, vec!["A2".to_owned()]);
        assert_eq!(closed.running, ["A1"]);
        assert_eq!(registry.session_count(), 1, "A is gone, B is not");
        assert_eq!(registry.generation(), 1, "closing a session does not replace the VM");

        // B1 is untouched and still queued behind A1's cleanup.
        assert_eq!(registry.session_of("B1"), Some("B"));
        registry.finish("A1", Terminal::cancelled("session closed"));
        assert_eq!(registry.dispatch_one().as_deref(), Some("B1"));
    }

    /// A closed session may not take new work; the VM itself stays up for the others.
    #[test]
    fn a_closed_session_cannot_accept_new_executions() {
        let mut registry = registry();
        open(&mut registry, "A");
        open(&mut registry, "B");
        registry.close_session("A");
        assert_eq!(
            registry.accept("A", "A9", DIGEST, 0, None),
            Accept::SessionUnknown
        );
        assert_eq!(registry.session_count(), 1);
        assert!(!registry.is_idle(), "B still holds the VM");
    }

    /// Re-sending the same id with the same arguments returns the original state instead of
    /// starting a second command; with different arguments it is a contract error.
    #[test]
    fn repeated_ids_are_deduplicated_and_conflicting_arguments_are_refused() {
        let mut registry = registry();
        open(&mut registry, "A");
        accept(&mut registry, "A", "A1");

        assert_eq!(
            registry.accept("A", "A1", DIGEST, 0, None),
            Accept::Duplicate {
                phase: Phase::Queued,
                terminal: None
            }
        );
        assert_eq!(registry.queued_len(), 1, "the duplicate did not queue again");

        assert_eq!(
            registry.accept("A", "A1", DIGEST ^ 1, 0, None),
            Accept::Conflict
        );

        registry.finish("A1", Terminal::new("exited", Some(3), ""));
        assert_eq!(
            registry.accept("A", "A1", DIGEST, 0, None),
            Accept::Duplicate {
                phase: Phase::Running,
                terminal: Some(Terminal::new("exited", Some(3), ""))
            }
        );
    }

    /// A cancel that overtakes its start must not let the start run later.
    #[test]
    fn a_cancel_that_arrives_before_the_start_stops_it_from_ever_running() {
        let mut registry = registry();
        open(&mut registry, "A");

        assert_eq!(registry.cancel("A1"), Cancel::Unknown);
        assert_eq!(
            registry.accept("A", "A1", DIGEST, 0, None),
            Accept::Cancelled
        );
        assert_eq!(registry.queued_len(), 0);
        assert_eq!(registry.dispatch_one(), None, "a cancelled id never runs");
    }

    /// Ids from a replaced VM instance must not resolve against the new one.
    #[test]
    fn ids_from_an_older_generation_are_refused() {
        let mut registry = registry();
        open(&mut registry, "A");
        let old = registry.generation();
        accept(&mut registry, "A", "A1");
        assert_eq!(registry.dispatch_one().as_deref(), Some("A1"));

        let new = registry.new_generation();
        assert!(new > old);
        assert!(registry.running_ids().is_empty(), "old work is gone with the old VM");
        assert_eq!(registry.session_count(), 0, "sessions belonged to that VM");

        old_style_accept_is_stale(&mut registry, old);
    }

    fn old_style_accept_is_stale(registry: &mut Registry, old: u64) {
        registry.open_session("A");
        assert_eq!(
            registry.accept("A", "A2", DIGEST, old, None),
            Accept::GenerationStale
        );
        assert!(matches!(
            registry.accept("A", "A2", DIGEST, 0, None),
            Accept::Queued { .. }
        ));
    }

    /// Admission is bounded: the queue refuses before it registers anything.
    #[test]
    fn a_full_queue_refuses_before_registering() {
        let mut registry = Registry::new(2, 1, 1);
        open(&mut registry, "A");
        accept(&mut registry, "A", "A1");
        accept(&mut registry, "A", "A2");

        assert_eq!(registry.accept("A", "A3", DIGEST, 0, None), Accept::QueueFull);
        assert_eq!(registry.queued_len(), 2, "nothing was added");
        assert_eq!(
            registry.accept("A", "A3", DIGEST, 0, Timeout::at(1).into_deadline()),
            Accept::QueueFull,
            "a deadline does not buy capacity"
        );
    }

    struct Timeout(Instant);

    impl Timeout {
        fn at(seconds: u64) -> Self {
            Self(Instant::now() + Duration::from_secs(seconds))
        }

        fn into_deadline(self) -> Option<Instant> {
            Some(self.0)
        }
    }

    /// A queue deadline parks nobody forever: an execution still waiting when it expires is
    /// terminal, and the slot it never held is not disturbed.
    #[test]
    fn a_queued_execution_expires_at_its_deadline() {
        let mut registry = registry();
        open(&mut registry, "A");
        accept(&mut registry, "A", "A1");
        let deadline = Some(Instant::now() + Duration::from_millis(10));
        let second = registry.accept("A", "A2", DIGEST, 0, deadline);
        assert_eq!(second, Accept::Queued { position: 1 });

        assert!(registry.expire_queued(Instant::now()).is_empty());
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            registry.expire_queued(Instant::now()),
            vec![("A2".to_owned(), "A".to_owned())]
        );
        assert_eq!(registry.terminal_of("A2").unwrap().outcome, "timedOut");
        assert_eq!(registry.queued_len(), 1, "A1 is still waiting its turn");
        assert_eq!(
            registry.dispatch_one().as_deref(),
            Some("A1"),
            "the running execution was untouched"
        );
    }

    /// Mount changes cannot be applied under a running execution on a shared VM.
    #[test]
    fn a_session_with_unfinished_work_refuses_mount_changes() {
        let mut registry = registry();
        open(&mut registry, "A");
        assert!(!registry.session_has_unfinished("A"), "nothing started yet");
        accept(&mut registry, "A", "A1");
        assert!(registry.session_has_unfinished("A"));
        registry.cancel("A1");
        assert!(!registry.session_has_unfinished("A"), "cancelled work is finished");
    }

    /// Finished detail is retained but bounded, so a long-lived VM cannot grow without limit.
    #[test]
    fn finished_records_are_bounded() {
        let mut registry = registry();
        registry.set_finished_limit(2);
        open(&mut registry, "A");
        for id in ["A1", "A2", "A3"] {
            accept(&mut registry, "A", id);
            registry.dispatch_one();
            registry.finish(id, Terminal::new("exited", Some(0), ""));
        }
        assert!(registry.terminal_of("A1").is_none(), "the oldest was evicted");
        assert!(registry.terminal_of("A3").is_some());
    }

    /// Renaming the arguments behind a finished id must not be mistaken for a repeat: the
    /// digest has to survive the terminal state, or "same id, new command" runs as a no-op
    /// with somebody else's exit code.
    #[test]
    fn a_finished_id_still_reports_conflicting_arguments() {
        let mut registry = registry();
        open(&mut registry, "A");
        accept(&mut registry, "A", "A1");
        registry.dispatch_one();
        registry.finish("A1", Terminal::new("exited", Some(0), ""));

        assert_eq!(
            registry.accept("A", "A1", DIGEST ^ 1, 0, None),
            Accept::Conflict
        );
        assert!(matches!(
            registry.accept("A", "A1", DIGEST, 0, None),
            Accept::Duplicate { .. }
        ));
    }

    /// The VM may only be reclaimed when nothing refers to it any more.
    #[test]
    fn the_vm_is_idle_only_after_every_reference_is_gone() {
        let mut registry = registry();
        open(&mut registry, "A");
        accept(&mut registry, "A", "A1");
        registry.dispatch_one();
        assert!(!registry.is_idle());

        registry.close_session("A");
        assert!(!registry.is_idle(), "A1 is still being cleaned up");
        registry.finish("A1", Terminal::cancelled("session closed"));
        assert!(registry.is_idle(), "no session, no queue, nothing running");
    }
}
