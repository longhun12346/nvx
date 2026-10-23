//! Bounded request queues for the control plane.
//!
//! Requests are accepted by a fixed set of workers, not by a thread per request: a caller that
//! sends faster than the sidecar can answer must be told so, and the sidecar must not grow a
//! thread for every message it receives. Two queues exist because the two kinds of request
//! have different deadlines:
//!
//! * **work** (open a session, start an execution) may be slow — a VM boots, a workspace is
//!   exported — and is bounded so a burst cannot exhaust memory.
//! * **control** (cancel, close, status, diagnostics) must still be served while the work queue
//!   is saturated, which is exactly when a caller needs to cancel or ask what happened.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};

struct State<T> {
    items: VecDeque<T>,
    closed: bool,
}

pub struct Queue<T> {
    state: Mutex<State<T>>,
    changed: Condvar,
    capacity: usize,
}

impl<T> Queue<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(State {
                items: VecDeque::new(),
                closed: false,
            }),
            changed: Condvar::new(),
            capacity: capacity.max(1),
        }
    }

    /// Queues one item, or hands it back when the queue is full.
    ///
    /// Never blocks: the caller answers the request with an overload error instead, so a
    /// saturated queue is visible to the caller rather than felt as a hang.
    pub fn try_push(&self, item: T) -> Result<(), T> {
        let mut state = self.state.lock().unwrap();
        if state.closed || state.items.len() >= self.capacity {
            return Err(item);
        }
        state.items.push_back(item);
        self.changed.notify_one();
        Ok(())
    }

    /// Takes the next item, waiting until there is one. `None` means the queue is closed and
    /// drained, which is how a worker learns to exit.
    pub fn pop(&self) -> Option<T> {
        let mut state = self.state.lock().unwrap();
        loop {
            if let Some(item) = state.items.pop_front() {
                return Some(item);
            }
            if state.closed {
                return None;
            }
            state = self.changed.wait(state).unwrap();
        }
    }

    /// Stops accepting and wakes every worker; already queued items are still returned first.
    pub fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        self.changed.notify_all();
    }

    pub fn depth(&self) -> usize {
        self.state.lock().unwrap().items.len()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn items_come_back_in_order() {
        let queue: Queue<u32> = Queue::new(4);
        for value in 0..4 {
            queue.try_push(value).unwrap();
        }
        for value in 0..4 {
            assert_eq!(queue.pop(), Some(value));
        }
    }

    /// Admission is bounded and reported, so the caller can be refused instead of the sidecar
    /// buffering without limit.
    #[test]
    fn a_full_queue_hands_the_item_back() {
        let queue: Queue<u32> = Queue::new(2);
        queue.try_push(1).unwrap();
        queue.try_push(2).unwrap();
        assert_eq!(queue.try_push(3), Err(3));
        assert_eq!(queue.depth(), 2);
    }

    /// A worker blocked on an empty queue must wake up and exit when the queue closes;
    /// otherwise shutdown would wait for a message that is never coming.
    #[test]
    fn closing_wakes_a_waiting_worker() {
        let queue = Arc::new(Queue::<u32>::new(2));
        let waiting = Arc::clone(&queue);
        let worker = std::thread::spawn(move || waiting.pop());
        std::thread::sleep(Duration::from_millis(20));
        queue.close();
        assert_eq!(worker.join().unwrap(), None);
    }

    /// Closing must not drop work that was already accepted.
    #[test]
    fn closing_still_returns_queued_items() {
        let queue: Queue<u32> = Queue::new(2);
        queue.try_push(7).unwrap();
        queue.close();
        assert_eq!(queue.pop(), Some(7));
        assert_eq!(queue.pop(), None);
        assert_eq!(queue.try_push(8), Err(8));
    }
}
