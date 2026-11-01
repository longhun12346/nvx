//! Collecting the statuses of the processes that a guest init or agent starts.
//!
//! A process has one status collector: the caller. Nothing in the guest libraries waits for an
//! arbitrary child, which could take the status of a child that another part of the caller
//! started. A [`Child`] waits only for the child that it names, with `waitid` on the child's
//! pidfd or on its process ID, and leaves the status of every other child to the caller.
//!
//! A caller that must collect the status of every child, such as a PID 1 that adopts orphaned
//! processes, keeps its own `waitpid(-1)` loop instead, and hands each status that it collects to
//! the [`Child`] that it belongs to with [`Child::observe`]:
//!
//! ```no_run
//! use std::process::ExitStatus;
//!
//! use nvx::guest::process::Child;
//! use nvx::guest::spawn::Command;
//!
//! /// The caller's own `waitpid(-1, WNOHANG)` loop, which returns the ID and the status of one
//! /// child that has ended.
//! fn reap_any() -> Option<(u32, ExitStatus)> {
//!     # unimplemented!()
//! }
//!
//! # fn main() -> std::io::Result<()> {
//! let spawned = Command::new(c"/bin/true".to_owned(), vec![c"true".to_owned()]).spawn()?;
//! let mut child = Child::new(spawned.id())?;
//! while child.status().is_none() {
//!     if let Some((id, status)) = reap_any() {
//!         child.observe(id, status);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Any other caller lets each [`Child`] collect its own status, for example once its
//! [pidfd](Child::pidfd) polls readable:
//!
//! ```no_run
//! use nvx::guest::process::Child;
//! use nvx::guest::spawn::Command;
//!
//! # fn main() -> std::io::Result<()> {
//! let spawned = Command::new(c"/bin/true".to_owned(), vec![c"true".to_owned()]).spawn()?;
//! let mut child = Child::with_pidfd(spawned.id())?;
//! // Poll `child.pidfd()` with the caller's other descriptors until it is readable, then:
//! let status = child.wait()?;
//! assert!(status.success());
//! # Ok(())
//! # }
//! ```

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use super::sys::{self, Errno, ProcessId, WaitTarget};

/// A child process that the caller started and whose status it collects.
///
/// Unlike [`std::process::Child`], it neither starts the process nor holds its standard streams:
/// it names a child of the caller, for example one that [`spawn`](super::spawn) started, and
/// keeps its status once it has one. Dropping it neither waits for the child nor stops it.
///
/// Its status is the one with which it ended: an exit, or a terminating signal. A stop does not
/// end it, not even one that a wait reports to the caller as the child's tracer. A wait names the
/// child whatever signal the child reports its end with: one that `clone` started with an exit
/// signal other than `SIGCHLD`, or none, reports with that signal until it runs a program.
#[derive(Debug)]
pub struct Child {
    /// The child's process ID.
    process: ProcessId,
    /// A pidfd that refers to the child, through which waits name it.
    pidfd: Option<OwnedFd>,
    /// The status with which the child ended, once a wait or an observation collected it.
    status: Option<ExitStatus>,
}

impl Child {
    /// Names the caller's child `id`, whose status nothing has collected yet. Its waits use
    /// `waitid` on the process ID, which names the child for as long as its status stays
    /// uncollected: a caller with a collector of its own hands the child every status that
    /// the collector takes for `id`, with [`observe`](Self::observe), before the child waits, as
    /// the process ID may name another process afterwards. A pidfd keeps naming the child
    /// whatever collects its status; see [`with_pidfd`](Self::with_pidfd).
    ///
    /// An ID of 0, or one above `i32::MAX`, which no process can have, is `EINVAL`.
    pub fn new(id: u32) -> io::Result<Self> {
        Ok(Self {
            process: process_id(id)?,
            pidfd: None,
            status: None,
        })
    }

    /// Names the caller's child `id`, whose status nothing has collected yet, by a new pidfd,
    /// which [`pidfd`](Self::pidfd) lends for polling: it polls readable once the child ends.
    /// Its waits use `waitid` on the pidfd, which keeps naming the child even after another
    /// collector takes its status. The pidfd is opened at once, while the process ID still names
    /// the child.
    ///
    /// An ID of 0, or one above `i32::MAX`, is `EINVAL`, and one that names no process `ESRCH`.
    pub fn with_pidfd(id: u32) -> io::Result<Self> {
        let process = process_id(id)?;
        let pidfd = sys::open_pidfd(process)?;
        Ok(Self {
            process,
            pidfd: Some(pidfd.into()),
            status: None,
        })
    }

    /// Names the caller's child `id` by `pidfd`, a pidfd for it that the caller holds, such as the
    /// one that `clone3` returns with `CLONE_PIDFD`, which [`pidfd`](Self::pidfd) lends for
    /// polling. Its waits use `waitid` on the pidfd, as with [`with_pidfd`](Self::with_pidfd).
    /// Nothing is opened by the child's ID, so a collector of the caller's may have taken the
    /// child's status already: a wait is `ECHILD` then, and that collector hands the status over
    /// with [`observe`](Self::observe). A pidfd that its opener made nonblocking, as
    /// `PIDFD_NONBLOCK` does, makes [`wait`](Self::wait) fail with `WouldBlock` while the child
    /// runs, as `waitid` through it does; [`try_wait`](Self::try_wait) and the pidfd's polls work
    /// as with any other, and so does an execution that adopts the child, which never blocks on
    /// its status.
    ///
    /// The pidfd must refer to the process `id`, which is not checked: statuses are matched to the
    /// child by that ID, and an execution signals the process group that the child leads by that
    /// ID before Linux 6.9.
    ///
    /// An ID of 0, or one above `i32::MAX`, is `EINVAL`.
    pub fn from_pidfd(id: u32, pidfd: OwnedFd) -> io::Result<Self> {
        Ok(Self {
            process: process_id(id)?,
            pidfd: Some(pidfd),
            status: None,
        })
    }

    /// Names the crate's own child, for the callers that hold its [`ProcessId`].
    pub(crate) fn from_process(process: ProcessId) -> Self {
        Self {
            process,
            pidfd: None,
            status: None,
        }
    }

    /// Opens a pidfd for the child by its ID, unless the child has one already or has ended: the
    /// ID names the child alone only while its status stays uncollected, which the caller
    /// guarantees until this returns.
    pub(crate) fn open_pidfd(&mut self) -> io::Result<()> {
        if self.pidfd.is_none() && self.status.is_none() {
            self.pidfd = Some(sys::open_pidfd(self.process)?.into());
        }
        Ok(())
    }

    /// Returns the child's process ID.
    pub fn id(&self) -> u32 {
        self.process.raw().unsigned_abs()
    }

    /// Returns the child's process ID for the crate's own callers.
    pub(crate) fn process(&self) -> ProcessId {
        self.process
    }

    /// Lends the child's pidfd, if [`with_pidfd`](Self::with_pidfd) opened one or
    /// [`from_pidfd`](Self::from_pidfd) took one, which polls readable once the child ends.
    pub fn pidfd(&self) -> Option<BorrowedFd<'_>> {
        self.pidfd.as_ref().map(AsFd::as_fd)
    }

    /// Returns the status with which the child ended, once a wait or
    /// [`observe`](Self::observe) collected it.
    pub fn status(&self) -> Option<ExitStatus> {
        self.status
    }

    /// Hands the child the status that the caller's own collector, such as its `waitpid(-1)`
    /// loop, collected for the process `id`, and returns whether it was this child's final
    /// status, which the child then keeps.
    ///
    /// Only a status with which a process ended counts: an exit, or a terminating signal. A stop
    /// or a continuation, which a collector that waits with `WUNTRACED` or `WCONTINUED` reports
    /// while the process lives, is not recorded, and this returns `false`. Only the first final
    /// status counts too: once the child has one, a later status for its ID belongs to another
    /// process that the ID was reused for, and this returns `false`.
    pub fn observe(&mut self, id: u32, status: ExitStatus) -> bool {
        let ended = status.code().is_some() || status.signal().is_some();
        if !ended || self.status.is_some() || id != self.id() {
            return false;
        }
        self.status = Some(status);
        true
    }

    /// Collects the child's status if it has ended, without blocking, and returns it, or `None`
    /// while the child runs. Once the child has a status, this returns it again.
    ///
    /// It collects no other child's status. A child that a pidfd names, and whose status another
    /// collector took without handing it over with [`observe`](Self::observe), is `ECHILD`.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.collect(false)
    }

    /// Waits until the child ends, collects its status, and returns it. Once the child has a
    /// status, this returns it again at once.
    ///
    /// It collects no other child's status. A child that a pidfd names, and whose status another
    /// collector took without handing it over with [`observe`](Self::observe), is `ECHILD`.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.collect(true)?
            .ok_or_else(|| io::Error::from(Errno::ECHILD))
    }

    /// Returns the child's status, which a wait for this child alone collects if the child has
    /// none yet, blocking until it ends when `block` is set.
    fn collect(&mut self, block: bool) -> io::Result<Option<ExitStatus>> {
        if self.status.is_none() {
            let target = match &self.pidfd {
                Some(pidfd) => WaitTarget::Pidfd(pidfd.as_fd()),
                None => WaitTarget::Process(self.process),
            };
            self.status = sys::wait_named(target, block)?.map(ExitStatus::from_raw);
        }
        Ok(self.status)
    }
}

/// Returns the process ID `id`, or `EINVAL` for one that no process can have.
fn process_id(id: u32) -> io::Result<ProcessId> {
    ProcessId::from_positive(i64::from(id)).ok_or_else(|| io::Error::from(Errno::EINVAL))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use nix::poll::{PollFd, PollFlags, PollTimeout};

    use super::*;
    use crate::guest::spawn::shell;

    /// Spawns `/bin/sh -c script` and returns its process ID.
    fn spawn_shell(script: &str) -> u32 {
        shell(script).spawn().unwrap().id()
    }

    /// Returns whether `pidfd` polls readable within `timeout`.
    fn readable(pidfd: BorrowedFd<'_>, timeout: Duration) -> bool {
        let mut descriptors = [PollFd::new(pidfd, PollFlags::POLLIN)];
        let timeout = PollTimeout::try_from(timeout).unwrap();
        nix::poll::poll(&mut descriptors, timeout).unwrap() == 1
    }

    /// Spawns a child that ends at once, and waits until it has ended without collecting its
    /// status.
    fn unrelated_zombie() -> std::process::Child {
        let child = std::process::Command::new("/bin/true").spawn().unwrap();
        let process = ProcessId::from_child(&child);
        while !sys::has_exited(process).unwrap() {
            std::thread::yield_now();
        }
        child
    }

    #[test]
    fn a_named_child_s_status_is_collected_and_no_other() {
        let mut unrelated = unrelated_zombie();
        for (script, code, signal) in [
            ("exit 3", Some(3), None),
            ("kill -TERM $$", None, Some(nix::libc::SIGTERM)),
            // A real-time signal, which `nix`'s wait decoding cannot represent.
            ("kill -40 $$", None, Some(40)),
        ] {
            for with_pidfd in [false, true] {
                let id = spawn_shell(script);
                let mut child = if with_pidfd {
                    Child::with_pidfd(id).unwrap()
                } else {
                    Child::new(id).unwrap()
                };
                assert_eq!(child.id(), id);
                assert_eq!(child.pidfd().is_some(), with_pidfd);
                let status = child.wait().unwrap();
                assert_eq!((status.code(), status.signal()), (code, signal), "{script}");
                // The status stays, and no further wait takes place.
                assert_eq!(child.try_wait().unwrap(), Some(status));
                assert_eq!(child.wait().unwrap(), status);
                assert_eq!(child.status(), Some(status));
            }
        }
        // Every wait named its child, so the unrelated child's status is still there.
        assert!(unrelated.try_wait().unwrap().unwrap().success());
    }

    #[test]
    fn a_pidfd_polls_readable_once_its_child_ends() {
        let (reader, mut writer) = std::io::pipe().unwrap();
        let spawned = shell("read line").stdin(reader).spawn().unwrap();
        let mut child = Child::with_pidfd(spawned.id()).unwrap();
        let pidfd = child.pidfd().unwrap().try_clone_to_owned().unwrap();
        assert!(!readable(pidfd.as_fd(), Duration::ZERO));
        assert_eq!(child.try_wait().unwrap(), None);
        std::io::Write::write_all(&mut writer, b"go\n").unwrap();
        assert!(readable(pidfd.as_fd(), Duration::from_secs(10)));
        assert!(child.try_wait().unwrap().unwrap().success());
    }

    #[test]
    fn a_child_named_by_the_caller_s_pidfd_is_waited_for_through_it() {
        let id = spawn_shell("exit 4");
        let pidfd = sys::open_pidfd(process_id(id).unwrap()).unwrap();
        let mut child = Child::from_pidfd(id, pidfd.into()).unwrap();
        assert_eq!(child.id(), id);
        assert!(child.pidfd().is_some());
        assert_eq!(child.wait().unwrap().code(), Some(4));
        // A collector of the caller's that took the status first leaves the pidfd's wait none,
        // until it hands the status over.
        let id = spawn_shell("exit 5");
        let pidfd = sys::open_pidfd(process_id(id).unwrap()).unwrap();
        let collected = Child::new(id).unwrap().wait().unwrap();
        let mut child = Child::from_pidfd(id, pidfd.into()).unwrap();
        assert_eq!(sys::errno_of(&child.try_wait().unwrap_err()), Errno::ECHILD);
        assert!(child.observe(id, collected));
        assert_eq!(child.wait().unwrap().code(), Some(5));
        // No process can have these IDs.
        for id in [0, 1 << 31] {
            let pidfd = OwnedFd::from(std::fs::File::open("/dev/null").unwrap());
            let error = Child::from_pidfd(id, pidfd).unwrap_err();
            assert_eq!(sys::errno_of(&error), Errno::EINVAL);
        }
    }

    #[test]
    fn a_child_that_reports_its_end_with_no_signal_is_waited_for() {
        let id = sys::spawn_child_without_exit_signal(7)
            .unwrap()
            .raw()
            .unsigned_abs();
        let mut child = Child::with_pidfd(id).unwrap();
        assert!(readable(child.pidfd().unwrap(), Duration::from_secs(10)));
        assert_eq!(child.try_wait().unwrap().unwrap().code(), Some(7));
        let id = sys::spawn_child_without_exit_signal(8)
            .unwrap()
            .raw()
            .unsigned_abs();
        assert_eq!(Child::new(id).unwrap().wait().unwrap().code(), Some(8));
    }

    #[test]
    fn an_observed_status_belongs_to_its_child_alone() {
        // The test collects the child's status itself, as a PID 1's own loop would.
        let mut process = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 7"])
            .spawn()
            .unwrap();
        let id = process.id();
        let collected = process.wait().unwrap();
        let mut child = Child::new(id).unwrap();
        assert!(!child.observe(id + 1, ExitStatus::from_raw(0)));
        assert_eq!(child.status(), None);
        assert!(child.observe(id, collected));
        // A later status for the ID belongs to another process.
        assert!(!child.observe(id, ExitStatus::from_raw(0)));
        assert_eq!(child.status().unwrap().code(), Some(7));
        // The observed status answers the waits, which would otherwise find no child.
        assert_eq!(child.try_wait().unwrap(), Some(collected));
        assert_eq!(child.wait().unwrap(), collected);
    }

    #[test]
    fn stops_and_continuations_do_not_end_an_observed_child() {
        // The statuses that `waitpid` reports with `WUNTRACED` and `WCONTINUED` for a child that
        // lives on.
        let stopped = ExitStatus::from_raw((nix::libc::SIGSTOP << 8) | 0x7f);
        let continued = ExitStatus::from_raw(0xffff);
        assert_eq!(stopped.stopped_signal(), Some(nix::libc::SIGSTOP));
        assert!(continued.continued());
        let mut child = Child::new(4242).unwrap();
        for status in [stopped, continued] {
            assert!(!child.observe(4242, status), "{status:?}");
            assert_eq!(child.status(), None);
        }
        // The final status still counts.
        let killed = ExitStatus::from_raw(nix::libc::SIGKILL);
        assert!(child.observe(4242, killed));
        assert_eq!(child.status().unwrap().signal(), Some(nix::libc::SIGKILL));
        assert!(!child.observe(4242, stopped));
        assert_eq!(child.status(), Some(killed));
    }

    /// Returns whether the process `id` reaches a tracing stop within ten seconds, or `false` once
    /// it has ended instead.
    fn stops_for_its_tracer(id: u32) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let stat = std::fs::read_to_string(format!("/proc/{id}/stat")).unwrap();
            // The state follows the command name, in parentheses, which may hold any character.
            match stat
                .rsplit_once(") ")
                .and_then(|(_, rest)| rest.chars().next())
            {
                Some('t') => return true,
                Some('Z') => return false,
                _ => {}
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{id} neither stopped nor ended"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_traced_child_s_stop_does_not_end_it() {
        for with_pidfd in [false, true] {
            let id = sys::spawn_traced_child(7).raw().unsigned_abs();
            let mut child = if with_pidfd {
                Child::with_pidfd(id)
            } else {
                Child::new(id)
            }
            .unwrap();
            if !stops_for_its_tracer(id) {
                // The system refuses tracing, which leaves nothing to check.
                assert_eq!(child.wait().unwrap().code(), Some(99));
                return;
            }
            // A wait reports the stop to the child's tracer whatever its options, but the child
            // still runs.
            assert_eq!(child.try_wait().unwrap(), None);
            assert_eq!(child.status(), None);
            sys::continue_traced(child.process());
            assert_eq!(child.wait().unwrap().code(), Some(7));
        }
        // A blocking wait goes on past the stop until the child ends, here by `SIGKILL`.
        let id = sys::spawn_traced_child(7).raw().unsigned_abs();
        let mut child = Child::new(id).unwrap();
        assert!(stops_for_its_tracer(id));
        let killer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            let process = nix::unistd::Pid::from_raw(i32::try_from(id).unwrap());
            nix::sys::signal::kill(process, nix::sys::signal::Signal::SIGKILL).unwrap();
        });
        assert_eq!(child.wait().unwrap().signal(), Some(nix::libc::SIGKILL));
        killer.join().unwrap();
    }

    #[test]
    fn a_child_whose_status_another_collector_took_is_echild() {
        let mut process = std::process::Command::new("/bin/true").spawn().unwrap();
        let mut child = Child::with_pidfd(process.id()).unwrap();
        // Another collector takes the status, and hands it over to no one.
        process.wait().unwrap();
        assert_eq!(
            child.try_wait().unwrap_err().raw_os_error(),
            Some(Errno::ECHILD as i32)
        );
        assert_eq!(
            child.wait().unwrap_err().raw_os_error(),
            Some(Errno::ECHILD as i32)
        );
        assert_eq!(child.status(), None);
    }

    #[test]
    fn ids_that_no_process_can_have_are_refused() {
        for id in [0, i32::MAX.unsigned_abs() + 1, u32::MAX] {
            for result in [Child::new(id), Child::with_pidfd(id)] {
                assert_eq!(
                    result.unwrap_err().raw_os_error(),
                    Some(Errno::EINVAL as i32),
                    "{id}"
                );
            }
        }
    }
}
