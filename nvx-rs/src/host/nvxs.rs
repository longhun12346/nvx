//! The host's I/O driver of an NVXS session: [`HostConnection`] runs the host's role of
//! [`protocol::nvxs`](crate::protocol::nvxs) over a platform [`Transport`], for NVX's control
//! protocol or any other application protocol.
//!
//! [`HostConnection::attach`] sends the launch capability and waits until the broker attaches the
//! host. [`send`](HostConnection::send) writes application bytes in as many DATA records as they
//! take, and [`receive`](HostConnection::receive) returns the payload of each DATA record from the
//! guest, in order. The connection reads at most 16 KiB at a time and keeps what it read until
//! the session consumes it, besides at most one partial record, so a receive that times out loses
//! nothing and callers can poll with short deadlines.
//!
//! A failure that leaves the stream unusable ends the connection, and every later call fails with
//! [`HostConnectionError::Ended`]. That includes a send that fails or times out after it wrote
//! anything, because a record or a message that the transport took only in part cannot be
//! resumed.
//!
//! # Example
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::{Duration, Instant};
//!
//! use nvx::host::nvxs::HostConnection;
//! use nvx::host::session;
//! # let (endpoint, pid, start_time) = ("", 0, 0);
//! # let capability = [0; nvx::protocol::CAPABILITY_LEN];
//!
//! // The VM's control endpoint, OpenVMM's process, and the capability that it was launched with.
//! let deadline = Instant::now() + Duration::from_secs(10);
//! let transport = session::connect(endpoint, pid, start_time, deadline)?;
//! let mut connection = HostConnection::attach(transport, &capability, deadline)?;
//! connection.send(b"a message of the application's protocol", Some(deadline))?;
//! let payload = connection.receive(Some(deadline))?;
//! # Ok(())
//! # }
//! ```

use std::fmt;
use std::io;
use std::time::{Duration, Instant};

use super::platform::Transport;
use crate::protocol::CAPABILITY_LEN;
use crate::protocol::nvxs::{
    ErrorCode, HostEvent, HostSession, Identity, RecordType, SessionError,
};

/// Most bytes that one read from the transport takes.
const READ_CHUNK: usize = 16 * 1024;

/// Failure of a [`HostConnection`].
#[derive(Debug)]
#[non_exhaustive]
pub enum HostConnectionError {
    /// The deadline passed. A receive that times out keeps what arrived, and the connection stays
    /// usable, as it does after a send that times out before it wrote anything.
    TimedOut,
    /// The broker closed the stream at a record boundary.
    Closed,
    /// The broker refused the host's attachment.
    Rejected(ErrorCode),
    /// The broker reset the session, which ended the host's attachment. The identity is the
    /// session's new one.
    Reset(Identity),
    /// The broker violated the protocol, or the stream ended inside a record.
    Protocol(SessionError),
    /// The transport failed.
    Io(io::Error),
    /// An earlier failure ended the connection.
    Ended,
}

impl fmt::Display for HostConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut => formatter.write_str("the NVXS operation timed out"),
            Self::Closed => formatter.write_str("the broker closed the NVXS session"),
            Self::Rejected(code) => {
                write!(formatter, "the broker refused the NVXS attachment: {code}")
            }
            Self::Reset(identity) => write!(
                formatter,
                "the broker reset the NVXS session to epoch {}",
                identity.epoch
            ),
            Self::Protocol(error) => error.fmt(formatter),
            Self::Io(error) => write!(formatter, "NVXS I/O failed: {error}"),
            Self::Ended => formatter.write_str("an earlier failure ended the NVXS connection"),
        }
    }
}

impl std::error::Error for HostConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// The host's end of an NVXS session over a platform transport.
pub struct HostConnection {
    /// Transport connected to the broker's host endpoint.
    transport: Box<dyn Transport>,
    /// The host's role of the session.
    session: HostSession,
    /// Identity that the broker attached the host to.
    identity: Identity,
    /// Bytes read from the transport.
    input: Box<[u8]>,
    /// Start of the bytes in `input` that the session has not consumed.
    start: usize,
    /// End of the bytes in `input`.
    end: usize,
    /// Records encoded for the transport.
    output: Vec<u8>,
    /// Whether a failure ended the connection.
    ended: bool,
}

impl HostConnection {
    /// Attaches the host to the broker over `transport` with the launch `capability`, and waits
    /// until `deadline` while the broker asks the host to wait for the guest.
    pub fn attach(
        transport: Box<dyn Transport>,
        capability: &[u8; CAPABILITY_LEN],
        deadline: Instant,
    ) -> Result<Self, HostConnectionError> {
        let mut connection = Self {
            transport,
            session: HostSession::new(),
            // The broker's READY replaces this before the caller sees the connection.
            identity: Identity {
                instance_id: [0; 16],
                epoch: 0,
            },
            input: vec![0; READ_CHUNK].into_boxed_slice(),
            start: 0,
            end: 0,
            output: Vec::new(),
            ended: false,
        };
        connection
            .session
            .attach(capability, &mut connection.output)
            .map_err(HostConnectionError::Protocol)?;
        let timeout = remaining(Some(deadline))?;
        connection.write(timeout)?;
        loop {
            match connection.next_event(Some(deadline))? {
                HostEvent::Wait => {}
                HostEvent::Attached(identity) => {
                    connection.identity = identity;
                    return Ok(connection);
                }
                HostEvent::Rejected(code) => return Err(HostConnectionError::Rejected(code)),
                // The session reports these only once the broker attached the host.
                HostEvent::Data(_) => return Err(unexpected(RecordType::Data)),
                HostEvent::Reset(_) => return Err(unexpected(RecordType::Reset)),
            }
        }
    }

    /// Returns the identity that the broker attached the host to.
    pub fn identity(&self) -> Identity {
        self.identity
    }

    /// Returns the host's role of the session.
    pub fn session(&self) -> &HostSession {
        &self.session
    }

    /// Sends `data` to the guest by `deadline`, or without a time limit, in as many DATA records
    /// as it takes, of at most [`OUTER_MAX_PAYLOAD`](crate::protocol::OUTER_MAX_PAYLOAD) bytes
    /// each.
    ///
    /// Data that fits one record travels in one, so an application protocol that needs one frame
    /// per record sends frames that fit. Empty data sends nothing.
    pub fn send(
        &mut self,
        data: &[u8],
        deadline: Option<Instant>,
    ) -> Result<(), HostConnectionError> {
        self.check()?;
        let mut rest = data;
        let mut wrote = false;
        while !rest.is_empty() {
            let timeout = match remaining(deadline) {
                Ok(timeout) => timeout,
                Err(error) if wrote => return Err(self.end(error)),
                Err(error) => return Err(error),
            };
            self.output.clear();
            let taken = self
                .session
                .send(rest, &mut self.output)
                .map_err(|error| self.end(HostConnectionError::Protocol(error)))?;
            self.write(timeout)?;
            wrote = true;
            rest = &rest[taken..];
        }
        Ok(())
    }

    /// Returns the payload of the next DATA record from the guest, waiting until `deadline`, or
    /// without a time limit.
    pub fn receive(&mut self, deadline: Option<Instant>) -> Result<Vec<u8>, HostConnectionError> {
        self.check()?;
        let error = match self.next_event(deadline)? {
            HostEvent::Data(payload) => return Ok(payload),
            HostEvent::Reset(identity) => HostConnectionError::Reset(identity),
            // The session reports these only while the broker attaches the host.
            HostEvent::Wait => unexpected(RecordType::Wait),
            HostEvent::Attached(_) => unexpected(RecordType::Ready),
            HostEvent::Rejected(_) => unexpected(RecordType::Error),
        };
        Err(self.end(error))
    }

    /// Returns the session's next event, reading from the transport until a record completes.
    fn next_event(&mut self, deadline: Option<Instant>) -> Result<HostEvent, HostConnectionError> {
        loop {
            if self.start < self.end {
                let (consumed, event) = self
                    .session
                    .receive(&self.input[self.start..self.end])
                    .map_err(|error| self.end(HostConnectionError::Protocol(error)))?;
                self.start += consumed;
                match event {
                    Some(event) => return Ok(event),
                    None => continue,
                }
            }
            let timeout = remaining(deadline)?;
            match self.transport.read(&mut self.input, timeout) {
                Ok(0) => {
                    let error = match self.session.disconnect() {
                        Ok(()) => HostConnectionError::Closed,
                        Err(error) => HostConnectionError::Protocol(error),
                    };
                    return Err(self.end(error));
                }
                Ok(count) => {
                    self.start = 0;
                    self.end = count.min(self.input.len());
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    return Err(HostConnectionError::TimedOut);
                }
                Err(error) => return Err(self.end(HostConnectionError::Io(error))),
            }
        }
    }

    /// Writes the encoded records within `timeout`, ending the connection if that fails.
    fn write(&mut self, timeout: Option<Duration>) -> Result<(), HostConnectionError> {
        self.transport
            .write_all(&self.output, timeout)
            .map_err(|error| {
                let error = if error.kind() == io::ErrorKind::TimedOut {
                    HostConnectionError::TimedOut
                } else {
                    HostConnectionError::Io(error)
                };
                self.end(error)
            })
    }

    /// Fails if an earlier failure ended the connection.
    fn check(&self) -> Result<(), HostConnectionError> {
        if self.ended {
            Err(HostConnectionError::Ended)
        } else {
            Ok(())
        }
    }

    /// Ends the connection with `error`, and returns it.
    fn end(&mut self, error: HostConnectionError) -> HostConnectionError {
        self.ended = true;
        error
    }
}

/// Converts a deadline into the time left, failing once it has passed.
fn remaining(deadline: Option<Instant>) -> Result<Option<Duration>, HostConnectionError> {
    match deadline {
        None => Ok(None),
        Some(deadline) => deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .map(Some)
            .ok_or(HostConnectionError::TimedOut),
    }
}

/// Returns the failure for an event that the session reports in no state that the connection
/// calls it in.
fn unexpected(record_type: RecordType) -> HostConnectionError {
    HostConnectionError::Protocol(SessionError::Unexpected(record_type))
}
