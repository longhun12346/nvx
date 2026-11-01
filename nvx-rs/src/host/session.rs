//! Host side of an authenticated control session with a sandbox's guest agent: NVX's control
//! protocol, `NVXC`, over the host's role of the shared NVXS session, [`HostConnection`].

use std::fmt;
use std::io;
use std::thread;
use std::time::{Duration, Instant};

use super::nvxs::{HostConnection, HostConnectionError};
use super::platform::{self, Transport};
use crate::protocol::nvxs::{self, RecordError, RecordType};
use crate::protocol::{
    self, APP_CANCEL, APP_ERROR, APP_EXEC, APP_EXIT, APP_FEATURES, APP_HEADER_LEN, APP_MAPS,
    APP_PING, APP_READY, APP_STDERR, APP_STDOUT, APP_STOP, APP_STOPPED, CAPABILITY_LEN,
    ExitCategory, GuestFeatures, HostMap, OUTER_MAX_PAYLOAD, ProtocolError, UNSUPPORTED_OPERATION,
    Workload,
};

/// Failure of a control session.
#[derive(Debug)]
pub enum SessionError {
    /// The deadline passed.
    TimedOut,
    /// The OpenVMM process exited.
    ProcessExited,
    /// The endpoint closed the stream.
    Closed,
    /// OpenVMM reset the session.
    Reset,
    /// OpenVMM rejected the capability.
    AuthenticationFailed,
    /// The endpoint cannot be used, for example because another process serves it.
    Refused(io::Error),
    /// The peer violated the protocol.
    Protocol(String),
    /// An I/O error occurred.
    Io(io::Error),
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut => formatter.write_str("the control operation timed out"),
            Self::ProcessExited => formatter.write_str("the OpenVMM process exited"),
            Self::Closed => formatter.write_str("the control endpoint closed the session"),
            Self::Reset => formatter.write_str("the control session was reset"),
            Self::AuthenticationFailed => {
                formatter.write_str("the control endpoint rejected the sandbox capability")
            }
            Self::Refused(error) => write!(formatter, "the control endpoint was refused: {error}"),
            Self::Protocol(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "control I/O failed: {error}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<ProtocolError> for SessionError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error.into_message())
    }
}

impl From<io::Error> for SessionError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::TimedOut {
            Self::TimedOut
        } else {
            Self::Io(error)
        }
    }
}

/// Connects to the control endpoint of OpenVMM process `pid`, retrying until `deadline` while
/// the endpoint is not yet available and the process is still alive.
pub fn connect(
    endpoint: &str,
    pid: u32,
    start_time: u64,
    deadline: Instant,
) -> Result<Box<dyn Transport>, SessionError> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match platform::connect_endpoint(endpoint, pid, remaining.min(Duration::from_millis(250))) {
            Ok(transport) => return Ok(transport),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return Err(SessionError::Refused(error));
            }
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                return Err(SessionError::Io(error));
            }
            Err(_) => {}
        }
        match platform::process_start_time(pid) {
            Ok(Some(current)) if current == start_time => {}
            // An inconclusive check keeps waiting for the endpoint until the deadline.
            Err(_) => {}
            Ok(_) => return Err(SessionError::ProcessExited),
        }
        if Instant::now() >= deadline {
            return Err(SessionError::TimedOut);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// Event observed while an execution runs.
#[derive(Debug, PartialEq, Eq)]
pub enum ExecEvent {
    /// A chunk of the workload's standard output.
    Stdout(Vec<u8>),
    /// A chunk of the workload's standard error.
    Stderr(Vec<u8>),
    /// The workload ended.
    Exit {
        /// How it ended.
        category: ExitCategory,
        /// Its exit status, 128 plus the signal number for [`ExitCategory::Signal`].
        status: i32,
    },
    /// The guest agent refused the workload, and nothing of it runs any longer.
    Rejected {
        /// The guest's error number.
        status: i32,
        /// The error category, such as [`LAUNCH_FAILED`](crate::protocol::LAUNCH_FAILED),
        /// truncated to 64 characters.
        category: String,
    },
}

/// Authenticated control session: `NVXC` frames, each in one DATA record of the host's NVXS
/// connection to OpenVMM's broker.
///
/// Received bytes are buffered until a whole record is available, so a read that times out
/// loses nothing and callers can poll with short deadlines. A failure that leaves the stream
/// unusable, such as a reset or a record that the protocol does not allow, ends the session, and
/// later calls fail.
pub struct ControlSession {
    /// The host's NVXS connection to OpenVMM's control endpoint.
    connection: HostConnection,
}

impl ControlSession {
    /// Authenticates with the capability OpenVMM received at launch, and waits until `deadline`
    /// while OpenVMM's broker waits for the guest to acknowledge the session.
    pub fn attach(
        transport: Box<dyn Transport>,
        capability: &[u8; CAPABILITY_LEN],
        deadline: Instant,
    ) -> Result<Self, SessionError> {
        let connection = HostConnection::attach(transport, capability, deadline)
            .map_err(|error| failure(error, Stage::Attach))?;
        Ok(Self { connection })
    }

    /// Waits until the guest agent acknowledges readiness.
    pub fn ping(&mut self, deadline: Instant) -> Result<(), SessionError> {
        self.acknowledged(APP_PING, APP_READY, "readiness", deadline)
    }

    /// Asks the guest agent which control features its image provides.
    ///
    /// An agent that predates the request refuses it as an unsupported operation, which means
    /// that the image provides none of them.
    pub fn features(&mut self, deadline: Instant) -> Result<GuestFeatures, SessionError> {
        let request_id = request_id()?;
        self.send_app(APP_FEATURES, request_id, &[], Some(deadline))?;
        let (kind, status, payload) = self.read_reply(request_id, Some(deadline))?;
        match kind {
            APP_READY if status == 0 => Ok(GuestFeatures::decode(&payload)?),
            APP_ERROR if payload == UNSUPPORTED_OPERATION => Ok(GuestFeatures::NONE),
            _ => Err(SessionError::Protocol(
                "the guest agent returned an invalid features response".to_owned(),
            )),
        }
    }

    /// Hands the guest agent the host mapping table, in as many requests as it takes, and waits
    /// until it has mounted every entry.
    pub fn map_host_paths(
        &mut self,
        maps: &[HostMap],
        deadline: Instant,
    ) -> Result<(), SessionError> {
        let payloads = protocol::encode_maps_payloads(maps, OUTER_MAX_PAYLOAD - APP_HEADER_LEN)?;
        for payload in payloads {
            let request_id = request_id()?;
            self.send_app(APP_MAPS, request_id, &payload, Some(deadline))?;
            let (kind, status, payload) = self.read_reply(request_id, Some(deadline))?;
            match kind {
                APP_READY if status == 0 && payload.is_empty() => {}
                APP_ERROR if payload == protocol::MAPPING_FAILED.as_bytes() => {
                    return Err(SessionError::Protocol(format!(
                        "the guest agent could not mount a mapped host path (error {status})"
                    )));
                }
                APP_ERROR => {
                    let category = error_category(&payload);
                    return Err(SessionError::Protocol(format!(
                        "the guest agent did not mount the host paths: {category} (status \
                         {status})"
                    )));
                }
                _ => {
                    return Err(SessionError::Protocol(
                        "the guest agent returned an invalid host mapping response".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Starts a workload and returns the request ID that identifies its events.
    pub fn start_exec(
        &mut self,
        workload: &Workload<'_>,
        deadline: Instant,
    ) -> Result<u64, SessionError> {
        let payload = protocol::encode_exec_payload(workload)?;
        let request_id = request_id()?;
        self.send_app(APP_EXEC, request_id, &payload, Some(deadline))?;
        Ok(request_id)
    }

    /// Reads the next event of the workload started with `request_id`.
    pub fn next_exec_event(
        &mut self,
        request_id: u64,
        deadline: Option<Instant>,
    ) -> Result<ExecEvent, SessionError> {
        let (kind, status, payload) = self.read_reply(request_id, deadline)?;
        match kind {
            APP_STDOUT => Ok(ExecEvent::Stdout(payload)),
            APP_STDERR => Ok(ExecEvent::Stderr(payload)),
            APP_EXIT => Ok(ExecEvent::Exit {
                category: ExitCategory::parse(&payload)?,
                status,
            }),
            APP_ERROR => Ok(ExecEvent::Rejected {
                status,
                category: error_category(&payload),
            }),
            _ => Err(SessionError::Protocol(
                "the guest agent returned an invalid exec response".to_owned(),
            )),
        }
    }

    /// Asks the guest agent to terminate the workload started with `request_id`.
    ///
    /// The guest reports the workload's outcome as a regular exec event, with the cancelled
    /// category if the request arrived before the workload exited. A request for a workload that
    /// already finished is ignored.
    pub fn cancel_exec(&mut self, request_id: u64, deadline: Instant) -> Result<(), SessionError> {
        self.send_app(APP_CANCEL, request_id, &[], Some(deadline))
    }

    /// Asks the guest agent to shut the VM down.
    pub fn stop(&mut self, deadline: Instant) -> Result<(), SessionError> {
        self.acknowledged(APP_STOP, APP_STOPPED, "stop", deadline)
    }

    /// Sends an application request of `kind` with `request_id` and `payload` in the next
    /// sequenced outer record, for a caller that checks the responses itself, as the `nvx-rs`
    /// CLI does with the messages of `nvx.py`.
    pub fn send_request(
        &mut self,
        kind: u8,
        request_id: u64,
        payload: &[u8],
        deadline: Instant,
    ) -> Result<(), SessionError> {
        self.send_app(kind, request_id, payload, Some(deadline))
    }

    /// Reads the next application frame, checked against the session's identity and sequence,
    /// and returns its kind, request ID, status, and payload.
    pub fn read_response(
        &mut self,
        deadline: Option<Instant>,
    ) -> Result<(u8, u64, i32, Vec<u8>), SessionError> {
        self.read_app(deadline)
    }

    /// Encodes and sends one application frame in the next DATA record.
    fn send_app(
        &mut self,
        kind: u8,
        request_id: u64,
        payload: &[u8],
        deadline: Option<Instant>,
    ) -> Result<(), SessionError> {
        let frame = protocol::encode_app(kind, request_id, 0, payload);
        // The guest agent takes each DATA record as one frame, so a frame must fit one.
        if frame.len() > OUTER_MAX_PAYLOAD {
            return Err(SessionError::Protocol(
                "control payload exceeds the outer protocol limit".to_owned(),
            ));
        }
        self.connection
            .send(&frame, deadline)
            .map_err(|error| failure(error, Stage::Data))
    }

    /// Reads and decodes the next application frame, the payload of the next DATA record.
    fn read_app(
        &mut self,
        deadline: Option<Instant>,
    ) -> Result<(u8, u64, i32, Vec<u8>), SessionError> {
        let payload = self
            .connection
            .receive(deadline)
            .map_err(|error| failure(error, Stage::Data))?;
        let frame = protocol::decode_app(&payload)?;
        Ok((
            frame.kind,
            frame.request_id,
            frame.status,
            frame.payload.to_vec(),
        ))
    }

    /// Reads the next application frame, which must answer `request_id`, and returns its kind,
    /// status, and payload.
    fn read_reply(
        &mut self,
        request_id: u64,
        deadline: Option<Instant>,
    ) -> Result<(u8, i32, Vec<u8>), SessionError> {
        let (kind, response_id, status, payload) = self.read_app(deadline)?;
        if response_id != request_id {
            return Err(SessionError::Protocol(
                "the guest agent returned a mismatched request ID".to_owned(),
            ));
        }
        Ok((kind, status, payload))
    }

    /// Sends a request of `kind` without a payload and waits until the guest agent acknowledges
    /// `what` with an empty `reply` of status 0.
    fn acknowledged(
        &mut self,
        kind: u8,
        reply: u8,
        what: &str,
        deadline: Instant,
    ) -> Result<(), SessionError> {
        let request_id = request_id()?;
        self.send_app(kind, request_id, &[], Some(deadline))?;
        let (kind, response_id, status, payload) = self.read_app(Some(deadline))?;
        if kind != reply || response_id != request_id || status != 0 || !payload.is_empty() {
            return Err(SessionError::Protocol(format!(
                "the guest agent did not acknowledge {what}"
            )));
        }
        Ok(())
    }
}

/// Stage of a control session at which a failure arrived, which names a protocol violation.
#[derive(Clone, Copy)]
enum Stage {
    /// The host attaches.
    Attach,
    /// Application frames flow.
    Data,
}

/// Converts a failure of the host's NVXS connection at `stage` into the session's failure.
///
/// A violation keeps the message of the check that it fails: a malformed or oversized header, a
/// payload in WAIT or READY, an empty DATA record, which carries no frame, and otherwise an
/// invalid attach response or data record. A stream that ends inside a record has closed.
fn failure(error: HostConnectionError, stage: Stage) -> SessionError {
    let violation = match error {
        HostConnectionError::TimedOut => return SessionError::TimedOut,
        HostConnectionError::Closed => return SessionError::Closed,
        HostConnectionError::Rejected(_) => return SessionError::AuthenticationFailed,
        HostConnectionError::Reset(_) => return SessionError::Reset,
        HostConnectionError::Io(error) => return error.into(),
        HostConnectionError::Ended => {
            return SessionError::Protocol(
                "the control session ended after an earlier failure".to_owned(),
            );
        }
        HostConnectionError::Protocol(violation) => violation,
    };
    let message = match (violation, stage) {
        (nvxs::SessionError::Truncated { .. }, _) => return SessionError::Closed,
        (
            nvxs::SessionError::Record(
                RecordError::Magic(_) | RecordError::Version(_) | RecordError::Flags(_),
            ),
            _,
        ) => "control endpoint returned an invalid outer record",
        (nvxs::SessionError::Record(RecordError::Length { length, .. }), _)
            if length > OUTER_MAX_PAYLOAD =>
        {
            "control endpoint returned an oversized outer record"
        }
        (
            nvxs::SessionError::Record(RecordError::Length {
                record_type: RecordType::Wait | RecordType::Ready,
                ..
            }),
            Stage::Attach,
        ) => "control attach response carried a payload",
        (
            nvxs::SessionError::Record(RecordError::Length {
                record_type: RecordType::Data,
                length: 0,
            }),
            Stage::Data,
        ) => "control endpoint returned a truncated application frame",
        (_, Stage::Attach) => "control endpoint returned an invalid attach response",
        (_, Stage::Data) => "control endpoint returned an invalid data record",
    };
    SessionError::Protocol(message.to_owned())
}

/// Returns the error category that the payload of an `APP_ERROR` response names, truncated to 64
/// characters.
fn error_category(payload: &[u8]) -> String {
    String::from_utf8_lossy(payload).chars().take(64).collect()
}

/// Generates a random nonzero request identifier.
fn request_id() -> Result<u64, SessionError> {
    loop {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).map_err(|error| SessionError::Io(io::Error::other(error)))?;
        let value = u64::from_le_bytes(bytes);
        if value != 0 {
            return Ok(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::protocol::nvxs::{ErrorCode, Identity};
    use crate::protocol::{
        OUTER_DATA, OUTER_ERROR, OUTER_HEADER_LEN, OUTER_HOST_ATTACH, OUTER_READY, OUTER_RESET,
        OUTER_WAIT, WorkloadEnvironment, decode_app, decode_outer_header, encode_app, encode_outer,
    };

    const INSTANCE: [u8; 16] = [7; 16];

    /// What a test shares with a [`Scripted`] transport.
    #[derive(Default)]
    struct Wire {
        /// Bytes for the host to read.
        input: VecDeque<u8>,
        /// Whether the stream ends once the host read `input`.
        closed: bool,
        /// Bytes that the host wrote.
        output: Vec<u8>,
    }

    /// Transport of a scripted guest, whose records the test supplies at any time. A read
    /// without input times out, or ends the stream once the test closed it.
    #[derive(Clone, Default)]
    struct Scripted(Arc<Mutex<Wire>>);

    impl Scripted {
        /// Supplies records for the host to read.
        fn supply(&self, records: &[Vec<u8>]) {
            self.0.lock().unwrap().input.extend(records.concat());
        }

        /// Ends the stream after the records that the test supplied.
        fn close(&self) {
            self.0.lock().unwrap().closed = true;
        }

        /// Returns the bytes that the host wrote.
        fn output(&self) -> Vec<u8> {
            self.0.lock().unwrap().output.clone()
        }
    }

    impl Transport for Scripted {
        fn read(&mut self, buffer: &mut [u8], _timeout: Option<Duration>) -> io::Result<usize> {
            let mut wire = self.0.lock().unwrap();
            if wire.input.is_empty() {
                return if wire.closed {
                    Ok(0)
                } else {
                    Err(io::ErrorKind::TimedOut.into())
                };
            }
            let count = buffer.len().min(wire.input.len());
            for (byte, input) in buffer.iter_mut().zip(wire.input.drain(..count)) {
                *byte = input;
            }
            Ok(count)
        }

        fn write_all(&mut self, data: &[u8], _timeout: Option<Duration>) -> io::Result<()> {
            self.0.lock().unwrap().output.extend_from_slice(data);
            Ok(())
        }
    }

    fn outer(record_type: u8, epoch: u64, sequence: u64, payload: &[u8]) -> Vec<u8> {
        let instance = if epoch == 0 { [0; 16] } else { INSTANCE };
        encode_outer(record_type, &instance, epoch, sequence, payload).unwrap()
    }

    /// Returns `record` with `bytes` at `offset`.
    fn patched(mut record: Vec<u8>, offset: usize, bytes: &[u8]) -> Vec<u8> {
        record[offset..offset + bytes.len()].copy_from_slice(bytes);
        record
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    /// Attaches through a scripted guest that supplied `records`, and returns the attachment
    /// with the guest's transport.
    fn scripted(records: &[Vec<u8>]) -> (Result<ControlSession, SessionError>, Scripted) {
        let wire = Scripted::default();
        wire.supply(records);
        let session =
            ControlSession::attach(Box::new(wire.clone()), &[1; CAPABILITY_LEN], deadline());
        (session, wire)
    }

    /// Attaches through a scripted guest whose broker attaches the host at its sequence 0, in
    /// epoch 1.
    fn ready() -> (ControlSession, Scripted) {
        let (session, wire) = scripted(&[outer(OUTER_READY, 1, 0, &[])]);
        (session.unwrap(), wire)
    }

    /// Kind and payload of each application request that a guest received.
    type Requests = Arc<Mutex<Vec<(u8, Vec<u8>)>>>;

    /// Transport of a guest that answers each application request with `answer(kind, request_id)`
    /// and records the kind and payload of each request.
    struct Responder {
        input: VecDeque<u8>,
        next_sequence: u64,
        answer: fn(u8, u64) -> Vec<u8>,
        requests: Requests,
    }

    impl Transport for Responder {
        fn read(&mut self, buffer: &mut [u8], _timeout: Option<Duration>) -> io::Result<usize> {
            if self.input.is_empty() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let count = buffer.len().min(self.input.len());
            for byte in &mut buffer[..count] {
                *byte = self.input.pop_front().unwrap();
            }
            Ok(count)
        }

        fn write_all(&mut self, data: &[u8], _timeout: Option<Duration>) -> io::Result<()> {
            let header = decode_outer_header(data[..OUTER_HEADER_LEN].try_into().unwrap()).unwrap();
            if header.record_type == OUTER_DATA {
                let request = decode_app(&data[OUTER_HEADER_LEN..]).unwrap();
                self.requests
                    .lock()
                    .unwrap()
                    .push((request.kind, request.payload.to_vec()));
                let reply = (self.answer)(request.kind, request.request_id);
                self.input
                    .extend(outer(OUTER_DATA, 1, self.next_sequence, &reply));
                self.next_sequence += 1;
            }
            Ok(())
        }
    }

    /// Attaches to a guest that answers each application request with `answer`.
    fn attached(answer: fn(u8, u64) -> Vec<u8>) -> ControlSession {
        attached_recording(answer).0
    }

    /// Attaches to a guest that answers each application request with `answer`, and returns the
    /// kind and payload of each request that the guest receives.
    fn attached_recording(answer: fn(u8, u64) -> Vec<u8>) -> (ControlSession, Requests) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let guest = Responder {
            input: outer(OUTER_READY, 1, 0, &[]).into(),
            next_sequence: 1,
            answer,
            requests: Arc::clone(&requests),
        };
        let session =
            ControlSession::attach(Box::new(guest), &[1; CAPABILITY_LEN], deadline()).unwrap();
        (session, requests)
    }

    /// Splits the host's writes into (record type, sequence, application frame) tuples.
    fn host_records(output: &[u8]) -> Vec<(u8, u64, Vec<u8>)> {
        let mut records = Vec::new();
        let mut rest = output;
        while !rest.is_empty() {
            let header = decode_outer_header(rest[..OUTER_HEADER_LEN].try_into().unwrap()).unwrap();
            let end = OUTER_HEADER_LEN + header.length;
            records.push((
                header.record_type,
                header.sequence,
                rest[OUTER_HEADER_LEN..end].to_vec(),
            ));
            rest = &rest[end..];
        }
        records
    }

    /// Checks that `error` is a protocol violation with `message`.
    #[track_caller]
    fn assert_violation(error: &SessionError, message: &str, case: &str) {
        let matched = matches!(error, SessionError::Protocol(text) if text == message);
        assert!(matched, "{case}: {error:?}");
    }

    #[test]
    fn attach_waits_for_the_guest_then_authenticates() {
        // The broker asks the host to wait while the guest has not acknowledged the session.
        let (session, wire) =
            scripted(&[outer(OUTER_WAIT, 0, 0, &[]), outer(OUTER_READY, 4, 1, &[])]);
        let session = session.unwrap();
        let identity = Identity {
            instance_id: INSTANCE,
            epoch: 4,
        };
        assert_eq!(session.connection.identity(), identity);
        let records = host_records(&wire.output());
        assert_eq!(records, [(OUTER_HOST_ATTACH, 0, vec![1; CAPABILITY_LEN])]);
    }

    #[test]
    fn attach_reports_authentication_failure() {
        let code = ErrorCode::Authentication.code().to_le_bytes();
        let (session, _) = scripted(&[outer(OUTER_ERROR, 0, 0, &code)]);
        assert!(matches!(session, Err(SessionError::AuthenticationFailed)));
    }

    #[test]
    fn attach_responses_that_the_protocol_does_not_allow_fail_closed() {
        let ready = outer(OUTER_READY, 1, 0, &[]);
        let oversized = u32::try_from(OUTER_MAX_PAYLOAD + 1).unwrap().to_le_bytes();
        let payload = "control attach response carried a payload";
        let invalid = "control endpoint returned an invalid attach response";
        let outer_record = "control endpoint returned an invalid outer record";
        let cases = [
            (
                "a READY with a payload",
                outer(OUTER_READY, 1, 0, b"x"),
                payload,
            ),
            (
                "a WAIT with a payload",
                outer(OUTER_WAIT, 0, 0, b"x"),
                payload,
            ),
            (
                "a READY without an identity",
                outer(OUTER_READY, 0, 0, &[]),
                invalid,
            ),
            (
                "a READY out of sequence",
                outer(OUTER_READY, 1, 3, &[]),
                invalid,
            ),
            ("DATA before READY", outer(OUTER_DATA, 1, 0, b"x"), invalid),
            (
                "an ERROR without a code",
                outer(OUTER_ERROR, 0, 0, &[]),
                invalid,
            ),
            (
                "an ERROR with an unknown code",
                outer(OUTER_ERROR, 0, 0, &2u32.to_le_bytes()),
                invalid,
            ),
            ("an unknown record type", outer(0x7f, 1, 0, &[]), invalid),
            (
                "a wrong magic",
                patched(ready.clone(), 0, b"NVXT"),
                outer_record,
            ),
            (
                "another version",
                patched(ready.clone(), 4, &2u16.to_le_bytes()),
                outer_record,
            ),
            (
                "nonzero flags",
                patched(ready.clone(), 7, &[1]),
                outer_record,
            ),
            (
                "an oversized record",
                patched(ready.clone(), 40, &oversized),
                "control endpoint returned an oversized outer record",
            ),
        ];
        for (case, record, message) in cases {
            let error = scripted(&[record]).0.err().unwrap();
            assert_violation(&error, message, case);
        }

        // A stream that ends, at a record boundary or inside a record, has closed.
        for records in [Vec::new(), vec![ready[..20].to_vec()]] {
            let wire = Scripted::default();
            wire.supply(&records);
            wire.close();
            let attached = ControlSession::attach(Box::new(wire), &[1; CAPABILITY_LEN], deadline());
            assert!(matches!(attached, Err(SessionError::Closed)));
        }
    }

    #[test]
    fn exec_streams_events_in_order() {
        // The request ID is random, so the scripted guest answers the frames the host sent.
        let (mut session, wire) = ready();
        let workload = Workload {
            argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), "echo hi".to_owned()],
            timeout_ms: 1000,
            cwd: None,
            environment: WorkloadEnvironment::Default,
        };
        let request_id = session.start_exec(&workload, deadline()).unwrap();
        let records = host_records(&wire.output());
        let (record_type, sequence, frame) = &records[1];
        assert_eq!((*record_type, *sequence), (OUTER_DATA, 0));
        let frame = decode_app(frame).unwrap();
        assert_eq!((frame.kind, frame.request_id), (APP_EXEC, request_id));

        wire.supply(&[
            outer(
                OUTER_DATA,
                1,
                1,
                &encode_app(APP_STDOUT, request_id, 0, b"hi\n"),
            ),
            outer(
                OUTER_DATA,
                1,
                2,
                &encode_app(APP_STDERR, request_id, 0, b"warn"),
            ),
            outer(
                OUTER_DATA,
                1,
                3,
                &encode_app(APP_EXIT, request_id, 3, b"exit"),
            ),
        ]);
        let events: Vec<ExecEvent> = (0..3)
            .map(|_| {
                session
                    .next_exec_event(request_id, Some(deadline()))
                    .unwrap()
            })
            .collect();
        assert_eq!(
            events,
            [
                ExecEvent::Stdout(b"hi\n".to_vec()),
                ExecEvent::Stderr(b"warn".to_vec()),
                ExecEvent::Exit {
                    category: ExitCategory::Exit,
                    status: 3
                },
            ]
        );
    }

    #[test]
    fn exec_sends_the_working_directory_and_reports_its_refusal() {
        let (mut session, wire) = ready();
        let workload = Workload {
            argv: vec!["/bin/pwd".to_owned()],
            timeout_ms: 0,
            cwd: Some("/work"),
            environment: WorkloadEnvironment::Default,
        };
        let request_id = session.start_exec(&workload, deadline()).unwrap();
        let records = host_records(&wire.output());
        let frame = decode_app(&records[1].2).unwrap();
        assert_eq!((frame.kind, frame.request_id), (APP_EXEC, request_id));
        assert_eq!(
            frame.payload,
            protocol::encode_exec_payload(&workload).unwrap()
        );

        let diagnostic = b"nvx-managed-agent: cannot enter working directory /work: No such file\n";
        wire.supply(&[
            outer(
                OUTER_DATA,
                1,
                1,
                &encode_app(APP_STDERR, request_id, 0, diagnostic),
            ),
            outer(
                OUTER_DATA,
                1,
                2,
                &encode_app(APP_ERROR, request_id, 2, protocol::CWD_FAILED.as_bytes()),
            ),
        ]);
        let events: Vec<ExecEvent> = (0..2)
            .map(|_| {
                session
                    .next_exec_event(request_id, Some(deadline()))
                    .unwrap()
            })
            .collect();
        assert_eq!(
            events,
            [
                ExecEvent::Stderr(diagnostic.to_vec()),
                ExecEvent::Rejected {
                    status: 2,
                    category: protocol::CWD_FAILED.to_owned()
                },
            ]
        );
    }

    #[test]
    fn records_that_the_protocol_does_not_allow_fail_closed() {
        let frame = encode_app(APP_STDOUT, 1, 0, b"x");
        let data = outer(OUTER_DATA, 1, 1, &frame);
        let oversized = u32::try_from(OUTER_MAX_PAYLOAD + 1).unwrap().to_le_bytes();
        let invalid = "control endpoint returned an invalid data record";
        let truncated = "control endpoint returned a truncated application frame";
        let cases = [
            (
                "DATA out of sequence",
                outer(OUTER_DATA, 1, 5, &frame),
                invalid,
            ),
            (
                "a repeated sequence number",
                outer(OUTER_DATA, 1, 0, &frame),
                invalid,
            ),
            (
                "DATA of another epoch",
                outer(OUTER_DATA, 2, 1, &frame),
                invalid,
            ),
            (
                "DATA of another instance",
                encode_outer(OUTER_DATA, &[9; 16], 1, 1, &frame).unwrap(),
                invalid,
            ),
            ("a WAIT", outer(OUTER_WAIT, 1, 1, &[]), invalid),
            (
                "a RESET of the session's epoch",
                outer(OUTER_RESET, 1, 1, &[]),
                invalid,
            ),
            ("an unknown record type", outer(0x7f, 1, 1, &[]), invalid),
            (
                "an empty DATA record",
                outer(OUTER_DATA, 1, 1, &[]),
                truncated,
            ),
            (
                "a truncated frame",
                outer(OUTER_DATA, 1, 1, &frame[..APP_HEADER_LEN - 1]),
                truncated,
            ),
            (
                "nonzero flags",
                patched(data.clone(), 7, &[1]),
                "control endpoint returned an invalid outer record",
            ),
            (
                "an oversized record",
                patched(data.clone(), 40, &oversized),
                "control endpoint returned an oversized outer record",
            ),
        ];
        for (case, record, message) in cases {
            let (mut session, wire) = ready();
            wire.supply(&[record]);
            let error = session.next_exec_event(1, Some(deadline())).unwrap_err();
            assert_violation(&error, message, case);
        }

        // A violation ends the session.
        let (mut session, wire) = ready();
        wire.supply(&[outer(OUTER_DATA, 1, 5, &frame)]);
        assert!(session.next_exec_event(1, Some(deadline())).is_err());
        wire.supply(std::slice::from_ref(&data));
        let error = session.next_exec_event(1, Some(deadline())).unwrap_err();
        let ended = "the control session ended after an earlier failure";
        assert_violation(&error, ended, "a call after a violation");
        let error = session.cancel_exec(1, deadline()).unwrap_err();
        assert_violation(&error, ended, "a request after a violation");

        // A reset to a later epoch ends the session too.
        let (mut session, wire) = ready();
        wire.supply(&[outer(OUTER_RESET, 2, 1, &[])]);
        assert!(matches!(
            session.next_exec_event(1, Some(deadline())),
            Err(SessionError::Reset)
        ));

        // A stream that ends, at a record boundary or inside a record, has closed.
        for records in [Vec::new(), vec![data[..OUTER_HEADER_LEN + 1].to_vec()]] {
            let (mut session, wire) = ready();
            wire.supply(&records);
            wire.close();
            assert!(matches!(
                session.next_exec_event(1, Some(deadline())),
                Err(SessionError::Closed)
            ));
        }
    }

    #[test]
    fn timed_out_polls_keep_partial_records() {
        let (mut session, wire) = ready();
        let record = outer(OUTER_DATA, 1, 1, &encode_app(APP_EXIT, 9, 0, b"cancelled"));
        let (first, second) = record.split_at(30);
        wire.supply(&[first.to_vec()]);
        assert!(matches!(
            session.next_exec_event(9, Some(deadline())),
            Err(SessionError::TimedOut)
        ));
        session.cancel_exec(9, deadline()).unwrap();
        wire.supply(&[second.to_vec()]);
        assert_eq!(
            session.next_exec_event(9, Some(deadline())).unwrap(),
            ExecEvent::Exit {
                category: ExitCategory::Cancelled,
                status: 0
            }
        );
        let records = host_records(&wire.output());
        let frame = decode_app(&records.last().unwrap().2).unwrap();
        assert_eq!((frame.kind, frame.request_id), (APP_CANCEL, 9));
    }

    #[test]
    fn frames_travel_in_one_record_each() {
        let (mut session, wire) = ready();
        let longest = vec![0x5a; OUTER_MAX_PAYLOAD - APP_HEADER_LEN];
        session
            .send_request(APP_EXEC, 1, &longest, deadline())
            .unwrap();
        let error = session
            .send_request(
                APP_EXEC,
                2,
                &[longest.as_slice(), &[0]].concat(),
                deadline(),
            )
            .unwrap_err();
        let message = "control payload exceeds the outer protocol limit";
        assert_violation(&error, message, "a frame longer than a record");
        let records = host_records(&wire.output());
        assert_eq!(records.len(), 2);
        let (record_type, sequence, frame) = &records[1];
        assert_eq!((*record_type, *sequence), (OUTER_DATA, 0));
        let frame = decode_app(frame).unwrap();
        assert_eq!((frame.kind, frame.request_id), (APP_EXEC, 1));
        assert_eq!(frame.payload, longest);
        // The refused frame changed nothing.
        session.cancel_exec(1, deadline()).unwrap();
        let records = host_records(&wire.output());
        assert_eq!((records[2].0, records[2].1), (OUTER_DATA, 1));
    }

    /// The response kind that acknowledges a ping or a stop request.
    fn acknowledgement(kind: u8) -> u8 {
        if kind == APP_PING {
            APP_READY
        } else {
            APP_STOPPED
        }
    }

    #[test]
    fn pings_and_stops_need_an_empty_acknowledgement() {
        let (mut session, requests) =
            attached_recording(|kind, id| encode_app(acknowledgement(kind), id, 0, &[]));
        session.ping(deadline()).unwrap();
        session.stop(deadline()).unwrap();
        assert_eq!(
            *requests.lock().unwrap(),
            [(APP_PING, Vec::new()), (APP_STOP, Vec::new())]
        );
        let answers: [fn(u8, u64) -> Vec<u8>; 4] = [
            |_, id| encode_app(APP_ERROR, id, 0, &[]),
            |kind, id| encode_app(acknowledgement(kind), id ^ 1, 0, &[]),
            |kind, id| encode_app(acknowledgement(kind), id, 1, &[]),
            |kind, id| encode_app(acknowledgement(kind), id, 0, b"x"),
        ];
        for answer in answers {
            let error = attached(answer).ping(deadline()).unwrap_err();
            assert_eq!(
                error.to_string(),
                "the guest agent did not acknowledge readiness"
            );
            let error = attached(answer).stop(deadline()).unwrap_err();
            assert_eq!(
                error.to_string(),
                "the guest agent did not acknowledge stop"
            );
        }
    }

    #[test]
    fn features_report_what_the_guest_provides() {
        let mut session = attached(|kind, id| {
            assert_eq!(kind, APP_FEATURES);
            encode_app(APP_READY, id, 0, &GuestFeatures::REQUIRED.encode())
        });
        assert_eq!(
            session.features(deadline()).unwrap(),
            GuestFeatures::REQUIRED
        );
    }

    #[test]
    fn guests_that_predate_the_features_request_provide_none() {
        // This is how an agent without the request refuses an unknown request kind.
        let mut session = attached(|_, id| encode_app(APP_ERROR, id, 95, b"unsupported-operation"));
        assert_eq!(session.features(deadline()).unwrap(), GuestFeatures::NONE);
    }

    #[test]
    fn malformed_features_responses_fail_closed() {
        let answers: [fn(u8, u64) -> Vec<u8>; 5] = [
            |_, id| encode_app(APP_READY, id, 0, &[1, 0]),
            |_, id| encode_app(APP_ERROR, id, 16, b"busy"),
            |_, id| encode_app(APP_READY, id, 1, &[0; 4]),
            |_, id| encode_app(APP_READY, id ^ 1, 0, &[0; 4]),
            |_, id| encode_app(APP_STDOUT, id, 0, &[0; 4]),
        ];
        for answer in answers {
            let mut session = attached(answer);
            assert!(matches!(
                session.features(deadline()),
                Err(SessionError::Protocol(_))
            ));
        }
    }

    #[test]
    fn host_mappings_travel_in_records_that_the_guest_acknowledges() {
        let (mut session, requests) = attached_recording(|kind, id| {
            assert_eq!(kind, APP_MAPS);
            encode_app(APP_READY, id, 0, &[])
        });
        let target = format!("/{}", "t".repeat(4000));
        let maps: Vec<HostMap> = (0..40)
            .map(|index| HostMap {
                source: format!("0/{index}"),
                target: target.clone(),
                read_only: index % 2 == 0,
            })
            .collect();
        session.map_host_paths(&maps, deadline()).unwrap();
        // Entries of about 4 KiB each fill a 64 KiB record 16 at a time.
        let requests = requests.lock().unwrap();
        let positions: Vec<(u32, u32)> = requests
            .iter()
            .map(|(_, payload)| {
                (
                    u32::from_le_bytes(payload[..4].try_into().unwrap()),
                    u32::from_le_bytes(payload[4..8].try_into().unwrap()),
                )
            })
            .collect();
        assert_eq!(positions, [(0, 16), (16, 16), (32, 8)]);
    }

    #[test]
    fn refused_host_mappings_fail_the_session() {
        let maps = [HostMap {
            source: "0".to_owned(),
            target: "/work".to_owned(),
            read_only: false,
        }];
        let mut session = attached(|_, id| encode_app(APP_ERROR, id, 2, b"mapping-failed"));
        let error = session.map_host_paths(&maps, deadline()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("could not mount a mapped host path (error 2)"),
            "{error}"
        );
        let answers: [fn(u8, u64) -> Vec<u8>; 4] = [
            |_, id| encode_app(APP_ERROR, id, 22, b"invalid-request"),
            |_, id| encode_app(APP_ERROR, id, 95, b"unsupported-operation"),
            |_, id| encode_app(APP_READY, id, 0, b"x"),
            |_, id| encode_app(APP_READY, id ^ 1, 0, &[]),
        ];
        for answer in answers {
            let mut session = attached(answer);
            assert!(matches!(
                session.map_host_paths(&maps, deadline()),
                Err(SessionError::Protocol(_))
            ));
        }
    }

    #[test]
    fn responses_to_another_request_fail_closed() {
        let mismatched = "the guest agent returned a mismatched request ID";
        let answer: fn(u8, u64) -> Vec<u8> = |_, id| encode_app(APP_READY, id ^ 1, 0, &[]);
        let error = attached(answer).features(deadline()).unwrap_err();
        assert_eq!(error.to_string(), mismatched);
        let maps = [HostMap {
            source: "0".to_owned(),
            target: "/work".to_owned(),
            read_only: true,
        }];
        let error = attached(answer)
            .map_host_paths(&maps, deadline())
            .unwrap_err();
        assert_eq!(error.to_string(), mismatched);
        let mut session = attached(|_, id| encode_app(APP_STDOUT, id ^ 1, 0, b"x"));
        let workload = Workload {
            argv: vec!["/bin/true".to_owned()],
            timeout_ms: 0,
            cwd: None,
            environment: WorkloadEnvironment::Default,
        };
        let request_id = session.start_exec(&workload, deadline()).unwrap();
        let error = session
            .next_exec_event(request_id, Some(deadline()))
            .unwrap_err();
        assert_eq!(error.to_string(), mismatched);
    }

    #[test]
    fn expired_deadlines_time_out() {
        let wire = Scripted::default();
        let error = ControlSession::attach(Box::new(wire), &[1; CAPABILITY_LEN], Instant::now())
            .err()
            .unwrap();
        assert!(matches!(error, SessionError::TimedOut));
    }
}
