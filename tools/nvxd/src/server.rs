//! The sidecar's request handling, on top of [`crate::vm`].
//!
//! Scaffold: probe (with the real boot probe), session.open/close for the one shared VM,
//! exec with streamed output and exit, diagnostics. Everything else the protocol names answers
//! `E_NVX_NOT_YET_SUPPORTED` (TODO: limits, OOM attribution, fairness slots, TTL, port ops, memory
//! trim, isolation, workspace mounts); the code of the previous implementation is in
//! `reference/server_old.rs`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use crate::capability::{Capability, Verdict};
use crate::outbound::Writer;
use crate::protocol;
use crate::vm::{Event, Vm, VmConfig};

pub const NOT_YET_SUPPORTED: &str = "E_NVX_NOT_YET_SUPPORTED";
const PROBE_WAIT: Duration = Duration::from_secs(30);

pub struct Failure {
    pub code: String,
    pub message: String,
}

fn fail(code: &str, message: impl std::fmt::Display) -> Failure {
    Failure { code: code.to_owned(), message: message.to_string() }
}

/// An execution whose events wait until its start reply has been sent.
struct ExecState {
    session: String,
    gated: bool,
    held: Vec<(Value, Vec<u8>)>,
}

pub struct Context {
    config: VmConfig,
    capability: Capability,
    writer: Arc<Writer>,
    provenance: Value,
    vm: Mutex<Option<Vm>>,
    sessions: Mutex<HashMap<String, String>>,
    execs: Arc<Mutex<HashMap<String, ExecState>>>,
    generation: AtomicU64,
    next_exec: AtomicU64,
    stopping: AtomicBool,
}

impl Context {
    pub fn new(config: VmConfig, capability: Capability, writer: Arc<Writer>, provenance: Value) -> Self {
        Self {
            config,
            capability,
            writer,
            provenance,
            vm: Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
            execs: Arc::new(Mutex::new(HashMap::new())),
            generation: AtomicU64::new(0),
            next_exec: AtomicU64::new(1),
            stopping: AtomicBool::new(false),
        }
    }

    /// Runs the machine's boot probe in the background so the first `probe` finds the answer.
    pub fn check_capability(&self) {
        let _ = self.capability.resolve(None, &|| self.boot_probe());
    }

    /// Boots a small VM once and ends it again.
    fn boot_probe(&self) -> Result<(), (String, String)> {
        let mut config = self.config.clone();
        config.memory_mib = protocol::PROBE_MEMORY_MIB;
        config.store = self.config.store.join("probe");
        let _ = std::fs::remove_dir_all(&config.store);
        let mut vm = Vm::launch(config, |_| true)?;
        vm.stop();
        Ok(())
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Relaxed)
    }

    pub fn shutdown_now(&self) {
        self.stopping.store(true, Ordering::Relaxed);
        if let Some(mut vm) = self.vm.lock().unwrap().take() {
            vm.stop();
        }
    }

    /// Called once the reply that carries `exec_id` has been sent: its events may flow now.
    pub fn release(&self, exec_id: &str) {
        let held = {
            let mut execs = self.execs.lock().unwrap();
            match execs.get_mut(exec_id) {
                Some(state) => {
                    state.gated = false;
                    std::mem::take(&mut state.held)
                }
                None => return,
            }
        };
        let finished = held.iter().any(|(head, _)| head["event"] == protocol::EVENT_EXEC_EXIT);
        for (head, payload) in held {
            self.emit(&head, &payload);
        }
        if finished {
            self.execs.lock().unwrap().remove(exec_id);
        }
    }

    fn emit(&self, head: &Value, payload: &[u8]) {
        let is_output = head["event"] != protocol::EVENT_EXEC_EXIT;
        let _ = if is_output {
            self.writer.send_output(head, payload)
        } else {
            self.writer.send(head, payload)
        };
    }

    pub fn handle_logged(&self, head: &Value) -> Result<Value, Failure> {
        let op = head.get("op").and_then(Value::as_str).unwrap_or("");
        let result = self.handle(op, head);
        if let Err(failure) = &result {
            eprintln!("nvxd: {op} failed: {} {}", failure.code, failure.message);
        }
        result
    }

    fn handle(&self, op: &str, head: &Value) -> Result<Value, Failure> {
        match op {
            protocol::OP_PROBE => self.probe(head),
            protocol::OP_SESSION_OPEN => self.session_open(head),
            protocol::OP_SESSION_CLOSE => self.session_close(head),
            protocol::OP_EXEC => self.exec(head),
            protocol::OP_DIAGNOSTICS => Ok(self.diagnostics()),
            _ => Err(fail(NOT_YET_SUPPORTED, format!("{op} is not supported by this build of the sidecar yet"))),
        }
    }

    fn probe(&self, head: &Value) -> Result<Value, Failure> {
        let wait = number(head.get("waitMs")).map_or(PROBE_WAIT, Duration::from_millis);
        match self.capability.resolve(Some(wait), &|| self.boot_probe()) {
            Some(Verdict::Capable) => Ok(json!({
                "backend": "nvx-whp",
                "provenance": self.provenance,
                "vmGeneration": self.generation.load(Ordering::Relaxed),
                "capabilities": {
                    "sharedVm": true,
                    "parallelExec": true,
                    "maxRunningPerVm": 8,
                    "maxRunningPerSession": 8,
                    "guestFeatures": 0,
                    "sessionIsolation": false,
                },
            })),
            Some(Verdict::Incapable { code, message }) => Err(fail(
                &code,
                format!("this machine cannot boot the microVM: {message}"),
            )),
            None => Err(fail(
                protocol::REASON_CAPABILITY_PENDING,
                "the check of whether this machine can boot the microVM is still running",
            )),
        }
    }

    fn session_open(&self, head: &Value) -> Result<Value, Failure> {
        let session = string(head, "session").ok_or_else(|| fail(protocol::REASON_PROTOCOL, "session is required"))?;
        if truthy(head.get("sessionIsolation")) {
            return Err(fail(NOT_YET_SUPPORTED, "session isolation is not ported to the new guest agent yet"));
        }
        if head.get("mounts").is_some() {
            return Err(fail(NOT_YET_SUPPORTED, "mounts are not ported yet"));
        }
        let memory = match head.get("memoryMiB") {
            None => protocol::DEFAULT_MEMORY_MIB,
            Some(value) => number(Some(value)).ok_or_else(|| {
                fail(protocol::REASON_MEMORY_UNSUPPORTED, "memoryMiB must be an unsigned integer")
            })?,
        };
        protocol::validate_memory(memory).map_err(|(code, message)| fail(code, message))?;
        // A machine that cannot boot the VM fails here with the stable code, not after a boot try.
        match self.capability.resolve(Some(PROBE_WAIT), &|| self.boot_probe()) {
            Some(Verdict::Capable) => {}
            Some(Verdict::Incapable { code, message }) => {
                return Err(fail(&code, format!("this machine cannot boot the microVM: {message}")));
            }
            None => return Err(fail(protocol::REASON_CAPABILITY_PENDING, "the capability check is still running")),
        }
        let mut vm = self.vm.lock().unwrap();
        if vm.is_none() {
            let mut config = self.config.clone();
            config.memory_mib = u32::try_from(memory).unwrap_or(1024);
            let started = Vm::launch(config, self.event_sink()).map_err(|(code, message)| fail(&code, message))?;
            self.generation.fetch_add(1, Ordering::Relaxed);
            *vm = Some(started);
        }
        self.sessions.lock().unwrap().insert(session, string(head, "workspace").unwrap_or_default());
        Ok(json!({
            "workspaceGuestPath": "/",
            "runtimeId": format!("rt-{:08x}", self.generation.load(Ordering::Relaxed)),
            "vmGeneration": self.generation.load(Ordering::Relaxed),
            "sharedVm": true,
        }))
    }

    fn session_close(&self, head: &Value) -> Result<Value, Failure> {
        let session = string(head, "session").ok_or_else(|| fail(protocol::REASON_PROTOCOL, "session is required"))?;
        let existed = self.sessions.lock().unwrap().remove(&session).is_some();
        Ok(if existed {
            json!({"state": "closed", "cleanupPending": false})
        } else {
            json!({"state": "closed", "alreadyClosed": true, "cleanupPending": false})
        })
    }

    fn exec(&self, head: &Value) -> Result<Value, Failure> {
        let session = string(head, "session").ok_or_else(|| fail(protocol::REASON_PROTOCOL, "session is required"))?;
        if !self.sessions.lock().unwrap().contains_key(&session) {
            return Err(fail(protocol::REASON_SESSION_UNKNOWN, format!("no session {session}")));
        }
        if head.get("mounts").is_some() {
            return Err(fail(NOT_YET_SUPPORTED, "mounts are not ported yet"));
        }
        if let Some(limits) = head.get("limits").and_then(Value::as_object) {
            if limits.values().any(|v| number(Some(v)).unwrap_or(0) > 0) {
                return Err(fail(NOT_YET_SUPPORTED, "request limits are not ported yet"));
            }
        }
        let arguments: Vec<Vec<u8>> = head
            .get("argv")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).map(|s| s.as_bytes().to_vec()).collect())
            .unwrap_or_default();
        if arguments.is_empty() {
            return Err(fail(protocol::REASON_PROTOCOL, "argv is required"));
        }
        // The guest takes the program as an absolute path, and an execution gets exactly the
        // environment it is given. TODO: resolve PATH in the guest agent, as the old agent did.
        let mut arguments = arguments;
        if !arguments[0].contains(&b'/') {
            let mut path = b"/usr/bin/".to_vec();
            path.extend_from_slice(&arguments[0]);
            arguments[0] = path;
        }
        let mut environment: Vec<Vec<u8>> = head
            .get("env")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .map(|(name, value)| format!("{name}={}", value.as_str().unwrap_or("")).into_bytes())
                    .collect()
            })
            .unwrap_or_default();
        if !environment.iter().any(|entry| entry.starts_with(b"PATH=")) {
            environment.push(b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_vec());
        }
        if !environment.iter().any(|entry| entry.starts_with(b"HOME=")) {
            environment.push(b"HOME=/tmp".to_vec());
        }
        let working_directory = string(head, "cwd").filter(|s| !s.is_empty()).map(String::into_bytes);
        let timeout = number(head.get("timeoutMs")).filter(|ms| *ms > 0).map(Duration::from_millis);
        let exec_id = string(head, "execId")
            .unwrap_or_else(|| format!("x{}", self.next_exec.fetch_add(1, Ordering::Relaxed)));
        {
            let mut execs = self.execs.lock().unwrap();
            if execs.contains_key(&exec_id) {
                return Err(fail(protocol::REASON_EXEC_CONFLICT, format!("execution {exec_id} exists")));
            }
            execs.insert(exec_id.clone(), ExecState { session, gated: true, held: Vec::new() });
        }
        let started = {
            let vm = self.vm.lock().unwrap();
            match vm.as_ref() {
                Some(vm) => vm.exec(exec_id.clone(), arguments, working_directory, environment, timeout),
                None => Err("no VM is running".to_owned()),
            }
        };
        if let Err(message) = started {
            self.execs.lock().unwrap().remove(&exec_id);
            return Err(fail(protocol::REASON_BACKEND_UNAVAILABLE, message));
        }
        Ok(json!({"execId": exec_id, "handle": exec_id, "state": "running", "queuePosition": 0}))
    }

    fn diagnostics(&self) -> Value {
        let stats = self.writer.stats();
        json!({
            "sessions": self.sessions.lock().unwrap().len(),
            "executions": self.execs.lock().unwrap().len(),
            "vmGeneration": self.generation.load(Ordering::Relaxed),
            "outbound": {"frames": stats.frames(), "refused": stats.refused(), "broken": stats.broken()},
        })
    }

    /// The callback with which the VM thread reports output and ends.
    fn event_sink(&self) -> impl Fn(Event) -> bool + Send + 'static {
        let (execs, writer) = (Arc::clone(&self.execs), Arc::clone(&self.writer));
        let generation = self.generation.load(Ordering::Relaxed) + 1;
        move |event| {
            let (id, head, payload, output) = match event {
                Event::Output { id, stderr, bytes } => {
                    let name = if stderr { protocol::EVENT_EXEC_STDERR } else { protocol::EVENT_EXEC_STDOUT };
                    (id, json!({"event": name}), bytes, true)
                }
                Event::Exit { id, outcome } => {
                    let detail = outcome.launch_failure.unwrap_or_default();
                    let code = outcome.code;
                    (id, json!({
                        "event": protocol::EVENT_EXEC_EXIT,
                        "outcome": outcome.kind,
                        "code": code,
                        "detail": detail,
                        "truncated": outcome.truncated,
                    }), Vec::new(), false)
                }
            };
            let mut head = head;
            {
                let mut execs = execs.lock().unwrap();
                let Some(state) = execs.get_mut(&id) else { return true };
                head["handle"] = json!(id);
                head["execId"] = json!(id);
                head["session"] = json!(state.session);
                head["generation"] = json!(generation);
                if state.gated {
                    state.held.push((head, payload));
                    return true;
                }
                if !output {
                    execs.remove(&id);
                }
            }
            if output { writer.send_output(&head, &payload).is_ok() } else { writer.send(&head, &payload).is_ok() }
        }
    }
}

fn string(head: &Value, key: &str) -> Option<String> {
    head.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Numbers arrive as JSON numbers or as strings, because the engine's JSON writer sends strings.
fn number(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(s.as_str(), "1" | "true" | "yes"),
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0) != 0,
        _ => false,
    }
}
