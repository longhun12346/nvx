//! NVX sidecar. Frames on stdin are requests, frames on stdout are replies and events;
//! diagnostics go to stderr. See `sandbox/doc/nvx_sidecar_integration.md`.
//!
//! Every runtime input is explicit and nothing is read from the environment: the NVX artifacts
//! (a release directory or a checkout), the guest agent, the root image and the CPU profile are
//! named on the command line.

mod capability;
mod control;
mod frame;
mod outbound;
mod protocol;
mod server;
mod vm;

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};

use control::Queue;
use frame::read_frame;
use server::Context;
use vm::VmConfig;

const DEFAULT_MAX_PENDING: usize = 32;
const CONTROL_CAPACITY: usize = 16;
const CONTROL_WORKERS: usize = 2;
const DEFAULT_WORK_WORKERS: usize = 2;

struct Args {
    artifacts: Option<PathBuf>,
    guest_agent: Option<PathBuf>,
    distro: Option<PathBuf>,
    cpu_profile: Option<String>,
    hypervisor: String,
    state_dir: PathBuf,
    capability_cache: Option<PathBuf>,
    outbound_capacity: usize,
    max_pending: usize,
    work_workers: usize,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        artifacts: None,
        guest_agent: None,
        distro: None,
        cpu_profile: None,
        hypervisor: "whp".to_owned(),
        state_dir: std::env::temp_dir().join(format!("nvxd-{}", std::process::id())),
        capability_cache: default_cache(),
        outbound_capacity: outbound::DEFAULT_CAPACITY,
        max_pending: DEFAULT_MAX_PENDING,
        work_workers: DEFAULT_WORK_WORKERS,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        let mut value = || iter.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--artifacts" => args.artifacts = Some(PathBuf::from(value()?)),
            "--guest-agent" => args.guest_agent = Some(PathBuf::from(value()?)),
            "--distro" => args.distro = Some(PathBuf::from(value()?)),
            "--cpu-profile" => args.cpu_profile = Some(value()?),
            "--hypervisor" => args.hypervisor = value()?,
            "--state-dir" => args.state_dir = PathBuf::from(value()?),
            "--capability-cache" => {
                let v = value()?;
                args.capability_cache = (v != "none").then(|| PathBuf::from(v));
            }
            "--outbound-capacity" => args.outbound_capacity = value()?.parse().map_err(|e| format!("{e}"))?,
            "--max-pending" => args.max_pending = value()?.parse().map_err(|e| format!("{e}"))?,
            "--work-workers" => args.work_workers = value()?.parse().map_err(|e| format!("{e}"))?,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(args)
}

fn default_cache() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("XDG_CACHE_HOME"))?;
    Some(PathBuf::from(base).join("nvxd").join("capability.json"))
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let cpu_profile = args
        .cpu_profile
        .clone()
        .ok_or("--cpu-profile is required (the profile is a deployment decision; `host` is the one that boots on Windows)")?;
    let artifacts = args.artifacts.clone().ok_or("--artifacts DIR is required (an NVX release directory or checkout)")?;
    let guest_agent = args.guest_agent.clone().ok_or("--guest-agent PATH is required")?;
    let distro = args
        .distro
        .clone()
        .unwrap_or_else(|| artifacts.join("guest").join("ubuntu-distro.erofs"));
    let hypervisor = match args.hypervisor.as_str() {
        "whp" => nvx::Hypervisor::Whp,
        other => return Err(format!("hypervisor {other} is not supported by the sidecar")),
    };
    let _ = std::fs::remove_dir_all(&args.state_dir);
    std::fs::create_dir_all(&args.state_dir).map_err(|e| e.to_string())?;
    let config = VmConfig {
        artifacts: artifacts.clone(),
        guest_agent: guest_agent.clone(),
        distro: distro.clone(),
        hypervisor,
        store: args.state_dir.join("store"),
        memory_mib: u32::try_from(protocol::DEFAULT_MEMORY_MIB).unwrap_or(1024),
        cpu_profile: cpu_profile.clone(),
        guest_build: runtime_adapter::GUEST_BUILD.to_owned(),
    };
    let provenance = json!({
        "sidecar": env!("CARGO_PKG_VERSION"),
        "artifacts": artifacts.display().to_string(),
        "guestAgent": guest_agent.display().to_string(),
        "distro": distro.display().to_string(),
        "cpuProfile": cpu_profile,
    });
    let _ = writeln!(std::io::stderr(), "nvxd: {provenance}");
    let paths = [
        artifacts.join("bin").join("openvmm.exe"),
        artifacts.join("guest").join("vmlinux"),
        guest_agent.clone(),
        distro.clone(),
    ];
    let path_refs: Vec<&std::path::Path> = paths.iter().map(PathBuf::as_path).collect();
    let capability = capability::Capability::new(
        args.capability_cache.clone(),
        capability::fingerprint(&path_refs, &format!("{}|{}", cpu_profile, protocol::VERSION)),
    );
    let (writer, writer_thread) = outbound::spawn(Box::new(std::io::stdout()), args.outbound_capacity);
    let writer = Arc::new(writer);
    let context = Arc::new(Context::new(config, capability, Arc::clone(&writer), provenance));
    {
        let context = Arc::clone(&context);
        std::thread::spawn(move || context.check_capability());
    }
    writer
        .send(&json!({"event": protocol::EVENT_READY, "protocol": protocol::VERSION}), &[])
        .map_err(|e| e.to_string())?;

    let work: Arc<Queue<Request>> = Arc::new(Queue::new(args.max_pending));
    let control: Arc<Queue<Request>> = Arc::new(Queue::new(CONTROL_CAPACITY));
    let mut workers = Vec::new();
    for _ in 0..args.work_workers {
        workers.push(spawn_worker(Arc::clone(&context), Arc::clone(&writer), Arc::clone(&work)));
    }
    for _ in 0..CONTROL_WORKERS {
        workers.push(spawn_worker(Arc::clone(&context), Arc::clone(&writer), Arc::clone(&control)));
    }

    let mut stdin = std::io::stdin().lock();
    while let Some((head, payload)) = read_frame(&mut stdin).map_err(|e| e.to_string())? {
        let op = head.get("op").and_then(Value::as_str).unwrap_or("").to_owned();
        if op == protocol::OP_SHUTDOWN {
            break;
        }
        let is_control = is_control_op(&op);
        let queue = if is_control { &control } else { &work };
        if let Err(request) = queue.try_push(Request { head, payload }) {
            let id = request.head.get("id").cloned().unwrap_or(Value::Null);
            let _ = writer.send(
                &json!({"id": id, "ok": false, "reasonCode": protocol::REASON_OVERLOAD,
                        "message": "the sidecar's request queue is full"}),
                &[],
            );
        }
    }
    work.close();
    control.close();
    context.shutdown_now();
    for worker in workers {
        let _ = worker.join();
    }
    drop(context);
    drop(writer);
    let finished = std::sync::mpsc::sync_channel::<()>(1);
    let waiter = std::thread::spawn(move || {
        let _ = writer_thread.join();
        let _ = finished.0.send(());
    });
    if finished.1.recv_timeout(std::time::Duration::from_secs(5)).is_err() {
        eprintln!("nvxd: the outbound writer did not stop; leaving it behind");
    }
    drop(waiter);
    let _ = std::fs::remove_dir_all(&args.state_dir);
    Ok(())
}

/// Requests that must be served while the work queue is saturated.
fn is_control_op(op: &str) -> bool {
    matches!(
        op,
        protocol::OP_SIGNAL
            | protocol::OP_SESSION_CLOSE
            | protocol::OP_EXEC_STATUS
            | protocol::OP_DIAGNOSTICS
            | protocol::OP_MEMORY_STATS
            | protocol::OP_MEMORY_TRIM
            | protocol::OP_PROBE
    )
}

struct Request {
    head: Value,
    payload: Vec<u8>,
}

fn spawn_worker(
    context: Arc<Context>,
    writer: Arc<outbound::Writer>,
    queue: Arc<Queue<Request>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while let Some(request) = queue.pop() {
            let id = request.head.get("id").cloned().unwrap_or(Value::Null);
            let reply = match context.handle_logged(&request.head) {
                Ok(mut body) => {
                    body["id"] = id;
                    body["ok"] = json!(true);
                    body
                }
                Err(failure) => json!({
                    "id": id, "ok": false, "reasonCode": failure.code, "message": failure.message,
                }),
            };
            let _ = writer.send(&reply, &[]);
            // The start reply must reach the caller before any event for that execution.
            if let Some(exec_id) = reply.get("execId").and_then(Value::as_str) {
                context.release(exec_id);
            }
            let _ = request.payload;
        }
    })
}

fn main() {
    if let Err(message) = run() {
        let _ = writeln!(std::io::stderr(), "nvxd: {message}");
        std::process::exit(1);
    }
}
