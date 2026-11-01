//! NVX sidecar. Frames on stdin are requests, frames on stdout are replies and events;
//! diagnostics go to stderr. See `sandbox/doc/nvx_sidecar_integration.md`.
//!
//! Every runtime input is explicit and nothing is read from the environment: the VMM, the kernel,
//! NVX's base initramfs, the root image, the guest agent and the CPU profile are named on the
//! command line (or come from a release directory or checkout through `--artifacts`, a
//! development convenience).

mod capability;
mod control;
mod frame;
mod live;
mod network;
mod plan;
mod outbound;
mod ports;
mod protocol;
mod registry;
mod server;
mod vm;
mod winmem;

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};

use control::Queue;
use frame::read_frame;
use server::{Context, Settings};
use vm::VmConfig;

/// Requests that may wait for a worker. Bounded: a caller that exceeds it is refused, which is
/// visible, instead of the sidecar spawning a thread per message.
const DEFAULT_MAX_PENDING: usize = 32;
/// Control requests wait in their own, smaller queue so they are never behind a work burst.
const CONTROL_CAPACITY: usize = 16;
const CONTROL_WORKERS: usize = 2;
const DEFAULT_WORK_WORKERS: usize = 2;
/// Executions the VM may run at once (upstream's runtime adapter serves eight per VM).
const MAX_RUNNING: usize = 8;

struct Args {
    /// A release directory or checkout whose conventional layout names the artifacts.
    artifacts: Option<PathBuf>,
    openvmm: Option<PathBuf>,
    kernel: Option<PathBuf>,
    initrd: Option<PathBuf>,
    distro: Option<PathBuf>,
    guest_agent: Option<PathBuf>,
    /// Required: the guest CPU profile is a deployment decision, never inferred.
    cpu_profile: Option<String>,
    hypervisor: String,
    state_dir: PathBuf,
    capability_cache: Option<PathBuf>,
    max_sessions: usize,
    max_queue: usize,
    max_running: usize,
    ingress_host_loopback: bool,
    network_egress: bool,
    private_networks_allow: bool,
    exec_memory_mb: u64,
    exec_cpu_percent: u64,
    exec_pids: u64,
    outbound_capacity: usize,
    max_pending: usize,
    work_workers: usize,
    session_ttl_secs: u64,
    idle_trim_secs: u64,
    session_isolation: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        artifacts: None,
        openvmm: None,
        kernel: None,
        initrd: None,
        distro: None,
        guest_agent: None,
        cpu_profile: None,
        hypervisor: "whp".to_owned(),
        state_dir: std::env::temp_dir().join(format!("nvxd-{}", std::process::id())),
        capability_cache: default_cache(),
        max_sessions: 0,
        max_queue: registry::DEFAULT_QUEUE_DEPTH,
        max_running: MAX_RUNNING,
        ingress_host_loopback: false,
        network_egress: false,
        private_networks_allow: false,
        exec_memory_mb: 0,
        exec_cpu_percent: 0,
        exec_pids: 0,
        outbound_capacity: outbound::DEFAULT_CAPACITY,
        max_pending: DEFAULT_MAX_PENDING,
        work_workers: DEFAULT_WORK_WORKERS,
        session_ttl_secs: 0,
        idle_trim_secs: 30,
        session_isolation: false,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        let mut value = || iter.next().ok_or_else(|| format!("{flag} needs a value"));
        let number = |text: String| text.parse::<u64>().map_err(|e| format!("{flag}: {e}"));
        match flag.as_str() {
            "--artifacts" | "--repo" => args.artifacts = Some(PathBuf::from(value()?)),
            "--openvmm" => args.openvmm = Some(PathBuf::from(value()?)),
            "--kernel" => args.kernel = Some(PathBuf::from(value()?)),
            "--initrd" => args.initrd = Some(PathBuf::from(value()?)),
            "--distro" => args.distro = Some(PathBuf::from(value()?)),
            "--guest-agent" => args.guest_agent = Some(PathBuf::from(value()?)),
            "--cpu-profile" => args.cpu_profile = Some(value()?),
            "--hypervisor" => args.hypervisor = value()?,
            "--state-dir" => args.state_dir = PathBuf::from(value()?),
            "--capability-cache" => {
                let v = value()?;
                args.capability_cache = (v != "none").then(|| PathBuf::from(v));
            }
            "--max-sessions" => args.max_sessions = number(value()?)? as usize,
            "--max-queue" => args.max_queue = number(value()?)? as usize,
            "--max-running" => args.max_running = number(value()?)? as usize,
            "--outbound-capacity" => args.outbound_capacity = number(value()?)? as usize,
            "--max-pending" => args.max_pending = number(value()?)? as usize,
            "--work-workers" => args.work_workers = number(value()?)? as usize,
            "--session-ttl-secs" => args.session_ttl_secs = number(value()?)?,
            "--idle-trim-secs" => args.idle_trim_secs = number(value()?)?,
            "--ingress" => match value()?.as_str() {
                "host-loopback" => args.ingress_host_loopback = true,
                "none" => args.ingress_host_loopback = false,
                other => return Err(format!("--ingress takes host-loopback or none, not {other:?}")),
            },
            "--network" => {
                args.network_egress = match value()?.as_str() {
                    "allow" => true,
                    "deny" => false,
                    other => return Err(format!("--network takes allow or deny, not {other:?}")),
                }
            }
            "--private-networks" => {
                args.private_networks_allow = match value()?.as_str() {
                    "allow" => true,
                    "deny" => false,
                    other => return Err(format!("--private-networks takes allow or deny, not {other:?}")),
                }
            }
            "--exec-memory-mb" => args.exec_memory_mb = number(value()?)?,
            "--exec-cpu-percent" => args.exec_cpu_percent = number(value()?)?,
            "--exec-pids" => args.exec_pids = number(value()?)?,
            "--session-isolation" => args.session_isolation = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.ingress_host_loopback && !args.network_egress {
        return Err("--ingress host-loopback needs --network allow".to_string());
    }
    if args.max_running == 0 || args.max_running > MAX_RUNNING {
        return Err(format!("--max-running must be within 1..={MAX_RUNNING}"));
    }
    Ok(args)
}

fn default_cache() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("XDG_CACHE_HOME"))?;
    Some(PathBuf::from(base).join("nvxd").join("capability.json"))
}

/// The guest agent next to this executable unless one is named.
fn default_guest_agent() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.parent()?.join("nvxd-guest");
    candidate.is_file().then_some(candidate)
}


fn run() -> Result<(), String> {
    let args = parse_args()?;
    let cpu_profile = args
        .cpu_profile
        .clone()
        .ok_or("--cpu-profile is required (the profile is a deployment decision; `host` is the one that boots on Windows)")?;
    let from_dir = |sub: &str| args.artifacts.as_ref().map(|dir| dir.join(sub));
    let openvmm = args
        .openvmm
        .clone()
        .or_else(|| from_dir("bin/openvmm.exe"))
        .ok_or("name --artifacts DIR, or --openvmm/--kernel/--initrd together")?;
    let kernel = args
        .kernel
        .clone()
        .or_else(|| from_dir("guest/vmlinux"))
        .ok_or("name --artifacts DIR, or --openvmm/--kernel/--initrd together")?;
    let initrd = args
        .initrd
        .clone()
        .or_else(|| from_dir("guest/initramfs.cpio.gz"))
        .ok_or("name --artifacts DIR, or --openvmm/--kernel/--initrd together")?;
    let distro = args
        .distro
        .clone()
        .or_else(|| from_dir("guest/ubuntu-distro.erofs"))
        .ok_or("--distro is required (the EROFS image of the guest root)")?;
    let guest_agent = args
        .guest_agent
        .clone()
        .or_else(default_guest_agent)
        .ok_or("--guest-agent PATH is required (or place nvxd-guest next to this executable)")?;
    let hypervisor = match args.hypervisor.as_str() {
        "whp" => nvx::Hypervisor::Whp,
        other => return Err(format!("hypervisor {other} is not supported by the sidecar")),
    };
    let _ = std::fs::remove_dir_all(&args.state_dir);
    std::fs::create_dir_all(&args.state_dir).map_err(|e| e.to_string())?;
    let config = VmConfig {
        openvmm: openvmm.clone(),
        kernel: kernel.clone(),
        initrd: initrd.clone(),
        guest_agent: guest_agent.clone(),
        distro: distro.clone(),
        hypervisor,
        store: args.state_dir.join("store"),
        memory_mib: u32::try_from(protocol::DEFAULT_MEMORY_MIB).unwrap_or(1024),
        cpu_profile: cpu_profile.clone(),
        guest_build: runtime_adapter::GUEST_BUILD.to_owned(),
        anchor: args.state_dir.join("export-anchor"),
        generation: 0,
        control_pipe: String::new(),
        network: network::network(args.network_egress, args.ingress_host_loopback, args.private_networks_allow)?,
    };
    let provenance = json!({
        "sidecar": env!("CARGO_PKG_VERSION"),
        "openvmm": openvmm.display().to_string(),
        "kernel": kernel.display().to_string(),
        "initrd": initrd.display().to_string(),
        "guestAgent": guest_agent.display().to_string(),
        "distro": distro.display().to_string(),
        "cpuProfile": cpu_profile,
    });
    let _ = writeln!(std::io::stderr(), "nvxd: {provenance}");
    let paths = [openvmm.clone(), kernel.clone(), initrd.clone(), guest_agent.clone(), distro.clone()];
    let path_refs: Vec<&std::path::Path> = paths.iter().map(PathBuf::as_path).collect();
    let capability = capability::Capability::new(
        args.capability_cache.clone(),
        capability::fingerprint(&path_refs, &format!("{}|{}", cpu_profile, protocol::VERSION)),
    );
    let (writer, writer_thread) = outbound::spawn(Box::new(std::io::stdout()), args.outbound_capacity);
    let writer = Arc::new(writer);
    let settings = Settings {
        session_isolation: args.session_isolation,
        max_queue: args.max_queue,
        max_sessions: args.max_sessions,
        max_running: args.max_running,
        ingress_host_loopback: args.ingress_host_loopback,
        network_egress: args.network_egress,
        exec_memory_mb: args.exec_memory_mb,
        exec_cpu_percent: args.exec_cpu_percent,
        exec_pids: args.exec_pids,
    };
    let context = Arc::new(Context::new(config, provenance, Arc::clone(&writer), settings, capability));
    // Find out whether this machine can boot the VM while the caller is still starting up, so its
    // first `probe` finds the answer instead of paying for the boot.
    {
        let context = Arc::clone(&context);
        std::thread::spawn(move || context.check_capability());
    }
    // One maintenance tick for everything time-based. It runs even with trimming and TTL off,
    // because a queued execution past its own deadline has to be reported either way.
    let maintenance = {
        let (context, idle, ttl) = (
            Arc::clone(&context),
            std::time::Duration::from_secs(args.idle_trim_secs),
            std::time::Duration::from_secs(args.session_ttl_secs),
        );
        std::thread::spawn(move || {
            while !context.is_stopping() {
                std::thread::sleep(std::time::Duration::from_millis(250));
                if context.is_stopping() {
                    break;
                }
                context.expire_queued_pass();
                if !ttl.is_zero() {
                    context.expire_idle_pass(ttl);
                }
                if !idle.is_zero() {
                    context.idle_trim_pass(idle);
                }
            }
        })
    };
    writer
        .send(&json!({"event": protocol::EVENT_READY, "protocol": protocol::VERSION}), &[])
        .map_err(|e| e.to_string())?;

    // A fixed set of workers instead of a thread per request. Control requests get their own
    // queue and workers so that a cancel or a close is still served while the work queue is
    // saturated, which is exactly when the caller needs it.
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
        let queue = if is_control_op(&op) { &control } else { &work };
        if let Err(request) = queue.try_push(Request { head, payload }) {
            let id = request.head.get("id").cloned().unwrap_or(Value::Null);
            eprintln!(
                "nvxd: refusing {op}: the {} queue holds {} of {} requests",
                if is_control_op(&op) { "control" } else { "work" },
                queue.depth(),
                queue.capacity()
            );
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
    let _ = maintenance.join();
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
    #[allow(dead_code)]
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
        }
    })
}

fn main() {
    if let Err(message) = run() {
        let _ = writeln!(std::io::stderr(), "nvxd: {message}");
        std::process::exit(1);
    }
}
