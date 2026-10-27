//! NVX sidecar. Frames on stdin are requests, frames on stdout are replies and
//! events; diagnostics go to stderr. See `sandbox/doc/nvx_sidecar_integration.md`.
//!
//! Every runtime input is explicit: the VMM executable, the guest kernel and the guest
//! initramfs are named on the command line (or come from a checkout's conventional layout via
//! `--repo`, which is a development convenience), and the CPU profile is a required setting.
//! Nothing is read from the environment, so what a VM runs with is what the caller configured.

mod control;
mod frame;
mod outbound;
mod plan;
mod protocol;
mod registry;
mod server;
mod winmem;

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use aci_edge_sandboxes::CpuProfile;
use aci_edge_sandboxes::AciEdgeSandbox;
use aci_edge_sandboxes::nvx::Hypervisor;
use aci_edge_sandboxes::nvx::host::artifacts::Artifacts;
use aci_edge_sandboxes::openvmm::{OpenVmmBackend, OpenVmmConfig};
use aci_edge_sandboxes::nvx::protocol::{MAX_EXEC_CPU_PERCENT, MAX_EXEC_MEMORY_MIB, MAX_EXEC_PIDS};
use serde_json::{Value, json};

use control::Queue;
use frame::read_frame;
use server::Context;

/// Requests that may wait for a worker. Bounded: a caller that exceeds it is refused, which is
/// visible, instead of the sidecar spawning a thread per message.
const DEFAULT_MAX_PENDING: usize = 32;
/// Control requests wait in their own, smaller queue so they are never behind a work burst.
const CONTROL_CAPACITY: usize = 16;
/// Two control workers keep a close and an unrelated status query from serialising behind
/// each other; work is queued per VM anyway, so a third worker would add nothing.
const CONTROL_WORKERS: usize = 2;
const DEFAULT_WORK_WORKERS: usize = 2;
/// Executions the guest agent can supervise at once (`MAX_EXEC_SLOTS` in
/// `guest/common/nvx-managed-agent.c`). Asking for more would have the guest refuse the surplus
/// with `busy` instead of admitting them, so the sidecar refuses the configuration outright.
const MAX_RUNNING: usize = 8;

struct Args {
    /// A checkout whose conventional layout names the artifacts; development only.
    repo: Option<PathBuf>,
    /// Explicit artifacts, as a product installation carries them.
    openvmm: Option<PathBuf>,
    kernel: Option<PathBuf>,
    initrd: Option<PathBuf>,
    distro: Option<PathBuf>,
    /// Required: the guest CPU profile is a deployment decision, never inferred.
    cpu_profile: Option<CpuProfile>,
    hypervisor: Option<Hypervisor>,
    state_dir: PathBuf,
    /// Seconds a session may sit idle before its VMM working set is trimmed; 0 turns it off.
    idle_trim_secs: u64,
    /// Seconds an idle session may live before it is closed; 0 keeps sessions open.
    ///
    /// This is the TTL the product configures: a session the caller abandoned must not hold
    /// the shared VM (and the host budget that came with it) indefinitely.
    session_ttl_secs: u64,
    /// How many logical sessions may share the VM; 0 means no limit.
    ///
    /// A session is a routing unit inside one VM (P5), not a VM of its own, so this bounds
    /// callers rather than memory: the VM's guest RAM is set at `session.open`.
    max_sessions: usize,
    /// How many executions may wait for the VM's single run slot.
    max_queue: usize,
    /// How many executions the VM may run at once.
    ///
    /// One keeps the serial behaviour of every earlier release. More is only honoured by a guest
    /// image that advertises concurrent executions, and the sidecar refuses to boot a VM whose
    /// image does not when this is above one.
    max_running: usize,
    /// Explicitly use guest session namespaces; unsupported images are rejected.
    session_isolation: bool,
    /// Give the VM a network interface with unrestricted outbound access (`--network allow`).
    /// `deny` (the default) leaves the guest with loopback only.
    network_egress: bool,
    /// Let the host reach whatever the guest listens on, on host loopback only
    /// (`--ingress host-loopback`). Needs `--network allow`.
    ingress_host_loopback: bool,
    /// Requests that may wait for a worker before the caller is refused.
    max_pending: usize,
    /// Workers that run the slow requests (open a session, start an execution).
    work_workers: usize,
    /// Frames that may wait for the caller to read them. Bounded on purpose: a caller that
    /// stops reading must cost a fixed amount of memory, not an unbounded backlog.
    outbound_capacity: usize,
    /// Resource limits applied to every execution: memory in MiB, CPU in hundredths of a core,
    /// and the largest number of tasks. Zero asks for no limit in that dimension.
    ///
    /// They exist so a deployment can bound executions without trusting each individual request;
    /// a guest that cannot enforce one refuses the execution instead of running it unlimited.
    exec_memory_mb: u32,
    exec_cpu_percent: u32,
    exec_pids: u32,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        repo: None,
        openvmm: None,
        kernel: None,
        initrd: None,
        distro: None,
        cpu_profile: None,
        hypervisor: None,
        state_dir: std::env::temp_dir().join(format!("nvxd-{}", std::process::id())),
        idle_trim_secs: 30,
        session_ttl_secs: 0,
        max_sessions: 0,
        max_queue: crate::registry::DEFAULT_QUEUE_DEPTH,
        // Concurrent executions are on by default, up to what the guest agent can supervise:
        // the run slots are the only concurrency limit and sessions are counted per VM. An image
        // that does not advertise EXEC_SLOTS is refused at startup rather than run serially
        // while claiming otherwise.
        max_running: MAX_RUNNING,
        session_isolation: false,
        network_egress: false,
        ingress_host_loopback: false,
        max_pending: DEFAULT_MAX_PENDING,
        work_workers: DEFAULT_WORK_WORKERS,
        outbound_capacity: outbound::DEFAULT_CAPACITY,
        exec_memory_mb: 0,
        exec_cpu_percent: 0,
        exec_pids: 0,
    };
    let mut input = std::env::args().skip(1);
    while let Some(flag) = input.next() {
        let mut value = || input.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--repo" => args.repo = Some(PathBuf::from(value()?)),
            "--openvmm" => args.openvmm = Some(PathBuf::from(value()?)),
            "--kernel" => args.kernel = Some(PathBuf::from(value()?)),
            "--initrd" => args.initrd = Some(PathBuf::from(value()?)),
            "--distro" => args.distro = Some(PathBuf::from(value()?)),
            "--cpu-profile" => {
                let text = value()?;
                args.cpu_profile = Some(CpuProfile::parse(&text).ok_or_else(|| {
                    format!("--cpu-profile must be 'auto' or 'host', not '{text}'")
                })?);
            }
            "--hypervisor" => args.hypervisor = Some(value()?.parse().map_err(|e| format!("{e}"))?),
            "--state-dir" => args.state_dir = PathBuf::from(value()?),
            "--max-sessions" => {
                args.max_sessions = value()?.parse().map_err(|e| format!("{e}"))?
            }
            "--max-queue" => {
                args.max_queue = value()?.parse().map_err(|e| format!("{e}"))?
            }
            "--max-running" => {
                args.max_running = value()?.parse().map_err(|e| format!("{e}"))?
            }
            "--session-isolation" => args.session_isolation = true,
            "--ingress" => {
                args.ingress_host_loopback = match value()?.as_str() {
                    "host-loopback" => true,
                    "none" => false,
                    other => {
                        return Err(format!("--ingress takes host-loopback or none, not {other:?}"))
                    }
                }
            }
            "--network" => {
                args.network_egress = match value()?.as_str() {
                    "allow" => true,
                    "deny" => false,
                    other => return Err(format!("--network takes allow or deny, not {other:?}")),
                }
            }
            "--exec-memory-mb" => {
                args.exec_memory_mb = value()?.parse().map_err(|e| format!("{e}"))?
            }
            "--exec-cpu-percent" => {
                args.exec_cpu_percent = value()?.parse().map_err(|e| format!("{e}"))?
            }
            "--exec-pids" => {
                args.exec_pids = value()?.parse().map_err(|e| format!("{e}"))?
            }
            "--max-pending" => {
                args.max_pending = value()?.parse().map_err(|e| format!("{e}"))?
            }
            "--work-workers" => {
                args.work_workers = value()?.parse().map_err(|e| format!("{e}"))?
            }
            "--outbound-capacity" => {
                args.outbound_capacity = value()?.parse().map_err(|e| format!("{e}"))?
            }
            "--session-ttl-secs" => {
                args.session_ttl_secs = value()?.parse().map_err(|e| format!("{e}"))?
            }
            "--idle-trim-secs" => {
                args.idle_trim_secs = value()?.parse().map_err(|e| format!("{e}"))?
            }
            other => return Err(format!("unexpected argument {other}")),
        }
    }
    // The values are handed to the guest, which refuses an execution whose limit it cannot
    // enforce; a value outside the agreed range is a configuration mistake, so it fails here
    // rather than as a refusal on every execution.
    if args.max_running == 0 || args.max_running > MAX_RUNNING {
        return Err(format!(
            "--max-running must be within 1..={MAX_RUNNING}; the guest agent supervises that many \
             executions"
        ));
    }
    if args.exec_memory_mb > MAX_EXEC_MEMORY_MIB {
        return Err(format!(
            "--exec-memory-mb must be at most {MAX_EXEC_MEMORY_MIB}"
        ));
    }
    if args.exec_cpu_percent > MAX_EXEC_CPU_PERCENT {
        return Err(format!(
            "--exec-cpu-percent must be at most {MAX_EXEC_CPU_PERCENT}"
        ));
    }
    if args.exec_pids > MAX_EXEC_PIDS {
        return Err(format!("--exec-pids must be at most {MAX_EXEC_PIDS}"));
    }
    if args.ingress_host_loopback && !args.network_egress {
        return Err("--ingress host-loopback needs --network allow".to_string());
    }
    Ok(args)
}

/// Names the three artifacts the VM runs: a checkout's conventional layout, or every artifact
/// given explicitly, with optional per-artifact overrides on top.
fn resolve_artifacts(args: &Args) -> Result<Artifacts, String> {
    let mut artifacts = match &args.repo {
        Some(repo) => Artifacts::from_dir(repo).map_err(|e| e.to_string())?,
        None => {
            let (Some(openvmm), Some(kernel), Some(initrd)) =
                (&args.openvmm, &args.kernel, &args.initrd)
            else {
                return Err(
                    "name --repo, or --openvmm/--kernel/--initrd together; either way any of \
                     --openvmm/--kernel/--initrd may override one artifact"
                        .into(),
                );
            };
            Artifacts::new(openvmm.clone(), kernel.clone(), initrd.clone())
        }
    };
    if let Some(openvmm) = &args.openvmm {
        artifacts.openvmm = openvmm.clone();
    }
    if let Some(kernel) = &args.kernel {
        artifacts.kernel = kernel.clone();
    }
    if let Some(initrd) = &args.initrd {
        artifacts.initrd = initrd.clone();
    }
    if let Some(distro) = &args.distro {
        artifacts.distro = Some(distro.clone());
    }
    Ok(artifacts)
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let cpu_profile = args
        .cpu_profile
        .ok_or("--cpu-profile is required (auto or host)")?;
    let hypervisor = match args.hypervisor {
        Some(hypervisor) => hypervisor,
        None => Hypervisor::from_env_or_default().map_err(|e| e.to_string())?,
    };
    let artifacts = resolve_artifacts(&args)?;
    let provenance = json!({
        "openvmm": artifacts.openvmm.display().to_string(),
        "kernel": artifacts.kernel.display().to_string(),
        "initrd": artifacts.initrd.display().to_string(),
        "distro": artifacts.distro.as_ref().map(|path| path.display().to_string()),
        "cpuProfile": cpu_profile.as_str(),
        "idleTrimSecs": args.idle_trim_secs,
        "sessionTtlSecs": args.session_ttl_secs,
        "maxSessions": args.max_sessions,
        "maxQueue": args.max_queue,
        "maxRunning": args.max_running,
        "sessionIsolation": args.session_isolation,
        "network": if args.network_egress { "allow" } else { "deny" },
        "ingress": if args.ingress_host_loopback { "host-loopback" } else { "none" },
        "execLimits": {
            "memMb": args.exec_memory_mb,
            "cpuPercent": args.exec_cpu_percent,
            "pidsMax": args.exec_pids,
        },
        "maxPending": args.max_pending,
        "workWorkers": args.work_workers,
        "outboundCapacity": args.outbound_capacity,
        "protocolVersion": protocol::VERSION,
    });
    let _ = writeln!(std::io::stderr(), "nvxd: {provenance}");
    let state_dir = args.state_dir.clone();
    let _ = std::fs::remove_dir_all(&state_dir);
    let request_root = args.state_dir.join("requests");
    std::fs::create_dir_all(&request_root).map_err(|e| e.to_string())?;
    let mut config =
        OpenVmmConfig::from_artifacts(artifacts, hypervisor, args.state_dir.join("state"));
    config.cpu_profile = cpu_profile;
    config.exec_limits = aci_edge_sandboxes::nvx::protocol::ExecLimits {
        mem_mb: args.exec_memory_mb,
        cpu_percent: args.exec_cpu_percent,
        pids_max: args.exec_pids,
    };
    let backend = Arc::new(OpenVmmBackend::new(config).map_err(|e| e.to_string())?);
    let client = AciEdgeSandbox::from_shared(backend.clone());
    // One bounded outbound path for every reply, event and chunk of output.
    let (writer, writer_thread) = outbound::spawn(
        Box::new(std::io::stdout()),
        args.outbound_capacity,
    );
    let writer = Arc::new(writer);
    let context = Arc::new(Context::new(
        backend,
        client,
        provenance,
        Arc::clone(&writer),
        args.max_queue,
        args.max_sessions,
        args.max_running,
        args.session_isolation,
        args.network_egress,
        args.ingress_host_loopback,
        state_dir.join("export-anchor"),
    ));

    // One maintenance tick for everything time-based. It runs even with trimming and TTL off,
    // because a queued execution past its own deadline has to be reported either way; the
    // worker cannot do it while it is blocked waiting for a running command.
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
                // Expiry first: a session past its TTL is closed, so trimming it would be
                // wasted work on a VM that is about to stop.
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
        .send(
            &json!({"event": protocol::EVENT_READY, "protocol": protocol::VERSION}),
            &[],
        )
        .map_err(|e| e.to_string())?;

    // A fixed set of workers instead of a thread per request: the caller's concurrent request
    // count is bounded here, and a burst is answered with an overload error rather than by
    // growing the process. Control requests get their own queue and worker so that a cancel or
    // a close is still served while the work queue is saturated — which is exactly when the
    // caller needs it.
    let work: Arc<Queue<Request>> = Arc::new(Queue::new(args.max_pending));
    let control: Arc<Queue<Request>> = Arc::new(Queue::new(CONTROL_CAPACITY));
    let mut workers = Vec::new();
    for _ in 0..args.work_workers {
        workers.push(spawn_worker(
            Arc::clone(&context),
            Arc::clone(&writer),
            Arc::clone(&work),
        ));
    }
    for _ in 0..CONTROL_WORKERS {
        workers.push(spawn_worker(
            Arc::clone(&context),
            Arc::clone(&writer),
            Arc::clone(&control),
        ));
    }

    let mut stdin = std::io::stdin().lock();
    while let Some((head, payload)) = read_frame(&mut stdin).map_err(|e| e.to_string())? {
        let op = head
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if op == protocol::OP_SHUTDOWN {
            break;
        }
        let is_control = is_control_op(&op);
        let request = Request { head, payload };
        let queue = if is_control { &control } else { &work };
        match queue.try_push(request) {
            Ok(()) => {}
            Err(request) => {
                // Refused before anything was registered: no handle exists, so the caller can
                // retry once the backlog drains.
                let id = request.head.get("id").cloned().unwrap_or(Value::Null);
                eprintln!(
                    "nvxd: refusing {op}: the {} queue holds {} of {} requests",
                    if is_control { "control" } else { "work" },
                    queue.depth(),
                    queue.capacity()
                );
                let _ = writer.send(
                    &json!({
                        "id": id, "ok": false,
                        "reasonCode": protocol::REASON_OVERLOAD,
                        "message": "the sidecar's request queue is full",
                    }),
                    &[],
                );
            }
        }
    }
    // Close in this order: stop accepting, give up on work whose output nobody can receive
    // (which is also what unblocks any in-flight VM call), then let the workers finish.
    work.close();
    control.close();
    context.shutdown_now();
    for worker in workers {
        let _ = worker.join();
    }
    // The maintenance thread holds a context of its own; it has to stop before the context can
    // be released, or the output thread would wait forever for a sender that is still alive.
    context.stop_maintenance();
    let _ = maintenance.join();
    // The context holds a writer handle of its own: releasing it before the join is what lets
    // the output thread see the channel close.
    drop(context);
    drop(writer);
    // Bounded wait: the output thread exits as soon as every sender is gone, but a stray
    // handle must not be able to keep the process alive after shutdown was requested.
    let finished = std::sync::mpsc::sync_channel::<()>(1);
    let waiter = std::thread::spawn(move || {
        let _ = writer_thread.join();
        let _ = finished.0.send(());
    });
    if finished.1.recv_timeout(std::time::Duration::from_secs(5)).is_err() {
        eprintln!("nvxd: the outbound writer did not stop; leaving it behind");
    }
    drop(waiter);
    let _ = std::fs::remove_dir_all(&state_dir);
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

/// One decoded request, moved to a worker as-is.
struct Request {
    head: Value,
    payload: Vec<u8>,
}

fn spawn_worker(
    context: Arc<Context>,
    writer: Arc<crate::outbound::Writer>,
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
                    "id": id, "ok": false,
                    "reasonCode": failure.code, "message": failure.message,
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
