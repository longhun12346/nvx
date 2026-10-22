//! GenFlow NVX sidecar. Frames on stdin are requests, frames on stdout are replies and
//! events; diagnostics go to stderr. See `sandbox/doc/nvx_sidecar_integration.md`.
//!
//! Every runtime input is explicit: the VMM executable, the guest kernel and the guest
//! initramfs are named on the command line (or come from a checkout's conventional layout via
//! `--repo`, which is a development convenience), and the CPU profile is a required setting.
//! Nothing is read from the environment, so what a VM runs with is what the caller configured.

mod frame;
mod plan;
mod protocol;
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
use serde_json::{Value, json};

use frame::{FrameWriter, read_frame};
use server::Context;

struct Args {
    /// A checkout whose conventional layout names the artifacts; development only.
    repo: Option<PathBuf>,
    /// Explicit artifacts, as a product installation carries them.
    openvmm: Option<PathBuf>,
    kernel: Option<PathBuf>,
    initrd: Option<PathBuf>,
    /// Required: the guest CPU profile is a deployment decision, never inferred.
    cpu_profile: Option<CpuProfile>,
    hypervisor: Option<Hypervisor>,
    state_dir: PathBuf,
    /// Seconds a session may sit idle before its VMM working set is trimmed; 0 turns it off.
    idle_trim_secs: u64,
    /// Seconds an idle session may live before it is closed; 0 keeps sessions open.
    ///
    /// This is the TTL the product configures: a session the caller abandoned must not hold
    /// a VM (and the host budget that came with it) indefinitely.
    session_ttl_secs: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        repo: None,
        openvmm: None,
        kernel: None,
        initrd: None,
        cpu_profile: None,
        hypervisor: None,
        state_dir: std::env::temp_dir().join(format!("genflow-nvxd-{}", std::process::id())),
        idle_trim_secs: 30,
        session_ttl_secs: 0,
    };
    let mut input = std::env::args().skip(1);
    while let Some(flag) = input.next() {
        let mut value = || input.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--repo" => args.repo = Some(PathBuf::from(value()?)),
            "--openvmm" => args.openvmm = Some(PathBuf::from(value()?)),
            "--kernel" => args.kernel = Some(PathBuf::from(value()?)),
            "--initrd" => args.initrd = Some(PathBuf::from(value()?)),
            "--cpu-profile" => {
                let text = value()?;
                args.cpu_profile = Some(CpuProfile::parse(&text).ok_or_else(|| {
                    format!("--cpu-profile must be 'auto' or 'host', not '{text}'")
                })?);
            }
            "--hypervisor" => args.hypervisor = Some(value()?.parse().map_err(|e| format!("{e}"))?),
            "--state-dir" => args.state_dir = PathBuf::from(value()?),
            "--session-ttl-secs" => {
                args.session_ttl_secs = value()?.parse().map_err(|e| format!("{e}"))?
            }
            "--idle-trim-secs" => {
                args.idle_trim_secs = value()?.parse().map_err(|e| format!("{e}"))?
            }
            other => return Err(format!("unexpected argument {other}")),
        }
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
        "cpuProfile": cpu_profile.as_str(),
        "idleTrimSecs": args.idle_trim_secs,
        "sessionTtlSecs": args.session_ttl_secs,
        "protocolVersion": protocol::VERSION,
    });
    let _ = writeln!(std::io::stderr(), "genflow-nvxd: {provenance}");
    let state_dir = args.state_dir.clone();
    let _ = std::fs::remove_dir_all(&state_dir);
    let request_root = args.state_dir.join("requests");
    std::fs::create_dir_all(&request_root).map_err(|e| e.to_string())?;
    let mut config =
        OpenVmmConfig::from_artifacts(artifacts, hypervisor, args.state_dir.join("state"));
    config.cpu_profile = cpu_profile;
    let backend = Arc::new(OpenVmmBackend::new(config).map_err(|e| e.to_string())?);
    let client = AciEdgeSandbox::from_shared(backend.clone());
    let writer = Arc::new(FrameWriter::new(std::io::stdout()));
    let context = Arc::new(Context::new(
        backend,
        client,
        provenance,
        Arc::clone(&writer),
    ));

    if args.idle_trim_secs > 0 || args.session_ttl_secs > 0 {
        let (context, idle, ttl) = (
            Arc::clone(&context),
            std::time::Duration::from_secs(args.idle_trim_secs),
            std::time::Duration::from_secs(args.session_ttl_secs),
        );
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                // Expiry first: a session past its TTL is closed, so trimming it would be
                // wasted work on a VM that is about to stop.
                if !ttl.is_zero() {
                    context.expire_idle_pass(ttl);
                }
                if !idle.is_zero() {
                    context.idle_trim_pass(idle);
                }
            }
        });
    }
    writer
        .send(
            &json!({"event": protocol::EVENT_READY, "protocol": protocol::VERSION}),
            &[],
        )
        .map_err(|e| e.to_string())?;
    let mut stdin = std::io::stdin().lock();
    while let Some((head, _payload)) = read_frame(&mut stdin).map_err(|e| e.to_string())? {
        if head.get("op").and_then(Value::as_str) == Some(protocol::OP_SHUTDOWN) {
            break;
        }
        let (context, writer) = (Arc::clone(&context), Arc::clone(&writer));
        std::thread::spawn(move || {
            let id = head.get("id").cloned().unwrap_or(Value::Null);
            let reply = match context.handle(&head) {
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
        });
    }
    context.close_all();
    let _ = std::fs::remove_dir_all(&state_dir);
    Ok(())
}

fn main() {
    if let Err(message) = run() {
        let _ = writeln!(std::io::stderr(), "genflow-nvxd: {message}");
        std::process::exit(1);
    }
}
