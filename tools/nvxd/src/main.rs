//! NVX sidecar (PoC). Frames on stdin are requests, frames on stdout are replies and
//! events; diagnostics go to stderr. See `sandbox/doc/nvx_sidecar_integration.md`.

mod frame;
mod plan;
mod protocol;
mod server;
mod winmem;

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use aci_edge_sandboxes::AciEdgeSandbox;
use aci_edge_sandboxes::nvx::Hypervisor;
use aci_edge_sandboxes::nvx::host::artifacts::Artifacts;
use aci_edge_sandboxes::openvmm::{OpenVmmBackend, OpenVmmConfig};
use serde_json::{Value, json};

use frame::{FrameWriter, read_frame};
use server::Context;

struct Args {
    repo: String,
    initrd: Option<PathBuf>,
    hypervisor: Option<Hypervisor>,
    state_dir: PathBuf,
    /// Seconds a session may sit idle before its VMM working set is trimmed; 0 turns it off.
    idle_trim_secs: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        repo: String::new(),
        initrd: None,
        hypervisor: None,
        state_dir: std::env::temp_dir().join(format!("nvxd-{}", std::process::id())),
        idle_trim_secs: 30,
    };
    let mut input = std::env::args().skip(1);
    while let Some(flag) = input.next() {
        let mut value = || input.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--repo" => args.repo = value()?,
            "--initrd" => args.initrd = Some(PathBuf::from(value()?)),
            "--hypervisor" => args.hypervisor = Some(value()?.parse().map_err(|e| format!("{e}"))?),
            "--state-dir" => args.state_dir = PathBuf::from(value()?),
            "--idle-trim-secs" => {
                args.idle_trim_secs = value()?.parse().map_err(|e| format!("{e}"))?
            }
            other => return Err(format!("unexpected argument {other}")),
        }
    }
    if args.repo.is_empty() {
        return Err("--repo is required".into());
    }
    Ok(args)
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let hypervisor = match args.hypervisor {
        Some(hypervisor) => hypervisor,
        None => Hypervisor::from_env_or_default().map_err(|e| e.to_string())?,
    };
    let artifacts = Artifacts::from_repo_layout(&args.repo).map_err(|e| e.to_string())?;
    let state_dir = args.state_dir.clone();
    let _ = std::fs::remove_dir_all(&state_dir);
    let request_root = args.state_dir.join("requests");
    std::fs::create_dir_all(&request_root).map_err(|e| e.to_string())?;
    // PoC hook in the NVX fork; P1 will replace this with explicit CPU profile configuration.
    if std::env::var_os("NVX_POC_CPU_PROFILE").is_none() {
        // SAFETY: no other thread exists yet.
        unsafe { std::env::set_var("NVX_POC_CPU_PROFILE", "host") };
    }
    let mut config =
        OpenVmmConfig::from_artifacts(artifacts, hypervisor, args.state_dir.join("state"));
    if let Some(initrd) = args.initrd {
        config.initrd = initrd;
    }
    let backend = Arc::new(OpenVmmBackend::new(config).map_err(|e| e.to_string())?);
    let client = AciEdgeSandbox::from_shared(backend.clone());
    let writer = Arc::new(FrameWriter::new(std::io::stdout()));
    let context = Arc::new(Context::new(
        backend,
        client,
        request_root,
        Arc::clone(&writer),
    ));

    if args.idle_trim_secs > 0 {
        let (context, idle) = (
            Arc::clone(&context),
            std::time::Duration::from_secs(args.idle_trim_secs),
        );
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                context.idle_trim_pass(idle);
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
        let _ = writeln!(std::io::stderr(), "nvxd: {message}");
        std::process::exit(1);
    }
}
