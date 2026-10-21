//! **Proof-of-concept** driver for adding a host directory to a running sandbox without a restart.
//!
//! It needs an OpenVMM and a guest initramfs that carry the live-share patches, and
//! `NVX_POC_LIVE_SHARE_DIR` set to a directory that only the current user can write, before this
//! process starts (OpenVMM inherits the variable):
//!
//! ```text
//! NVX_POC_LIVE_SHARE_DIR=/path/to/private/dir cargo run --example live_share_poc -- \
//!     --repo /path/to/nvx --initrd /path/to/initramfs-patched.cpio.gz --hypervisor whp
//! ```

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use aci_edge_sandboxes::nvx::Hypervisor;
use aci_edge_sandboxes::nvx::host::artifacts::Artifacts;
use aci_edge_sandboxes::nvx::host::poc_live::LiveShare;
use aci_edge_sandboxes::openvmm::{OpenVmmBackend, OpenVmmConfig};
use aci_edge_sandboxes::{AciEdgeSandbox, ExecRequest, ProvisionRequest};

fn describe(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => {
            println!("LIVE-SHARE-POC: PASS");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("LIVE-SHARE-POC: FAIL");
            ExitCode::FAILURE
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<bool, String> {
    let (mut repo, mut initrd, mut hypervisor) = (None, None, None);
    let mut stress = 0usize;
    let mut memory_mib = None;
    let mut probes: Vec<String> = Vec::new();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or_else(|| format!("{argument} requires a value"))
        };
        match argument.as_str() {
            "--repo" => repo = Some(value()?),
            "--initrd" => initrd = Some(PathBuf::from(value()?)),
            "--hypervisor" => hypervisor = Some(value()?.parse::<Hypervisor>().map_err(describe)?),
            "--stress" => stress = value()?.parse::<usize>().map_err(describe)?,
            "--memory-mib" => memory_mib = Some(value()?.parse::<u32>().map_err(describe)?),
            "--probe" => probes.push(value()?),
            other => return Err(format!("unexpected argument {other}")),
        }
    }
    let request_dir = PathBuf::from(
        std::env::var_os("NVX_POC_LIVE_SHARE_DIR")
            .ok_or("set NVX_POC_LIVE_SHARE_DIR before starting this process")?,
    );
    std::fs::create_dir_all(&request_dir).map_err(describe)?;
    let hypervisor = match hypervisor {
        Some(hypervisor) => hypervisor,
        None => Hypervisor::from_env_or_default().map_err(describe)?,
    };
    let artifacts =
        Artifacts::from_repo_layout(repo.ok_or("--repo is required")?).map_err(describe)?;
    let state_root = std::env::temp_dir().join("nvx-live-share-poc-state");
    let mut config = OpenVmmConfig::from_artifacts(artifacts, hypervisor, state_root);
    if let Some(initrd) = initrd {
        config.initrd = initrd;
    }
    if let Some(memory_mib) = memory_mib {
        config.memory_mib = memory_mib;
    }

    // Host fixtures: `base` is mapped at provision; `extra` is added while the guest runs.
    let fixtures = std::env::temp_dir().join("nvx-live-share-poc-fixtures");
    let _ = std::fs::remove_dir_all(&fixtures);
    let (base, extra) = (fixtures.join("base"), fixtures.join("extra"));
    std::fs::create_dir_all(&base).map_err(describe)?;
    std::fs::create_dir_all(&extra).map_err(describe)?;
    std::fs::write(base.join("hello.txt"), "base-file").map_err(describe)?;
    std::fs::write(extra.join("live.txt"), "added-while-running").map_err(describe)?;
    // A provisioned mapping lands at the guest path of the resolved host path (so 8.3 short
    // names and letter case do not matter); use the same derivation for the base path.
    let guest = |path: &std::path::Path| {
        aci_edge_sandboxes::nvx::host::filesystem::resolve_guest_path(path)
            .ok_or_else(|| "no guest path".to_owned())
    };
    let (base_target, extra_target) = (guest(&base)?, guest(&extra)?);

    let backend = OpenVmmBackend::new(config.clone()).map_err(describe)?;
    let client = AciEdgeSandbox::openvmm(config).map_err(describe)?;
    let request: ProvisionRequest = serde_json::from_value(serde_json::json!({
        "filesystem": { "readwritePaths": [base.to_string_lossy()] }
    }))
    .map_err(describe)?;
    let boot_started = std::time::Instant::now();
    let sandbox = client.provision(&request).map_err(describe)?.sandbox_id;
    println!("provision took {:?}", boot_started.elapsed());

    let outcome = (|| -> Result<bool, String> {
        client.start(&sandbox).map_err(describe)?;
        println!("provision+start took {:?}", boot_started.elapsed());
        let sh = |command: &str| -> Result<(String, String), String> {
            let output = client
                .exec(&sandbox, &ExecRequest::command_line(command))
                .and_then(|execution| execution.wait_with_output())
                .map_err(describe)?;
            Ok((
                String::from_utf8_lossy(&output.stdout).into_owned(),
                format!("{:?}", output.outcome),
            ))
        };
        for probe in &probes {
            let started = std::time::Instant::now();
            let output = client
                .exec(&sandbox, &ExecRequest::command_line(probe))
                .and_then(|execution| execution.wait_with_output())
                .map_err(describe)?;
            println!(
                "probe [{probe}] => {:?} in {:?}
  stdout: {:?}
  stderr: {:?}",
                output.outcome,
                started.elapsed(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let (_, before) = sh(&format!("test -e '{extra_target}/live.txt'"))?;
        println!("before add: test -e extra => {before} (must not exit 0)");

        let share = LiveShare {
            child: "live0",
            host_path: &extra,
            target: &extra_target,
            read_only: true,
        };
        backend
            .add_share_poc(&sandbox, &request_dir, 0, &share, Duration::from_secs(30))
            .map_err(describe)?;
        println!("add_share_poc: ok");

        let (content, outcome) = sh(&format!("cat '{extra_target}/live.txt'"))?;
        println!("after add: cat => {content:?} {outcome}");
        let (_, write) = sh(&format!("echo x > '{extra_target}/new.txt'"))?;
        println!("after add: write to ro share => {write} (must not exit 0)");
        let (base_content, base_outcome) = sh(&format!("cat '{base_target}/hello.txt'"))?;
        println!("base share still works => {base_content:?} {base_outcome}");

        let visible = content == "added-while-running";
        let still_ro = !extra.join("new.txt").exists() && !write.contains("Exited(0)");

        // The guest refuses to unmount a mapping of the announced table.
        let refused = backend
            .remove_share_poc(&sandbox, &request_dir, "base", &base_target, Duration::from_secs(30))
            .is_err();
        println!("unmount of an announced mapping refused => {refused}");
        let (base_kept, _) = sh(&format!("cat '{base_target}/hello.txt'"))?;

        // Remove the runtime share: the guest unmounts it, then the VMM stops exporting it.
        backend
            .remove_share_poc(&sandbox, &request_dir, "live0", &extra_target, Duration::from_secs(30))
            .map_err(describe)?;
        let (_, gone) = sh(&format!("test -e '{extra_target}/live.txt'"))?;
        println!("after remove: test -e extra => {gone} (must not exit 0)");
        let (base_after, _) = sh(&format!("cat '{base_target}/hello.txt'"))?;
        println!("after remove: base share => {base_after:?}");

        // Add the same host directory again under a new child name; names are never reused.
        let share_again = LiveShare {
            child: "live1",
            ..share
        };
        backend
            .add_share_poc(&sandbox, &request_dir, 1, &share_again, Duration::from_secs(30))
            .map_err(describe)?;
        let (again, again_outcome) = sh(&format!("cat '{extra_target}/live.txt'"))?;
        println!("after re-add as live1: cat => {again:?} {again_outcome}");

        // Informational only: reuse the name of a removed child.
        let reuse = backend
            .remove_share_poc(&sandbox, &request_dir, "live1", &extra_target, Duration::from_secs(30))
            .and_then(|()| {
                let same = LiveShare {
                    child: "live0",
                    ..share
                };
                backend.add_share_poc(&sandbox, &request_dir, 2, &same, Duration::from_secs(30))
            });
        let (reuse_content, reuse_outcome) = sh(&format!("cat '{extra_target}/live.txt'"))?;
        println!("INFO reuse of removed name live0 => {reuse:?}: {reuse_content:?} {reuse_outcome}");

        // A share that the guest refuses (here: its target is already a runtime mapping) must not
        // leak the VMM's export, and must not use up a sequence number.
        let dup_dir = fixtures.join("dup");
        std::fs::create_dir_all(&dup_dir).map_err(describe)?;
        std::fs::write(dup_dir.join("d.txt"), "dup").map_err(describe)?;
        let clash = LiveShare {
            child: "dup0",
            host_path: &dup_dir,
            target: &extra_target,
            read_only: true,
        };
        let clash_refused = backend
            .add_share_poc(&sandbox, &request_dir, 3, &clash, Duration::from_secs(30))
            .is_err();
        let retry = LiveShare {
            child: "dup0",
            target: "/mnt/dup/ok",
            ..clash
        };
        let retry_ok = backend
            .add_share_poc(&sandbox, &request_dir, 3, &retry, Duration::from_secs(30))
            .is_ok();
        let (dup_content, _) = sh("cat /mnt/dup/ok/d.txt")?;
        println!(
            "guest-refused add (duplicate target) => refused={clash_refused}; retry under the same child name and sequence => ok={retry_ok}, content={dup_content:?}"
        );
        let dup_ok = clash_refused && retry_ok && dup_content == "dup";

        let stress_ok = if stress > 0 {
            run_stress(&backend, &sandbox, &request_dir, &fixtures, stress, 4, &sh)?
        } else {
            true
        };

        Ok(visible
            && still_ro
            && base_content == "base-file"
            && !before.contains("Exited(0)")
            && refused
            && base_kept == "base-file"
            && !gone.contains("Exited(0)")
            && base_after == "base-file"
            && again == "added-while-running"
            && dup_ok
            && stress_ok)
    })();
    let _ = client.stop(&sandbox);
    let _ = client.deprovision(&sandbox);
    outcome
}

/// Churns `rounds` add/remove cycles through the same guest path (so the runtime sequence number
/// passes the 4096-entry table bound only if `rounds` is large, and the guest's slots are reused),
/// then fills the aggregate until the VMM or the guest refuses another share, checks that the
/// refusal leaks nothing, and that removing shares makes room again. `next_sequence` is the number
/// of runtime shares added so far.
fn run_stress(
    backend: &OpenVmmBackend,
    sandbox: &aci_edge_sandboxes::SandboxId,
    request_dir: &std::path::Path,
    fixtures: &std::path::Path,
    rounds: usize,
    mut next_sequence: usize,
    sh: &dyn Fn(&str) -> Result<(String, String), String>,
) -> Result<bool, String> {
    let timeout = Duration::from_secs(30);
    let mut ok = true;
    let churn = fixtures.join("churn");
    std::fs::create_dir_all(&churn).map_err(describe)?;
    std::fs::write(churn.join("f.txt"), "churn").map_err(describe)?;
    let started = std::time::Instant::now();
    for round in 0..rounds {
        let child = format!("ch{round}");
        let share = LiveShare {
            child: &child,
            host_path: &churn,
            target: "/mnt/stress/ch",
            read_only: true,
        };
        backend
            .add_share_poc(sandbox, request_dir, next_sequence, &share, timeout)
            .map_err(|error| format!("churn round {round}: add: {error}"))?;
        next_sequence += 1;
        if round % 50 == 0 {
            let (content, _) = sh("cat /mnt/stress/ch/f.txt")?;
            if content != "churn" {
                println!("churn round {round}: unexpected content {content:?}");
                ok = false;
            }
        }
        backend
            .remove_share_poc(sandbox, request_dir, &child, "/mnt/stress/ch", timeout)
            .map_err(|error| format!("churn round {round}: remove: {error}"))?;
    }
    println!(
        "churn: {rounds} add/remove rounds through one guest path in {:.0?}, sequence now {next_sequence}",
        started.elapsed()
    );

    // Fill until a share is refused. Each share needs a host root of its own.
    let limit = 300usize;
    let mut mounted = Vec::new();
    let mut refusal = None;
    for index in 0..limit {
        let host = fixtures.join(format!("fill{index}"));
        std::fs::create_dir_all(&host).map_err(describe)?;
        std::fs::write(host.join("v.txt"), index.to_string()).map_err(describe)?;
        let child = format!("fl{index}");
        let target = format!("/mnt/fill/{index}");
        let share = LiveShare {
            child: &child,
            host_path: &host,
            target: &target,
            read_only: true,
        };
        match backend.add_share_poc(sandbox, request_dir, next_sequence, &share, timeout) {
            Ok(()) => {
                next_sequence += 1;
                mounted.push((child, target));
            }
            Err(error) => {
                refusal = Some((index, error.to_string()));
                break;
            }
        }
    }
    let Some((refused_at, message)) = refusal else {
        println!("fill: {limit} shares were all accepted; no limit reached");
        return Ok(false);
    };
    println!("fill: share #{refused_at} refused after {} mounted: {message}", mounted.len());
    let (first, _) = sh("cat /mnt/fill/0/v.txt")?;
    let last_index = mounted.len() - 1;
    let (last, _) = sh(&format!("cat /mnt/fill/{last_index}/v.txt"))?;
    println!("fill: first => {first:?}, last => {last:?}");
    ok &= first == "0" && last == last_index.to_string();

    // Removing shares makes room again, and the refusal leaked no export slot.
    for (child, target) in mounted.drain(..) {
        backend
            .remove_share_poc(sandbox, request_dir, &child, &target, timeout)
            .map_err(|error| format!("fill cleanup of {child}: {error}"))?;
    }
    let host = fixtures.join("after");
    std::fs::create_dir_all(&host).map_err(describe)?;
    std::fs::write(host.join("v.txt"), "after").map_err(describe)?;
    let share = LiveShare {
        child: "after0",
        host_path: &host,
        target: "/mnt/fill/after",
        read_only: true,
    };
    backend
        .add_share_poc(sandbox, request_dir, next_sequence, &share, timeout)
        .map_err(|error| format!("add after cleanup: {error}"))?;
    let (after, _) = sh("cat /mnt/fill/after/v.txt")?;
    println!("fill: add after removing every fill share => {after:?}");
    ok &= after == "after";
    Ok(ok)
}
