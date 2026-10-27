"""Build and run the target-guest negative matrix during this gate invocation."""

from __future__ import annotations

import argparse
import json
import pathlib
import hashlib
import subprocess
import time
from runtime_assets import distro_path


REQUIRED_CHECKS = {
    "requires-root",
    "disposable-agent-state",
    "workspace-fixtures",
    "session-wire",
    "unknown-network-policy-refused",
    "workspace-symlink-refused",
    "agent-secret-fd",
    "create-a",
    "create-b",
    "production-scheduler-two-by-two-cgroups",
    "identity-proc-capabilities-fds",
    "a-private-state",
    "same-session-state",
    "cross-session-state",
    "same-session-sysv-ipc",
    "cross-session-sysv-ipc-denied",
    "late-mount-fixtures",
    "same-target-in-independent-sessions",
    "late-mount-write-isolated",
    "foreign-source-denied",
    "mount-traversal-denied",
    "recursive-readonly-enforced",
    "private-unmount-preserves-other-authorized-view",
    "b-mount-survives-a-unmount",
    "all-private-directory-mounts-revoked",
    "file-source",
    "file-bind-and-strict-unmount",
    "busy-revoke-fixture",
    "busy-revoke-holder",
    "busy-revoke-escalates-group-failure",
    "scoped-mount-matrix",
    "a-loopback-server",
    "cross-session-loopback-denied",
    "same-session-loopback",
    "agent-descriptors-preserved",
    "close-a",
    "b-survives-a-close",
    "id-reuse-refused",
    "reopen-new-id",
    "private-state-reset-authorized-workspace-persists",
    "cleanup-all",
    "session-directories-removed",
    "legacy-migration-refused",
    "fault-injection-session",
    "fault-injection-kill-keeper",
    "fault-injection-reap-keeper",
    "keeper-loss-escalates-group-failure",
}


def sha256(path):
    return hashlib.file_digest(path.open("rb"), "sha256").hexdigest()


def linux_path(path):
    return subprocess.check_output(
        ["wsl", "--exec", "wslpath", "-a", str(path.resolve())],
        text=True, timeout=15).strip()


def probe_command(openvmm, kernel, diagnostic, diagnostic_distro=None):
    cmdline = "nvx_exec=/p8-probe-boot"
    if diagnostic_distro is not None:
        cmdline += " nvx_overlay_upper=ramfs"
    command = [
        str(openvmm), "--single-process", "--machine", "microvm",
        "--processors", "2", "--hypervisor", "whp", "--cpu-profile", "host",
        "--memory", "1024M", "--kernel", str(kernel),
        "--initrd", str(diagnostic), "--cmdline", cmdline,
    ]
    if diagnostic_distro is not None:
        command += ["--microvm-sandbox-block", f"distro:file:{diagnostic_distro},ro"]
    return command


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvxd", required=True, type=pathlib.Path)
    parser.add_argument("--repo", required=True, type=pathlib.Path)
    parser.add_argument("--initrd", required=True, type=pathlib.Path)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    args = parser.parse_args()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    inputs = {
        "runtime": args.initrd.resolve(),
        "kernel": args.repo / "build/vmlinux",
        "openvmm": args.repo / "openvmm/target/release/openvmm.exe",
        "agent": args.repo / "guest/common/nvx-managed-agent.c",
        "session": args.repo / "guest/common/nvx-guest-session.h",
        "probe": args.repo / "scripts/guest_session_probe.c",
        "builder": args.repo / "scripts/build_guest_session_probe.sh",
    }
    distro = distro_path()
    if distro:
        inputs["distro"] = distro
        inputs["erofsBuilder"] = args.repo / "scripts/diagnostic_erofs.sh"
    hashes = {key: sha256(path) for key, path in inputs.items()}
    diagnostic = out / "probe.cpio.gz"
    with (out / "build.log").open("wb") as log:
        subprocess.run(["wsl", "--exec", "sh", linux_path(inputs["builder"]),
                        linux_path(args.initrd), linux_path(diagnostic),
                        *([linux_path(distro)] if distro else [])],
                       stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120)
    started = time.monotonic()
    diagnostic_distro = pathlib.Path(str(diagnostic) + ".erofs") if distro else None
    command = probe_command(
        inputs["openvmm"], inputs["kernel"], diagnostic, diagnostic_distro)
    with (out / "boot.log").open("wb") as log:
        # subprocess.run kills and waits for this specific process on timeout.
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=60)
    text = (out / "boot.log").read_text(errors="replace")
    found = [line.split("P8-PROBE-PASS ", 1)[1].strip()
             for line in text.splitlines() if "P8-PROBE-PASS " in line]
    checks = set(found)
    missing = sorted(REQUIRED_CHECKS - checks)
    stable = hashes == {key: sha256(path) for key, path in inputs.items()}
    passed = (result.returncode == 0 and not missing and stable
              and "P8-PROBE-COMPLETE" in text and "P8-PROBE-FAIL" not in text
              and len(found) == len(checks))
    report = {
        "passed": passed, "exitCode": result.returncode, "args": command,
        "elapsedSeconds": time.monotonic() - started, "sha256": hashes,
        "diagnosticSha256": sha256(diagnostic), "inputsUnchanged": stable,
        "diagnosticDistroSha256": sha256(diagnostic_distro) if diagnostic_distro else None,
        "checks": found, "missing": missing,
    }
    (out / "result.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    if not passed:
        raise RuntimeError(f"fresh target-guest probe failed; see {out / 'result.json'}")
    print("CASE p8.guest_probe.target_negative_matrix PASS", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        raise SystemExit(f"guest probe report validation failed: {error!r}")
