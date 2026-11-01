"""Build and run the target-guest negative matrix during this gate invocation."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import pathlib
import hashlib
import subprocess
import time


REQUIRED_CHECKS = {
    "requires-root",
    "disposable-agent-state",
    "workspace-fixtures",
    "session-wire",
    "unknown-network-policy-refused",
    "shared-network-policy-decoded",
    "create-shared-network",
    "shared-network-is-the-vm-namespace",
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


GUEST_DIRECTORY = pathlib.Path(__file__).resolve().parents[2] / "nvxd-guest"
TARGET = "x86_64-unknown-linux-musl"
NUL = bytes(1)
BOOT_SCRIPT = (
    "#!/bin/sh\n"
    "status=0\n"
    "/p8-session-probe || status=$?\n"
    'exec /sbin/nvx-exit "$status"\n'
).encode()


def cpio_entry(name, data, mode):
    encoded = name.encode() + NUL
    fields = (0, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0)
    header = b"070701" + b"".join(b"%08X" % value for value in fields)
    return (header + encoded + NUL * (-(110 + len(encoded)) % 4)
            + data + NUL * (-len(data) % 4))


def append_probe(base, probe, output):
    entries = [("p8-session-probe", probe.read_bytes(), 0o100755),
               ("p8-probe-boot", BOOT_SCRIPT, 0o100755)]
    archive = b"".join(cpio_entry(*entry) for entry in entries)
    archive += cpio_entry("TRAILER!!!", b"", 0)
    archive += NUL * (-len(archive) % 512)
    output.write_bytes(base.read_bytes() + gzip.compress(archive, mtime=0))


def build_probe(log):
    environment = dict(os.environ)
    environment["CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"] = "rust-lld"
    environment["CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS"] = (
        "-Clinker-flavor=ld.lld -Clink-self-contained=yes")
    subprocess.run(
        ["cargo", "build", "--release", "--locked", "--features", "session-probe",
         "--target", TARGET, "--bin", "nvxd-guest-probe"],
        cwd=GUEST_DIRECTORY, env=environment, stdout=log, stderr=subprocess.STDOUT,
        check=True, timeout=900)
    return GUEST_DIRECTORY / "target" / TARGET / "release" / "nvxd-guest-probe"


def probe_command(openvmm, kernel, diagnostic):
    return [
        str(openvmm), "--single-process", "--machine", "microvm",
        "--processors", "2", "--hypervisor", "whp", "--cpu-profile", "host",
        "--memory", "1024M", "--kernel", str(kernel),
        "--initrd", str(diagnostic), "--cmdline", "nvx_exec=/p8-probe-boot",
    ]


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
        "agent": GUEST_DIRECTORY / "src/session/mod.rs",
        "session": GUEST_DIRECTORY / "ISOLATION.md",
        "probe": GUEST_DIRECTORY / "src/bin/nvxd-guest-probe.rs",
        "builder": pathlib.Path(__file__).resolve(),
    }
    for key, variable in (("kernel", "NVX_KERNEL"), ("openvmm", "NVX_OPENVMM"),
                          ("runtime", "NVX_INITRD")):
        if os.environ.get(variable):
            inputs[key] = pathlib.Path(os.environ[variable]).resolve()
    hashes = {key: sha256(path) for key, path in inputs.items()}
    diagnostic = out / "probe.cpio.gz"
    with (out / "build.log").open("wb") as log:
        probe = build_probe(log)
    append_probe(inputs["runtime"], probe, diagnostic)
    started = time.monotonic()
    command = probe_command(inputs["openvmm"], inputs["kernel"], diagnostic)
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
        "probeBinarySha256": sha256(probe),
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
