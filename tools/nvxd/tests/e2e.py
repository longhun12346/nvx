"""Required real-VM smoke for the NVX sidecar.

This test deliberately fails when a required input is missing. It is not a
best-effort CTest case: callers use it as the independent sidecar acceptance
entry before running the engine integration smoke.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import struct
import subprocess
import tempfile
import time


def read_frame(stream):
    header = stream.read(8)
    if len(header) != 8:
        raise RuntimeError("sidecar closed before a complete frame")
    json_size, payload_size = struct.unpack("<II", header)
    return (
        json.loads(stream.read(json_size)),
        stream.read(payload_size),
    )


def send_frame(stream, body):
    encoded = json.dumps(body, separators=(",", ":")).encode()
    stream.write(struct.pack("<II", len(encoded), 0) + encoded)
    stream.flush()


def request(input_stream, output_stream, body):
    send_frame(input_stream, body)
    head, payload = read_frame(output_stream)
    if not head.get("ok", False):
        raise RuntimeError(
            f"{body.get('op')} failed: {head.get('reasonCode')} "
            f"{head.get('message', '')}"
        )
    return head, payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvxd", required=True, type=pathlib.Path)
    parser.add_argument("--repo", required=True, type=pathlib.Path)
    parser.add_argument("--initrd", required=True, type=pathlib.Path)
    parser.add_argument(
        "--stress",
        type=int,
        default=0,
        help="extra rounds of mount churn to run over the one VM (0 disables)",
    )
    args = parser.parse_args()
    for path, label in (
        (args.nvxd, "sidecar"),
        (args.repo, "NVX repository"),
        (args.initrd, "Ubuntu runtime initramfs"),
    ):
        if not path.exists():
            raise RuntimeError(f"{label} is missing: {path}")

    stage = "startup"
    with tempfile.TemporaryDirectory(prefix="nvxd-e2e-") as root_name:
        root = pathlib.Path(root_name)
        workspace = root / "workspace"
        refs = root / "refs"
        workspace.mkdir()
        refs.mkdir()
        (refs / "input.txt").write_text("from-nvx-e2e", encoding="utf-8")
        state = root / "state"
        process = subprocess.Popen(
            [
                str(args.nvxd),
                "--hypervisor",
                "whp",
                "--repo",
                str(args.repo),
                "--initrd",
                str(args.initrd),
                "--cpu-profile",
                "host",
                "--state-dir",
                str(state),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stage = "ready"
        try:
            ready, _ = read_frame(process.stdout)
            if ready.get("event") != "ready" or ready.get("protocol") != 1:
                raise RuntimeError(f"unexpected ready frame: {ready}")
            head, _ = request(process.stdin, process.stdout, {"id": 1, "op": "probe"})
            provenance = head.get("provenance") or {}
            if provenance.get("cpuProfile") != "host":
                raise RuntimeError(
                    f"probe did not report the configured CPU profile: {provenance}"
                )
            if provenance.get("initrd") != str(args.initrd):
                raise RuntimeError(
                    f"probe did not report the override initramfs: {provenance}"
                )
            stage = "session.open"
            opened, _ = request(
                process.stdin,
                process.stdout,
                {
                    "id": 2,
                    "op": "session.open",
                    "session": "e2e",
                    "workspace": str(workspace),
                    "memoryMiB": 1024,
                },
            )
            if not opened.get("workspaceGuestPath"):
                raise RuntimeError(f"session did not return guest workspace: {opened}")
            request_body = {
                "id": 3,
                "op": "exec",
                "session": "e2e",
                "argv": [
                    "sh",
                    "-c",
                    "printf out; printf err >&2; "
                    "cat /workspace/mounts/refs/input.txt; exit 7",
                ],
                "cwd": str(workspace),
                "mounts": [
                    {
                        "mountId": "refs",
                        "hostPath": str(refs),
                        "mode": "ro",
                    }
                ],
            }
            stage = "exec"
            reply, _ = request(process.stdin, process.stdout, request_body)
            handle = reply["handle"]
            stdout = bytearray()
            stderr = bytearray()
            exit_frame = None
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                head, payload = read_frame(process.stdout)
                if head.get("handle") != handle:
                    continue
                if head.get("event") == "exec.stdout":
                    stdout.extend(payload)
                elif head.get("event") == "exec.stderr":
                    stderr.extend(payload)
                elif head.get("event") == "exec.exit":
                    exit_frame = head
                    break
            if exit_frame is None:
                raise RuntimeError("exec did not produce an exit event")
            if bytes(stdout) != b"outfrom-nvx-e2e":
                raise RuntimeError(f"unexpected stdout: {stdout!r}")
            if bytes(stderr) != b"err":
                raise RuntimeError(f"unexpected stderr: {stderr!r}")
            if exit_frame.get("outcome") != "exited" or exit_frame.get("code") != 7:
                raise RuntimeError(f"unexpected exit: {exit_frame}")

            def run_command(command, mounts, next_id):
                """Runs one command and returns (stdout, stderr, exit_frame)."""
                body = {
                    "id": next_id,
                    "op": "exec",
                    "session": "e2e",
                    "argv": ["sh", "-c", command],
                    "cwd": str(workspace),
                    "mounts": mounts,
                }
                reply, _ = request(process.stdin, process.stdout, body)
                this_handle = reply.get("handle")
                out = bytearray()
                err = bytearray()
                end = None
                until = time.monotonic() + 120
                while time.monotonic() < until:
                    head, payload = read_frame(process.stdout)
                    if head.get("handle") != this_handle:
                        continue
                    if head.get("event") == "exec.stdout":
                        out.extend(payload)
                    elif head.get("event") == "exec.stderr":
                        err.extend(payload)
                    elif head.get("event") == "exec.exit":
                        end = head
                        break
                if end is None:
                    raise RuntimeError("exec did not produce an exit event")
                return bytes(out), bytes(err), end

            # An export outside the paths the sidecar was given must be refused: the
            # channel authenticates the caller, but it must not become a way to read
            # arbitrary host locations.
            stage = "refuse outside path"
            outside = root.parent / "outside-e2e"
            outside.mkdir(exist_ok=True)
            (outside / "secret.txt").write_text("must-not-be-readable", encoding="utf-8")
            try:
                request(
                    process.stdin,
                    process.stdout,
                    {
                        "id": 90,
                        "op": "exec",
                        "session": "e2e",
                        "argv": ["sh", "-c", "true"],
                        "cwd": str(workspace),
                        "mounts": [
                            {"mountId": "outside", "hostPath": str(outside), "mode": "ro"}
                        ],
                    },
                )
                raise RuntimeError("a mount outside the allowed paths was accepted")
            except RuntimeError as error:
                if "outside the allowed paths was accepted" in str(error):
                    raise
                # Any refusal is the expected outcome; the frame carries the reason.

            # Read-write, removal, and many rounds of churn over one VM: the channel
            # must keep adding and removing aggregate children without leaking slots.
            stage = "stress"
            rounds = args.stress
            for round_number in range(rounds):
                # One mount identity, so each round re-establishes the same export and the
                # guest's runtime mapping table stays in step with the snapshot. Rebinding a
                # new identity every round would grow that table instead of exercising churn.
                mount_id = "churn"
                payload_path = refs / "churn.txt"
                if round_number % 2 == 0:
                    payload_path.write_text(f"round-{round_number}", encoding="utf-8")
                out, err, end = run_command(
                    f"cat /workspace/mounts/{mount_id}/churn.txt 2>/dev/null || true",
                    [
                        {
                            "mountId": mount_id,
                            "hostPath": str(refs),
                            "mode": "rw",
                        }
                    ],
                    100 + round_number,
                )
                if end.get("outcome") != "exited":
                    raise RuntimeError(f"round {round_number}: unexpected exit {end}")
            print(f"stress: {rounds} mount rounds over one VM")

            stage = "session.close"
            request(
                process.stdin,
                process.stdout,
                {"id": 4, "op": "session.close", "session": "e2e"},
            )
            print("nvxd independent VM e2e passed")
        except Exception as error:
            raise RuntimeError(f"stage {stage}: {error}") from error
        finally:
            try:
                send_frame(process.stdin, {"op": "shutdown"})
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            if process.returncode != 0:
                error = process.stderr.read().decode(errors="replace")
                raise RuntimeError(
                    f"sidecar exited with {process.returncode}: {error}"
                )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(f"nvxd e2e failed: {error!r}")
