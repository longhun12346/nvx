"""Prove the selected product VM uses EROFS/overlay and a healthy time daemon."""

import argparse
import hashlib
import pathlib
import subprocess
import tempfile
import time

from p8_support import BoundedSidecar, stop_sidecar
from runtime_assets import artifact_args, distro_path


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for name in ("nvxd", "repo", "initrd"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    args = parser.parse_args()
    distro = distro_path()
    if distro is None:
        raise RuntimeError("EROFS acceptance requires NVX_DISTRO")
    inputs = (args.initrd, distro)
    before = [digest(path) for path in inputs]
    with tempfile.TemporaryDirectory(prefix="nvx-erofs-acceptance-") as temporary:
        root = pathlib.Path(temporary)
        workspace = root / "workspace"
        workspace.mkdir()
        process = subprocess.Popen([
            str(args.nvxd), *artifact_args(args.repo, args.initrd),
            "--hypervisor", "whp", "--cpu-profile", "host",
            "--state-dir", str(root / "state"),
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            sidecar = BoundedSidecar(process)
            deadline = time.monotonic() + 90
            sidecar.ok(dict(id=1, op="session.open", session="erofs",
                            workspace=str(workspace), memoryMiB=1024), deadline)
            script = (
                'test "$(stat -f -c %T /)" = overlayfs; '
                'test "$(cat /sys/class/block/vda/ro)" = 1; '
                'test "$(cat /sys/class/block/vda/size)" -gt 0; '
                'test ! -w /init; test ! -w /usr/sbin/nvx-managed-agent; '
                'test ! -w /usr/bin; '
                'test "$(stat -f -c %T /var/tmp)" = overlayfs; '
                'file=$(mktemp /var/tmp/erofs-review.XXXXXX); '
                'trap \'rm -f "$file"\' EXIT; '
                'echo copy-up >"$file"; test "$(cat "$file")" = copy-up; '
                'python3 -c "print(123)"; node -e "console.log(456)"; '
                '/sbin/nvx-time status; grep "^violations=0$" /run/nvx/time/state'
            )
            sidecar.ok(dict(id=2, op="exec", session="erofs", execId="root",
                            argv=["sh", "-ec", script], timeoutMs=60000), deadline)
            sidecar.succeeded(["root"], deadline)
            text = sidecar.stdout_of("root").decode()
            if ("NVX-TIME-ABI: v=1 phase=boot status=ok" not in text
                    or "violations=0" not in text):
                raise RuntimeError(f"missing conformant time status: {text}")
            sidecar.ok(dict(id=3, op="session.close", session="erofs"), deadline)
        finally:
            stop_sidecar(process)
        if before != [digest(path) for path in inputs]:
            raise RuntimeError("EROFS acceptance modified runtime inputs")
    print("CASE erofs.root_readonly_overlay_and_time PASS", flush=True)


if __name__ == "__main__":
    main()
