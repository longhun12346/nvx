"""Use the gate's explicit assets instead of sidecar repository auto-discovery."""

import os
from pathlib import Path


def distro_path():
    value = os.environ.get("NVX_DISTRO")
    if not value:
        return None
    path = Path(value).resolve()
    if not path.is_file():
        raise ValueError(f"NVX_DISTRO is missing: {path}")
    return path


def artifact_args(repo, initrd, *, distro=None):
    repo = Path(repo)
    arguments = [
        "--openvmm", str(repo / "openvmm/target/release/openvmm.exe"),
        "--kernel", str(repo / "build/vmlinux"),
        "--initrd", str(initrd),
    ]
    layer = distro if distro is not None else distro_path()
    if layer is not None:
        arguments += ["--distro", str(layer)]
    return arguments
