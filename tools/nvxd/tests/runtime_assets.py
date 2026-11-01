"""The gate's explicit assets, passed to the sidecar one by one.

Each asset can be named by an environment variable; what is not named is taken from a repository
checkout's conventional layout (`repo`) as before:

    NVX_OPENVMM      the OpenVMM executable
    NVX_KERNEL       the guest kernel (vmlinux)
    NVX_INITRD       NVX's base initramfs (the sidecar boots a copy of it with the guest agent)
    NVX_DISTRO       the EROFS image of the guest root
    NVX_GUEST_AGENT  the guest agent (static musl executable)
"""

import os
from pathlib import Path


def _named(variable):
    value = os.environ.get(variable)
    if not value:
        return None
    path = Path(value).resolve()
    if not path.is_file():
        raise ValueError(f"{variable} is missing: {path}")
    return path


def distro_path():
    return _named("NVX_DISTRO")


def artifact_args(repo, initrd, *, distro=None):
    repo = Path(repo)
    openvmm = _named("NVX_OPENVMM") or repo / "openvmm/target/release/openvmm.exe"
    kernel = _named("NVX_KERNEL") or repo / "build/vmlinux"
    base = _named("NVX_INITRD") or Path(initrd)
    arguments = [
        "--openvmm", str(openvmm),
        "--kernel", str(kernel),
        "--initrd", str(base),
    ]
    layer = distro if distro is not None else distro_path()
    if layer is not None:
        arguments += ["--distro", str(layer)]
    agent = _named("NVX_GUEST_AGENT")
    if agent is not None:
        arguments += ["--guest-agent", str(agent)]
    return arguments
