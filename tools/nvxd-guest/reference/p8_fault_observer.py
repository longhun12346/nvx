"""Privileged observer included only in a disposable P8 diagnostic initrd.

The production agent is copied byte for byte from the supplied runtime. This
separate process injects failures from outside workload namespaces/cgroups.
No observer or trigger is added to the production runtime.
"""

import os
import pathlib
import signal
import time


def keeper_for(workspace):
    identity = (workspace / "p8-target").read_text()
    for process in pathlib.Path("/proc").glob("[0-9]*"):
        try:
            status = (process / "status").read_text()
            nested = next(line.split()[1:] for line in status.splitlines()
                          if line.startswith("NSpid:"))
            if len(nested) < 2 or nested[-1] != "1":
                continue
            root = process / "root"
            if (root / "workspace/p8-target").read_text() == identity:
                return int(process.name), root
        except (OSError, StopIteration):
            continue
    return None


def main():
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        for trigger in pathlib.Path("/sessions").glob("*/workspace/p8-fire"):
            workspace = trigger.parent
            try:
                mode = trigger.read_text().strip()
                keeper = keeper_for(workspace)
                if keeper is None:
                    continue
                pid, root = keeper
                held = None
                if mode == "keeper":
                    os.kill(pid, signal.SIGKILL)
                elif mode == "strict-revoke":
                    held = (root / "workspace/mounts/data/marker").open("rb")
                elif mode in ("source-unmap", "close-export"):
                    sources = list(workspace.parent.glob("mounts/*/marker"))
                    if len(sources) != 1:
                        continue
                    held = sources[0].open("rb")
                elif mode == "close-directory":
                    for directory in pathlib.Path("/run/nvx/session-store").iterdir():
                        (directory / "p8-injected-busy").mkdir()
                else:
                    raise RuntimeError("unknown diagnostic fault")
                (workspace / "p8-injected").write_text(f"{mode} keeper={pid}")
                # Retain the exact mount object until this diagnostic VM exits.
                while time.monotonic() < deadline:
                    if held:
                        os.fstat(held.fileno())
                    time.sleep(0.05)
                return
            except OSError as error:
                (workspace / "p8-observer-error").write_text(repr(error))
                raise
        time.sleep(0.02)
    raise RuntimeError("diagnostic fault was never requested")


if __name__ == "__main__":
    main()
