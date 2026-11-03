"""WHP acceptance for explicit vCPU topology, parallel work and cancellation.

Uses the same explicit NVX_* artifact inputs as the other acceptance suites.
Only processes owned by this test are inspected or cleaned up.
"""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time

from p8_support import BoundedSidecar, stop_sidecar, vmm_processes
from runtime_assets import artifact_args


WORK = r"""
import json, multiprocessing as mp, os, time
mp.set_start_method("fork")
expected = EXPECTED
assert os.cpu_count() == expected, (os.cpu_count(), expected)
assert len(os.sched_getaffinity(0)) == expected
def worker(cpu, output):
    os.sched_setaffinity(0, {cpu})
    start = time.process_time()
    n = 0
    while time.process_time() - start < 0.6:
        n += 1
    output.put((cpu, time.process_time() - start, n))
q = mp.Queue()
workers = [mp.Process(target=worker, args=(cpu, q)) for cpu in range(expected)]
start = time.monotonic()
for p in workers: p.start()
results = [q.get(timeout=30) for p in workers]
for p in workers:
    p.join(10)
    assert p.exitcode == 0, p.exitcode
wall = time.monotonic() - start
assert sorted(r[0] for r in results) == list(range(expected))
print(json.dumps(dict(processors=expected, wallSeconds=wall,
    cpuSeconds=sum(r[1] for r in results), workers=results)))
"""


def run_case(args, count, isolated, root):
    workspace = root / "workspace"
    workspace.mkdir()
    command = [
        str(args.nvxd), *artifact_args(args.repo, args.initrd),
        "--cpu-profile", "host", "--processors", str(count),
        "--capability-cache", "none", "--state-dir", str(root / "state"),
    ]
    if isolated:
        command += ["--session-isolation"]
    process = subprocess.Popen(command, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    owned = []
    try:
        sidecar = BoundedSidecar(process)
        deadline = time.monotonic() + 90
        probe = sidecar.ok({"id": 1, "op": "probe", "waitMs": 60000}, deadline)
        assert probe["processors"] == count
        sidecar.ok({"id": 2, "op": "session.open", "session": "cpu",
                    "workspace": str(workspace), "memoryMiB": 1024}, deadline)
        owned = vmm_processes(process.pid)
        sidecar.ok({"id": 3, "op": "exec", "session": "cpu", "execId": "work",
                    "argv": ["python3", "-c", WORK.replace("EXPECTED", str(count))]},
                   deadline)
        sidecar.succeeded(["work"], deadline)
        report = json.loads(sidecar.stdout_of("work"))
        diagnostic = sidecar.ok({"id": 4, "op": "diagnostics"}, deadline)
        assert diagnostic["vm"]["processors"] == count
        assert diagnostic["vm"]["memoryMiB"] == 1024
        runtime = diagnostic["vm"]["runtimeId"]
        sidecar.ok({"id": 5, "op": "exec", "session": "cpu", "execId": "cancel",
                    "argv": ["python3", "-c",
                             "import multiprocessing as m,time\nm.set_start_method('fork')\n"
                             "def spin():\n while True: pass\n"
                             f"ps=[m.Process(target=spin) for _ in range({count})]\n"
                             "[p.start() for p in ps]\ntime.sleep(60)"]}, deadline)
        time.sleep(0.3)
        started = time.monotonic()
        sidecar.ok({"id": 6, "op": "signal", "execId": "cancel"}, deadline)
        terminal = sidecar.await_exits(["cancel"], deadline)["cancel"]
        assert terminal["outcome"] == "cancelled", terminal
        report["cancelSeconds"] = time.monotonic() - started
        diagnostic = sidecar.ok({"id": 7, "op": "diagnostics"}, deadline)
        assert diagnostic["vm"]["runtimeId"] == runtime
        sidecar.ok({"id": 8, "op": "exec", "session": "cpu", "execId": "alive",
                    "argv": ["true"]}, deadline)
        sidecar.succeeded(["alive"], deadline)
        sidecar.ok({"id": 9, "op": "session.close", "session": "cpu"}, deadline)
        report["isolated"] = isolated
        print(json.dumps(report), flush=True)
    finally:
        try:
            stop_sidecar(process)
        finally:
            for handle in owned:
                try:
                    handle.wait()
                finally:
                    handle.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvxd", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--initrd", type=Path, required=True)
    parser.add_argument("--processors", type=int, nargs="+", choices=[1, 2, 4, 8],
                        default=[1, 2, 4, 8])
    args = parser.parse_args()
    for count in args.processors:
        for isolated in [False, True]:
            with tempfile.TemporaryDirectory(prefix=f"nvxd-cpu-{count}-") as directory:
                run_case(args, count, isolated, Path(directory))


if __name__ == "__main__":
    main()
