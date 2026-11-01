"""Times fresh-sidecar starts: process start to ready, then the first session.open (VM boot plus
mount), the second open, a plain exec and the close. Environment as in runtime_assets.py, plus
NVXD_EXE for the sidecar. Set NVXD_TRACE_PHASES=1 to print the sidecar's per-phase launch timing
(from its stderr). Usage: python cold_start.py [rounds] [--keep-capability-cache] [--delay-ms=N]
(--delay-ms waits between probe and the first open, to show how much of the launch the sidecar can do ahead)"""
import os, pathlib, shutil, statistics, subprocess, sys, tempfile, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import faults
from runtime_assets import artifact_args

rounds = int(next((a for a in sys.argv[1:] if a.isdigit()), "12"))
keep_cache = "--keep-capability-cache" in sys.argv
delay = float(next((a.split("=")[1] for a in sys.argv[1:] if a.startswith("--delay-ms=")), "0")) / 1000.0
root = pathlib.Path(tempfile.mkdtemp(prefix="cold-start-"))
cache = pathlib.Path(os.environ.get("LOCALAPPDATA", "")) / "nvxd" / "capability.json"
rows, phases = [], []
for k in range(rounds):
    if not keep_cache and k == 0:
        cache.unlink(missing_ok=True)
    workspace = root / f"w{k}"
    workspace.mkdir()
    lines = []
    started = time.perf_counter()
    p = subprocess.Popen(
        [os.environ["NVXD_EXE"], "--hypervisor", "whp", *artifact_args(os.environ.get("NVX_REPO", "."), os.environ["NVX_INITRD"]),
         "--cpu-profile", "host", "--state-dir", str(root / f"s{k}")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    threading.Thread(target=lambda: [lines.append(l.decode(errors="replace").rstrip()) for l in p.stderr], daemon=True).start()
    faults.read_frame(p.stdout)
    ready = time.perf_counter() - started

    def call(body):
        faults.send_frame(p.stdin, body)
        while True:
            f = faults.read_frame(p.stdout)
            if f is None:
                raise RuntimeError("eof")
            if f[0].get("id") == body["id"]:
                return f[0]

    t = time.perf_counter(); r = call({"id": 1, "op": "probe"}); probe = time.perf_counter() - t
    time.sleep(delay)
    t = time.perf_counter(); r = call({"id": 2, "op": "session.open", "session": "A", "workspace": str(workspace), "memoryMiB": 1024}); first = time.perf_counter() - t
    assert r.get("ok"), r
    t = time.perf_counter(); call({"id": 3, "op": "exec", "session": "A", "execId": "E", "argv": ["true"], "cwd": str(workspace)})
    while True:
        f = faults.read_frame(p.stdout)
        if f[0].get("event") == "exec.exit":
            break
    plain = time.perf_counter() - t
    t = time.perf_counter(); call({"id": 4, "op": "session.close", "session": "A"}); close = time.perf_counter() - t
    faults.send_frame(p.stdin, {"op": "shutdown"}); p.stdin.close(); p.wait(timeout=60)
    rows.append((ready, probe, first, plain, close))
    phases.append([l for l in lines if "phase " in l])
    print("round %2d: ready %.3f probe %.3f open(boot) %.3f exec %.3f close %.3f" % (k + 1, *rows[-1]), flush=True)
cols = list(zip(*rows))
names = ["ready", "probe", "open(boot)", "exec", "close"]
print("MEDIAN: " + "  ".join("%s %.3f" % (n, statistics.median(c)) for n, c in zip(names, cols)))
if phases and phases[-1]:
    print("phases of the last round:")
    print("\n".join(phases[-1]))
shutil.rmtree(root, ignore_errors=True)
