"""Times the workspace mount operations of the sidecar over one VM (open, exec that adds or drops a
mount, close). Environment as in runtime_assets.py, plus NVXD_EXE for the sidecar."""
import os, pathlib, subprocess, sys, tempfile, time, statistics
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import faults
from runtime_assets import artifact_args

root = pathlib.Path(tempfile.mkdtemp(prefix="mount-timing-"))
p = subprocess.Popen([os.environ["NVXD_EXE"], "--hypervisor", "whp", *artifact_args(os.environ.get("NVX_REPO", "."), os.environ["NVX_INITRD"]),
                      "--cpu-profile", "host", "--state-dir", str(root / "s")],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
faults.read_frame(p.stdout)
n = [100]


def call(body):
    faults.send_frame(p.stdin, body)
    while True:
        f = faults.read_frame(p.stdout)
        if f is None:
            raise RuntimeError("eof")
        if f[0].get("id") == body["id"]:
            return f[0]


def run(session, argv, mounts=None, cwd=None):
    n[0] += 1
    eid = f"E{n[0]}"
    body = {"id": n[0], "op": "exec", "session": session, "execId": eid, "argv": argv}
    if mounts:
        body["mounts"] = mounts
    if cwd:
        body["cwd"] = cwd
    t = time.monotonic()
    r = call(body)
    assert r.get("ok"), r
    out = b""
    while True:
        f = faults.read_frame(p.stdout)
        if f[0].get("execId") == eid or f[0].get("handle") == eid:
            if f[0].get("event") == "exec.stdout":
                out += f[1]
            if f[0].get("event") == "exec.exit":
                return time.monotonic() - t, out, f[0]


def ws(name):
    d = root / name
    d.mkdir()
    (d / "hello.txt").write_text(name)
    return d


a, b = ws("wa"), ws("wb")
extra = []
for i in range(5):
    d = root / f"m{i}"
    d.mkdir()
    (d / "f.txt").write_text(f"m{i}")
    extra.append(d)
n[0] += 1
t = time.monotonic(); r = call({"id": n[0], "op": "session.open", "session": "A", "workspace": str(a), "memoryMiB": 1024}); print("open A (boots VM + workspace mount): %.3f s" % (time.monotonic() - t), r.get("workspaceGuestPath"))
n[0] += 1
t = time.monotonic(); r = call({"id": n[0], "op": "session.open", "session": "B", "workspace": str(b), "memoryMiB": 1024}); print("open B (workspace mount only): %.3f s" % (time.monotonic() - t), r.get("workspaceGuestPath"))
plain = [run("A", ["cat", "hello.txt"], cwd=str(a))[0] for _ in range(5)]
print("exec without mount change: median %.3f s" % statistics.median(plain))
add_times, rm_times = [], []
for i, d in enumerate(extra):
    elapsed, out, _ = run("A", ["cat", f"/workspace/mounts/m{i}/f.txt"], mounts=[{"mountId": f"m{i}", "hostPath": str(d), "mode": "ro"}], cwd=str(a))
    add_times.append(elapsed)
    assert out == f"m{i}".encode(), out
    elapsed, out, _ = run("A", ["cat", "hello.txt"], cwd=str(a))
    rm_times.append(elapsed)
print("exec that adds a mount (add + bind + run): median %.3f s, max %.3f s" % (statistics.median(add_times), max(add_times)))
print("exec that drops the previous mount (unbind + remove + run): median %.3f s" % statistics.median(rm_times))
n[0] += 1
t = time.monotonic(); r = call({"id": n[0], "op": "session.close", "session": "B"}); print("close B (unmount + unexport workspace): %.3f s" % (time.monotonic() - t), r.get("state"))
n[0] += 1
d = call({"id": n[0], "op": "diagnostics"})
print("stats:", {k: v for k, v in d.get("stats", {}).items() if k.startswith(("shares", "mounts"))}, "cleanupPending", d.get("cleanupPending"))
faults.send_frame(p.stdin, {"op": "shutdown"})
p.stdin.close()
p.wait(timeout=60)
