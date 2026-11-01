import os, pathlib, subprocess, sys, tempfile, time, threading
sys.path.insert(0, r"D:\github\spikes\nvx-mig\tools\nvxd\tests")
import faults
from runtime_assets import artifact_args

nvxd = os.environ["NVXD_EXE"]
root = pathlib.Path(tempfile.mkdtemp(prefix="beh-"))
extra = ["--max-running", "1", "--ingress", "host-loopback", "--session-ttl-secs", "6", "--max-sessions", "3"]
p = subprocess.Popen([nvxd, *artifact_args(r"D:\github\nvx", os.environ["NVX_INITRD"]), "--hypervisor", "whp", "--cpu-profile", "host",
                      "--state-dir", str(root / "s"), *extra], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
lock = threading.Condition()
replies, exits, out = {}, {}, {}
def reader():
    while True:
        f = faults.read_frame(p.stdout)
        if f is None: return
        h, pl = f
        with lock:
            if "id" in h: replies[h["id"]] = h
            elif h.get("event") == "exec.exit": exits[h["execId"]] = h
            elif h.get("event") in ("exec.stdout", "exec.stderr"): out[h["execId"]] = out.get(h["execId"], b"") + pl
            lock.notify_all()
threading.Thread(target=reader, daemon=True).start()
n = [100]
def call(op, wait=60, **kw):
    n[0] += 1
    faults.send_frame(p.stdin, {"id": n[0], "op": op, **kw})
    end = time.time() + wait
    with lock:
        while n[0] not in replies and time.time() < end: lock.wait(0.2)
        return replies.get(n[0], {"ok": False, "message": "no reply"})
def wait_exit(eid, wait=30):
    end = time.time() + wait
    with lock:
        while eid not in exits and time.time() < end: lock.wait(0.2)
        return exits.get(eid)
def show(label, value): print(f"{label}: {value}")

(root / "w").mkdir()
show("probe", call("probe").get("ok"))
show("open A", call("session.open", session="A", workspace=str(root / "w"), memoryMiB=1024).get("ok"))
show("open B", call("session.open", session="B", workspace=str(root / "w"), memoryMiB=1024).get("ok"))
show("open A again", call("session.open", session="A", workspace=str(root / "w"), memoryMiB=1024).get("reasonCode"))
call("exec", session="A", execId="R1", argv=["sh", "-c", "sleep 60"])
r2 = call("exec", session="B", execId="Q1", argv=["sh", "-c", "echo queued-ran"])
show("second exec is queued behind the first (max-running 1)", r2.get("state"))
show("status running", call("exec.status", execId="R1").get("state"))
show("signal queued", call("signal", execId="Q1"))
show("queued exit", (wait_exit("Q1") or {}).get("outcome"))
show("signal running", call("signal", execId="R1"))
e = wait_exit("R1")
show("running exit", (e or {}).get("outcome"))
show("status finished", call("exec.status", execId="R1").get("state"))
show("status unknown", call("exec.status", execId="NOPE").get("state"))
show("signal unknown exec id", call("signal", execId="NOPE2"))
show("signal unknown handle", call("signal", handle="NOPE3").get("reasonCode"))
show("duplicate start (same args)", call("exec", session="B", execId="D1", argv=["sh", "-c", "echo d"]).get("state"))
wait_exit("D1")
show("duplicate start again", call("exec", session="B", execId="D1", argv=["sh", "-c", "echo d"]))
show("conflicting duplicate", call("exec", session="B", execId="D1", argv=["sh", "-c", "echo other"]).get("reasonCode"))
show("exec in unknown session", call("exec", session="Z", execId="Z1", argv=["true"]).get("reasonCode"))
show("exec with stdin", call("exec", session="A", execId="S1", argv=["cat"], stdin="x").get("reasonCode"))
show("timeout", None)
call("exec", session="A", execId="T1", argv=["sh", "-c", "sleep 30"], timeoutMs=1500)
show("timeout exit", (wait_exit("T1", 20) or {}).get("outcome"))
show("env and bare program", None)
call("exec", session="A", execId="E1", argv=["sh", "-c", "echo $FOO:$HOME"], env={"FOO": "bar"})
wait_exit("E1"); show("env output", out.get("E1"))
show("memory.stats", {k: v for k, v in call("memory.stats").items() if k in ("ok", "workingSetMiB", "busy")})
show("memory.trim", {k: v for k, v in call("memory.trim").items() if k in ("ok", "beforeMiB", "afterMiB", "reasonCode")})
show("port.allocate", call("port.allocate").get("port"))
show("close B with a running exec", None)
call("exec", session="B", execId="C1", argv=["sh", "-c", "sleep 60"])
time.sleep(1)
t = time.time(); c = call("session.close", session="B"); show("close", (c.get("state"), round(time.time() - t, 2)))
show("running exec after close", (wait_exit("C1") or {}).get("outcome"))
show("close twice", call("session.close", session="B").get("alreadyClosed"))
show("diagnostics sessions", [s["session"] for s in call("diagnostics").get("sessions", [])])
show("TTL: waiting for the idle session A to expire (ttl 6 s)", None)
time.sleep(9)
d = call("diagnostics"); show("sessions after ttl", [s["session"] for s in d.get("sessions", [])]); show("vm after ttl", d.get("vm"))
faults.send_frame(p.stdin, {"op": "shutdown"}); p.stdin.close()
t = time.time(); p.wait(60); show("shutdown seconds", round(time.time() - t, 2))
