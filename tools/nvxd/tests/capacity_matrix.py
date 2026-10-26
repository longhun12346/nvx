"""Measure the locked runtime, eight sessions and eight resident 32 MiB tasks.

This workload-specific report does not promise arbitrary eight-task memory safety.
It measures each VM through its own sidecar, and records SHA256 for all inputs.
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import pathlib
import subprocess
import tempfile
import time


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def process_memory(pid):
    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
            (key, ctypes.c_size_t) for key in (
                "peakWorkingSet", "workingSet", "peakPaged", "paged",
                "peakNonPaged", "nonPaged", "pagefile", "peakPagefile", "privateBytes")]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    handle = kernel.OpenProcess(0x410, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return {key + "MiB": getattr(counters, key) / (1 << 20)
                for key in ("workingSet", "peakWorkingSet", "privateBytes")}
    finally:
        kernel.CloseHandle(handle)


def measure(args, isolated, memory_mib, repetition):
    from p8_support import BoundedSidecar, stop_sidecar, vmm_processes

    root = pathlib.Path(tempfile.mkdtemp(prefix="nvx-d6-capacity-matrix-"))
    workspaces = {name: root / name for name in "abcdefgh"}
    for path in workspaces.values():
        path.mkdir()
    command = [
        str(args.nvxd), "--hypervisor", "whp", "--cpu-profile", "host",
        "--repo", str(args.repo), "--initrd", str(args.initrd),
        "--max-running", "8", "--max-sessions", "8",
        "--idle-trim-secs", "0", "--state-dir", str(root / "state"),
    ]
    if isolated:
        command.append("--session-isolation")
    started = time.monotonic()
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    sidecar = BoundedSidecar(process)
    ready_seconds = time.monotonic() - started
    deadline = started + 300
    sequence = 0
    handles = []

    def call(op, **fields):
        nonlocal sequence
        sequence += 1
        return sidecar.ok(dict(id=sequence, op=op, **fields), deadline)

    try:
        opened = {}
        for name, path in workspaces.items():
            opened[name] = call("session.open", session=name, workspace=str(path),
                                memoryMiB=memory_mib, sessionIsolation=isolated)
        sequence += 1
        sidecar.refused(dict(id=sequence, op="session.open", session="overflow",
                            workspace=str(root), memoryMiB=memory_mib),
                        deadline, "E_BACKEND_BUSY")
        open_seconds = time.monotonic() - started
        handles = vmm_processes(process.pid)
        cold_idle = call("memory.stats")
        process_samples = {"cold": {"sidecar": process_memory(process.pid),
                                   "vmm": [process_memory(handle.pid) for handle in handles]}}
        for name in workspaces:
            key = "warm-" + name
            call("exec", session=name, execId=key,
                 argv=["python3", "-c", "import os; print(os.cpu_count())"])
            sidecar.succeeded([key], deadline)
        vcpus = int(sidecar.stdout_of("warm-a").strip())
        idle = call("memory.stats")
        process_samples["warm"] = {"sidecar": process_memory(process.pid),
                                  "vmm": [process_memory(handle.pid) for handle in handles]}
        members = [(name, f"work-{index}") for index, name in enumerate(workspaces)]
        launch_started = time.monotonic()
        for name, key in members:
            guest = opened[name]["workspaceGuestPath"]
            script = (
                "import pathlib,time\n"
                "memory=bytearray(32*1024*1024)\n"
                "for i in range(0,len(memory),4096): memory[i]=1\n"
                + ("pathlib.Path('/tmp/resident').write_bytes(b'x'*(8*1024*1024))\n"
                   if isolated else "") +
                f"root=pathlib.Path({guest!r})\n"
                f"(root/{(key + '.ready')!r}).write_text('ready')\n"
                "until=time.monotonic()+90\n"
                f"while not (root/{(key + '.release')!r}).exists():\n"
                " assert time.monotonic()<until, 'barrier expired'\n"
                " time.sleep(0.02)\n"
                "assert sum(memory)==8192\n"
            )
            call("exec", session=name, execId=key, argv=["python3", "-c", script],
                 limits={"memMb": 96}, timeoutMs=120000)
        while not all((workspaces[name] / (key + ".ready")).exists() for name, key in members):
            if time.monotonic() >= deadline or any(key in sidecar.exits for _, key in members):
                raise RuntimeError(f"eight live workloads not reached: {sidecar.exits}")
            call("diagnostics")
            time.sleep(0.02)
        ready_all = time.monotonic() - launch_started
        active = call("diagnostics")
        if len(active["running"]) != 8:
            raise RuntimeError(f"capacity barrier has fewer than eight live execs: {active}")
        loaded_samples = []
        for _ in range(5):
            loaded_samples.append(call("memory.stats")["workingSetMiB"])
            time.sleep(0.2)
        process_samples["loaded"] = {"sidecar": process_memory(process.pid),
                                    "vmm": [process_memory(handle.pid) for handle in handles]}
        for name, key in members:
            (workspaces[name] / (key + ".release")).write_text("go", encoding="utf-8")
        sidecar.succeeded([key for _, key in members], deadline)
        after = call("memory.stats")
        private_storage = []
        if isolated:
            # A saturates each private tmpfs separately while B remains alive.
            # This tests ENOSPC boundaries, persistence and recovery without
            # claiming resistance to group-wide resource exhaustion.
            guest_b = opened["b"]["workspaceGuestPath"]
            call("exec", session="b", execId="storage-peer",
                 argv=["sh", "-ec", f"echo ready >{guest_b}/storage.ready; "
                       f"while [ ! -f {guest_b}/storage.release ]; do sleep 0.05; done"],
                 timeoutMs=90000)
            while not (workspaces["b"] / "storage.ready").exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError("storage peer did not become ready")
                call("diagnostics")
            for directory, maximum in (("/tmp", 32), ("/home/sandbox", 32), ("/dev/shm", 16)):
                key = "fill-" + directory.replace("/", "-")
                script = (
                    "import errno,json,os,pathlib\n"
                    f"root=pathlib.Path({directory!r})\n"
                    "root = pathlib.Path(os.environ['HOME']) if str(root)=='/home/sandbox' else root\n"
                    "block=b'x'*(1024*1024)\n"
                    "count=0\n"
                    "try:\n"
                    " with (root/'capacity-fill').open('wb',buffering=0) as f:\n"
                    "  while count<128: count+=f.write(block)//len(block)\n"
                    "except OSError as error:\n"
                    " assert error.errno==errno.ENOSPC, error\n"
                    "else: raise AssertionError('private tmpfs has no enforced bound')\n"
                    f"assert {maximum - 10}<=count<={maximum}, count\n"
                    "print(json.dumps({'path':str(root),'writtenMiB':count}))\n"
                )
                call("exec", session="a", execId=key, argv=["python3", "-c", script],
                     limits={"memMb": 96}, timeoutMs=30000)
                sidecar.succeeded([key], deadline)
                sample = json.loads(sidecar.stdout_of(key))
                sample["workingSetMiB"] = call("memory.stats")["workingSetMiB"]
                private_storage.append(sample)
                call("exec", session="a", execId=key + "-clean", argv=["sh", "-ec",
                     'rm -f /tmp/capacity-fill "$HOME/capacity-fill" /dev/shm/capacity-fill'])
                sidecar.succeeded([key + "-clean"], deadline)
            if "storage-peer" not in call("diagnostics")["running"]:
                raise RuntimeError("private tmpfs saturation terminated the peer")
            (workspaces["b"] / "storage.release").write_text("go")
            sidecar.succeeded(["storage-peer"], deadline)
        for name in workspaces:
            call("session.close", session=name)
        clean = call("diagnostics")
        if clean["vm"] or clean["sessionCount"] or clean["cleanupPending"] or clean["closingGuestSessions"]:
            raise RuntimeError(f"capacity run did not clean its group: {clean}")
        for handle in handles:
            handle.wait()
        return {
            "isolated": isolated, "guestMemoryMiB": memory_mib, "repetition": repetition,
            "readySeconds": ready_seconds, "eightSessionOpenSeconds": open_seconds,
            "logicalSessions": len(workspaces), "privateStorage": private_storage,
            "hostProcessMemory": process_samples,
            "privateTmpMiBPerSession": 8 if isolated else 0,
            "eightResidentReadySeconds": ready_all, "residentBytesPerTask": 32 << 20,
            "limitMiBPerExec": 96, "effectiveConcurrentExecs": 8,
            "guestVcpus": vcpus,
            "coldIdleVmmWorkingSetMiB": cold_idle["workingSetMiB"],
            "idleVmmWorkingSetMiB": idle["workingSetMiB"],
            "loadedVmmWorkingSetSamplesMiB": loaded_samples,
            "afterExecVmmWorkingSetMiB": after["workingSetMiB"],
            "identity": active["vm"], "vmmPids": [handle.pid for handle in handles],
            "cleaned": True, "workDirectory": str(root),
        }
    finally:
        try:
            stop_sidecar(process)
        finally:
            for handle in handles:
                handle.close()


def main():
    parser = argparse.ArgumentParser()
    for name in ("repo", "nvxd", "initrd", "output"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    parser.add_argument("--repetitions", type=int, default=2)
    args = parser.parse_args()
    if args.repetitions < 1:
        raise ValueError("at least one complete matrix repetition is required")
    if args.output.exists():
        raise RuntimeError("choose a new report path")
    sources = {
        "sidecar": args.nvxd, "runtime": args.initrd, "kernel": args.repo / "build/vmlinux",
        "openvmm": args.repo / "openvmm/target/release/openvmm.exe",
        "helper": args.repo / "tools/nvxd/tests/p8_support.py",
        "measurement": pathlib.Path(__file__),
    }
    hashes = {name: digest(path) for name, path in sources.items()}
    report = {
        "nvxRevision": subprocess.check_output(["git", "-C", str(args.repo), "rev-parse", "HEAD"],
                                              text=True).strip(),
        "recordedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "openvmmRevision": subprocess.check_output(
            ["git", "-C", str(args.repo / "openvmm"), "rev-parse", "HEAD"], text=True).strip(),
        "workingTree": subprocess.check_output(
            ["git", "-C", str(args.repo), "status", "--short"], text=True).splitlines(),
        "host": json.loads(subprocess.check_output([
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "$os=Get-CimInstance Win32_OperatingSystem;"
            "$sys=Get-CimInstance Win32_ComputerSystem;"
            "@{machine=$env:COMPUTERNAME;os=$os.Caption;build=$os.BuildNumber;"
            "physicalBytes=$sys.TotalPhysicalMemory;logicalProcessors=$sys.NumberOfLogicalProcessors;"
            "freePhysicalKiB=$os.FreePhysicalMemory;hypervisor=$sys.HypervisorPresent}"
            " | ConvertTo-Json -Compress",
        ], text=True, timeout=20)),
        "tokenMode": "ordinary development runner; no restricted-token claim",
        "scope": "eight sessions, eight Python tasks holding 32 MiB each; isolated /tmp 8 MiB each; "
                 "individual private tmpfs saturation with a live peer; memory trim disabled",
        "sha256": hashes, "results": [], "passed": False,
    }
    try:
        for memory in (1024, 2048, 3072, 4096):
            for repetition in range(args.repetitions):
                for isolated in (False, True):
                    result = measure(args, isolated, memory, repetition)
                    report["results"].append(result)
                    print(json.dumps(result), flush=True)
        if hashes != {name: digest(path) for name, path in sources.items()}:
            raise RuntimeError("input assets changed during measurement")
        report["passed"] = True
        print("CASE p8.capacity.eight_sessions_four_tiers PASS", flush=True)
    finally:
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
