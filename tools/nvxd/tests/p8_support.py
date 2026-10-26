"""Bounded frame reads and process ownership checks for the WHP acceptance suites."""

import ctypes
from ctypes import wintypes
import json
import pathlib
import queue
import subprocess
import threading
import time

from shared_vm import Sidecar, read_frame


class BoundedSidecar(Sidecar):
    def __init__(self, process):
        super().__init__(process)
        self.frames = queue.Queue()
        self.stderr = []

        def read():
            try:
                while True:
                    self.frames.put(read_frame(process.stdout))
            except Exception as error:
                self.frames.put(error)

        threading.Thread(target=read, daemon=True).start()
        threading.Thread(target=lambda: [
            self.stderr.append(line.decode(errors="replace").rstrip())
            for line in process.stderr
        ], daemon=True).start()
        ready, _ = self.read(time.monotonic() + 15)
        if ready.get("event") != "ready":
            raise RuntimeError(f"unexpected startup frame: {ready}")

    def read(self, deadline):
        try:
            value = self.frames.get(timeout=max(0, deadline - time.monotonic()))
        except queue.Empty:
            raise RuntimeError(f"sidecar frame deadline expired; stderr={self.stderr[-15:]}")
        if isinstance(value, Exception):
            raise RuntimeError(f"sidecar stream ended: {value}; stderr={self.stderr[-15:]}")
        return value

    def pump(self, deadline):
        head, payload = self.read(deadline)
        if "event" in head:
            if head["event"] == "exec.exit":
                key = head.get("execId") or head.get("handle")
                if key in self.exits:
                    raise RuntimeError(f"duplicate exit for {key}: {head}")
                self.exits[key] = head
            self.events.append((head, payload))
        else:
            self.replies[head.get("id")] = head

    def succeeded(self, ids, deadline):
        exits = self.await_exits(ids, deadline)
        for key, terminal in exits.items():
            if terminal.get("outcome") != "exited" or terminal.get("code") != 0:
                raise RuntimeError(f"{key} failed: {terminal}; events={self.events[-15:]}")
        return exits


def vmm_processes(sidecar_pid):
    """Find only descendants of this test's sidecar, never all VMMs on the machine."""
    command = (
        "$all=@(Get-CimInstance Win32_Process);"
        f"$owned=@({int(sidecar_pid)});"
        "do {$new=@($all | Where-Object {"
        "$_.ParentProcessId -in $owned -and $_.ProcessId -notin $owned });"
        "$owned+=@($new.ProcessId)} while($new.Count -gt 0);"
        "ConvertTo-Json -Compress -InputObject @($all | Where-Object {"
        "$_.ProcessId -in $owned -and $_.Name -eq 'openvmm.exe'"
        "} | Select-Object ProcessId,ExecutablePath)"
    )
    result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                            capture_output=True, text=True, check=True, timeout=20)
    rows = json.loads(result.stdout)
    if not rows:
        raise RuntimeError(f"no VMM descendant of test sidecar {sidecar_pid}")
    return [VmmHandle(row["ProcessId"], row["ExecutablePath"]) for row in rows]


class VmmHandle:
    """Pin process identity before injecting a fault or checking retirement."""
    def __init__(self, pid, expected_path):
        self.pid = pid
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.api.OpenProcess.restype = wintypes.HANDLE
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.api.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        self.handle = self.api.OpenProcess(0x100001 | 0x1000, False, pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        path = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(path))
        if not self.api.QueryFullProcessImageNameW(self.handle, 0, path, ctypes.byref(size)):
            self.close()
            raise ctypes.WinError(ctypes.get_last_error())
        if not expected_path or pathlib.Path(path.value) != pathlib.Path(expected_path):
            self.close()
            raise RuntimeError(f"VMM process identity changed for PID {pid}")

    def kill(self):
        if self.api.WaitForSingleObject(self.handle, 0) != 0:
            if not self.api.TerminateProcess(self.handle, 1):
                raise ctypes.WinError(ctypes.get_last_error())

    def wait(self, seconds=15):
        if self.api.WaitForSingleObject(self.handle, int(seconds * 1000)) != 0:
            raise RuntimeError(f"test VMM PID {self.pid} survived retirement")

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def stop_sidecar(process):
    if process.poll() is None:
        try:
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        # Only this test's sidecar and descendants are eligible for cleanup.
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)],
                       capture_output=True, timeout=15)
        process.wait(timeout=5)
        raise RuntimeError("sidecar did not shut down within 20 seconds")
    if process.returncode != 0:
        raise RuntimeError(f"sidecar exited with {process.returncode}")
