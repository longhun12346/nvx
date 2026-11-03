# nvxd

> **Status: ported to the `nvx` library.** The sidecar drives the VM through `nvx` (the
> supervisor, sessions and execution engine, as `tests/runtime-adapter` does) with the runtime
> adapter's guest agent. Working, with the engine's protocol and launch arguments unchanged:
> `ready`, `probe` with the real 128 MiB boot probe and its cache, several sessions on one shared
> VM (session cap, queue, run slots, generation fences), `exec` with streamed stdout/stderr,
> backpressure and exit events, cancel (`signal`) of queued and running executions, `exec.status`,
> duplicate and conflicting starts, timeouts, `session.close`, session TTL, `memory.stats`/
> `memory.trim` and idle trimming, `port.check`/`port.allocate`, VM-lost reporting with the
> generation guard, `diagnostics`, `shutdown`. Output the caller is not ready to read is held back
> (counted as `outbound.deferred`) and delivered later; it is never dropped.
>
> Workspace mounts work: the VM boots with an empty anchor directory exported through the aggregate
> virtio-fs device, so that the export channel exists. Each session's workspace, and the mounts of
> its `exec` requests (the whole set with every start; no `mounts` key is the empty set), are then
> exported while the VM runs, through the fork's `--microvm-virtiofs-control` pipe (`live.rs`), and
> bound at their guest paths by the guest agent, which takes the fork's mount messages (kinds 100 to
> 103 of the adapter's framing) after the start. Revoking a mount unmounts it in the guest first and
> then stops the export; an export that cannot be taken back is retried (`cleanupPending`).
>
> Per-execution limits work: the deployment's `--exec-memory-mb`, `--exec-cpu-percent` and
> `--exec-pids`, overridden field by field by a request's `limits`, reach the guest agent in an
> `ExecLimits` message (kind 104) before the start and become `memory.max`, `cpu.max` and `pids.max`
> of the execution's cgroup. The guest refuses a start whose limits it cannot apply: a kernel
> without `CONFIG_CFS_BANDWIDTH` (upstream's prebuilt one; this fork's config sets it) refuses cpu
> limits as a launch failure rather than running the program unlimited. A kill by the kernel's
> OOM killer is reported before the terminal record in an `ExecOom` message (kind 105) and becomes
> the exit event's `detail`: `oom` when the execution reached its own limit, `vmOom` otherwise. The
> executions share a workload cgroup sized from the guest's RAM, and the agent exempts itself from
> the OOM killer. The time daemon NVX's `/init` starts publishes its status at `/run/nvx/time`
> inside every execution.
>
> Session isolation works (`--session-isolation`): a keeper process per session with its own mount, PID, IPC, UTS
> and network namespaces, scoped mounts and strict revocation, implemented in the guest agent (kinds 106 to 112 of
> its framing; the contract and the tests that prove it are in `../nvxd-guest/ISOLATION.md`).
>
> The network policy works: `--network allow|deny`, `--private-networks allow|deny` and `--ingress
> host-loopback|none` become a `SandboxNetwork` on the guest address `10.0.0.2/24` (`src/network.rs`). Egress is
> open except the private and link-local ranges unless `--private-networks allow` (the guest's gateway is the one
> exception, for DNS); the host's own loopback is closed unless ingress publishes the guest's listeners. The guest
> agent writes the DNS servers of the kernel command line into the assembled root.
>
> Cold start: the first `session.open` of a fresh sidecar, which boots the VM and mounts the workspace, takes about
> 0.24 s on the Win11 development host (the previous stack took 0.19 s; before the prewarm it was 0.69 s) and about
> 0.8 s on the nested Windows 10 VM (nested, not physical; the previous stack 0.59 s). The digests of the files a
> launch uses, the staged EROFS image and the composed initramfs are computed once per process, on parallel threads,
> and prewarming starts with the process; nothing is cached across processes, so every launch re-verifies the
> files it uses (about 85 ms of the remaining cost, deliberately kept). `NVXD_TRACE_PHASES=1` prints the phase
> timings and `tests/cold_start.py` measures 12 fresh starts.
>
> Build: `cargo build --release` here; the guest agent is built from `tools/nvxd-guest` (a fork-owned copy of upstream's runtime adapter)
> (`--features guest --target x86_64-unknown-linux-musl --bin nvxd-guest`, linker
> `rust-lld`, which works from Windows without WSL or Docker; see the `sidecar` job in
> `.github/workflows/fork-ci.yml`). Launch: the engine's `--openvmm --kernel --initrd --distro
> --cpu-profile ...` plus `--guest-agent PATH` (or `nvxd-guest` next to the executable); `--artifacts
> DIR` derives the first four from a release directory. Tests: `tests/runtime_assets.py` reads
> `NVX_OPENVMM`, `NVX_KERNEL`, `NVX_INITRD`, `NVX_DISTRO` (a distro with Python and Node for the
> suites that run them) and `NVX_GUEST_AGENT`; `tests/behaviour_checks.py` exercises the
> operations above on a live VM.

`nvxd` is the NVX sidecar. It owns the stdio frame protocol,
session lifecycle, live-share reconciliation, and the OpenVMM-backed execution
adapter used by the Windows sandbox host.

The crate is maintained in the NVX fork because it is coupled to the fork's OpenVMM
(live virtio-fs share control, the Windows 10 path) and to the fork's guest agent. It is a standalone
Cargo package that depends on the `nvx` crate by path and must build from a clean NVX checkout
with `cargo build --locked`.

The sidecar keeps the v1 product contract explicit:

- one VM per sidecar, shared by its logical sessions; guest size is fixed at boot,
  accepts 512–4096 MiB (1024 by default), and the engine chooses a tier before creating the VM;
- `hardTimeoutSec` maps to guest execution timeout;
- up to eight concurrent executions by default, with per-execution memory, CPU,
  and process limits when the guest advertises the required features;
- stdin and input remain explicitly unsupported;
- zero-valued limits inherit deployment defaults.

`--session-isolation` selects a fixed mode for the lifetime of the sidecar.
It requires the guest's session-isolation capability, creates private
mount/PID/IPC/network environments, and supports only deny-external-network
policy. It does not provide a separate kernel or session aggregate resource
budgets. Mode migration requires draining the old group and creating a new VM.

An isolated close cancels its executions, destroys its guest context, then
removes source exports without waiting for unrelated sessions to idle.
An unprovable revoke or cleanup failure retires the whole group and gives all
affected executions terminal events. An unsuccessful private bind rolls its
new source export back; failed rollback also retires the group.

Independently authorized sessions may export the same host directory with
separate read-only/read-write policies. They intentionally see shared host
content, while private HOME/tmp and mount permissions remain per session.
This requires the matching OpenVMM revision from the dependency lock.

The engine's `verify-nvx-vm.ps1 -Stage P8` runs the required integration matrix,
including the guest probe, external cleanup fault injection, and the four-tier
capacity matrix. The inputs are NVX's base initramfs (`-Initrd`), the guest agent
(`-GuestAgent`), the locked read-only layer (`-Distro`), the kernel and OpenVMM. The
gate passes `NVX_OPENVMM`, `NVX_KERNEL`, `NVX_INITRD`, `NVX_GUEST_AGENT` and
`NVX_DISTRO` to every suite; tests pass explicit artifact paths to the sidecar
instead of discovering other files from the checkout. Standalone Python suites
read the same variables.

The guest probe (`tests/guest_probe_report.py`) builds `nvxd-guest-probe` from the
`session-probe` feature as a static musl binary and boots it from a disposable copy
of the initramfs. The cleanup fault injection (`tests/isolated_cleanup_faults.py`,
`--diagnostic-agent`) uses a second agent built with the `fault-observer` feature;
the production agent is built without it. Diagnostic helpers are not part of the
production runtime.

## Diagnostics

`--processors 1|2|4|8` selects the VM's vCPU count (default `1` for existing
callers). The count is fixed for the lifetime of the sidecar and is passed explicitly
to OpenVMM, including the capability probe. The capability cache key includes it:
a successful single-processor probe does not prove a larger topology works.
Startup provenance, `probe.processors`, and `diagnostics.processors` report the
configured count; a running `diagnostics.vm` also reports `processors` and
`memoryMiB`. Per-execution `cpuPercent` remains hundredths of one logical CPU,
independent of topology; zero inherits the deployment default.

Run `tests/processors.py --nvxd PATH --repo PATH --initrd PATH` on a WHP host
with explicit `NVX_*` artifacts to verify all four counts in shared and isolated
modes. It checks guest CPU count and affinity, pins a worker to every CPU, records
CPU time and elapsed time, cancels a process tree, verifies the VM survives, and
checks that its VMM exits at shutdown. It never terminates unrelated VMM processes.

Two things exist so a failure can be explained without a debugger or a test harness.

`{"op":"diagnostics"}` (read-only) answers with this sidecar's own counters and the state
of every session:

```json
{
  "runtimePrefix": "…",
  "maxSessions": 0,
  "sessions": [
    {"session":"e2e","runtimeId":"rt-…-00000001","workspace":"…",
     "busy":false,"shares":1,"mountedOnce":1,"idleMs":812}
  ],
  "handles": 0,
  "stats": {"requests":9,"failures":1,"execs":7,"sharesAdded":6,"sharesRemoved":4,
            "lastFailure":{"reasonCode":"E_WORKSPACE_MOUNT_DENIED","message":"…"}}
}
```

It never opens, closes, or changes anything, so it is safe to call while a workload runs.

Every request is also logged with its outcome and its own latency:

```
nvxd: request op=exec session=e2e result=error reasonCode=E_BACKEND_SESSION_UNKNOWN durationMs=0 message=…
nvxd: request op=session.open session=e2e result=ok durationMs=1173
```

Failures are always logged; successful requests only when they took at least one second, so
a healthy run stays quiet. Set `NVXD_LOG_REQUESTS=1` to log every request, which is
what to reach for when a caller reports that something “did nothing”.
