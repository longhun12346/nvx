# nvxd

`nvxd` is the NVX sidecar. It owns the stdio frame protocol,
session lifecycle, live-share reconciliation, and the OpenVMM-backed execution
adapter used by the Windows sandbox host.

The crate is intentionally maintained in the NVX fork because it is coupled to
the `aci_edge_sandboxes` and OpenVMM APIs. It is a standalone Cargo package and
must build from a clean NVX checkout with `cargo build --locked`.

The sidecar keeps the v1 product contract explicit:

- one VM per sidecar, shared by its logical sessions; guest size is fixed at boot,
  accepts 1024–4096 MiB, and the engine chooses a tier before creating the VM;
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
including fresh diagnostic guest probes, external cleanup fault injection,
and the four-tier capacity matrix. For EROFS, pass the stage initramfs as
`-Initrd` and the locked read-only layer as `-Distro`. The gate passes
`NVX_DISTRO` to every test; tests pass explicit artifact paths to the sidecar
instead of discovering other files from the checkout. Standalone Python suites
use the same environment variable. Leave it unset for full-initramfs tests.

Diagnostic fault observers live in disposable copies of the runtime: appended
archives for full initramfs, or rebuilt EROFS layers paired with an unchanged
stage image. The cleanup observer preserves the production agent's bytes.
Diagnostic helpers are not part of the production runtime.

## Diagnostics

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
