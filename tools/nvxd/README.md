# nvxd

`nvxd` is the NVX sidecar. It owns the stdio frame protocol,
session lifecycle, live-share reconciliation, and the OpenVMM-backed execution
adapter used by the Windows sandbox host.

The crate is intentionally maintained in the NVX fork because it is coupled to
the `aci_edge_sandboxes` and OpenVMM APIs. It is a standalone Cargo package and
must build from a clean NVX checkout with `cargo build --locked`.

The sidecar keeps the v1 product contract explicit:

- one fixed 1024 MiB guest configuration per session;
- `hardTimeoutSec` maps to guest execution timeout;
- positive per-exec memory and CPU limits, stdin, and input are rejected with
  stable reason codes until their later product phases are implemented;
- zero-valued limits are accepted as “no additional request limit”.

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
