# genflow-nvxd

`genflow-nvxd` is the GenFlow NVX sidecar. It owns the stdio frame protocol,
session lifecycle, live-share reconciliation, and the OpenVMM-backed execution
adapter used by the Windows GenFlow sandbox.

The crate is intentionally maintained in the NVX fork because it is coupled to
the `aci_edge_sandboxes` and OpenVMM APIs. It is a standalone Cargo package and
must build from a clean NVX checkout with `cargo build --locked`.

The sidecar keeps the v1 product contract explicit:

- one fixed 1024 MiB guest configuration per session;
- `hardTimeoutSec` maps to guest execution timeout;
- positive per-exec memory and CPU limits, stdin, and input are rejected with
  stable reason codes until their later product phases are implemented;
- zero-valued limits are accepted as “no additional request limit”.
