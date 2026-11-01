# Session isolation in the guest agent: behaviour contract

The sidecar can run the shared VM in isolated mode (`--session-isolation`, `sessionIsolation` at
`session.open`). This file is the contract the guest side implements, taken from the previous C
implementation (`reference/nvx-guest-session.h.txt` and `git show 4f19a650:guest/common/nvx-managed-agent.c`)
and from the P8 suites that prove it. Each guarantee names the test that shows it.

## Mechanism

- One **keeper** per session: a process that is PID 1 of a PID namespace created together with new mount,
  IPC, UTS and (unless the VM shares its network) network namespaces. Created by the helper mode
  `nvxd-guest __session-keeper`, which unshares the namespaces and forks the keeper (the agent cannot
  fork-and-setup safely: it is multithreaded). Namespaces are owned by root, because the guest kernel has
  no `USER_NS`.
- The keeper builds the session's root before it reports ready: a read-only bind of the sandbox root as
  lower layer, a 64 MiB tmpfs for the overlay upper, empty tmpfs mounts hiding `run`, `root`, `sessions`,
  `mnt` and `sys`, private `/tmp` (32 MiB), `/home` (32 MiB, account `session`), `/dev` (a few nodes,
  `/dev/shm` 16 MiB), the session's workspace as `/workspace`, a procfs of the session's PID namespace,
  hostname `nvx-session-<id>`, fresh `passwd` and `group` files, a `chroot`, and `lo` up in a private
  network namespace. It then drops every capability, sets no-new-privs and only reaps children.
- An **execution** of an isolated session runs through the helper `nvxd-guest __session-enter`, spawned by
  the ordinary execution path (so the execution keeps its cgroup, limits, process group and pipes). The
  helper joins the keeper's namespaces (`setns`), enters its root, forks into the PID namespace, drops
  to the session's own user and group (no groups, no new privileges, no capabilities), enters the working
  directory, and executes the program; the helper mirrors the program's exit status.
- A **scoped mount** is a clone of an authorized agent mount (`open_tree`), made read-only on request,
  attached to the session's mount namespace at `/workspace/mounts/<leaf>` with `move_mount`. Unmounting
  moves the mount to a staging point and unmounts it strictly: no lazy unmount; failure marks the agent
  broken and the host retires the VM.
- Closing a session kills the keeper (PID 1 of its namespace takes every process with it) and waits for
  the kernel teardown. A keeper that does not go away is an isolation fault: the agent is marked broken.
- The agent polls its keepers while sessions exist (50 ms). A keeper that ended on its own leaves the
  isolation unproven: the worker ends, the VM goes down, and the host fails every session of that VM.
- Exports below `/sessions/` are unmounted strictly (EBUSY retried for 1 s), so a handle another process
  still holds fails the removal instead of being hidden by a lazy unmount. An isolated close whose export
  cannot be taken back fails with `E_SESSION_CLOSE_FAILED` and retires the VM.

## Diagnostic agent

`cargo build --release --features guest,fault-observer --target x86_64-unknown-linux-musl --bin nvxd-guest`
builds an agent whose first session starts `__p8-observer`, a root process outside every workload
namespace and cgroup. It injects a fault when a workspace holds a `p8-fire` file naming it. The cleanup
suite passes it as `--diagnostic-agent`; the product agent is built without the feature.

## Guarantees and the tests that prove them

| Guarantee | Test |
|---|---|
| Isolation is advertised only by an active VM that supports it | `isolated_session.py` `p8.sidecar.capability` |
| Mode, network and kernel policy are refused, not granted | `isolated_session.py` `p8.sidecar.unsupported_policy_refused`, `migration.py` |
| Another session's files in `/tmp` and mounts are invisible; the same session's are visible | `p8.sidecar.cross_session_private_state`, `p8.sidecar.same_session_state` |
| A reopened session name starts with no earlier private state | `p8.sidecar.reopen_private_state_reset` |
| 66 open/close cycles do not exhaust the 64 guest slots and keep a peer alive | `p8.sidecar.guest_session_close_reclaims` |
| Other sessions' environments, processes, network and `/run/nvx`, `/sessions` are not visible; only `lo` | `isolated_boundaries.py` `p8.boundary.process_environment_network` |
| Closing a session with running and queued work cancels it and leaves peers untouched | `p8.lifecycle.active_close_preserves_peer` |
| Concurrent isolated sessions, cancel isolation, fairness and OOM isolation | `isolated_parallel.py` |
| Two sessions may be authorized for the same host root independently | `isolated_shared_authorization.py` |
| A failed bind rolls the export back | `p8.mounts.bind_failure_rollback` |
| VM loss fails every session; a rebuilt VM starts clean | `isolated_faults.py` |
| Cleanup faults escalate and do not leave exports | `isolated_cleanup_faults.py` |
| Mode switches need a drained, rebuilt backend; old state is not inherited | `migration.py` |

Limits kept from the C implementation: 64 resident sessions per VM, identities are monotonic and never
reused, one UID per session starting at 100000, the 5 s bound on keeper readiness and mount changes.

## Probe

`tools/nvxd/tests/guest_probe_report.py` builds `nvxd-guest-probe` (feature `session-probe`, static musl,
from Windows with `rust-lld`, no WSL), appends it with a boot script to the base initramfs and boots that
as `nvx_exec=/p8-probe-boot`. It runs as root in the guest and drives the production `Sessions` type with
real namespaces, mounts and cgroups. It prints `P8-PROBE-PASS <check>` for each check and
`P8-PROBE-COMPLETE`; the report requires all 49 check names, unchanged from the C probe.

What changed against the C probe:

- The three decode checks (`session-wire`, `shared-network-policy-decoded`, `unknown-network-policy-refused`)
  run `session::decode_open`, the one decoder of the session open request. It now refuses any network
  value but `0` and `1`; before, any other value was taken as a private network.
- `production-scheduler-two-by-two-cgroups` starts four programs in two sessions, each in its own
  `ExecutionCgroup` leaf, and requires the leaves occupied together, the programs of a session to meet
  in its private `/tmp`, and the leaves gone afterwards.
- `fault-injection-reap-keeper` waits for the agent to notice the dead keeper through `Sessions::health`;
  the launcher reaps it.
- Python is gone: the checks that ran Python (SysV IPC, loopback) run the probe binary itself inside the
  session (`__in-session`).
- Found by the port and fixed: the enter helper left the caller's descriptors open for the program
  (`agent-secret-fd`, `identity-proc-capabilities-fds`); it now closes every descriptor above 2 first.

Negative proofs (a deliberately broken agent fails the named check): no IPC namespace
(`cross-session-sysv-ipc-denied`), lazy instead of strict unmount (`busy-revoke-escalates-group-failure`),
unknown network policy granted (`unknown-network-policy-refused`), inherited descriptors kept
(`identity-proc-capabilities-fds`).
