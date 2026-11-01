# nvxd-guest

The guest agent and the host framing of the sidecar. The sources under `src/` are a copy of upstream's
`tests/runtime-adapter` library (`src/`, taken at upstream `4f9a3214`) plus the sidecar's additions, so
that upstream's test crate stays untouched and a later upstream merge does not conflict in it. The
library keeps upstream's crate name (`runtime_adapter`); the package is `nvxd-guest`, and the guest
binary is `nvxd-guest`. The host program, its binary and the integration tests of the original crate
were not copied.

Differences from upstream's copy (carry these over by diff when the adapter changes upstream):

- `src/frame.rs`, `src/worker.rs`: the messages `MountAdd`, `MountRemove`, `Mounted` and
  `MountFailed` (kinds 100 to 103, clear of the codes upstream assigns next) and their handling after
  the start, so the sidecar can bind and unbind children of the live host export.
- `ExecLimits` (104) and `ExecOom` (105): per-execution `memory.max`, `memory.swap.max`, `cpu.max` and
  `pids.max` in the execution's cgroup, and the `oom` / `vmOom` attribution; the agent exempts itself from
  the OOM killer and the workload cgroup is sized from the guest's RAM.
- `src/session/` and kinds 106 to 112: session isolation (keeper, namespaces, scoped mounts, strict
  revocation); the contract is `ISOLATION.md`.
- `src/resolver.rs`: writes the DNS servers of the kernel command line into the assembled root.
- `src/bin/nvxd-guest-probe.rs` (feature `session-probe`): the guest probe of the P8 gate; the feature
  `fault-observer` builds the diagnostic agent of the cleanup fault injection.
- `src/bin/nvxd-guest.rs`: the binary name in the usage text.

Build (static `x86_64-unknown-linux-musl`, from Windows with `rust-lld`, no WSL or Docker, about ten
seconds):

    cd tools/nvxd-guest
    rustup target add x86_64-unknown-linux-musl
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-Clinker-flavor=ld.lld -Clink-self-contained=yes" \
    cargo build --release --locked --features guest --target x86_64-unknown-linux-musl --bin nvxd-guest

The sidecar (`tools/nvxd`) uses the same crate with the `host` feature for its control framing, root
configuration and execution messages, writes a copy of NVX's initramfs that holds the agent,
stages the EROFS image as the root and boots it with a RAM upper.

The sources of the previous C implementation of the session isolation are in `reference/`.
