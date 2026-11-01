# nvxd-guest

The guest side of the sidecar. For now the sidecar boots the runtime adapter's guest agent
(`tests/runtime-adapter`, binary `runtime-adapter-guest`), built as a static
`x86_64-unknown-linux-musl` executable:

    cd tests/runtime-adapter
    rustup target add x86_64-unknown-linux-musl
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-Clinker-flavor=ld.lld -Clink-self-contained=yes" \
    cargo build --release --locked --features guest --target x86_64-unknown-linux-musl --bin runtime-adapter-guest

This builds from Windows in about ten seconds (`rust-lld` only; no WSL or Docker). The sidecar
writes a copy of NVX's initramfs that holds the agent, stages the EROFS image as the root and
boots it with a RAM upper (`nvxd::vm`).

Still to be written here: this crate's own guest agent, built on `nvx::guest`, carrying the
session isolation (a keeper per session, namespaces, scoped mounts), runtime mounts, per-execution
limits and OOM attribution. The sources of the previous C implementation are in `reference/`.
