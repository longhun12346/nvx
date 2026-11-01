# Reference sources

`server_old.rs`, `main_old.rs`, `plan_old.rs` and `winmem_old.rs` are the sidecar before it was ported onto the
`nvx` library (still on the removed `aci_edge_sandboxes` crate). The behaviour not ported yet (limits, OOM
attribution, fair slots, TTL, ports, memory trim, isolation, mounts) is read from them.

These files came from `nvx-rs/src/host/` and `aci_edge_sandboxes/` before the upstream
merge removed the modules they belonged to. They are not part of any crate and are not
compiled. They stay here only as the starting point for porting the sidecar's live
share control onto the `nvx` library; delete the directory once that port has landed.

- `control/control.rs`, `control_pipe.rs`, `live_control.rs`, `poc_live.rs`: the client
  side of OpenVMM's live virtio-fs share control (named pipe `nvx-live-*`).
