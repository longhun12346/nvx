# Reference sources

These files came from `nvx-rs/src/host/` and `aci_edge_sandboxes/` before the upstream
merge removed the modules they belonged to. They are not part of any crate and are not
compiled. They stay here only as the starting point for porting the sidecar's live
share control onto the `nvx` library; delete the directory once that port has landed.

- `control/control.rs`, `control_pipe.rs`, `live_control.rs`, `poc_live.rs`: the client
  side of OpenVMM's live virtio-fs share control (named pipe `nvx-live-*`).
