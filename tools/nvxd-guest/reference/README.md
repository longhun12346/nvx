# Reference sources

`guest_session.rs` is the guest-session wire protocol that lived in
`nvx-rs/src/protocol/` before the upstream merge. It is not compiled; it is the starting
point for the session-isolation messages of the Rust guest agent and should be deleted
once those messages exist in the agent's own protocol module.

The probe and fault tooling that the old P8 sidecar suites used also lives here and is not
built or run any more:

- `nvx-guest-session.h.txt`, `guest_session_probe.c.txt`: the C guest-session header and the
  probe program (renamed so the repository has no C sources outside OpenVMM, which a CLI test
  enforces).
- `build_guest_session_probe.sh`, `build_p8_fault_runtime.sh`, `diagnostic_erofs.sh`,
  `p8_fault_observer.py`: scripts that built or drove them; they still point at the old paths.

Rewrite the probe and the observer in Rust together with the guest agent, then delete this
directory.
