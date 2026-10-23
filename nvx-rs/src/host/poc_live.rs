//! **Proof-of-concept**: adds one host path to a running guest without a restart.
//!
//! This pairs with OpenVMM's `NVX_POC_LIVE_SHARE_DIR` request-file trigger (OpenVMM
//! `virtiofs/src/microvm/poc_live.rs`): the host first asks the VMM to export the path as a new
//! child of the aggregate virtio-fs device, then hands the guest agent one more entry of its host
//! mapping table, which the agent binds at `target`. The next workload sees it.
//!
//! It is not the product control plane: the VMM trigger is a request file in a directory that the
//! caller must keep private to the VMM's user, and nothing here removes a share again.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::instance::{Instance, RuntimeRecord};
use super::session::SharedSession;
use crate::error::{Error, Result};
use crate::protocol::{CAPABILITY_LEN, GuestFeatures, HostMap};

/// One host path to add to a running guest.
#[derive(Debug, Clone, Copy)]
pub struct LiveShare<'a> {
    /// Name of the new child under the aggregate export: ASCII letters, digits, `.`, `_`, `-`.
    pub child: &'a str,
    /// Absolute host directory (or regular file) to export.
    pub host_path: &'a Path,
    /// Absolute guest path at which the guest agent binds it.
    pub target: &'a str,
    /// Whether the export, and the guest's bind, are read-only.
    pub read_only: bool,
}


impl Instance {
    fn live_session(
        &self,
        runtime: &RuntimeRecord,
        capability: &[u8; CAPABILITY_LEN],
        deadline: Instant,
    ) -> Result<Arc<SharedSession>> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::timed_out(format!(
                "sandbox {}: no time left to reach the guest",
                self.name()
            )));
        }
        // The VM serves one control session, which its executions use as well: a session of our
        // own would wait for that one to end instead of reaching the guest.
        let guest = self
            .control_session(runtime, capability, remaining)
            .map_err(|error| {
                Error::protocol(format!(
                    "sandbox {}: cannot open a control session: {error}",
                    self.name()
                ))
            })?;
        let features = match guest.features(deadline) {
            Ok(features) => features,
            Err(error) => {
                // The session is unusable; a later call attaches a new one, which then reports a
                // VM that stopped as such instead of as a protocol failure.
                self.forget_control_session(runtime);
                return Err(Error::protocol(format!(
                    "sandbox {}: cannot read the guest features: {error:?}",
                    self.name()
                )));
            }
        };
        if !features.contains(GuestFeatures::RUNTIME_MAPPINGS) {
            return Err(Error::unsupported(format!(
                "the guest image of sandbox {} does not accept runtime host mappings",
                self.name()
            )));
        }
        Ok(guest)
    }


    /// Adds `share` to the running guest of `runtime` over the authenticated control
    /// pipe, and binds it in the guest.
    ///
    /// `export_pipe` is the pipe the VMM was started with (`name=`), `generation` the
    /// VM's boot generation, and `sequences` the launcher's ordering state: the VMM
    /// refuses a request whose generation differs or whose sequence does not increase,
    /// so a replayed request cannot re-add an export. `first` is the number of runtime
    /// shares the guest already knows, which numbers this bind.
    ///
    /// Nothing is written to disk and nothing polls: the VMM exports the child on
    /// demand over the pipe, and a failed guest bind takes the export back so a child
    /// slot is never leaked.
    #[expect(clippy::too_many_arguments)]
    pub fn add_share_control(
        &self,
        runtime: &RuntimeRecord,
        capability: &[u8; CAPABILITY_LEN],
        export_pipe: &str,
        generation: u64,
        sequences: &mut crate::host::live_control::Sequences,
        first: usize,
        share: &LiveShare<'_>,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut pipe = crate::host::control_pipe::connect(export_pipe, timeout).map_err(|error| {
            Error::io(format!(
                "cannot reach the export channel of sandbox {}",
                self.name()
            ))
            .with_source(error)
        })?;
        crate::host::live_control::export_or_rollback(
            &mut pipe,
            generation,
            sequences,
            self.name(),
            share,
            || {
                let guest = self.live_session(runtime, capability, deadline)?;
                let map = HostMap {
                    source: share.child.to_owned(),
                    target: share.target.to_owned(),
                    read_only: share.read_only,
                };
                guest.append_host_paths(first, &[map], deadline).map_err(|error| {
                    Error::protocol(format!(
                        "sandbox {}: the guest did not mount the share: {error:?}",
                        self.name()
                    ))
                })
            },
        )
    }

    /// Removes a share that [`Self::add_share_control`] added: the guest unmounts
    /// `target` first, so nothing uses the export, and then the VMM stops exporting
    /// `child`.
    #[expect(clippy::too_many_arguments)]
    pub fn remove_share_control(
        &self,
        runtime: &RuntimeRecord,
        capability: &[u8; CAPABILITY_LEN],
        export_pipe: &str,
        generation: u64,
        sequences: &mut crate::host::live_control::Sequences,
        child: &str,
        target: &str,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let guest = self.live_session(runtime, capability, deadline)?;
        guest.unmap_host_path(target, deadline).map_err(|error| {
            Error::protocol(format!(
                "sandbox {}: the guest did not unmount the share: {error:?}",
                self.name()
            ))
        })?;
        drop(guest);
        let mut pipe = crate::host::control_pipe::connect(export_pipe, timeout).map_err(|error| {
            Error::io(format!(
                "cannot reach the export channel of sandbox {}",
                self.name()
            ))
            .with_source(error)
        })?;
        crate::host::live_control::unexport(
            &mut pipe,
            generation,
            sequences.next(),
            self.name(),
            child,
            target,
        )
    }
}
