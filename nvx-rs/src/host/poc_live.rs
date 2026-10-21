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
use std::time::{Duration, Instant};

use super::instance::{Instance, RuntimeRecord};
use super::session::{self, ControlSession};
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

/// Asks the VMM to handle one request file and waits for its result. The VMM deletes the request
/// when it has handled it and leaves `<stem>.result`.
fn ask_vmm(request_dir: &Path, file: &str, body: &str, deadline: Instant, name: &str) -> Result<()> {
    let request = request_dir.join(file);
    let result = request.with_extension("result");
    let _ = std::fs::remove_file(&result);
    std::fs::write(&request, body).map_err(|error| {
        Error::io(format!("cannot write {}", request.display())).with_source(error)
    })?;
    let outcome = loop {
        // The VMM creates (truncates) the result before writing it, so an empty file means the
        // answer is not there yet.
        if let Ok(text) = std::fs::read_to_string(&result)
            && !text.trim().is_empty()
            && !request.exists()
        {
            break text;
        }
        if Instant::now() >= deadline {
            let _ = std::fs::remove_file(&request);
            return Err(Error::timed_out(format!(
                "the VMM of sandbox {name} did not handle {file} in time; was it started with NVX_POC_LIVE_SHARE_DIR?"
            )));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = std::fs::remove_file(&result);
    if outcome.trim() == "ok" {
        Ok(())
    } else {
        Err(Error::other(format!(
            "the VMM refused {file}: {}",
            outcome.trim()
        )))
    }
}

impl Instance {
    fn live_session(
        &self,
        runtime: &RuntimeRecord,
        capability: &[u8; CAPABILITY_LEN],
        deadline: Instant,
    ) -> Result<ControlSession> {
        let fail = |error: session::SessionError| {
            Error::protocol(format!(
                "sandbox {}: cannot open a control session: {error:?}",
                self.name()
            ))
        };
        let mut guest = session::connect(&runtime.endpoint, runtime.pid, runtime.start_time, deadline)
            .and_then(|transport| ControlSession::attach(transport, capability, deadline))
            .map_err(fail)?;
        let features = guest.features(deadline).map_err(|error| {
            Error::protocol(format!(
                "sandbox {}: cannot read the guest features: {error:?}",
                self.name()
            ))
        })?;
        if !features.contains(GuestFeatures::RUNTIME_MAPPINGS) {
            return Err(Error::unsupported(format!(
                "the guest image of sandbox {} does not accept runtime host mappings",
                self.name()
            )));
        }
        Ok(guest)
    }

    /// Adds `share` to the running guest of `runtime`; `first` is the number of runtime shares that
    /// were added before, removed or not (the sequence number of this request).
    ///
    /// `request_dir` is the directory that the VMM polls (the `NVX_POC_LIVE_SHARE_DIR` it was
    /// launched with).
    pub fn add_share_poc(
        &self,
        runtime: &RuntimeRecord,
        capability: &[u8; CAPABILITY_LEN],
        request_dir: &Path,
        first: usize,
        share: &LiveShare<'_>,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mode = if share.read_only { "ro" } else { "rw" };
        ask_vmm(
            request_dir,
            &format!("{}.add", share.child),
            &format!("{}\n{mode}\n{}\n", share.child, share.host_path.display()),
            deadline,
            self.name(),
        )?;
        // The VMM already exports the child; take the export back if the guest does not mount it,
        // so that a refused share does not leak one of the aggregate's child slots.
        let rollback = |this: &Self, error: Error| {
            let _ = ask_vmm(
                request_dir,
                &format!("{}.remove", share.child),
                &format!("{}\n", share.child),
                Instant::now() + Duration::from_secs(10),
                this.name(),
            );
            error
        };
        let mut guest = match self.live_session(runtime, capability, deadline) {
            Ok(guest) => guest,
            Err(error) => return Err(rollback(self, error)),
        };
        let map = HostMap {
            source: share.child.to_owned(),
            target: share.target.to_owned(),
            read_only: share.read_only,
        };
        guest
            .append_host_paths(first, &[map], deadline)
            .map_err(|error| {
                rollback(
                    self,
                    Error::protocol(format!(
                        "sandbox {}: the guest did not mount the share: {error:?}",
                        self.name()
                    )),
                )
            })
    }

    /// Removes a share that [`Self::add_share_poc`] added: the guest unmounts `target` first, so
    /// that nothing uses the export, and then the VMM stops exporting `child`.
    pub fn remove_share_poc(
        &self,
        runtime: &RuntimeRecord,
        capability: &[u8; CAPABILITY_LEN],
        request_dir: &Path,
        child: &str,
        target: &str,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut guest = self.live_session(runtime, capability, deadline)?;
        guest.unmap_host_path(target, deadline).map_err(|error| {
            Error::protocol(format!(
                "sandbox {}: the guest did not unmount the share: {error:?}",
                self.name()
            ))
        })?;
        drop(guest);
        ask_vmm(
            request_dir,
            &format!("{child}.remove"),
            &format!("{child}\n"),
            deadline,
            self.name(),
        )
    }
}
