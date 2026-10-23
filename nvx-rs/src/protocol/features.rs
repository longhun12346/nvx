//! The control features that a guest image advertises in response to `APP_FEATURES`.

use std::ops::BitOr;

use super::{ProtocolError, array, violation};

/// Control features of a guest image, advertised in the response to
/// [`APP_FEATURES`](super::APP_FEATURES).
///
/// The bits are defined by the guest agent in `guest/common/nvx-managed-agent.c`, which also
/// speaks for the features of its image's init script. A host drives a sandbox only when its
/// guest provides every feature in [`GuestFeatures::REQUIRED`]; an older image would silently
/// ignore the policy or the request that depends on the missing feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestFeatures(u32);

impl GuestFeatures {
    /// What a guest agent that predates the `APP_FEATURES` request provides.
    pub const NONE: Self = Self(0);
    /// Terminates a workload on `APP_CANCEL` and reports the `cancelled` exit category.
    pub const CANCEL: Self = Self(1 << 0);
    // Bit 1 announced the bind mounts that `nvx_map=` kernel command-line tokens listed. Guests
    // no longer set it, so a host that still sends those tokens refuses them.
    /// Creates the account that `nvx_workload_account=create` selects.
    pub const WORKLOAD_ACCOUNT: Self = Self(1 << 2);
    /// Runs each workload in a cgroup of its own and kills whatever it leaves behind.
    pub const EXEC_CGROUP: Self = Self(1 << 3);
    /// Applies the working directory and the explicit environment of an extended `EXEC` request
    /// to that execution alone, and layers the environment over the default one on request.
    pub const EXEC_ENVIRONMENT: Self = Self(1 << 4);
    /// Starts each workload in the working directory that its `EXEC` request names, or in `/`,
    /// entered with the workload's identity, and refuses the launch with the `cwd-failed`
    /// category when the workload cannot enter it.
    pub const EXEC_CWD: Self = Self(1 << 5);
    /// Bind-mounts the host mapping table of `APP_MAPS` requests, as many entries as the
    /// `nvx_maps=` kernel command-line token announces, keeps the shared export root-only, and
    /// refuses workloads until every entry is mounted.
    pub const HOST_MAPPING_TABLE: Self = Self(1 << 6);
    /// Accepts `APP_MAPS` entries that continue the host mapping table at run time, after the
    /// table that `nvx_maps=` announced is mounted. Not in [`GuestFeatures::REQUIRED`]: only the
    /// live-share experiment needs it.
    pub const RUNTIME_MAPPINGS: Self = Self(1 << 7);
    /// Serves several executions at once: each `EXEC` request keeps its own process, cgroup,
    /// output stream and deadline, so cancelling or timing out one leaves the others running.
    /// Not in [`GuestFeatures::REQUIRED`]: a host that starts only one execution at a time works
    /// with an image that lacks it.
    pub const EXEC_SLOTS: Self = Self(1 << 8);
    /// Enforces the `memMb`, `cpuPercent` and `pidsMax` limits of an `EXEC` request on the
    /// execution's own cgroup, and refuses an execution whose limit it cannot enforce. Not in
    /// [`GuestFeatures::REQUIRED`]: a host that asks for no limits works without it.
    pub const EXEC_LIMITS: Self = Self(1 << 9);
    /// The features that the host depends on.
    pub const REQUIRED: Self = Self(
        Self::CANCEL.0
            | Self::WORKLOAD_ACCOUNT.0
            | Self::EXEC_CGROUP.0
            | Self::EXEC_ENVIRONMENT.0
            | Self::EXEC_CWD.0
            | Self::HOST_MAPPING_TABLE.0,
    );

    /// Human-readable names of every feature, used in compatibility errors.
    pub(crate) const NAMES: [(Self, &'static str); 8] = [
        (Self::CANCEL, "cancellation"),
        (Self::WORKLOAD_ACCOUNT, "workload accounts"),
        (Self::EXEC_CGROUP, "workload containment"),
        (Self::EXEC_ENVIRONMENT, "per-execution environments"),
        (Self::EXEC_CWD, "working directories"),
        (Self::HOST_MAPPING_TABLE, "host path mapping tables"),
        (Self::EXEC_SLOTS, "concurrent executions"),
        (Self::EXEC_LIMITS, "per-execution resource limits"),
    ];

    /// Returns the features whose bits are set in `bits`.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the bits of these features.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns whether this set holds every feature of `other`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Decodes the payload of a features response.
    ///
    /// Later revisions may append fields, so trailing bytes are ignored.
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        let bits = payload
            .get(..4)
            .ok_or_else(|| violation("the guest agent returned a truncated features response"))?;
        Ok(Self(u32::from_le_bytes(array(bits))))
    }

    /// Encodes the payload of a features response, as a guest agent sends it.
    pub const fn encode(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    /// Names the features of `required` that this set lacks.
    pub fn missing(self, required: Self) -> Vec<&'static str> {
        Self::NAMES
            .iter()
            .filter(|(feature, _)| required.0 & feature.0 != 0 && self.0 & feature.0 == 0)
            .map(|(_, name)| *name)
            .collect()
    }
}

impl BitOr for GuestFeatures {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
