//! Configuration that a native host takes once, when it opens.
//!
//! [`SetupConfig`] names the runtime bundle, the state root, and the hypervisor, together with
//! defaults that every sandbox inherits unless its [`SandboxSpec`](crate::SandboxSpec) overrides
//! them. Nothing here is specific to one sandbox.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::hex;
use crate::image::ImageDigest;
use crate::spec::{ImageSource, Resources};

/// Hypervisor that runs the sandbox VMs: NVX's, whose serde form is its OpenVMM spelling.
pub use nvx::Hypervisor;

/// Configuration that a native host takes once, when it opens.
///
/// Every field except [`state_root`](Self::state_root) and [`runtime`](Self::runtime) has a
/// default, so `{"stateRoot": …, "runtime": …}` is a complete configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SetupConfig {
    /// Format of this configuration; [`SetupConfig::SCHEMA_VERSION`].
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    /// Directory that holds every sandbox's state. No mapped host path may expose it.
    pub state_root: PathBuf,
    /// The VMM and guest artifacts.
    pub runtime: RuntimeSource,
    /// Hypervisor; `None` selects the platform default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypervisor: Option<Hypervisor>,
    /// CPU profile of every guest.
    #[serde(default)]
    pub cpu_profile: CpuProfile,
    /// Operation deadlines.
    #[serde(default)]
    pub timeouts: Timeouts,
    /// How long the host keeps a guest session.
    #[serde(default)]
    pub guest_session: GuestSessionPolicy,
    /// Values that sandboxes inherit unless their spec sets them.
    #[serde(default)]
    pub defaults: SandboxDefaults,
    /// Image cache settings.
    #[serde(default)]
    pub images: ImageSettings,
    /// Flow control of streamed executions.
    #[serde(default)]
    pub exec: ExecSettings,
    /// Diagnostic switches.
    #[serde(default)]
    pub diagnostics: Diagnostics,
}

fn schema_version() -> u32 {
    SetupConfig::SCHEMA_VERSION
}

impl SetupConfig {
    /// The configuration format this crate reads and writes.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Creates a configuration with the default value of every optional field.
    pub fn new(state_root: impl Into<PathBuf>, runtime: RuntimeSource) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            state_root: state_root.into(),
            runtime,
            hypervisor: None,
            cpu_profile: CpuProfile::default(),
            timeouts: Timeouts::default(),
            guest_session: GuestSessionPolicy::default(),
            defaults: SandboxDefaults::default(),
            images: ImageSettings::default(),
            exec: ExecSettings::default(),
            diagnostics: Diagnostics::default(),
        }
    }

    /// Selects the hypervisor.
    #[must_use]
    pub fn with_hypervisor(mut self, hypervisor: Hypervisor) -> Self {
        self.hypervisor = Some(hypervisor);
        self
    }

    /// Selects the CPU profile.
    #[must_use]
    pub fn with_cpu_profile(mut self, profile: CpuProfile) -> Self {
        self.cpu_profile = profile;
        self
    }

    /// Sets the defaults that sandboxes inherit.
    #[must_use]
    pub fn with_defaults(mut self, defaults: SandboxDefaults) -> Self {
        self.defaults = defaults;
        self
    }

    /// Sets the image settings.
    #[must_use]
    pub fn with_images(mut self, images: ImageSettings) -> Self {
        self.images = images;
        self
    }

    /// Sets the diagnostic switches.
    #[must_use]
    pub fn with_diagnostics(mut self, diagnostics: Diagnostics) -> Self {
        self.diagnostics = diagnostics;
        self
    }

    /// Checks the configuration's structure without touching the host, reporting
    /// [`ErrorCode::MalformedRequest`](crate::ErrorCode::MalformedRequest).
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(Error::malformed_request(format!(
                "setup schemaVersion {} is not supported; use {}",
                self.schema_version,
                Self::SCHEMA_VERSION
            )));
        }
        if self.state_root.as_os_str().is_empty() {
            return Err(Error::malformed_request("setup stateRoot is empty"));
        }
        self.runtime.validate()?;
        self.timeouts.validate()?;
        self.guest_session.validate()?;
        self.defaults.validate()?;
        self.images.validate()?;
        self.exec.validate()
    }
}

/// Where the VMM and guest artifacts come from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub enum RuntimeSource {
    /// A release bundle: a directory with a `SOURCE-MANIFEST.json`, trusted through the
    /// manifest's SHA-256 digest.
    Bundle(BundleSource),
    /// Explicit files, each optionally pinned to an approved SHA-256 digest.
    Files(RuntimeFiles),
}

impl RuntimeSource {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Bundle(bundle) => {
                if bundle.path.as_os_str().is_empty() {
                    return Err(Error::malformed_request(
                        "setup runtime.bundle.path is empty",
                    ));
                }
                Ok(())
            }
            Self::Files(files) => {
                for (path, field) in [
                    (&files.openvmm, "openvmm"),
                    (&files.kernel, "kernel"),
                    (&files.initrd, "initrd"),
                ] {
                    if path.as_os_str().is_empty() {
                        return Err(Error::malformed_request(format!(
                            "setup runtime.files.{field} is empty"
                        )));
                    }
                }
                Ok(())
            }
        }
    }
}

/// A release bundle and the digest that makes it trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleSource {
    /// Directory that holds `SOURCE-MANIFEST.json`, `bin/`, and `guest/`.
    pub path: PathBuf,
    /// SHA-256 of `SOURCE-MANIFEST.json`, written as 64 lowercase hexadecimal digits.
    #[serde(with = "hex::sha256")]
    pub manifest_sha256: [u8; 32],
}

/// Explicit VMM and guest files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeFiles {
    /// The OpenVMM executable.
    pub openvmm: PathBuf,
    /// The guest kernel.
    pub kernel: PathBuf,
    /// The guest initramfs.
    pub initrd: PathBuf,
    /// Approved digests; the host refuses files that differ. `None` accepts the files as found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_sha256: Option<RuntimeDigests>,
}

/// SHA-256 digests of the runtime files, written as 64 lowercase hexadecimal digits each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeDigests {
    /// Digest of the OpenVMM executable.
    #[serde(with = "hex::sha256")]
    pub openvmm: [u8; 32],
    /// Digest of the guest kernel.
    #[serde(with = "hex::sha256")]
    pub kernel: [u8; 32],
    /// Digest of the guest initramfs.
    #[serde(with = "hex::sha256")]
    pub initrd: [u8; 32],
}

/// CPU profile of the guests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CpuProfile {
    /// The built-in profile of the host's CPU model.
    #[default]
    Auto,
    /// A profile derived from the host CPU, for hosts that no built-in profile serves.
    Host,
}

impl CpuProfile {
    /// The name OpenVMM's `--cpu-profile` accepts for this profile.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Host => "host",
        }
    }

    /// Parses the name that [`Self::as_str`] returns; `None` for anything else.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "auto" => Some(Self::Auto),
            "host" => Some(Self::Host),
            _ => None,
        }
    }
}

/// Operation deadlines, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Timeouts {
    /// From launch until the guest is ready.
    #[serde(default = "default_start_ms")]
    pub start_ms: u64,
    /// A control operation on a running guest.
    #[serde(default = "default_control_ms")]
    pub control_ms: u64,
    /// From the shutdown request until the VM is gone, before it is forced off.
    #[serde(default = "default_stop_ms")]
    pub stop_ms: u64,
    /// How long after an execution's own timeout the host waits for the guest's verdict.
    #[serde(default = "default_exec_grace_ms")]
    pub exec_grace_ms: u64,
}

fn default_start_ms() -> u64 {
    60_000
}

fn default_control_ms() -> u64 {
    60_000
}

fn default_stop_ms() -> u64 {
    30_000
}

fn default_exec_grace_ms() -> u64 {
    30_000
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            start_ms: default_start_ms(),
            control_ms: default_control_ms(),
            stop_ms: default_stop_ms(),
            exec_grace_ms: default_exec_grace_ms(),
        }
    }
}

impl Timeouts {
    /// Longest accepted deadline: one day.
    pub const MAX_MS: u64 = 24 * 60 * 60 * 1000;

    fn validate(&self) -> Result<()> {
        for (value, field) in [
            (self.start_ms, "startMs"),
            (self.control_ms, "controlMs"),
            (self.stop_ms, "stopMs"),
            (self.exec_grace_ms, "execGraceMs"),
        ] {
            if value == 0 || value > Self::MAX_MS {
                return Err(Error::malformed_request(format!(
                    "setup timeouts.{field} must be between 1 and {}",
                    Self::MAX_MS
                )));
            }
        }
        Ok(())
    }
}

/// How long the host keeps a running sandbox's guest session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestSessionPolicy {
    /// Keeps the session while the sandbox runs. The VM accepts one host session at a time, so
    /// another process's operations on the sandbox wait until this process releases it.
    #[serde(default = "default_hold")]
    pub hold: bool,
    /// With `hold` off, releases a session after it has been idle this long.
    #[serde(default = "default_linger_ms")]
    pub linger_ms: u64,
}

fn default_hold() -> bool {
    true
}

fn default_linger_ms() -> u64 {
    25
}

impl Default for GuestSessionPolicy {
    fn default() -> Self {
        Self {
            hold: default_hold(),
            linger_ms: default_linger_ms(),
        }
    }
}

impl GuestSessionPolicy {
    fn validate(&self) -> Result<()> {
        if self.linger_ms > Timeouts::MAX_MS {
            return Err(Error::malformed_request(format!(
                "setup guestSession.lingerMs must not exceed {}",
                Timeouts::MAX_MS
            )));
        }
        Ok(())
    }
}

/// Values that a sandbox inherits unless its spec sets them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxDefaults {
    /// Image of sandboxes whose spec names none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageSource>,
    /// How the host registers [`image`](Self::image) when it is a local path. The host registers
    /// it when it opens, reading the file only if no registration that the file still matches
    /// exists and the digest is not [`ImageDigest::Trusted`].
    #[serde(default, skip_serializing_if = "ImageDigest::is_compute")]
    pub image_digest: ImageDigest,
    /// Guest resources.
    #[serde(default = "default_resources")]
    pub resources: Resources,
    /// The guest's `ADDRESS/PREFIX` on its private network.
    #[serde(default = "default_guest_network")]
    pub guest_network: String,
    /// The guest's hostname.
    #[serde(default = "default_hostname")]
    pub hostname: String,
}

/// Default guest memory, in MiB.
pub const DEFAULT_MEMORY_MIB: u32 = 256;
/// Default number of virtual processors.
pub const DEFAULT_VCPUS: u32 = 1;
/// Default guest network.
pub const DEFAULT_GUEST_NETWORK: &str = "10.0.0.2/24";
/// Default guest hostname.
pub const DEFAULT_HOSTNAME: &str = "nvx-sandbox";

fn default_resources() -> Resources {
    Resources {
        vcpus: Some(DEFAULT_VCPUS),
        memory_mib: Some(DEFAULT_MEMORY_MIB),
    }
}

fn default_guest_network() -> String {
    DEFAULT_GUEST_NETWORK.to_owned()
}

fn default_hostname() -> String {
    DEFAULT_HOSTNAME.to_owned()
}

impl Default for SandboxDefaults {
    fn default() -> Self {
        Self {
            image: None,
            image_digest: ImageDigest::Compute,
            resources: default_resources(),
            guest_network: default_guest_network(),
            hostname: default_hostname(),
        }
    }
}

impl SandboxDefaults {
    /// Sets the default image.
    #[must_use]
    pub fn with_image(mut self, image: ImageSource) -> Self {
        self.image = Some(image);
        self
    }

    /// Sets how the host registers a default image that is a local path.
    #[must_use]
    pub fn with_image_digest(mut self, digest: ImageDigest) -> Self {
        self.image_digest = digest;
        self
    }

    fn validate(&self) -> Result<()> {
        if let Some(image) = &self.image {
            image.validate("setup defaults.image")?;
        }
        if self.resources.vcpus.is_none() || self.resources.memory_mib.is_none() {
            return Err(Error::malformed_request(
                "setup defaults.resources must set vcpus and memoryMib",
            ));
        }
        self.resources.validate("setup defaults.resources")?;
        crate::spec::guest_network(&self.guest_network, "setup defaults.guestNetwork")?;
        crate::spec::hostname(&self.hostname, "setup defaults.hostname")
    }
}

/// Image cache settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageSettings {
    /// Images to make available when the host opens: the host registers local paths and checks
    /// registered digests. Registry references are reserved for a later version.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefetch: Vec<ImageSource>,
    /// How a host that pulls registry references materializes them.
    #[serde(default, skip_serializing_if = "ReferenceSettings::is_default")]
    pub references: ReferenceSettings,
}

impl ImageSettings {
    /// Sets how the host materializes registry references.
    #[must_use]
    pub fn with_references(mut self, references: ReferenceSettings) -> Self {
        self.references = references;
        self
    }

    fn validate(&self) -> Result<()> {
        for (index, image) in self.prefetch.iter().enumerate() {
            image.validate(&format!("setup images.prefetch[{index}]"))?;
        }
        self.references.validate()
    }
}

/// How a host that pulls registry references materializes them.
///
/// Such a host converts an [`ImageSource::Reference`] into a local disk image with an external
/// tool the first time a sandbox uses it, and caches the result by the reference's text: later
/// sandboxes with the same reference boot the cached image, and the host does not check a tag
/// again. A moving tag such as `latest` therefore keeps naming the content that was first pulled;
/// use a version tag or a digest (`repository@sha256:…`) to control what a sandbox boots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReferenceSettings {
    /// Longest time that materializing one reference may take, in milliseconds. The host abandons
    /// a pull that takes longer.
    #[serde(default = "default_pull_timeout_ms")]
    pub pull_timeout_ms: u64,
    /// Host-side Docker-compatible JSON credentials file. `None` keeps anonymous pulls.
    /// The host reads it only when it must pull a reference, not for local or cached images.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_file: Option<PathBuf>,
}

/// Default limit on materializing one reference: 30 minutes.
pub const DEFAULT_PULL_TIMEOUT_MS: u64 = 30 * 60 * 1000;

fn default_pull_timeout_ms() -> u64 {
    DEFAULT_PULL_TIMEOUT_MS
}

impl Default for ReferenceSettings {
    fn default() -> Self {
        Self {
            pull_timeout_ms: default_pull_timeout_ms(),
            auth_file: None,
        }
    }
}

impl ReferenceSettings {
    /// Sets the longest time that materializing one reference may take, in milliseconds.
    #[must_use]
    pub fn with_pull_timeout_ms(mut self, pull_timeout_ms: u64) -> Self {
        self.pull_timeout_ms = pull_timeout_ms;
        self
    }

    /// Selects the host-side registry credentials file.
    #[must_use]
    pub fn with_auth_file(mut self, auth_file: impl Into<PathBuf>) -> Self {
        self.auth_file = Some(auth_file.into());
        self
    }

    fn is_default(&self) -> bool {
        *self == Self::default()
    }

    fn validate(&self) -> Result<()> {
        if self.pull_timeout_ms == 0 || self.pull_timeout_ms > Timeouts::MAX_MS {
            return Err(Error::malformed_request(format!(
                "setup images.references.pullTimeoutMs must be between 1 and {}",
                Timeouts::MAX_MS
            )));
        }
        if self
            .auth_file
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(Error::malformed_request(
                "setup images.references.authFile is empty",
            ));
        }
        Ok(())
    }
}

/// Flow control of streamed executions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecSettings {
    /// Output frames that the guest may send ahead of the consumer.
    #[serde(default = "default_output_window_frames")]
    pub output_window_frames: u32,
    /// Input frames that the host may send ahead of the guest.
    #[serde(default = "default_input_window_frames")]
    pub input_window_frames: u32,
}

/// Most frames that one execution may have in flight in both directions. The transport buffers at
/// most 12 frames per stream, and three more are reserved for the start, terminal, and close
/// frames.
pub const MAX_EXEC_WINDOW_FRAMES: u32 = 9;

fn default_output_window_frames() -> u32 {
    4
}

fn default_input_window_frames() -> u32 {
    2
}

impl Default for ExecSettings {
    fn default() -> Self {
        Self {
            output_window_frames: default_output_window_frames(),
            input_window_frames: default_input_window_frames(),
        }
    }
}

impl ExecSettings {
    fn validate(&self) -> Result<()> {
        if self.output_window_frames == 0 || self.input_window_frames == 0 {
            return Err(Error::malformed_request(
                "setup exec windows must be at least one frame",
            ));
        }
        if self
            .output_window_frames
            .saturating_add(self.input_window_frames)
            > MAX_EXEC_WINDOW_FRAMES
        {
            return Err(Error::malformed_request(format!(
                "setup exec windows may total at most {MAX_EXEC_WINDOW_FRAMES} frames"
            )));
        }
        Ok(())
    }
}

/// Diagnostic switches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Diagnostics {
    /// Boots guests with verbose kernel and agent logging.
    #[serde(default)]
    pub guest_debug: bool,
    /// Hashes every runtime file and image again before each start, instead of trusting their
    /// recorded identity.
    #[serde(default)]
    pub content_verification: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    fn files() -> RuntimeSource {
        RuntimeSource::Files(RuntimeFiles {
            openvmm: "/opt/nvx/bin/openvmm".into(),
            kernel: "/opt/nvx/guest/vmlinux".into(),
            initrd: "/opt/nvx/guest/initramfs-edge.cpio.gz".into(),
            approved_sha256: None,
        })
    }

    #[test]
    fn minimal_configuration_takes_every_default() {
        let config: SetupConfig = serde_json::from_str(
            r#"{"stateRoot":"/var/lib/nvx","runtime":{"bundle":{"path":"/opt/nvx","manifestSha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}}"#,
        )
        .unwrap();
        assert_eq!(config.schema_version, SetupConfig::SCHEMA_VERSION);
        assert_eq!(config.cpu_profile, CpuProfile::Auto);
        assert_eq!(config.timeouts, Timeouts::default());
        assert!(config.guest_session.hold);
        assert_eq!(config.defaults, SandboxDefaults::default());
        assert_eq!(config.exec, ExecSettings::default());
        assert_eq!(config.images, ImageSettings::default());
        assert_eq!(
            config.images.references.pull_timeout_ms,
            DEFAULT_PULL_TIMEOUT_MS
        );
        assert!(config.images.references.auth_file.is_none());
        config.validate().unwrap();
    }

    #[test]
    fn reference_settings_are_omitted_until_set_and_round_trip() {
        let config = SetupConfig::new("/var/lib/nvx", files());
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("references"), "{json}");
        assert!(!json.contains("authFile"), "{json}");

        let config = config.with_images(
            ImageSettings::default()
                .with_references(ReferenceSettings::default().with_pull_timeout_ms(60_000)),
        );
        let json = serde_json::to_string(&config).unwrap();
        assert!(
            json.contains(r#""references":{"pullTimeoutMs":60000}"#),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<SetupConfig>(&json).unwrap(), config);
        config.validate().unwrap();
    }

    #[test]
    fn registry_auth_file_round_trips_without_inline_credentials() {
        let config = SetupConfig::new("/var/lib/nvx", files())
            .with_images(ImageSettings::default().with_references(
                ReferenceSettings::default().with_auth_file("registry-auth.json"),
            ));
        let json = serde_json::to_string(&config).unwrap();
        assert!(
            json.contains(r#""authFile":"registry-auth.json""#),
            "{json}"
        );
        assert!(!json.contains("password"), "{json}");
        assert_eq!(serde_json::from_str::<SetupConfig>(&json).unwrap(), config);
        config.validate().unwrap();

        let old: ReferenceSettings = serde_json::from_str(r#"{"pullTimeoutMs":60000}"#).unwrap();
        assert_eq!(old.pull_timeout_ms, 60_000);
        assert!(old.auth_file.is_none());
    }

    #[test]
    fn configurations_round_trip_and_reject_unknown_fields() {
        let config = SetupConfig::new("/var/lib/nvx", files())
            .with_hypervisor(Hypervisor::Mshv)
            .with_cpu_profile(CpuProfile::Host);
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains(r#""hypervisor":"mshv""#), "{json}");
        assert!(json.contains(r#""cpuProfile":"host""#), "{json}");
        assert_eq!(serde_json::from_str::<SetupConfig>(&json).unwrap(), config);
        let unknown = json.replace(r#""cpuProfile""#, r#""cpuProfiles""#);
        assert!(serde_json::from_str::<SetupConfig>(&unknown).is_err());
    }

    #[test]
    fn validation_rejects_malformed_configurations() {
        let mut bad = Vec::new();
        let mut config = SetupConfig::new("/var/lib/nvx", files());
        config.schema_version = 2;
        bad.push(config);
        bad.push(SetupConfig::new("", files()));
        bad.push(SetupConfig::new(
            "/var/lib/nvx",
            RuntimeSource::Bundle(BundleSource {
                path: "".into(),
                manifest_sha256: [1; 32],
            }),
        ));
        let mut config = SetupConfig::new("/var/lib/nvx", files());
        config.timeouts.control_ms = 0;
        bad.push(config);
        let mut config = SetupConfig::new("/var/lib/nvx", files());
        config.exec.output_window_frames = 8;
        bad.push(config);
        // Windows whose sum overflows a u32 are too large, not small.
        let mut config = SetupConfig::new("/var/lib/nvx", files());
        config.exec.output_window_frames = u32::MAX;
        config.exec.input_window_frames = 2;
        bad.push(config);
        let mut config = SetupConfig::new("/var/lib/nvx", files());
        config.defaults.guest_network = "10.0.0.2".into();
        bad.push(config);
        let mut config = SetupConfig::new("/var/lib/nvx", files());
        config.defaults.resources.memory_mib = None;
        bad.push(config);
        for references in [
            ReferenceSettings::default().with_pull_timeout_ms(0),
            ReferenceSettings::default().with_pull_timeout_ms(Timeouts::MAX_MS + 1),
            ReferenceSettings::default().with_auth_file(""),
        ] {
            bad.push(
                SetupConfig::new("/var/lib/nvx", files())
                    .with_images(ImageSettings::default().with_references(references)),
            );
        }
        for config in bad {
            let error = config.validate().unwrap_err();
            assert_eq!(error.code(), ErrorCode::MalformedRequest, "{config:?}");
        }
    }

    #[test]
    fn digests_are_hexadecimal_on_the_wire() {
        let json = r#"{"stateRoot":"/s","runtime":{"bundle":{"path":"/b","manifestSha256":"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"}}}"#;
        assert!(serde_json::from_str::<SetupConfig>(json).is_err());
        let digests = RuntimeDigests {
            openvmm: [1; 32],
            kernel: [2; 32],
            initrd: [3; 32],
        };
        let text = serde_json::to_string(&digests).unwrap();
        assert!(text.contains(&"02".repeat(32)), "{text}");
        assert_eq!(
            serde_json::from_str::<RuntimeDigests>(&text).unwrap(),
            digests
        );
    }

    #[test]
    fn hypervisors_keep_their_json_and_error_codes() {
        for hypervisor in [Hypervisor::Kvm, Hypervisor::Mshv, Hypervisor::Whp] {
            assert_eq!(
                serde_json::to_string(&hypervisor).unwrap(),
                format!("\"{}\"", hypervisor.as_str())
            );
            let config = SetupConfig::new("/var/lib/nvx", files()).with_hypervisor(hypervisor);
            let json = serde_json::to_value(&config).unwrap();
            assert_eq!(json["hypervisor"], hypervisor.as_str());
        }
        let error = Error::from("hyperv".parse::<Hypervisor>().unwrap_err());
        assert_eq!(error.code(), ErrorCode::BackendUnavailable);
        assert_eq!(
            error.message(),
            "unknown hypervisor \"hyperv\"; choose kvm, mshv, or whp"
        );
    }
}
