//! The CPU-profile guidance that `nvx-rs run` prints after OpenVMM fails a cold boot on a host
//! whose CPU no built-in CPU profile serves.
//!
//! OpenVMM presents each guest a CPU profile, by default the built-in profile of the host CPU's
//! generation (`doc/usage.md`, "CPU profiles"). `cpu_generations.json` copies the identity of
//! every profile that OpenVMM pins, from its document in `vmm_core/cpu_profile/profiles/` of the
//! OpenVMM submodule: its ID, the vendor of its CPUs, and its generation's name and CPU models,
//! each a display family, a display model, and the first and last of its steppings. The revisions
//! of a generation's profile share its generation, which the guidance lists once.
//! `tests/openvmm_cpu_profiles.rs` compares the copy with the submodule's documents.
//! [`HostCpu::current`] identifies the host CPU with CPUID, as OpenVMM does.
//!
//! On an Intel or AMD CPU that no built-in profile serves, `--cpu-profile auto`, the default, falls
//! back to a profile derived from the host, which OpenVMM warns about, and on another vendor's
//! CPU, `auto` and `host` fail with `E_PROFILE_HOST_UNKNOWN`. OpenVMM keeps its standard error on
//! the terminal, so `nvx-rs run` cannot read the code that ended a cold boot: [`guidance`] says
//! what `auto` does on such a CPU, and on an Intel or AMD CPU, asks for the CPU's fingerprint,
//! from which NVX can add a built-in profile for it. An explicit profile ID fails with its own
//! code, and `host` on an Intel or AMD CPU with OpenVMM's own explanation, which need none.

use serde::Deserialize;

/// The identities of the built-in CPU profiles, in the order in which [`guidance`] lists their
/// generations.
const CATALOG: &str = include_str!("cpu_generations.json");
/// The `--cpu-profile` of a profile that OpenVMM derives from the host that it runs on.
const HOST_PROFILE: &str = "host";
/// The code with which OpenVMM fails a cold boot where no CPU profile serves the host's CPU.
const PROFILE_HOST_UNKNOWN: &str = "E_PROFILE_HOST_UNKNOWN";
/// The marker that leads OpenVMM's warning of each cold boot whose `--cpu-profile auto` falls back
/// to a host profile.
const FALLBACK_MARKER: &str = "NVX-CPU-PROFILE-FALLBACK:";
/// NVX's issue form that requests a built-in CPU profile for a CPU.
const REQUEST_URL: &str = "https://github.com/microsoft/nvx/issues/new?template=cpu-profile.yml";
/// The vendors whose CPUs host profiles serve, by their CPUID vendor strings, each with its name
/// and the issue that tracks built-in profiles for more of its CPUs.
const HOST_PROFILE_VENDORS: [(&str, &str, &str); 2] = [
    (
        "GenuineIntel",
        "Intel",
        "https://github.com/microsoft/nvx/issues/408",
    ),
    (
        "AuthenticAMD",
        "AMD",
        "https://github.com/microsoft/nvx/issues/409",
    ),
];

/// A CPU model of a generation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CpuModel {
    /// The display family.
    family: u32,
    /// The display model.
    model: u32,
    /// The first and the last stepping that the generation covers.
    steppings: [u32; 2],
}

impl CpuModel {
    /// Returns the model as the guidance names it: `6/106`, or `6/85 steppings 0-4` if the
    /// generation covers only some of its steppings.
    fn describe(&self) -> String {
        let name = format!("{}/{}", self.family, self.model);
        match self.steppings {
            [0, 15] => name,
            [first, last] => format!("{name} steppings {first}-{last}"),
        }
    }
}

/// The CPU generation that a built-in profile serves.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Generation {
    /// The generation's name, such as `skylake-sp`.
    name: String,
    /// The generation's CPU models.
    cpus: Vec<CpuModel>,
}

/// The identity of a built-in CPU profile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    /// The profile's ID, such as `intel.skylake-sp.v1`.
    id: String,
    /// The CPUID vendor string of the generation's CPUs, such as `GenuineIntel`.
    vendor: String,
    /// The generation that the profile serves.
    generation: Generation,
}

impl Profile {
    /// Returns whether the profile serves `cpu`.
    fn serves(&self, cpu: &HostCpu) -> bool {
        self.vendor == cpu.vendor
            && self.generation.cpus.iter().any(|model| {
                (model.family, model.model) == (cpu.family, cpu.model)
                    && (model.steppings[0]..=model.steppings[1]).contains(&cpu.stepping)
            })
    }

    /// Returns the profile's generation and its CPU models, such as `alderlake 6/151 and 6/154`.
    fn describe(&self) -> String {
        let cpus: Vec<String> = self
            .generation
            .cpus
            .iter()
            .map(CpuModel::describe)
            .collect();
        format!("{} {}", self.generation.name, cpus.join(" and "))
    }
}

/// Returns the built-in CPU profiles of [`CATALOG`].
fn catalog() -> Vec<Profile> {
    serde_json::from_str(CATALOG).expect("cpu_generations.json lists the built-in CPU profiles")
}

/// Returns the generations of the built-in profiles in `catalog` as the guidance lists them, such
/// as `milan 25/1, genoa 25/17`: each once, in the order of its first profile, since the revisions
/// of a generation's profile share it.
fn describe_generations(catalog: &[Profile]) -> String {
    let mut generations: Vec<String> = Vec::new();
    for generation in catalog.iter().map(Profile::describe) {
        if !generations.contains(&generation) {
            generations.push(generation);
        }
    }
    generations.join(", ")
}

/// A host CPU, as CPUID identifies it. Only x86-64 hosts have CPUID, so elsewhere, nothing
/// identifies one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) struct HostCpu {
    /// The vendor string of CPUID leaf 0, such as `GenuineIntel`.
    vendor: String,
    /// The display family.
    family: u32,
    /// The display model.
    model: u32,
    /// The stepping.
    stepping: u32,
    /// The brand string of CPUID leaves 0x80000002 to 0x80000004, or nothing.
    brand: String,
}

impl HostCpu {
    /// Identifies the CPU that this process runs on, or returns `None` on a host without CPUID,
    /// which is not an x86-64 host.
    pub(crate) fn current() -> Option<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            Some(Self::from_cpuid(cpuid))
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            None
        }
    }

    /// Identifies the CPU from `cpuid`, which returns EAX, EBX, ECX, and EDX of a leaf, as
    /// OpenVMM's `cpu_profile` crate identifies it: Intel extends the model for families 6 and 15,
    /// and AMD only for family 15.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    fn from_cpuid(mut cpuid: impl FnMut(u32) -> [u32; 4]) -> Self {
        let [max_basic, ebx, ecx, edx] = cpuid(0);
        let vendor = register_text(&[ebx, edx, ecx]);
        let signature = if max_basic >= 1 { cpuid(1)[0] } else { 0 };
        let brand = if cpuid(0x8000_0000)[0] >= 0x8000_0004 {
            let registers: Vec<u32> = (0x8000_0002..=0x8000_0004).flat_map(&mut cpuid).collect();
            register_text(&registers)
        } else {
            String::new()
        };
        let stepping = signature & 0xf;
        let base_model = (signature >> 4) & 0xf;
        let base_family = (signature >> 8) & 0xf;
        let family = if base_family == 0xf {
            base_family + ((signature >> 20) & 0xff)
        } else {
            base_family
        };
        let extended = base_family == 0xf || (base_family == 6 && vendor == "GenuineIntel");
        let model = if extended {
            (((signature >> 16) & 0xf) << 4) | base_model
        } else {
            base_model
        };
        Self {
            vendor,
            family,
            model,
            stepping,
            brand,
        }
    }

    /// Returns the CPU's vendor and display family, model, and stepping, such as
    /// `GenuineIntel 6/173/1`.
    fn signature(&self) -> String {
        format!(
            "{} {}/{}/{}",
            self.vendor, self.family, self.model, self.stepping
        )
    }

    /// Returns the CPU as the guidance names it: its signature and its brand string, if any, such
    /// as `GenuineIntel 6/173/1 (Intel(R) Xeon(R) 6973P-C)`.
    fn describe(&self) -> String {
        if self.brand.is_empty() {
            self.signature()
        } else {
            format!("{} ({})", self.signature(), self.brand)
        }
    }

    /// Returns the link to the CPU profile request form for the CPU, which prefills the form's
    /// title and CPU fields, as OpenVMM's fallback warning does.
    fn request_url(&self) -> String {
        let mut url = format!(
            "{REQUEST_URL}&title={}&signature={}",
            encode_query_value(&format!("CPU profile: {}", self.describe())),
            encode_query_value(&self.signature())
        );
        if !self.brand.is_empty() {
            url.push_str("&cpu=");
            url.push_str(&encode_query_value(&self.brand));
        }
        url
    }
}

/// Runs CPUID with `leaf` and subleaf 0, and returns EAX, EBX, ECX, and EDX.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code, unused_unsafe)]
fn cpuid(leaf: u32) -> [u32; 4] {
    // SAFETY: CPUID executes in user mode on every x86-64 processor and accesses no memory. The
    // intrinsic became a safe function after the crate's minimum Rust version.
    let result = unsafe { core::arch::x86_64::__cpuid_count(leaf, 0) };
    [result.eax, result.ebx, result.ecx, result.edx]
}

/// Returns the text of the little-endian bytes of `registers`, as CPUID's vendor and brand
/// strings hold it, without the NULs that pad it or the spaces around it.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn register_text(registers: &[u32]) -> String {
    let bytes: Vec<u8> = registers
        .iter()
        .flat_map(|register| register.to_le_bytes())
        .collect();
    String::from_utf8_lossy(&bytes)
        .trim_end_matches('\0')
        .trim()
        .to_owned()
}

/// Percent-encodes `value` for a URL query, as OpenVMM's fallback warning does: every byte but
/// ASCII letters, digits, `-`, `.`, `_`, and `~`.
fn encode_query_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// Returns what to print after OpenVMM failed a cold boot with `--cpu-profile cpu_profile`, or
/// with its default, `auto`, if `None`, on the CPU `host` with the `hypervisor` backend, where
/// `openvmm` is the OpenVMM executable, quoted for the shell. Returns `None` unless no built-in
/// profile serves the CPU and the profile is `auto`, or `host` on a CPU of a vendor that host
/// profiles do not serve either, and where the CPU is unknown.
pub(crate) fn guidance(
    cpu_profile: Option<&str>,
    host: Option<&HostCpu>,
    openvmm: &str,
    hypervisor: &str,
) -> Option<String> {
    let host = host?;
    let catalog = catalog();
    if catalog.iter().any(|profile| profile.serves(host)) {
        return None;
    }
    let vendor = HOST_PROFILE_VENDORS
        .iter()
        .find(|(vendor, ..)| *vendor == host.vendor);
    match cpu_profile {
        None | Some("auto") => {}
        Some(HOST_PROFILE) if vendor.is_none() => {}
        Some(_) => return None,
    }
    let unserved = format!(
        "nvx: no built-in CPU profile serves this host's CPU, {}",
        host.describe()
    );
    let generations = format!(
        "the built-in profiles cover {}.",
        describe_generations(&catalog)
    );
    let Some((_, name, issue)) = vendor else {
        return Some(format!(
            "{unserved}, so a cold boot with --cpu-profile auto, the default, fails on it with \
             {PROFILE_HOST_UNKNOWN}; {generations}\n\
             nvx: --cpu-profile {HOST_PROFILE} cannot boot on it either: host CPU profiles serve \
             only Intel and AMD CPUs."
        ));
    };
    Some(
        [
            format!(
                "{unserved}, so --cpu-profile auto, the default, falls back on it to a CPU profile \
                 derived from this host, which OpenVMM warns about with {FALLBACK_MARKER}; \
                 {generations}"
            ),
            "nvx: OpenVMM's error above names the cause of this failure, and says so where the \
             host profile cannot boot; doc/usage.md (\"CPU profiles\") explains a host profile's \
             limits."
                .to_owned(),
            "nvx: Help NVX add a built-in profile for this CPU: run".to_owned(),
            format!(
                "nvx:   {openvmm} --hypervisor {hypervisor} --cpu-fingerprint fingerprint.json"
            ),
            "nvx: and attach fingerprint.json to a CPU profile request:".to_owned(),
            format!("nvx:   {}", host.request_url()),
            format!("nvx: {issue} tracks CPU profiles for more {name} CPUs."),
        ]
        .join("\n"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns the CPU of `vendor` with the display `family`, `model`, and `stepping`, and the
    /// brand string `brand`.
    fn cpu(vendor: &str, family: u32, model: u32, stepping: u32, brand: &str) -> HostCpu {
        HostCpu {
            vendor: vendor.to_owned(),
            family,
            model,
            stepping,
            brand: brand.to_owned(),
        }
    }

    /// Returns the guidance for `host` with `--cpu-profile cpu_profile`, for `/nvx/openvmm` on KVM.
    fn guide(cpu_profile: Option<&str>, host: &HostCpu) -> Option<String> {
        guidance(cpu_profile, Some(host), "/nvx/openvmm", "kvm")
    }

    /// Returns the name of the generation that serves the CPU of `vendor` with `family`, `model`,
    /// and `stepping`, if any.
    fn generation(vendor: &str, family: u32, model: u32, stepping: u32) -> Option<String> {
        let host = cpu(vendor, family, model, stepping, "");
        catalog()
            .into_iter()
            .find(|profile| profile.serves(&host))
            .map(|profile| profile.generation.name)
    }

    #[test]
    fn the_catalog_lists_the_built_in_profiles() {
        let catalog = catalog();
        let ids: Vec<&str> = catalog.iter().map(|profile| profile.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "intel.skylake-sp.v1",
                "intel.icelake-sp.v1",
                "intel.emeraldrapids.v1",
                "intel.alderlake.v1",
                "amd.milan.v1",
                "amd.genoa.v1",
                "amd.genoa.v2",
                "amd.turin.v1",
            ]
        );
        // The two revisions of Genoa's profile share its generation, which the guidance lists
        // once.
        assert_eq!(
            describe_generations(&catalog),
            "skylake-sp 6/85 steppings 0-4, icelake-sp 6/106, emeraldrapids 6/207, alderlake \
             6/151 and 6/154, milan 25/1, genoa 25/17, turin 26/2"
        );
    }

    #[test]
    fn cpus_map_to_the_generations_of_the_built_in_profiles() {
        let intel = |model, stepping| generation("GenuineIntel", 6, model, stepping);
        assert_eq!(intel(85, 4).as_deref(), Some("skylake-sp"));
        assert_eq!(intel(106, 6).as_deref(), Some("icelake-sp"));
        assert_eq!(intel(207, 2).as_deref(), Some("emeraldrapids"));
        // Alder Lake-S and Alder Lake-P and -H share one profile.
        assert_eq!(intel(151, 2).as_deref(), Some("alderlake"));
        assert_eq!(intel(154, 3).as_deref(), Some("alderlake"));
        // Cascade Lake and Cooper Lake share model 85 but have no profile, and neither have
        // Sapphire Rapids, Tiger Lake, and Raptor Lake.
        for (model, stepping) in [(85, 7), (85, 11), (143, 8), (140, 1), (183, 1)] {
            assert_eq!(intel(model, stepping), None, "6/{model}/{stepping}");
        }
        // Milan's profile serves every stepping of AMD's family 25 model 1, Genoa's every stepping
        // of model 17, and Turin's every stepping of family 26 model 2.
        for (family, model, expected) in [(25, 1, "milan"), (25, 17, "genoa"), (26, 2, "turin")] {
            for stepping in [0, 1, 2, 15] {
                assert_eq!(
                    generation("AuthenticAMD", family, model, stepping).as_deref(),
                    Some(expected)
                );
            }
        }
        // Vermeer and Raphael (Ryzen), Turin Dense, and Granite Ridge have no profile, and neither
        // has another vendor's CPU with the signature of an AMD generation.
        for (vendor, family, model) in [
            ("AuthenticAMD", 1, 1),
            ("AuthenticAMD", 25, 33),
            ("AuthenticAMD", 25, 97),
            ("AuthenticAMD", 26, 17),
            ("AuthenticAMD", 26, 68),
            ("GenuineIntel", 25, 1),
            ("HygonGenuine", 25, 1),
            ("GenuineIntel", 26, 2),
        ] {
            assert_eq!(
                generation(vendor, family, model, 1),
                None,
                "{vendor} {family}/{model}"
            );
        }
    }

    /// Returns the registers of a CPUID leaf that hold `text`, as the vendor and brand leaves
    /// hold it.
    fn words(text: &[u8]) -> Vec<u32> {
        text.chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }

    /// Returns the CPUID of a CPU of `vendor` with the CPUID.1:EAX `signature` and, if not empty,
    /// the 48-byte `brand`.
    fn fake_cpuid(vendor: &[u8; 12], signature: u32, brand: &[u8]) -> impl FnMut(u32) -> [u32; 4] {
        let vendor = words(vendor);
        let brand = words(brand);
        let max_extended = if brand.is_empty() {
            0x8000_0001
        } else {
            0x8000_0004
        };
        move |leaf| match leaf {
            0 => [0x1b, vendor[0], vendor[2], vendor[1]],
            1 => [signature, 0, 0, 0],
            0x8000_0000 => [max_extended, 0, 0, 0],
            0x8000_0002..=0x8000_0004 if !brand.is_empty() => {
                let first = (leaf - 0x8000_0002) as usize * 4;
                [
                    brand[first],
                    brand[first + 1],
                    brand[first + 2],
                    brand[first + 3],
                ]
            }
            _ => [0; 4],
        }
    }

    #[test]
    fn cpuid_identifies_the_cpu_as_openvmm_does() {
        let skylake = HostCpu::from_cpuid(fake_cpuid(
            b"GenuineIntel",
            0x0005_0654,
            b"Intel(R) Xeon(R) Silver 4114 CPU @ 2.20GHz\0\0\0\0\0\0",
        ));
        assert_eq!(
            skylake,
            cpu(
                "GenuineIntel",
                6,
                85,
                4,
                "Intel(R) Xeon(R) Silver 4114 CPU @ 2.20GHz"
            )
        );
        // Older Intel brand strings start with spaces, which are trimmed as NULs are.
        let padded = HostCpu::from_cpuid(fake_cpuid(
            b"GenuineIntel",
            0x000c_06f2,
            b"        Intel(R) Xeon(R) Platinum 8573C\0\0\0\0\0\0\0\0\0",
        ));
        assert_eq!((padded.family, padded.model, padded.stepping), (6, 207, 2));
        assert_eq!(padded.brand, "Intel(R) Xeon(R) Platinum 8573C");
        // AMD extends the family and the model of family 15 alone.
        let genoa = HostCpu::from_cpuid(fake_cpuid(b"AuthenticAMD", 0x00a1_0f11, b""));
        assert_eq!(genoa, cpu("AuthenticAMD", 25, 17, 1, ""));
        let k7 = HostCpu::from_cpuid(fake_cpuid(b"AuthenticAMD", 0x0001_0661, b""));
        assert_eq!((k7.family, k7.model, k7.stepping), (6, 6, 1));
        let p6 = HostCpu::from_cpuid(fake_cpuid(b"GenuineIntel", 0x0001_0661, b""));
        assert_eq!((p6.family, p6.model, p6.stepping), (6, 22, 1));
    }

    /// Returns the host CPU as the host OS reports it, without its brand string: the first
    /// processor of `/proc/cpuinfo` on Linux, and `PROCESSOR_IDENTIFIER` on Windows, such as
    /// `Intel64 Family 6 Model 85 Stepping 4, GenuineIntel`.
    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", windows)))]
    fn reported_cpu() -> Option<HostCpu> {
        if cfg!(windows) {
            let identifier = std::env::var("PROCESSOR_IDENTIFIER").ok()?;
            let (description, vendor) = identifier.split_once(", ")?;
            let words: Vec<&str> = description.split_whitespace().collect();
            let number = |name: &str| {
                let position = words.iter().position(|word| *word == name)?;
                words.get(position + 1)?.parse().ok()
            };
            return Some(cpu(
                vendor.trim(),
                number("Family")?,
                number("Model")?,
                number("Stepping")?,
                "",
            ));
        }
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        let field = |name: &str| {
            cpuinfo.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == name).then(|| value.trim().to_owned())
            })
        };
        Some(cpu(
            &field("vendor_id")?,
            field("cpu family")?.parse().ok()?,
            field("model")?.parse().ok()?,
            field("stepping")?.parse().ok()?,
            "",
        ))
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", windows)))]
    #[test]
    fn the_host_cpu_is_the_one_that_the_host_os_reports() {
        let current = HostCpu::current().unwrap();
        let reported = reported_cpu().expect("the host OS reports the CPU");
        assert_eq!(
            HostCpu {
                brand: String::new(),
                ..current.clone()
            },
            reported
        );
        if cfg!(target_os = "linux") && !current.brand.is_empty() {
            let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap();
            assert!(
                cpuinfo
                    .lines()
                    .any(|line| line.split_once(':').is_some_and(|(key, value)| {
                        key.trim() == "model name" && value.trim() == current.brand
                    })),
                "{current:?}"
            );
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn hosts_without_cpuid_identify_no_cpu() {
        assert_eq!(HostCpu::current(), None);
    }

    #[test]
    fn request_links_prefill_the_cpu() {
        let granite_rapids = cpu("GenuineIntel", 6, 173, 1, "Intel(R) Xeon(R) 6973P-C");
        assert_eq!(granite_rapids.signature(), "GenuineIntel 6/173/1");
        assert_eq!(
            granite_rapids.describe(),
            "GenuineIntel 6/173/1 (Intel(R) Xeon(R) 6973P-C)"
        );
        // The link that OpenVMM's fallback warning gives the same CPU.
        assert_eq!(
            granite_rapids.request_url(),
            "https://github.com/microsoft/nvx/issues/new?template=cpu-profile.yml\
             &title=CPU%20profile%3A%20GenuineIntel%206%2F173%2F1%20%28Intel%28R%29\
             %20Xeon%28R%29%206973P-C%29&signature=GenuineIntel%206%2F173%2F1\
             &cpu=Intel%28R%29%20Xeon%28R%29%206973P-C"
        );
        // A CPU without a brand string prefills only its signature.
        let brandless = cpu("GenuineIntel", 6, 173, 1, "");
        assert_eq!(brandless.describe(), "GenuineIntel 6/173/1");
        assert_eq!(
            brandless.request_url(),
            format!(
                "{REQUEST_URL}&title=CPU%20profile%3A%20GenuineIntel%206%2F173%2F1\
                 &signature=GenuineIntel%206%2F173%2F1"
            )
        );
        assert!(
            cpu("GenuineIntel", 6, 173, 1, "&=?#%+ é")
                .request_url()
                .ends_with("&cpu=%26%3D%3F%23%25%2B%20%C3%A9")
        );
    }

    #[test]
    fn unserved_intel_and_amd_cpus_get_the_fallback_and_a_profile_request() {
        let tiger_lake = cpu(
            "GenuineIntel",
            6,
            140,
            1,
            "11th Gen Intel(R) Core(TM) i7-1185G7",
        );
        let guidance = guide(None, &tiger_lake).unwrap();
        let lines: Vec<&str> = guidance.lines().collect();
        assert!(
            lines.iter().all(|line| line.starts_with("nvx: ")),
            "{guidance}"
        );
        // auto falls back on the CPU, so the guidance says what auto does there, not which code
        // ended this run, which nvx-rs run cannot read.
        assert_eq!(
            lines[0],
            "nvx: no built-in CPU profile serves this host's CPU, GenuineIntel 6/140/1 (11th Gen \
             Intel(R) Core(TM) i7-1185G7), so --cpu-profile auto, the default, falls back on it to \
             a CPU profile derived from this host, which OpenVMM warns about with \
             NVX-CPU-PROFILE-FALLBACK:; the built-in profiles cover skylake-sp 6/85 steppings \
             0-4, icelake-sp 6/106, emeraldrapids 6/207, alderlake 6/151 and 6/154, milan 25/1, \
             genoa 25/17, turin 26/2."
        );
        assert!(lines[1].contains("OpenVMM's error above names the cause"));
        assert!(!guidance.contains(PROFILE_HOST_UNKNOWN));
        // It asks for the CPU's fingerprint through the CPU profile request form, which the link
        // prefills with the CPU.
        let request = format!("nvx:   {}", tiger_lake.request_url());
        assert_eq!(
            lines[2..],
            [
                "nvx: Help NVX add a built-in profile for this CPU: run",
                "nvx:   /nvx/openvmm --hypervisor kvm --cpu-fingerprint fingerprint.json",
                "nvx: and attach fingerprint.json to a CPU profile request:",
                request.as_str(),
                "nvx: https://github.com/microsoft/nvx/issues/408 tracks CPU profiles for more \
                 Intel CPUs.",
            ]
        );
        assert_eq!(guide(Some("auto"), &tiger_lake).as_ref(), Some(&guidance));
        // A host profile that fails on this CPU fails for a reason that OpenVMM's own error
        // explains.
        assert_eq!(guide(Some(HOST_PROFILE), &tiger_lake), None);

        // Host profiles serve AMD CPUs too: an AMD CPU without a built-in profile, such as
        // Raphael (Ryzen 7000), falls back as an Intel one does, with the issue that tracks
        // profiles for more AMD CPUs.
        let raphael = cpu("AuthenticAMD", 25, 97, 2, "");
        let guidance = guide(None, &raphael).unwrap();
        assert!(guidance.contains(
            "this host's CPU, AuthenticAMD 25/97/2, so --cpu-profile auto, the default, falls \
             back on it"
        ));
        assert!(guidance.contains(&raphael.request_url()));
        assert!(guidance.ends_with(
            "\nnvx: https://github.com/microsoft/nvx/issues/409 tracks CPU profiles for more AMD \
             CPUs."
        ));
        assert!(!guidance.contains("issues/408"));
        assert_eq!(guide(Some(HOST_PROFILE), &raphael), None);
    }

    #[test]
    fn unserved_cpus_of_other_vendors_get_no_profile_request() {
        // Another vendor's CPU fails with either profile, and gets no request form and no issue:
        // the time ABI does not serve its CPUs.
        let hygon = cpu("HygonGenuine", 24, 0, 1, "");
        let guidance = guide(Some("auto"), &hygon).unwrap();
        assert_eq!(
            guidance,
            "nvx: no built-in CPU profile serves this host's CPU, HygonGenuine 24/0/1, so a cold \
             boot with --cpu-profile auto, the default, fails on it with E_PROFILE_HOST_UNKNOWN; \
             the built-in profiles cover skylake-sp 6/85 steppings 0-4, icelake-sp 6/106, \
             emeraldrapids 6/207, alderlake 6/151 and 6/154, milan 25/1, genoa 25/17, turin \
             26/2.\nnvx: --cpu-profile host cannot boot on it either: host CPU profiles serve only \
             Intel and AMD CPUs."
        );
        assert_eq!(guide(None, &hygon).as_ref(), Some(&guidance));
        assert_eq!(guide(Some(HOST_PROFILE), &hygon).as_ref(), Some(&guidance));
    }

    #[test]
    fn served_cpus_explicit_profiles_and_unknown_cpus_get_none() {
        let tiger_lake = cpu("GenuineIntel", 6, 140, 1, "");
        let raphael = cpu("AuthenticAMD", 25, 97, 2, "");
        let hygon = cpu("HygonGenuine", 24, 0, 1, "");
        let alder_lake = cpu("GenuineIntel", 6, 154, 3, "");
        let milan = cpu("AuthenticAMD", 25, 1, 1, "");
        let genoa = cpu("AuthenticAMD", 25, 17, 1, "");
        let turin = cpu("AuthenticAMD", 26, 2, 1, "");
        for (cpu_profile, host) in [
            (None, &alder_lake),
            (Some(HOST_PROFILE), &alder_lake),
            (None, &milan),
            (Some(HOST_PROFILE), &milan),
            (None, &genoa),
            (None, &turin),
            (Some(HOST_PROFILE), &turin),
            (Some("intel.alderlake.v1"), &tiger_lake),
            (Some("intel.alderlake.v1"), &raphael),
            (Some("intel.skylake-sp.v1"), &milan),
            (Some("intel.skylake-sp.v1"), &hygon),
        ] {
            assert_eq!(guide(cpu_profile, host), None, "{cpu_profile:?} {host:?}");
        }
        assert_eq!(guidance(None, None, "/nvx/openvmm", "kvm"), None);
    }
}
