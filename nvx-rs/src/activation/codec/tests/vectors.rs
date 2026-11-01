//! Tests of the canonical encoding against the conformance vectors, which give records from the
//! encoding's definition, never from the code that they check.

use std::net::IpAddr;
use std::num::NonZeroU64;

use crate::activation::{
    ActivationError, ActivationRecord, Configuration, ExpectedResources, Export, ExportKind,
    Identity, Image, Journal, MachineIdMode, Network, OverlayMode, Publication, RestoreSection,
    StoreGeneration, TemplateReference, TransactionId, Upper, WorkloadIdentity, WorkloadView,
};
use crate::tests::{ACTIVATION_V1, Values, Vector, of_kind};
use crate::uuid::Uuid;

/// The names of the vectors of records, in order.
const RECORDS: [&str; 5] = [
    "COLD",
    "CLONE",
    "SCRATCH_AGGREGATE",
    "GPT_DIRECTORY",
    "LARGEST",
];

/// Reads a byte string of exactly `N` bytes.
fn array<const N: usize>(values: &mut Values<'_>) -> [u8; N] {
    values
        .bytes()
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("{} bytes are not {N}", bytes.len()))
}

/// Reads an identity.
fn identity(values: &mut Values<'_>) -> Identity {
    Identity::from_bytes(array(values))
}

/// Reads a UUID or a GUID, in the order of its canonical text.
fn uuid(values: &mut Values<'_>) -> Uuid {
    Uuid::from_bytes(array(values))
}

/// Reads a word, which must be one of those of `choices`, and returns the choice that it names.
fn choice<T: Copy>(values: &mut Values<'_>, choices: &[(&str, T)]) -> T {
    let word = values.word();
    choices
        .iter()
        .find(|(name, _)| *name == word)
        .map(|(_, choice)| *choice)
        .unwrap_or_else(|| panic!("{word} names no choice of its value"))
}

/// Returns the record that a `RECORD` vector's values give.
fn record_of(vector: &Vector) -> ActivationRecord {
    let mut values = vector.values();
    let restore = values.optional(|values| RestoreSection {
        transaction: TransactionId::from_bytes(array(values)),
        template: TemplateReference {
            generation: StoreGeneration::new(
                NonZeroU64::new(values.number()).expect("a store generation of 0"),
            ),
            key: identity(values),
        },
    });
    let image = match values.word() {
        "EROFS" => Image::Erofs {
            binding: identity(&mut values),
            uuid: values.optional(uuid),
        },
        "GPT" => Image::Gpt {
            binding: identity(&mut values),
            first_partition_bound: values.number(),
            disk_guid: values.optional(uuid),
        },
        format => panic!("{format} is no image format"),
    };
    let upper = match values.word() {
        "TMPFS" => Upper::Tmpfs,
        "SCRATCH" => Upper::Scratch {
            binding: identity(&mut values),
            journal: choice(
                &mut values,
                &[
                    ("ALLOWED", Journal::Allowed),
                    ("FORBIDDEN", Journal::Forbidden),
                ],
            ),
        },
        upper => panic!("{upper} is no upper"),
    };
    let overlay = choice(
        &mut values,
        &[
            ("TRUSTED_LOWERS", OverlayMode::TrustedLowers),
            ("UNTRUSTED_LOWERS", OverlayMode::UntrustedLowers),
        ],
    );
    let export = values.optional(|values| {
        let kind = choice(
            values,
            &[
                ("DIRECTORY", ExportKind::Directory),
                ("AGGREGATE", ExportKind::Aggregate),
            ],
        );
        let plan = identity(values);
        (Export { kind, plan }, values.number())
    });
    let (export, mappings) = match export {
        Some((export, mappings)) => (Some(export), mappings),
        None => (None, 0),
    };
    let network = values.optional(|values| Network {
        policy: identity(values),
        publication: choice(
            values,
            &[
                ("PUBLISHED", Publication::Published),
                ("UNPUBLISHED", Publication::Unpublished),
            ],
        ),
        dns: values.optional(|values| {
            let bytes = values.bytes();
            match <[u8; 4]>::try_from(&bytes[..]) {
                Ok(address) => IpAddr::from(address),
                Err(_) => IpAddr::from(<[u8; 16]>::try_from(&bytes[..]).unwrap()),
            }
        }),
        proxy: values.optional(|values| String::from_utf8(values.text()).unwrap()),
    });
    let hostname = values.text();
    let machine_id = choice(
        &mut values,
        &[
            ("IMAGE", MachineIdMode::Image),
            ("GENERATED", MachineIdMode::Generated),
        ],
    );
    let workload_identity = values.optional(|values| WorkloadIdentity {
        uid: values.number(),
        gid: values.number(),
    });
    let resources = ExpectedResources {
        cpus: values.number(),
        memory: values.number(),
    };
    drop(values);
    let configuration = Configuration {
        image,
        upper,
        overlay,
        export,
        mappings,
        network,
        workload: WorkloadView {
            hostname,
            machine_id,
            identity: workload_identity,
        },
        resources,
    };
    ActivationRecord::new(restore, configuration)
        .unwrap_or_else(|error| panic!("RECORD {}: {error}", vector.name))
}

#[test]
fn records_match_their_vectors() {
    for vector in of_kind(ACTIVATION_V1, "RECORD", &RECORDS) {
        let name = vector.name;
        let record = record_of(&vector);
        assert_eq!(record.encode(), vector.bytes, "{name}");
        assert_eq!(
            ActivationRecord::decode(&vector.bytes).as_ref(),
            Ok(&record),
            "{name}"
        );
    }
}

#[test]
fn invalid_records_are_refused() {
    let names = [
        "EMPTY",
        "TRUNCATED_VERSION",
        "NO_FIELDS",
        "VERSION_0",
        "VERSION_2",
        "TOO_LONG",
        "TRUNCATED_FIELD_HEADER",
        "TRUNCATED_FIELD_VALUE",
        "UNKNOWN_FIELD",
        "REPEATED_FIELD",
        "UPPER_BEFORE_IMAGE",
        "RESTORE_LAST",
        "EMPTY_OVERLAY",
        "LONG_OVERLAY",
        "OVERLAY_CODE_0",
        "OVERLAY_CODE_3",
        "IMAGE_FORMAT_3",
        "GPT_WITHOUT_BOUND",
        "SHORT_RESTORE",
        "SHORT_IMAGE_IDENTITY",
        "SCRATCH_WITHOUT_JOURNAL",
        "MACHINE_ID_CODE_0",
        "DNS_OF_5_BYTES",
        "SHORT_RESOURCES",
        "ZERO_GENERATION",
        "MISSING_IMAGE",
        "MISSING_RESOURCES",
        "EXPORT_WITHOUT_MAPPINGS",
        "MAPPINGS_WITHOUT_EXPORT",
        "ZERO_MAPPINGS",
        "DNS_WITHOUT_NETWORK",
        "PROXY_WITHOUT_NETWORK",
        "TOO_MANY_MAPPINGS",
        "EMPTY_PROXY",
        "PROXY_WITH_CREDENTIALS",
        "PROXY_WITH_SPACE",
        "PROXY_NOT_ASCII",
        "EMPTY_HOSTNAME",
        "HOSTNAME_WITH_NUL",
        "LONG_HOSTNAME",
        "ZERO_FIRST_PARTITION_BOUND",
        "ZERO_UID",
        "ZERO_GID",
        "UNCHANGED_UID",
        "UNCHANGED_GID",
        "ZERO_CPUS",
        "ZERO_MEMORY",
    ];
    for vector in of_kind(ACTIVATION_V1, "INVALID_RECORD", &names) {
        let refusal: Result<_, ActivationError> = ActivationRecord::decode(&vector.bytes);
        assert!(refusal.is_err(), "{} is admitted", vector.name);
    }
}
