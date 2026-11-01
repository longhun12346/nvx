//! The JSON files that the CLI reads and writes: the configuration record of a sandbox, the
//! outcome reports of OpenVMM and of `exec`, and the output of `artifacts` and `egress compile`.
//!
//! - [`read_object`] reads a file as egress policy files and distro manifests are read: RFC 8259
//!   JSON, as `serde_json` reads it, in which no object repeats a field, and arrays and objects
//!   nest at most [`MAX_JSON_DEPTH`] deep, whatever the features of `serde_json` in the build. Its
//!   root is an object whose version field names one of the versions that the reader takes.
//! - [`pretty`] writes a value with `serde_json`'s pretty printer, two spaces of indentation per
//!   level, with the members of every object sorted by name. Another crate of a build can make
//!   `serde_json`'s maps keep the order in which their members were inserted, so the printer
//!   sorts them itself.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use super::{Exit, Result};
use crate::ErrorCode;
use crate::host::network::policy::MAX_JSON_DEPTH;
use crate::host::network::policy::json::{ReadError, read_document};

/// A JSON object.
pub(crate) type Object = Map<String, Value>;

/// Reads the JSON object at `path`, which messages call `description`, such as `sandbox
/// configuration`, and whose member `version_field` is one of the integers `versions`.
///
/// A file that cannot be read, that is not UTF-8, or that is not JSON fails as `failed to read
/// DESCRIPTION: PATH`, with the code [`ErrorCode::Io`], which names the object that repeats a
/// field, as in `failed to read DESCRIPTION: PATH: layers[0] has duplicate field "path"`, or the
/// array or object that nests too deep. Another value than an object, or another version, fails as
/// `DESCRIPTION has an unsupported format: PATH`, with [`ErrorCode::FormatUnsupported`].
pub(crate) fn read_object(
    path: &Path,
    description: &str,
    version_field: &str,
    versions: &[u64],
) -> Result<Object> {
    let unreadable = |detail: Option<String>| {
        let detail = detail
            .map(|detail| format!(": {detail}"))
            .unwrap_or_default();
        Exit::error(
            ErrorCode::Io,
            format!("failed to read {description}: {}{detail}", path.display()),
        )
    };
    let bytes = std::fs::read(path).map_err(|_| unreadable(None))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| unreadable(None))?;
    let value = read_document(text, description).map_err(|error| match error {
        ReadError::Syntax(_) => unreadable(None),
        ReadError::Repeated { object, field } => {
            unreadable(Some(format!("{object} has duplicate field {field:?}")))
        }
        ReadError::TooDeep { line, column } => unreadable(Some(format!(
            "arrays and objects nest more than {MAX_JSON_DEPTH} deep at line {line} column \
             {column}"
        ))),
    })?;
    match value {
        Value::Object(object)
            if object
                .get(version_field)
                .and_then(Value::as_u64)
                .is_some_and(|version| versions.contains(&version)) =>
        {
            Ok(object)
        }
        _ => Err(Exit::error(
            ErrorCode::FormatUnsupported,
            format!(
                "{description} has an unsupported format: {}",
                path.display()
            ),
        )),
    }
}

/// Returns `value` as `serde_json`'s pretty printer writes it, with the members of every object
/// sorted by name, and without a final line end.
pub(crate) fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(&Sorted(value)).expect("a JSON value serializes")
}

/// Returns the serde form of `value` as [`pretty`] writes it, or the error that `description`
/// names if it has no JSON form.
pub(crate) fn pretty_serde(value: &impl Serialize, description: &str) -> Result<String> {
    serde_json::to_value(value)
        .map(|value| pretty(&value))
        .map_err(|error| {
            Exit::error(
                ErrorCode::Other,
                format!("cannot encode the {description}: {error}"),
            )
        })
}

/// A JSON value that serializes with the members of every object sorted by name.
struct Sorted<'a>(&'a Value);

impl Serialize for Sorted<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self.0 {
            Value::Array(items) => serializer.collect_seq(items.iter().map(Sorted)),
            Value::Object(members) => serializer.collect_map(
                members
                    .iter()
                    .map(|(name, member)| (name, Sorted(member)))
                    .collect::<BTreeMap<_, _>>(),
            ),
            scalar => scalar.serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn values_print_with_sorted_members_and_two_spaces() {
        let value = json!({
            "zeta": [1, null],
            "alpha": true,
            "empty": [],
            "nested": {"b": "x", "a": false},
            "none": {},
            "big": u64::MAX,
            "text": "a\"b\\c\n\u{7f}é\u{1f600}",
        });
        assert_eq!(
            pretty(&value),
            "{\n  \"alpha\": true,\n  \"big\": 18446744073709551615,\n  \"empty\": [],\n  \
             \"nested\": {\n    \"a\": false,\n    \"b\": \"x\"\n  },\n  \"none\": {},\n  \
             \"text\": \"a\\\"b\\\\c\\n\u{7f}é\u{1f600}\",\n  \"zeta\": [\n    1,\n    null\n  \
             ]\n}"
        );
        assert_eq!(pretty(&json!([])), "[]");
    }

    #[test]
    fn objects_are_read_strictly_with_their_versions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("record.json");
        let read = |text: &[u8]| {
            std::fs::write(&path, text).unwrap();
            read_object(&path, "record", "format", &[1, 7])
                .map_err(|exit| (exit.code().unwrap(), exit.message().unwrap().to_owned()))
        };
        let shown = path.display();
        assert_eq!(
            read(br#"{"format": 7, "x": [1]}"#).unwrap()["x"],
            json!([1])
        );
        let unreadable = |detail: &str| {
            (
                ErrorCode::Io,
                format!("failed to read record: {shown}{detail}"),
            )
        };
        assert_eq!(read(b"{"), Err(unreadable("")));
        assert_eq!(read(b"\xff"), Err(unreadable("")));
        assert_eq!(read(b"{\"format\": NaN}"), Err(unreadable("")));
        assert_eq!(
            read(br#"{"format": 1, "format": 1}"#),
            Err(unreadable(": record has duplicate field \"format\""))
        );
        assert_eq!(
            read(br#"{"format": 1, "layers": [{"a": 1, "a": 2}]}"#),
            Err(unreadable(": layers[0] has duplicate field \"a\""))
        );
        let deep = format!(
            "{}{}",
            "[".repeat(MAX_JSON_DEPTH + 1),
            "]".repeat(MAX_JSON_DEPTH + 1)
        );
        let (code, message) = read(deep.as_bytes()).unwrap_err();
        assert_eq!(code, ErrorCode::Io);
        assert!(message.contains("nest more than 32 deep"), "{message}");
        let unsupported = Err((
            ErrorCode::FormatUnsupported,
            format!("record has an unsupported format: {shown}"),
        ));
        for text in [
            &br#"[]"#[..],
            br#"{}"#,
            br#"{"format": 2}"#,
            br#"{"format": 1.0}"#,
            br#"{"format": true}"#,
            br#"{"format": "1"}"#,
            br#"{"format": -1}"#,
        ] {
            assert_eq!(read(text), unsupported, "{}", String::from_utf8_lossy(text));
        }
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            read_object(&path, "record", "format", &[1])
                .unwrap_err()
                .code(),
            Some(ErrorCode::Io)
        );
    }
}
