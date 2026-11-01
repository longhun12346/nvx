//! The images of a layered root that the host program stages in a sandbox's store for its
//! launches, as a [`Staged`] record: the binding of the image, which NVX's `DistroBinding::verify`
//! makes, hashing the image only when a manifest is beside it, and the binding of the ext4 scratch
//! image of an upper on scratch, which NVX's `ScratchBinding::bind` makes without reading the
//! image. Staging is where hashing belongs: a launch never hashes.
//!
//! A launch takes the [bindings](Staged::bindings) that the record stages for its own images,
//! checks them before it spawns its VM, and records them; see [`crate::layered`].

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use nvx::host::sandbox::SandboxPlan;
use nvx::host::sandbox::distro::{DISTRO_POLICY_REVISION, DistroBinding};
use nvx::host::sandbox::scratch::ScratchBinding;
use nvx::protocol::root::ImageFormat;
use nvx::uuid::Uuid;
use nvx::{Error, Result};
use serde_json::{Value, json};

use crate::layered::{self, Bindings};

/// The name of the record of the staged images in the sandbox's store.
pub const STAGED_NAME: &str = "runtime-adapter-staged.json";
/// The format of the record of the staged images that this build writes and reads.
pub const STAGED_FORMAT: u64 = 1;

/// A file that the host program staged: its path, absolute and normalized as a plan names it, and
/// its binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedFile<B> {
    /// The file's path.
    pub path: PathBuf,
    /// The file's binding.
    pub binding: B,
}

/// The images that the host program staged in a sandbox's store for its launches: the image, with
/// the binding that its explicit verification made, and the ext4 scratch image of an upper on
/// scratch, if any, with its binding.
///
/// [`stage`](Self::stage) stages them, and [`write`](Self::write) records them in the store, in
/// [`STAGED_NAME`], in place of the images staged earlier. A launch [reads](Self::read) the record,
/// takes the [bindings](Self::bindings) of its own images from it, and checks them before it spawns
/// its VM; see [`LayeredLaunch::prepare`](crate::layered::LayeredLaunch::prepare). The record is
/// JSON in format [`STAGED_FORMAT`]:
///
/// ```json
/// {"format": 1,
///  "distro": {"path": "/images/distro.erofs", "binding": DISTRO_BINDING},
///  "scratch": {"path": "/sandboxes/one/scratch.ext4", "binding": SCRATCH_BINDING}}
/// ```
///
/// Each `path` is the absolute path of a file, as a plan names it, and each binding the serde form
/// of NVX's `DistroBinding` of the image or `ScratchBinding` of the scratch image. `scratch` is
/// `null` when no scratch image was staged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Staged {
    /// The image, and the binding that its explicit verification made.
    pub distro: StagedFile<DistroBinding>,
    /// The scratch image and its binding, if one was staged.
    pub scratch: Option<StagedFile<ScratchBinding>>,
}

impl Staged {
    /// Stages the image at `distro`, in `format`, of which the guest expects the identity
    /// `identity`, and the ext4 scratch image at `scratch`, if any.
    ///
    /// It plans the images as a launch over the scratch image, or over RAM without one, would, and
    /// checks the plan against the host, as `SandboxPlan::validated` does. It then verifies the
    /// image explicitly with NVX's `DistroBinding::verify`, which hashes the image only when a
    /// manifest is beside it, checks the binding from metadata, as a launch checks it, so that it
    /// stages no binding that every launch would refuse, and binds the scratch image with NVX's
    /// `ScratchBinding::bind`, which neither reads nor claims it.
    ///
    /// Fails as those do: with [`ErrorKind::Unsupported`](nvx::ErrorKind::Unsupported) for a path
    /// that is not Unicode and for a manifest that does not match the image, with
    /// [`ErrorKind::Unavailable`](nvx::ErrorKind::Unavailable) for an image that is not a regular
    /// file, and with [`ErrorKind::Io`](nvx::ErrorKind::Io) if an image cannot be read or sealed.
    pub fn stage(
        distro: &Path,
        format: ImageFormat,
        identity: Uuid,
        scratch: Option<&Path>,
    ) -> Result<Self> {
        let plan = layered::plan(distro, format, identity, scratch)?;
        let path = plan.distro().path();
        let layer = layered::layer(path, format, identity)?;
        let binding = DistroBinding::verify(&layer)?;
        binding.check(&layer, DISTRO_POLICY_REVISION)?;
        let scratch = match plan.upper().scratch_path() {
            Some(path) => Some(StagedFile {
                path: path.to_owned(),
                binding: ScratchBinding::bind(path)?,
            }),
            None => None,
        };
        Ok(Self {
            distro: StagedFile {
                path: path.to_owned(),
                binding,
            },
            scratch,
        })
    }

    /// Returns the bindings that this record stages for the images of `plan`: the image's, if the
    /// record stages the image at the path of the plan's, and the scratch image's, if the plan's
    /// upper is on a scratch image that the record stages at its path. The paths compare as text,
    /// as a plan normalizes them.
    pub fn bindings(&self, plan: &SandboxPlan) -> Bindings {
        let staged_at = |staged: &Path, planned: &Path| staged.as_os_str() == planned.as_os_str();
        Bindings {
            distro: staged_at(&self.distro.path, plan.distro().path())
                .then(|| self.distro.binding.clone()),
            scratch: self
                .scratch
                .as_ref()
                .zip(plan.upper().scratch_path())
                .filter(|(scratch, planned)| staged_at(&scratch.path, planned))
                .map(|(scratch, _)| scratch.binding.clone()),
        }
    }

    /// Returns the record as JSON.
    ///
    /// Fails with [`ErrorKind::Unsupported`](nvx::ErrorKind::Unsupported) for a path that is not
    /// Unicode, and with [`ErrorKind::Other`](nvx::ErrorKind::Other) if a binding has no JSON
    /// form.
    pub fn to_json(&self) -> Result<Value> {
        let distro = layered::binding_json(serde_json::to_value(&self.distro.binding))?;
        let scratch = match &self.scratch {
            Some(scratch) => file_json(
                &scratch.path,
                layered::binding_json(serde_json::to_value(&scratch.binding))?,
            )?,
            None => Value::Null,
        };
        Ok(json!({
            "format": STAGED_FORMAT,
            "distro": file_json(&self.distro.path, distro)?,
            "scratch": scratch,
        }))
    }

    /// Returns the record whose JSON form, as [`to_json`](Self::to_json) writes it, is `value`.
    ///
    /// Fails with [`ErrorKind::Unavailable`](nvx::ErrorKind::Unavailable) for a record of another
    /// format, an object that lacks a member or has another, a path that is not a string, and a
    /// binding that does not decode, as NVX's bindings decode their serde forms.
    pub fn from_json(value: &Value) -> Result<Self> {
        let [format, distro, scratch] = members(value, ["format", "distro", "scratch"])
            .ok_or_else(|| {
                invalid("is not an object of a format, an image, and a scratch image")
            })?;
        if format.as_u64() != Some(STAGED_FORMAT) {
            return Err(invalid(&format!(
                "has the format {format}, which this build does not read"
            )));
        }
        let (path, binding) = file(distro, "image")?;
        let distro = StagedFile {
            path,
            binding: serde_json::from_value(binding.clone()).map_err(|error| {
                invalid("holds a binding of the image that does not decode").with_source(error)
            })?,
        };
        let scratch = match scratch {
            Value::Null => None,
            scratch => {
                let (path, binding) = file(scratch, "scratch image")?;
                Some(StagedFile {
                    path,
                    binding: serde_json::from_value(binding.clone()).map_err(|error| {
                        invalid("holds a binding of the scratch image that does not decode")
                            .with_source(error)
                    })?,
                })
            }
        };
        Ok(Self { distro, scratch })
    }

    /// Writes the record in `directory`, the sandbox's store, in place of an earlier one.
    ///
    /// Fails as [`to_json`](Self::to_json) does, and with
    /// [`ErrorKind::Io`](nvx::ErrorKind::Io) if the record cannot be written.
    pub fn write(&self, directory: &Path) -> Result<()> {
        layered::write_record(&directory.join(STAGED_NAME), &self.to_json()?)
    }

    /// Reads the record of the images staged in `directory`, the sandbox's store, or returns
    /// `None` if the store has none.
    ///
    /// Fails with [`ErrorKind::Io`](nvx::ErrorKind::Io) if the record cannot be read, and with
    /// [`ErrorKind::Unavailable`](nvx::ErrorKind::Unavailable) if it is not JSON, or
    /// [`from_json`](Self::from_json) refuses it.
    pub fn read(directory: &Path) -> Result<Option<Self>> {
        let path = directory.join(STAGED_NAME);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(Error::io(format!("cannot read {}", path.display())).with_source(error));
            }
        };
        let unreadable = || {
            Error::unavailable(format!(
                "cannot read the record of the staged images {}",
                path.display()
            ))
        };
        let value = serde_json::from_str(&text).map_err(|error| unreadable().with_source(error))?;
        Self::from_json(&value)
            .map(Some)
            .map_err(|error| unreadable().with_source(error))
    }
}

/// Returns the JSON form of a staged file at `path`, whose binding's JSON form is `binding`.
///
/// Fails with [`ErrorKind::Unsupported`](nvx::ErrorKind::Unsupported) for a path that is not
/// Unicode.
fn file_json(path: &Path, binding: Value) -> Result<Value> {
    Ok(json!({"path": layered::unicode(path)?, "binding": binding}))
}

/// Returns the path and the JSON form of the binding of the staged file whose JSON form is
/// `value`, an object of a `path`, a string, and a `binding`, which the record calls `what`.
fn file<'a>(value: &'a Value, what: &str) -> Result<(PathBuf, &'a Value)> {
    let [path, binding] = members(value, ["path", "binding"])
        .ok_or_else(|| invalid(&format!("does not name its {what} by a path and a binding")))?;
    let path = path
        .as_str()
        .ok_or_else(|| invalid(&format!("names its {what} by a path that is not a string")))?;
    Ok((PathBuf::from(path), binding))
}

/// Returns the members `names` of `value`, in their order, if it is an object of those members and
/// no other.
fn members<'a, const N: usize>(value: &'a Value, names: [&str; N]) -> Option<[&'a Value; N]> {
    let object = value.as_object().filter(|object| object.len() == N)?;
    names
        .iter()
        .map(|name| object.get(*name))
        .collect::<Option<Vec<_>>>()?
        .try_into()
        .ok()
}

/// Returns the error of a record in the sandbox's store that is invalid, which `problem` says.
pub(crate) fn invalid(problem: &str) -> Error {
    Error::unavailable(format!("the record {problem}"))
}
