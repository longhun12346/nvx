//! The shares of an export plan in the form that a launch delivers at boot, and the bootstrap
//! tokens that OpenVMM appends to the kernel command line for them.

use std::path::Path;

use super::request::command_line_fragment;
use super::{
    AGGREGATE_COMMAND_LINE_SUFFIX, AGGREGATE_MOUNT_TARGET, MountAccess, MountKind, MountOwner,
    PolicyKind, aggregate_child_argument, aggregate_child_name, mount_argument,
    validate_mount_target,
};
use crate::error::Result;
use crate::host::filesystem::{ExportPlan, GUEST_EXPORT, Owner};
use crate::host::sandbox::refused;

/// The form in which a launch delivers an export plan at boot: OpenVMM's arguments that attach
/// its directories and files, the kernel parameters that the plan adds for them, and the
/// bootstrap tokens that OpenVMM appends to the kernel command line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootShares {
    /// OpenVMM's arguments: one directory share or an aggregate with its children, in order, the
    /// access-policy paths of each, absolute, and the owner unless it is `vmm`.
    pub arguments: Vec<String>,
    /// The kernel parameters: as [`boot_shares`] renders them, the `nvx_share=` tokens of an
    /// aggregate, one for each child, in order, and none for one directory share; for a mapping
    /// table, the `nvx_maps=` token of its number of mappings.
    pub tokens: Vec<String>,
    /// The bootstrap tokens that OpenVMM appends after the kernel command line.
    pub fragment: String,
}

/// Renders `plan` in the form that the guest's shell reads at boot.
///
/// The shell binds each exported directory or file at one target, so every child of the plan
/// must be mapped exactly once, at its root, with the access with which OpenVMM exports it, at a
/// target that [`validate_mount_target`] accepts.
/// One directory then uses OpenVMM's virtio-fs device directly, and anything else shares it as
/// the children of an aggregate, named by [`aggregate_child_name`].
///
/// Fails with [`ErrorKind::Unsupported`](crate::ErrorKind::Unsupported) for a plan that the boot
/// tokens cannot express, such as one that maps a path below a share's root, rather than extend
/// what the shell reads.
pub fn boot_shares(plan: &ExportPlan) -> Result<BootShares> {
    let mut shares = Vec::with_capacity(plan.children.len());
    for (index, child) in plan.children.iter().enumerate() {
        let root = path_text(&child.root)?;
        let binds: Vec<_> = plan
            .binds
            .iter()
            .filter(|bind| bind.child == index)
            .collect();
        let bind = match binds[..] {
            [bind] if bind.source.is_empty() => bind,
            [bind] => {
                return Err(refused(format!(
                    "the boot tokens of a share cannot map {}, a path below the share's root {root}",
                    child.root.join(&bind.source).display()
                )));
            }
            _ => {
                return Err(refused(format!(
                    "the boot tokens of a share map {root} at one target, not {}",
                    binds.len()
                )));
            }
        };
        validate_mount_target(&bind.target)?;
        // The tokens mount a share with the access with which OpenVMM exports it, so a bind of
        // another access, such as a read-only bind of a directory whose writes OpenVMM narrows to
        // a path inside it, would let the guest write what the plan keeps read-only.
        if bind.read_only == child.writable {
            let (bound, exported) = if child.writable {
                ("read-only", "read-write")
            } else {
                ("read-write", "read-only")
            };
            return Err(refused(format!(
                "the boot tokens of a share cannot map {root} {bound} while OpenVMM exports it \
                 {exported}"
            )));
        }
        let access = if child.writable {
            MountAccess::ReadWrite
        } else {
            MountAccess::ReadOnly
        };
        shares.push((child, root, bind.target.as_str(), access));
    }
    if plan.binds.len() != shares.len() {
        return Err(refused(
            "the boot tokens of a share cannot map a path of an unknown host directory",
        ));
    }
    let mut boot = BootShares::default();
    match shares[..] {
        [] => return Ok(boot),
        [(child, root, target, access)] if !child.file => {
            boot.arguments = vec!["--mount".to_owned(), mount_argument(target, root, access)];
            boot.fragment = command_line_fragment(target, access);
        }
        _ => {
            boot.arguments = vec![
                "--mount-aggregate".to_owned(),
                AGGREGATE_MOUNT_TARGET.to_owned(),
            ];
            for (index, &(child, root, target, access)) in shares.iter().enumerate() {
                let name = aggregate_child_name(index, target);
                let (kind, file) = if child.file {
                    (MountKind::File, ",file")
                } else {
                    (MountKind::Directory, "")
                };
                boot.arguments.push("--mount-child".to_owned());
                boot.arguments
                    .push(aggregate_child_argument(&name, root, access, kind));
                boot.tokens
                    .push(format!("nvx_share={name},{target},{access}{file}"));
            }
            let accesses: Vec<MountAccess> =
                shares.iter().map(|&(_, _, _, access)| access).collect();
            boot.fragment = aggregate_command_line_fragment(&accesses);
        }
    }
    for &(child, ..) in &shares {
        for (kind, paths) in [
            (PolicyKind::Denied, &child.denied),
            (PolicyKind::Allowed, &child.allowed),
            (PolicyKind::Writable, &child.write),
        ] {
            for path in paths {
                boot.arguments.push(kind.option().to_owned());
                boot.arguments.push(path_text(path)?.to_owned());
            }
        }
    }
    if plan.owner == Owner::Caller {
        boot.arguments.push("--mount-owner".to_owned());
        boot.arguments.push(MountOwner::Caller.as_str().to_owned());
    }
    Ok(boot)
}

/// Returns the text of a host path of an export plan, which OpenVMM's options carry.
///
/// Fails with [`ErrorKind::Unsupported`](crate::ErrorKind::Unsupported) for a path that is not
/// valid UTF-8.
pub(super) fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| refused(format!("{} is not valid UTF-8", path.display())))
}

/// Returns the kernel command-line tokens that tell the guest where to bind each child of an
/// aggregate, given each share's guest target, access, and kind. A file child's token ends in
/// `,file`, so the guest binds it at a file.
pub fn aggregate_share_tokens(shares: &[(&str, MountAccess, MountKind)]) -> Vec<String> {
    shares
        .iter()
        .enumerate()
        .map(|(index, &(target, access, kind))| {
            let file = if kind == MountKind::File { ",file" } else { "" };
            format!(
                "nvx_share={},{target},{access}{file}",
                aggregate_child_name(index, target)
            )
        })
        .collect()
}

/// Returns the bootstrap tokens that OpenVMM appends for an aggregate of shares with
/// `accesses`, which it mounts read-write if any child is.
pub fn aggregate_command_line_fragment(accesses: &[MountAccess]) -> String {
    aggregate_fragment(AGGREGATE_MOUNT_TARGET, accesses)
}

/// Returns the bootstrap tokens that OpenVMM appends for the export of `plan` at
/// [`GUEST_EXPORT`], the aggregate from which a managed sandbox's guest agent maps the plan's
/// mapping table.
pub(crate) fn export_command_line_fragment(plan: &ExportPlan) -> String {
    let accesses: Vec<MountAccess> = plan
        .children
        .iter()
        .map(|child| {
            if child.writable {
                MountAccess::ReadWrite
            } else {
                MountAccess::ReadOnly
            }
        })
        .collect();
    aggregate_fragment(GUEST_EXPORT, &accesses)
}

/// Returns the bootstrap tokens that OpenVMM appends for an aggregate at `target` whose children
/// have `accesses`, which it mounts read-write if any child is.
fn aggregate_fragment(target: &str, accesses: &[MountAccess]) -> String {
    let access = if accesses.contains(&MountAccess::ReadWrite) {
        MountAccess::ReadWrite
    } else {
        MountAccess::ReadOnly
    };
    command_line_fragment(target, access) + AGGREGATE_COMMAND_LINE_SUFFIX
}
