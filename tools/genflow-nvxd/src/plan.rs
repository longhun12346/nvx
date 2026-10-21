//! Pure planning logic: which live shares to add or remove before an exec, and how to place a
//! host working directory inside the guest. No VM is involved, so it is unit-tested.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub id: String,
    pub host_path: String,
    pub read_only: bool,
}

/// A share that is live in the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub mount: Mount,
    /// VMM export name; never reused within a sandbox.
    pub child: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Remove(Share),
    Add(Mount),
}

pub fn guest_target(mount_id: &str) -> String {
    format!("/workspace/mounts/{mount_id}")
}

/// Removals come first so that a mount whose id was reused for another directory is replaced,
/// and so that capacity is released before it is needed.
pub fn plan(current: &[Share], desired: &[Mount]) -> Vec<Step> {
    let mut steps = Vec::new();
    for share in current {
        if !desired.contains(&share.mount) {
            steps.push(Step::Remove(share.clone()));
        }
    }
    for mount in desired {
        if !current.iter().any(|share| &share.mount == mount) {
            steps.push(Step::Add(mount.clone()));
        }
    }
    steps
}

fn normalize(path: &str) -> String {
    let mut text = path.replace('\\', "/").to_lowercase();
    while text.len() > 1 && text.ends_with('/') {
        text.pop();
    }
    text
}

/// Returns the part of `path` below `root`, or `None` if `path` is not inside `root`.
fn relative_to<'a>(path: &'a str, root: &str) -> Option<&'a str> {
    let (norm_path, norm_root) = (normalize(path), normalize(root));
    if norm_path == norm_root {
        return Some("");
    }
    let prefix = format!("{norm_root}/");
    if norm_path.starts_with(&prefix) {
        // `normalize` keeps byte lengths for ASCII; fall back to None otherwise.
        let tail = path.get(prefix.len()..)?;
        return Some(tail.trim_start_matches(['/', '\\']));
    }
    None
}

/// Places a host working directory in the guest: inside a live mount it becomes the mount's
/// guest path plus the remainder; anything else goes through `main`, the translation of the
/// primary workspace.
pub fn translate_cwd(
    host_cwd: &str,
    mounts: &[Mount],
    main: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    let best = mounts
        .iter()
        .filter_map(|mount| relative_to(host_cwd, &mount.host_path).map(|tail| (mount, tail)))
        .max_by_key(|(mount, _)| mount.host_path.len());
    if let Some((mount, tail)) = best {
        let base = guest_target(&mount.id);
        return Some(if tail.is_empty() {
            base
        } else {
            format!("{base}/{}", tail.replace('\\', "/"))
        });
    }
    main(host_cwd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount(id: &str, path: &str, read_only: bool) -> Mount {
        Mount {
            id: id.into(),
            host_path: path.into(),
            read_only,
        }
    }

    fn share(mount: Mount, child: &str) -> Share {
        let target = guest_target(&mount.id);
        Share {
            mount,
            child: child.into(),
            target,
        }
    }

    #[test]
    fn nothing_to_do_when_the_sets_match() {
        let current = [share(mount("a", "C:\\a", true), "m0")];
        assert!(plan(&current, &[mount("a", "C:\\a", true)]).is_empty());
    }

    #[test]
    fn additions_and_removals_are_planned_removals_first() {
        let current = [share(mount("old", "C:\\old", true), "m0")];
        let desired = [mount("new", "C:\\new", false)];
        assert_eq!(
            plan(&current, &desired),
            vec![
                Step::Remove(current[0].clone()),
                Step::Add(desired[0].clone())
            ]
        );
    }

    #[test]
    fn a_changed_mode_or_directory_replaces_the_share() {
        let current = [share(mount("a", "C:\\a", true), "m0")];
        for changed in [mount("a", "C:\\a", false), mount("a", "C:\\b", true)] {
            let steps = plan(&current, std::slice::from_ref(&changed));
            assert_eq!(
                steps,
                vec![Step::Remove(current[0].clone()), Step::Add(changed)]
            );
        }
    }

    #[test]
    fn working_directories_inside_a_mount_use_its_guest_path() {
        let mounts = [mount("refs", "C:\\Users\\me\\refs", true)];
        let main = |path: &str| Some(format!("main:{path}"));
        assert_eq!(
            translate_cwd("c:\\users\\ME\\refs", &mounts, main).as_deref(),
            Some("/workspace/mounts/refs")
        );
        assert_eq!(
            translate_cwd("C:\\Users\\me\\refs\\sub\\dir", &mounts, main).as_deref(),
            Some("/workspace/mounts/refs/sub/dir")
        );
        assert_eq!(
            translate_cwd("C:\\Users\\me\\refs2", &mounts, main).as_deref(),
            Some("main:C:\\Users\\me\\refs2")
        );
    }

    #[test]
    fn the_deepest_mount_wins() {
        let mounts = [
            mount("outer", "C:\\x", true),
            mount("inner", "C:\\x\\y", true),
        ];
        assert_eq!(
            translate_cwd("C:\\x\\y\\z", &mounts, |_| None).as_deref(),
            Some("/workspace/mounts/inner/z")
        );
    }
}
