//! Pure planning logic: which live shares to add or remove before an exec, and how to place a
//! host working directory inside the guest. No VM is involved, so it is unit-tested.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub id: String,
    pub host_path: String,
    pub read_only: bool,
    /// The guest path the caller asked for, when it named one. The caller may only get it if
    /// no other session in the shared VM already owns that path.
    pub guest_path: Option<String>,
}

/// Where a mount should appear in the guest: what the caller asked for, or the default rule.
pub fn guest_target_for(mount: &Mount) -> String {
    mount
        .guest_path
        .clone()
        .unwrap_or_else(|| guest_target(&mount.id))
}

/// A share that is live in the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub mount: Mount,
    /// VMM export name; never reused within a sandbox.
    pub child: String,
    pub source_target: String,
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
pub fn relative_to<'a>(path: &'a str, root: &str) -> Option<&'a str> {
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

/// Places a host working directory under a live share, using the path that share was actually
/// exported at.
///
/// A shared VM serves several sessions: a mount belongs to the session that declared it, so a
/// working directory outside every share is not "the workspace" — it may be another session's.
pub fn translate_cwd_shares(host_cwd: &str, shares: &[Share]) -> Option<String> {
    let best = shares
        .iter()
        .filter_map(|share| {
            relative_to(host_cwd, &share.mount.host_path).map(|tail| (share, tail))
        })
        .max_by_key(|(share, _)| share.mount.host_path.len());
    best.map(|(share, tail)| join_guest(&share.target, tail))
}

/// Appends a relative path to a guest path, keeping exactly one separator.
pub fn join_guest(base: &str, tail: &str) -> String {
    let tail = tail.trim_start_matches(['/', '\\']).replace('\\', "/");
    if tail.is_empty() {
        base.to_owned()
    } else {
        format!("{base}/{tail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount(id: &str, path: &str, read_only: bool) -> Mount {
        Mount {
            id: id.into(),
            host_path: path.into(),
            read_only,
            guest_path: None,
        }
    }

    fn share(mount: Mount, child: &str) -> Share {
        let target = guest_target(&mount.id);
        Share {
            mount,
            child: child.into(),
            source_target: target.clone(),
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
    fn working_directories_inside_a_share_use_its_guest_path() {
        let shares = [share(mount("refs", "C:\\Users\\me\\refs", true), "c0")];
        assert_eq!(
            translate_cwd_shares("c:\\users\\ME\\refs", &shares).as_deref(),
            Some("/workspace/mounts/refs")
        );
        assert_eq!(
            translate_cwd_shares("C:\\Users\\me\\refs\\sub\\dir", &shares).as_deref(),
            Some("/workspace/mounts/refs/sub/dir")
        );
        // Outside every share the caller decides, because on a shared VM "outside" may be
        // another session's tree rather than this session's workspace.
        assert_eq!(translate_cwd_shares("C:\\Users\\me\\refs2", &shares), None);
    }

    /// A share exported at a session-scoped path must be used at that path, not at the
    /// default one: otherwise a colliding mount id would send the command into the other
    /// session's directory.
    #[test]
    fn a_session_scoped_share_is_used_at_its_own_path() {
        let shares = [Share {
            mount: mount("same", "C:\\m", true),
            child: "B-m0".into(),
            source_target: "/sessions/B/mounts/same".into(),
            target: "/sessions/B/mounts/same".into(),
        }];        assert_eq!(
            translate_cwd_shares("C:\\m\\sub", &shares).as_deref(),
            Some("/sessions/B/mounts/same/sub")
        );
    }

    #[test]
    fn the_deepest_share_wins() {
        let shares = [
            share(mount("outer", "C:\\x", true), "c0"),
            share(mount("inner", "C:\\x\\y", true), "c1"),
        ];
        assert_eq!(
            translate_cwd_shares("C:\\x\\y\\z", &shares).as_deref(),
            Some("/workspace/mounts/inner/z")
        );
    }

    #[test]
    fn joining_a_guest_path_keeps_one_separator() {
        assert_eq!(join_guest("/sessions/A/workspace", ""), "/sessions/A/workspace");
        assert_eq!(
            join_guest("/sessions/A/workspace", "sub\\dir"),
            "/sessions/A/workspace/sub/dir"
        );
        assert_eq!(
            join_guest("/sessions/A/workspace", "sub/dir"),
            "/sessions/A/workspace/sub/dir"
        );
    }
}
