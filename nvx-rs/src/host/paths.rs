//! Host paths, which `std::path` holds: how the sandbox launch profile and the CLI spell them, make
//! them absolute, and resolve their links.
//!
//! - [`normalized`] spells a path with its components alone, as [`Path::components`] reads them:
//!   without repeated separators, without `.` components but a leading one, and without a trailing
//!   separator, with the separator of the host between components, `\` on Windows. Every component
//!   that `components` reads stays, `..` ones included, and on Windows the `.` ones of a path with
//!   a verbatim prefix, `\\?\`, which [`PathBuf::push`] would remove from such a path.
//! - [`absolute`] is the one function that makes a host path absolute. It joins a relative path to
//!   the current directory, as [`absolute_in`] joins it to a directory, without consulting the
//!   filesystem, so it resolves neither links nor `..` components, even below a directory with a
//!   verbatim prefix, and an absolute path stays as it is. On Windows, a path with a drive and no root, such as `D:relative`, names a path below
//!   the directory if the drive is the directory's own, and otherwise below the current directory
//!   of its drive, which the process keeps for each drive, as [`std::path::absolute`] gives it.
//! - [`resolve`] makes a path absolute, resolves the links of its longest existing prefix as
//!   [`std::fs::canonicalize`] resolves them, and appends the rest. On Windows, it drops the
//!   verbatim prefix `\\?\` that `canonicalize` gives, and turns `\\?\UNC\` into `\\`, unless only
//!   the verbatim path names the object, as for a name that ends in a period or a space.
//!
//! Host paths that are not valid Unicode are refused, as [`text`] refuses them, since the CLI
//! records them as JSON strings and messages name them.

use std::ffi::OsString;
use std::io;
use std::path::{Component, MAIN_SEPARATOR_STR, Path, PathBuf, Prefix};

/// Returns the error for an operating-system string, which messages call `what`, that is not
/// valid Unicode.
pub(crate) fn not_unicode(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{what} is not valid Unicode"),
    )
}

/// Returns `path` as text, or fails as [`not_unicode`] does.
pub(crate) fn text(path: &Path) -> io::Result<&str> {
    path.to_str()
        .ok_or_else(|| not_unicode(&format!("the path {}", path.display())))
}

/// Returns `path` spelled with its components alone, as the module describes.
pub(crate) fn normalized(path: &Path) -> PathBuf {
    spelled(path.components())
}

/// Returns the path of `components`, separated as [`PathBuf::push`] separates them, but each of
/// them kept: `push` removes the `.` and `..` components that it appends to a path with a verbatim
/// prefix.
fn spelled<'a>(components: impl IntoIterator<Item = Component<'a>>) -> PathBuf {
    let mut text = OsString::new();
    let mut separated = true;
    for component in components {
        if !separated && component != Component::RootDir {
            text.push(MAIN_SEPARATOR_STR);
        }
        text.push(component.as_os_str());
        separated = match component {
            Component::RootDir => true,
            // A drive's relative path follows the drive at once, as in `C:relative`.
            Component::Prefix(prefix) => matches!(prefix.kind(), Prefix::Disk(_)),
            Component::CurDir | Component::ParentDir | Component::Normal(_) => false,
        };
    }
    PathBuf::from(text)
}

/// Returns the current directory, which must be valid Unicode.
pub(crate) fn current_dir() -> io::Result<PathBuf> {
    let directory = std::env::current_dir()?;
    text(&directory)?;
    Ok(directory)
}

/// Returns `path` absolute, joined to the current directory if it is relative, as the module
/// describes.
pub(crate) fn absolute(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    absolute_in(&current_dir()?, path)
}

/// Returns `path` absolute, joined to `directory`, an absolute directory, if it is relative, as
/// [`absolute`] joins it to the current directory.
pub(crate) fn absolute_in(directory: &Path, path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut components = path.components();
    // A relative path's only prefix is a drive, as in `D:relative`.
    #[cfg(windows)]
    if let Some(letter) = drive(path) {
        if drive(directory) != Some(letter) {
            return std::path::absolute(path);
        }
        components.next();
    }
    Ok(appended(directory, components))
}

/// Returns `directory` with `components`, the components of a path without a prefix, after it: a
/// root keeps the prefix of `directory` alone, as [`PathBuf::push`] keeps it, and the other
/// components follow as they are, `.` and `..` ones included, as [`spelled`] spells them.
fn appended<'a>(directory: &'a Path, components: impl Iterator<Item = Component<'a>>) -> PathBuf {
    let mut joined: Vec<Component<'a>> = directory.components().collect();
    for component in components {
        if component == Component::RootDir {
            joined.retain(|kept| matches!(kept, Component::Prefix(_)));
        }
        joined.push(component);
    }
    spelled(joined)
}

/// Returns the drive letter of `path`, in uppercase, if `path` starts with a drive, as `C:` or
/// `\\?\C:` do.
#[cfg(windows)]
fn drive(path: &Path) -> Option<u8> {
    match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                Some(letter.to_ascii_uppercase())
            }
            _ => None,
        },
        _ => None,
    }
}

/// Returns `path` absolute, with the links of its longest existing prefix resolved, as the module
/// describes.
///
/// Fails as [`std::fs::canonicalize`] fails for a prefix for another reason than that it does not
/// exist, and as [`text`] fails for a resolved path that is not valid Unicode.
pub(crate) fn resolve(path: &Path) -> io::Result<PathBuf> {
    let absolute = absolute(path)?;
    let mut existing = absolute.as_path();
    let mut missing = Vec::new();
    loop {
        match std::fs::canonicalize(existing) {
            Ok(resolved) => {
                let mut resolved = without_verbatim_prefix(resolved);
                resolved.extend(missing.iter().rev());
                text(&resolved)?;
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) else {
                    return Err(error);
                };
                missing.push(name);
                existing = parent;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Returns `path`, which [`std::fs::canonicalize`] gave, without its verbatim prefix, unless only
/// the verbatim path names the object that it names.
#[cfg(windows)]
fn without_verbatim_prefix(path: PathBuf) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path;
    };
    let plain = match text.strip_prefix(r"\\?\") {
        Some(rest) => match rest.strip_prefix(r"UNC\") {
            Some(share) => format!(r"\\{share}"),
            None => rest.to_owned(),
        },
        None => return path,
    };
    if std::fs::canonicalize(&plain).is_ok_and(|again| again == path) {
        PathBuf::from(plain)
    } else {
        path
    }
}

/// Returns `path` as it is: hosts other than Windows have no verbatim prefix.
#[cfg(not(windows))]
fn without_verbatim_prefix(path: PathBuf) -> PathBuf {
    path
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// Returns `path` with `/` as the separator of the host.
    fn native(path: &str) -> PathBuf {
        PathBuf::from(path.replace('/', std::path::MAIN_SEPARATOR_STR))
    }

    #[test]
    fn paths_are_spelled_with_their_components() {
        for (path, expected) in [
            ("a//b", "a/b"),
            ("a/./b/.", "a/b"),
            ("a/b/", "a/b"),
            ("./a", "./a"),
            ("../a", "../a"),
            ("a/../b", "a/../b"),
            ("/a//b", "/a/b"),
        ] {
            let spelled = normalized(Path::new(path));
            assert_eq!(
                spelled.as_os_str(),
                native(expected).as_os_str(),
                "{path:?}"
            );
        }
        #[cfg(windows)]
        for (path, expected) in [
            ("C:/a//b", r"C:\a\b"),
            (r"\\server\share", r"\\server\share\"),
            (r"\\?\C:\a\work.", r"\\?\C:\a\work."),
            ("D:relative", "D:relative"),
            // `PathBuf::push` would remove these components of a path with a verbatim prefix.
            (r"\\?\C:\base\link\..\share", r"\\?\C:\base\link\..\share"),
            (r"\\?\C:\base\.\share", r"\\?\C:\base\.\share"),
        ] {
            assert_eq!(
                normalized(Path::new(path)).as_os_str(),
                expected,
                "{path:?}"
            );
        }
    }

    #[test]
    fn relative_paths_join_the_directory_without_resolving_anything() {
        let directory = native("/fixture/cwd");
        let directory = absolute(&directory).unwrap();
        for (path, expected) in [
            ("link/share", directory.join("link").join("share")),
            (
                "link/../share",
                directory.join("link").join("..").join("share"),
            ),
        ] {
            assert_eq!(
                absolute_in(&directory, &native(path)).unwrap(),
                expected,
                "{path}"
            );
        }
        let absolute_path = directory.join("elsewhere");
        assert_eq!(
            absolute_in(&native("/other"), &absolute_path).unwrap(),
            absolute_path
        );
        assert_eq!(
            absolute(Path::new("relative")).unwrap(),
            std::env::current_dir().unwrap().join("relative")
        );
    }

    #[cfg(windows)]
    #[test]
    fn drive_relative_paths_are_below_the_directory_on_its_drive() {
        let current = std::env::current_dir().unwrap();
        let Some(letter) = drive(&current).map(char::from) else {
            // A current directory on a share has no drive of its own to compare.
            return;
        };
        // A directory on the current directory's drive that is not the current directory, as a
        // share's root is.
        let root = PathBuf::from(format!(r"{letter}:\fixture\share"));
        let lower = letter.to_ascii_lowercase();
        for (path, expected) in [
            (format!("{letter}:secret"), root.join("secret")),
            (
                format!(r"{lower}:secret\deeper"),
                root.join("secret").join("deeper"),
            ),
            (format!("{letter}:"), root.clone()),
        ] {
            assert_eq!(
                absolute_in(&root, Path::new(&path)).unwrap(),
                expected,
                "{path}"
            );
        }
        let verbatim = PathBuf::from(format!(r"\\?\{letter}:\fixture\share"));
        assert_eq!(
            absolute_in(&verbatim, Path::new(&format!("{letter}:secret"))).unwrap(),
            verbatim.join("secret")
        );
        // Another drive's path is below the current directory of that drive.
        let other = if letter == 'Q' { 'R' } else { 'Q' };
        let elsewhere = format!("{other}:secret");
        assert_eq!(
            absolute_in(&root, Path::new(&elsewhere)).unwrap(),
            std::path::absolute(&elsewhere).unwrap()
        );
        // The current directory is below its own drive's.
        assert_eq!(
            absolute(Path::new(&format!("{letter}:relative"))).unwrap(),
            current.join("relative")
        );
    }

    #[cfg(windows)]
    #[test]
    fn verbatim_directories_keep_the_components_after_them() {
        let directory = Path::new(r"\\?\C:\base");
        for (path, expected) in [
            (r"link\..\share", r"\\?\C:\base\link\..\share"),
            (r".\share", r"\\?\C:\base\.\share"),
            (r"C:link\..\share", r"\\?\C:\base\link\..\share"),
            (r"\rooted\..\x", r"\\?\C:\rooted\..\x"),
        ] {
            let joined = absolute_in(directory, Path::new(path)).unwrap();
            assert_eq!(joined.as_os_str(), expected, "{path}");
        }
    }

    #[test]
    fn resolution_follows_links_and_keeps_missing_components() {
        let directory = tempfile::tempdir().unwrap();
        let root = resolve(directory.path()).unwrap();
        assert!(root.is_absolute());
        let target = root.join("target");
        fs::create_dir(&target).unwrap();
        assert_eq!(resolve(&target).unwrap(), target);
        assert_eq!(
            resolve(&root.join("missing").join("deeper")).unwrap(),
            root.join("missing").join("deeper")
        );
        assert_eq!(
            resolve(&root.join("target").join("..").join("target")).unwrap(),
            target
        );
        let link = root.join("link");
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&target, &link);
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_dir(&target, &link);
        if linked.is_ok() {
            assert_eq!(resolve(&link).unwrap(), target);
            assert_eq!(resolve(&link.join("child")).unwrap(), target.join("child"));
        }
    }

    #[cfg(windows)]
    #[test]
    fn resolution_keeps_the_verbatim_path_that_alone_names_the_object() {
        let directory = tempfile::tempdir().unwrap();
        let verbatim = fs::canonicalize(directory.path()).unwrap();
        assert!(verbatim.to_str().unwrap().starts_with(r"\\?\"));
        let root = resolve(directory.path()).unwrap();
        assert!(!root.to_str().unwrap().starts_with(r"\\?\"), "{root:?}");
        // Windows drops the trailing period of a name in a path without the verbatim prefix.
        let dotted = PathBuf::from(format!(r"{}\work.", verbatim.display()));
        fs::create_dir(&dotted).unwrap();
        assert_eq!(resolve(&dotted).unwrap(), dotted);
    }
}
