use std::ffi::{CStr, CString};

use crate::guest::entry::Prepared;
use crate::guest::parse::parse_decimal;
use crate::guest::spawn::Command;
use crate::guest::sys::{self, Errno, FileDescriptor, Mode, OpenFlags, c_string};
use crate::protocol::GuestExecPayload;

use super::AgentConfig;
use super::environment;
use super::seam::{Paths, path_c_string};

/// One workload's launch inputs: its borrowed request, and the descriptors that its child takes.
pub(crate) struct LaunchRequest<'a> {
    /// Agent mode and configured workload identity.
    pub(crate) config: &'a AgentConfig,
    /// Decoded workload request.
    pub(crate) execution: &'a GuestExecPayload,
    /// Writer of the workload's standard output.
    pub(crate) stdout: FileDescriptor,
    /// Writer of the workload's standard error.
    pub(crate) stderr: FileDescriptor,
}

/// Builds the command that launches one workload of the direct agent.
///
/// The workload's standard input is the null device, its standard output and error are the
/// request's pipes, the sealed configuration `config_fd` stays open at its descriptor number, and
/// the child leads a new process group. It runs `setpriv`, which takes the workload's identity
/// and runs the helper; the child first joins the execution cgroup, then enters the working
/// directory as the workload and records the physical path in `PWD` for a noncanonical name. The
/// helper then applies the request's environment entries.
pub(crate) fn direct_command(
    paths: &Paths,
    request: LaunchRequest<'_>,
    config_fd: FileDescriptor,
) -> Result<Command, Errno> {
    let config = request.config;
    let directory = working_directory(request.execution)?;
    let uid = parse_id(config.uid.as_bytes())?;
    let gid = parse_id(config.gid.as_bytes())?;
    let helper = path_c_string(&paths.helper)?;
    let setpriv = path_c_string(&paths.setpriv)?;
    let config_argument = config_fd.argument();
    let mut arguments = Vec::new();
    for value in [
        b"setpriv".as_slice(),
        b"--reuid",
        config.uid.as_bytes(),
        b"--regid",
        config.gid.as_bytes(),
        b"--clear-groups",
        b"--no-new-privs",
        b"--bounding-set=-all",
        b"--inh-caps=-all",
        b"--ambient-caps=-all",
        helper.as_bytes(),
        b"--exec-config-fd",
        config_argument.as_bytes(),
        b"--",
    ] {
        arguments.push(c_string(value)?);
    }
    for argument in &request.execution.argv {
        arguments.push(c_string(argument)?);
    }
    let (environment, physical_pwd) = defaults(config, request.execution, &directory)?;
    let cgroup = super::cgroup::placement(paths)?;
    let mut command = Command::new(setpriv, arguments)
        .environment(environment)
        .stdin(null_device(paths)?)
        .stdout(request.stdout)
        .stderr(request.stderr)
        .inherit(config_fd)
        .new_process_group()
        .working_directory(directory)
        .check_working_directory_as(uid, gid)
        .cgroup(cgroup);
    if physical_pwd {
        command = command.export_physical_working_directory();
    }
    Ok(command)
}

/// Builds the command that launches one workload of the sandbox agent, which enters `prepared`.
///
/// The workload's standard input is the null device, and its standard output and error are the
/// request's pipes. The child waits at its barrier until the agent has placed it in its cgroup,
/// and then enters the execution, as the first process of its PID namespace and the leader of a
/// new session, enters the working directory as the workload, records the physical path in `PWD`
/// for a noncanonical name, and runs the workload itself. The agent builds the environment as the
/// direct agent and its helper do: its own, with the workload's `HOME`, `USER`, `LOGNAME`, and
/// `PWD`, and then the request's entries in order, which replace it unless they layer over it.
pub(crate) fn sandbox_command(
    paths: &Paths,
    request: LaunchRequest<'_>,
    prepared: Prepared,
) -> Result<Command, Errno> {
    let execution = request.execution;
    let directory = working_directory(execution)?;
    let (mut environment, mut physical_pwd) = defaults(request.config, execution, &directory)?;
    if let Some(entries) = &execution.environment {
        if !execution.inherit_default_env {
            environment.clear();
        }
        for entry in entries {
            let equals = entry
                .iter()
                .position(|&byte| byte == b'=')
                .ok_or(Errno::EINVAL)?;
            let (name, value) = (&entry[..equals], &entry[equals + 1..]);
            // An entry's `PWD` replaces the physical path, as it replaced the helper's.
            physical_pwd &= name != b"PWD";
            environment::set(&mut environment, name, value)?;
        }
    }
    let arguments = execution
        .argv
        .iter()
        .map(|argument| c_string(argument))
        .collect::<Result<Vec<_>, _>>()?;
    let program = arguments.first().cloned().ok_or(Errno::EINVAL)?;
    let mut command = Command::new(program, arguments)
        .environment(environment)
        .stdin(null_device(paths)?)
        .stdout(request.stdout)
        .stderr(request.stderr)
        .working_directory(directory)
        .barrier()
        .enter(prepared);
    if physical_pwd {
        command = command.export_physical_working_directory();
    }
    Ok(command)
}

/// Returns the request's working directory, or `/` without one.
fn working_directory(execution: &GuestExecPayload) -> Result<CString, Errno> {
    c_string(execution.cwd.as_deref().unwrap_or(b"/"))
}

/// Opens the null device, the workload's standard input.
fn null_device(paths: &Paths) -> Result<FileDescriptor, Errno> {
    sys::open(
        &path_c_string(&paths.null_device)?,
        OpenFlags::O_RDONLY | OpenFlags::O_CLOEXEC,
        Mode::empty(),
    )
}

/// Returns the agent's environment with the workload's `HOME`, `USER`, and `LOGNAME`, and, unless
/// the request replaces the environment, its `PWD`: the name of the working directory `directory`
/// when it is canonical, and otherwise a placeholder whose place the directory's physical path
/// takes once the child has entered it, which the returned flag asks for.
fn defaults(
    config: &AgentConfig,
    execution: &GuestExecPayload,
    directory: &CStr,
) -> Result<(Vec<CString>, bool), Errno> {
    let mut environment = environment::inherited()?;
    environment::set(&mut environment, b"HOME", config.home.as_bytes())?;
    environment::set(&mut environment, b"USER", config.user.as_bytes())?;
    environment::set(&mut environment, b"LOGNAME", config.user.as_bytes())?;
    let mut physical_pwd = false;
    if execution.environment.is_none() || execution.inherit_default_env {
        let directory = directory.to_bytes();
        environment::set(&mut environment, b"PWD", directory)?;
        physical_pwd = directory != b"/" && !safe_path(directory);
    }
    Ok((environment, physical_pwd))
}

/// Returns whether an absolute path has only canonical nonempty components.
pub(crate) fn safe_path(path: &[u8]) -> bool {
    let Some(components) = path.strip_prefix(b"/") else {
        return false;
    };
    !components.is_empty()
        && components
            .split(|&byte| byte == b'/')
            .all(|component| !matches!(component, b"" | b"." | b".."))
}

/// Parses one nonzero decimal UID or GID while excluding the unchanged-ID sentinel.
pub(super) fn parse_id(text: &[u8]) -> Result<u32, Errno> {
    parse_decimal(text)
        .filter(|&id| id != 0 && id < u64::from(u32::MAX))
        .and_then(|id| u32::try_from(id).ok())
        .ok_or(Errno::EINVAL)
}
#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use crate::guest::spawn::LaunchStage;
    use crate::guest::sys::PreparedChild;
    use crate::protocol::GuestExecPayload;

    use super::*;

    fn config(direct: bool) -> AgentConfig {
        AgentConfig {
            rootfs: CString::new(if direct { "-" } else { "/rootfs" }).unwrap(),
            hostname: c"sandbox".to_owned(),
            uid: c"1000".to_owned(),
            gid: c"1001".to_owned(),
            user: c"workload".to_owned(),
            home: c"/home/workload".to_owned(),
            direct,
            entry: None,
        }
    }

    fn execution() -> GuestExecPayload {
        GuestExecPayload {
            timeout_ms: 0,
            argv: vec![b"/bin/echo".to_vec(), b"ok".to_vec()],
            cwd: Some(b"/work".to_vec()),
            environment: None,
            inherit_default_env: false,
        }
    }

    fn descriptor() -> FileDescriptor {
        FileDescriptor::from_owned(tempfile::tempfile().unwrap().into())
    }

    fn request<'a>(config: &'a AgentConfig, execution: &'a GuestExecPayload) -> LaunchRequest<'a> {
        LaunchRequest {
            config,
            execution,
            stdout: descriptor(),
            stderr: descriptor(),
        }
    }

    /// Returns a direct agent's paths, whose cgroup root, in `directory`, holds `nvx-exec`.
    fn direct_paths(directory: &std::path::Path) -> Paths {
        std::fs::create_dir(directory.join("nvx-exec")).unwrap();
        std::fs::write(directory.join("nvx-exec/cgroup.procs"), b"").unwrap();
        Paths {
            cgroup_root: directory.to_owned(),
            setpriv: "/test/setpriv".into(),
            helper: "/test/nvx-managed-agent".into(),
            ..Paths::default()
        }
    }

    /// Prepares the child that launches `execution` with the direct agent's `config`, and
    /// returns it with the number of its sealed configuration descriptor.
    fn prepare_direct(
        paths: &Paths,
        config: &AgentConfig,
        execution: &GuestExecPayload,
    ) -> (PreparedChild, CString) {
        let config_fd = descriptor();
        let argument = config_fd.argument();
        let command = direct_command(paths, request(config, execution), config_fd).unwrap();
        (command.prepare(), argument)
    }

    /// Prepares the child that launches `execution` with the sandbox agent's configuration.
    fn prepare_sandbox(execution: &GuestExecPayload) -> PreparedChild {
        let config = config(false);
        let prepared = Prepared::simulated(None);
        sandbox_command(&Paths::default(), request(&config, execution), prepared)
            .unwrap()
            .prepare()
    }

    fn strings(strings: &[CString]) -> Vec<&[u8]> {
        strings.iter().map(|string| string.to_bytes()).collect()
    }

    #[test]
    fn direct_launch_uses_setpriv_and_clears_every_capability_set() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = direct_paths(temporary.path());
        let config = config(true);
        let execution = execution();
        let (plan, descriptor_argument) = prepare_direct(&paths, &config, &execution);
        assert_eq!(
            strings(plan.arguments()),
            [
                b"setpriv".as_slice(),
                b"--reuid",
                b"1000",
                b"--regid",
                b"1001",
                b"--clear-groups",
                b"--no-new-privs",
                b"--bounding-set=-all",
                b"--inh-caps=-all",
                b"--ambient-caps=-all",
                b"/test/nvx-managed-agent",
                b"--exec-config-fd",
                descriptor_argument.as_bytes(),
                b"--",
                b"/bin/echo",
                b"ok",
            ]
        );
        assert_eq!(plan.program().as_bytes(), b"/test/setpriv");
        let environment = strings(plan.environment());
        for expected in [
            b"HOME=/home/workload".as_slice(),
            b"USER=workload",
            b"LOGNAME=workload",
            b"PWD=/work",
        ] {
            assert!(environment.contains(&expected), "{expected:?}");
        }
        assert!(plan.has_cgroup());
        assert_eq!(plan.barrier_entry_and_session(), (false, false, false));
    }

    #[test]
    fn sandbox_launch_runs_the_workload_itself_through_its_entry() {
        let plan = prepare_sandbox(&execution());
        assert_eq!(plan.program().as_bytes(), b"/bin/echo");
        assert_eq!(strings(plan.arguments()), [b"/bin/echo".as_slice(), b"ok"]);
        let environment = strings(plan.environment());
        for expected in [
            b"HOME=/home/workload".as_slice(),
            b"USER=workload",
            b"LOGNAME=workload",
            b"PWD=/work",
        ] {
            assert!(environment.contains(&expected), "{expected:?}");
        }
        assert!(plan.physical_pwd().is_none());
        // The agent places the child at its barrier, so the child joins no cgroup itself.
        assert!(!plan.has_cgroup());
        assert_eq!(plan.barrier_entry_and_session(), (true, true, true));
    }

    #[test]
    fn sandbox_launch_applies_exact_and_layered_environments_in_order() {
        let exact = GuestExecPayload {
            environment: Some(vec![b"EMPTY=".to_vec(), b"VALUE=a=b".to_vec()]),
            ..execution()
        };
        let plan = prepare_sandbox(&exact);
        assert_eq!(
            strings(plan.environment()),
            [b"EMPTY=".as_slice(), b"VALUE=a=b"]
        );
        assert!(plan.physical_pwd().is_none());

        let layered = GuestExecPayload {
            environment: Some(vec![
                b"HOME=/layered".to_vec(),
                b"ADDED=1".to_vec(),
                b"ADDED=2".to_vec(),
            ]),
            inherit_default_env: true,
            ..execution()
        };
        // The request's entries layer over the defaults, wherever the agent's own environment
        // put them: a name that the defaults hold keeps its place, and a new one is appended once,
        // with its last value.
        let defaults = prepare_sandbox(&execution());
        let mut expected = strings(defaults.environment());
        let home = expected
            .iter()
            .position(|entry| *entry == b"HOME=/home/workload")
            .unwrap();
        expected[home] = b"HOME=/layered".as_slice();
        expected.push(b"ADDED=2");
        let plan = prepare_sandbox(&layered);
        assert_eq!(strings(plan.environment()), expected);
    }

    #[test]
    fn sandbox_pwd_is_physical_only_for_noncanonical_names_without_an_entry() {
        let noncanonical = GuestExecPayload {
            cwd: Some(b"/a/../b".to_vec()),
            ..execution()
        };
        let plan = prepare_sandbox(&noncanonical);
        let index = plan.physical_pwd_index().expect("PWD is deferred");
        assert_eq!(&plan.physical_pwd().unwrap()[..4], b"PWD=");
        assert!(
            strings(plan.environment())
                .iter()
                .all(|entry| !entry.starts_with(b"PWD="))
        );
        assert!(index <= plan.environment().len());

        let named = GuestExecPayload {
            environment: Some(vec![b"PWD=/named".to_vec()]),
            inherit_default_env: true,
            ..noncanonical
        };
        let plan = prepare_sandbox(&named);
        assert!(plan.physical_pwd().is_none());
        assert!(strings(plan.environment()).contains(&b"PWD=/named".as_slice()));
    }

    #[test]
    fn sandbox_launch_reports_a_simulated_stage_without_privileges() {
        let config = config(false);
        let execution = execution();
        let prepared = Prepared::simulated(Some((LaunchStage::Proc, Errno::EPERM)));
        let mut spawned =
            sandbox_command(&Paths::default(), request(&config, &execution), prepared)
                .unwrap()
                .spawn()
                .unwrap();
        let process = spawned.process();
        spawned.take_barrier().unwrap().release().unwrap();
        let failure = spawned.into_report().wait().unwrap().unwrap();
        assert_eq!(
            (failure.stage(), failure.raw_os_error()),
            (LaunchStage::Proc, Errno::EPERM as i32)
        );
        assert_eq!(sys::wait(process), Some(sys::ChildStatus::Exited(125)));
    }

    #[test]
    fn workload_ids_are_nonzero_decimal_and_not_the_unchanged_value() {
        for (text, expected) in [
            (b"1".as_slice(), Some(1)),
            (b"1000", Some(1000)),
            (b"4294967294", Some(u32::MAX - 1)),
            (b"0", None),
            (b"4294967295", None),
            (b"4294967296", None),
            (b"+1", None),
            (b"-1", None),
            (b" 1", None),
            (b"1x", None),
        ] {
            assert_eq!(parse_id(text).ok(), expected, "{text:?}");
        }
    }

    #[test]
    fn safe_working_directory_names_match_the_c_helper() {
        for path in [b"/".as_slice(), b"/tmp", b"/a/b", b"relative"] {
            assert_eq!(
                safe_path(path),
                path != b"/" && path != b"relative",
                "{path:?}"
            );
        }
        for path in [b"/a//b".as_slice(), b"/a/./b", b"/a/../b", b"/a/"] {
            assert!(!safe_path(path), "{path:?}");
        }
    }

    #[test]
    fn direct_pwd_is_deferred_only_for_noncanonical_names() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = direct_paths(temporary.path());
        let config = config(true);
        for cwd in [b"/a/./b".as_slice(), b"/a/../b", b"/a//b", b"/a/b/"] {
            let execution = GuestExecPayload {
                cwd: Some(cwd.to_vec()),
                ..execution()
            };
            let (plan, _) = prepare_direct(&paths, &config, &execution);
            let slot = plan.physical_pwd().expect("PWD is deferred");
            assert_eq!(&slot[..4], b"PWD=");
            assert!(slot[4..].iter().all(|&byte| byte == 0));
            assert!(plan.physical_pwd_index().is_some());
            assert!(
                strings(plan.environment())
                    .iter()
                    .all(|entry| !entry.starts_with(b"PWD=")),
                "{cwd:?}"
            );
        }
        let execution = GuestExecPayload {
            cwd: Some(b"/symlinked/component".to_vec()),
            ..execution()
        };
        let (plan, _) = prepare_direct(&paths, &config, &execution);
        assert!(plan.physical_pwd().is_none());
        assert!(strings(plan.environment()).contains(&b"PWD=/symlinked/component".as_slice()));
        assert!(plan.has_cgroup());
    }
}
