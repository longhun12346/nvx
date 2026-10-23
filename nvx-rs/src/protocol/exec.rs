//! `EXEC` payloads: the workload that an [`APP_EXEC`](super::APP_EXEC) request asks the guest agent
//! to run.
//!
//! A payload starts with the timeout in milliseconds (`u32`), the number of arguments (`u16`), and
//! an extension field (`u16`). A legacy payload, whose extension is zero, continues with the
//! arguments. An extended payload, whose extension is [`EXEC_EXTENDED`], continues with its flags
//! (`u16`), the number of environment entries (`u16`), and the length of the working directory
//! (`u32`), followed by the arguments, the working directory, and the environment entries. Each
//! argument and entry is its length (`u32`) followed by its bytes.

use std::collections::BTreeSet;

use super::{APP_HEADER_LEN, OUTER_MAX_PAYLOAD, ProtocolError, u16_at, u32_at, violation};

/// Largest number of workload arguments, including the program.
pub const MAX_ARGUMENTS: usize = 64;
/// Largest encoded size of one workload argument, working directory, or environment entry.
pub const MAX_ARGUMENT_BYTES: usize = 4096;
/// Largest working directory that hosts send: Linux's `PATH_MAX` without the terminating NUL, one
/// byte below the agent's bound.
pub const MAX_CWD_BYTES: usize = 4095;
/// Largest number of workload environment entries.
pub const MAX_ENVIRONMENT: usize = 256;
/// Largest workload timeout the guest agent accepts: any value of the exec request's 32-bit
/// timeout field, which is also the largest `process.timeout` that MXC's schema allows.
pub const MAX_TIMEOUT_MS: u32 = u32::MAX;
/// Largest combined stdout and stderr volume the guest agent forwards for one execution.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Extension field of a payload that carries flags, a working directory, and an environment.
pub const EXEC_EXTENDED: u16 = 1;
/// Extension field of a payload that additionally carries the execution's resource limits.
///
/// A guest accepts it only when it advertises
/// [`EXEC_LIMITS`](crate::protocol::GuestFeatures::EXEC_LIMITS); the limits are enforced on the
/// execution's own cgroup, and an execution whose limit cannot be enforced is refused instead of
/// running unlimited.
pub const EXEC_EXTENDED_V2: u16 = 2;
/// Largest per-execution memory limit, in MiB.
pub const MAX_EXEC_MEMORY_MIB: u32 = 4096;
/// Largest per-execution CPU limit, in hundredths of one core.
pub const MAX_EXEC_CPU_PERCENT: u32 = 6400;
/// Largest per-execution task limit.
pub const MAX_EXEC_PIDS: u32 = 4096;

/// Resource limits of one execution alone. Zero in a field means "no limit" there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExecLimits {
    /// Memory the execution and its descendants may charge, in MiB.
    pub mem_mb: u32,
    /// CPU time budget as a percentage of one core; 100 is one core's worth of time.
    pub cpu_percent: u32,
    /// Largest number of tasks the execution and its descendants may hold.
    pub pids_max: u32,
}

impl ExecLimits {
    /// Whether the request asks for no limit at all, in which case the payload stays compatible
    /// with guests that predate per-execution limits.
    pub const fn is_unset(self) -> bool {
        self.mem_mb == 0 && self.cpu_percent == 0 && self.pids_max == 0
    }

    /// Whether every field is inside the range the guest agent accepts.
    pub const fn is_supported(self) -> bool {
        self.mem_mb <= MAX_EXEC_MEMORY_MIB
            && self.cpu_percent <= MAX_EXEC_CPU_PERCENT
            && self.pids_max <= MAX_EXEC_PIDS
    }
}
/// Flag of an extended payload that carries a working directory.
pub const EXEC_CWD_PRESENT: u16 = 1 << 0;
/// Flag of an extended payload that carries an explicit environment.
pub const EXEC_ENVIRONMENT_PRESENT: u16 = 1 << 1;
/// Flag of an extended payload whose environment entries layer over the default environment.
pub const EXEC_INHERIT_DEFAULT_ENV: u16 = 1 << 2;

/// The environment that the guest agent gives a workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadEnvironment<'a> {
    /// The guest's default environment.
    Default,
    /// Exactly these `KEY=VALUE` entries; an empty slice is an empty environment.
    Replaced(&'a [String]),
    /// These entries layered over the default environment, each replacing the default variable
    /// of the same name.
    Layered(&'a [String]),
}

/// A workload that an `EXEC` request asks the guest agent to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workload<'a> {
    /// The program, an absolute guest path, followed by its arguments.
    pub argv: Vec<String>,
    /// Timeout in milliseconds; zero disables it.
    pub timeout_ms: u32,
    /// Absolute guest directory that the guest agent enters before it starts the program;
    /// `None` selects `/`.
    pub cwd: Option<&'a str>,
    /// The program's environment.
    pub environment: WorkloadEnvironment<'a>,
    /// Resource limits of this execution alone; the default asks for none.
    pub limits: ExecLimits,
}

/// Encodes the payload of an `EXEC` request.
///
/// The guest agent requires 1 to [`MAX_ARGUMENTS`] non-empty arguments without NUL bytes, each
/// at most [`MAX_ARGUMENT_BYTES`] long, an absolute program path, an absolute working directory
/// of at most [`MAX_ARGUMENT_BYTES`] without NUL bytes, and at most [`MAX_ENVIRONMENT`]
/// `KEY=VALUE` environment entries with unique names. It accepts any timeout up to
/// [`MAX_TIMEOUT_MS`], and zero disables it. A workload without a working directory or an
/// explicit environment keeps the legacy payload.
pub fn encode_exec_payload(workload: &Workload<'_>) -> Result<Vec<u8>, ProtocolError> {
    let argv = &workload.argv;
    if argv.is_empty() || argv.len() > MAX_ARGUMENTS {
        return Err(violation(format!(
            "exec requires 1 to {MAX_ARGUMENTS} arguments"
        )));
    }
    if !argv[0].starts_with('/') {
        return Err(violation("exec program must be an absolute guest path"));
    }
    let cwd = workload.cwd.map(str::as_bytes);
    if let Some(cwd) = cwd
        && (!cwd.starts_with(b"/") || cwd.len() > MAX_ARGUMENT_BYTES || cwd.contains(&0))
    {
        return Err(violation(format!(
            "exec working directory must be an absolute guest path of at most \
             {MAX_ARGUMENT_BYTES} bytes without NUL characters"
        )));
    }
    let (environment, mut flags) = match workload.environment {
        WorkloadEnvironment::Default => (&[][..], 0),
        WorkloadEnvironment::Replaced(entries) => (entries, EXEC_ENVIRONMENT_PRESENT),
        WorkloadEnvironment::Layered(entries) => {
            (entries, EXEC_ENVIRONMENT_PRESENT | EXEC_INHERIT_DEFAULT_ENV)
        }
    };
    if environment.len() > MAX_ENVIRONMENT {
        return Err(violation(format!(
            "exec environment must not exceed {MAX_ENVIRONMENT} entries"
        )));
    }
    if cwd.is_some() {
        flags |= EXEC_CWD_PRESENT;
    }
    let count = u16::try_from(argv.len()).unwrap_or(u16::MAX);
    if !workload.limits.is_supported() {
        return Err(violation(format!(
            "exec limits must be at most {MAX_EXEC_MEMORY_MIB} MiB of memory, \
             {MAX_EXEC_CPU_PERCENT} hundredths of a core, and {MAX_EXEC_PIDS} tasks"
        )));
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(&workload.timeout_ms.to_le_bytes());
    payload.extend_from_slice(&count.to_le_bytes());
    if flags == 0 && workload.limits.is_unset() {
        payload.extend_from_slice(&0u16.to_le_bytes());
    } else {
        let environment_count = u16::try_from(environment.len()).unwrap_or(u16::MAX);
        let cwd_len = u32::try_from(cwd.map_or(0, <[u8]>::len)).unwrap_or(u32::MAX);
        payload.extend_from_slice(
            &(if workload.limits.is_unset() {
                EXEC_EXTENDED
            } else {
                EXEC_EXTENDED_V2
            })
            .to_le_bytes(),
        );
        payload.extend_from_slice(&flags.to_le_bytes());
        payload.extend_from_slice(&environment_count.to_le_bytes());
        payload.extend_from_slice(&cwd_len.to_le_bytes());
        if !workload.limits.is_unset() {
            payload.extend_from_slice(&workload.limits.mem_mb.to_le_bytes());
            payload.extend_from_slice(&workload.limits.cpu_percent.to_le_bytes());
            payload.extend_from_slice(&workload.limits.pids_max.to_le_bytes());
        }
    }
    for argument in argv {
        let bytes = argument.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_ARGUMENT_BYTES || bytes.contains(&0) {
            return Err(violation(format!(
                "exec arguments must be 1 to {MAX_ARGUMENT_BYTES} bytes without NUL characters"
            )));
        }
        let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        payload.extend_from_slice(&length.to_le_bytes());
        payload.extend_from_slice(bytes);
    }
    payload.extend_from_slice(cwd.unwrap_or_default());
    let mut names = BTreeSet::new();
    for entry in environment {
        let bytes = entry.as_bytes();
        let name = entry
            .split_once('=')
            .map(|(name, _)| name)
            .filter(|name| !name.is_empty());
        let Some(name) = name.filter(|_| bytes.len() <= MAX_ARGUMENT_BYTES && !bytes.contains(&0))
        else {
            return Err(violation(format!(
                "exec environment entries must be KEY=VALUE strings of at most \
                 {MAX_ARGUMENT_BYTES} bytes without NUL characters"
            )));
        };
        // The guest agent refuses a request that names a variable twice.
        if !names.insert(name) {
            return Err(violation(format!(
                "exec environment names must be unique, but {name:?} repeats"
            )));
        }
        let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        payload.extend_from_slice(&length.to_le_bytes());
        payload.extend_from_slice(bytes);
    }
    if APP_HEADER_LEN + payload.len() > OUTER_MAX_PAYLOAD {
        return Err(violation("exec request exceeds the control protocol limit"));
    }
    Ok(payload)
}

/// An `EXEC` payload as the guest agent reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPayload {
    /// Timeout in milliseconds; zero disables it.
    pub timeout_ms: u32,
    /// The program, followed by its arguments.
    pub argv: Vec<String>,
    /// Absolute guest directory to start the program in; `None` selects `/`.
    pub cwd: Option<String>,
    /// The explicit `KEY=VALUE` environment entries, or `None` for the default environment.
    pub environment: Option<Vec<String>>,
    /// Whether the program starts from the default environment: true without explicit entries,
    /// and true when the entries layer over the default environment rather than replace it.
    pub inherit_default_env: bool,
    /// Resource limits the request asked for; zero fields mean "no limit".
    pub limits: ExecLimits,
}

/// Decodes the payload of an `EXEC` request.
///
/// It refuses what the guest agent refuses: a truncated payload, a number of arguments outside 1
/// to [`MAX_ARGUMENTS`], an unknown extension or flag, a working-directory length without the
/// working-directory flag or the reverse, environment entries without the environment flag, more
/// than [`MAX_ENVIRONMENT`] entries, an empty argument, working directory, or entry, or one
/// longer than [`MAX_ARGUMENT_BYTES`], text that is not UTF-8 or contains NUL characters, a
/// relative program or working directory, an entry without a name, a name that repeats, and
/// trailing bytes.
pub fn decode_exec_payload(payload: &[u8]) -> Result<ExecPayload, ProtocolError> {
    let truncated = || violation("the exec request is truncated");
    if payload.len() < 8 {
        return Err(truncated());
    }
    let timeout_ms = u32_at(payload, 0).ok_or_else(truncated)?;
    let count = usize::from(u16_at(payload, 4).ok_or_else(truncated)?);
    let extension = u16_at(payload, 6).ok_or_else(truncated)?;
    if count == 0 || count > MAX_ARGUMENTS {
        return Err(violation(format!(
            "exec requires 1 to {MAX_ARGUMENTS} arguments"
        )));
    }
    let (flags, environment_count, cwd_len, limits, mut offset) = match extension {
        0 => (0, 0, 0, ExecLimits::default(), 8),
        EXEC_EXTENDED | EXEC_EXTENDED_V2 => {
            let header_len = if extension == EXEC_EXTENDED_V2 { 28 } else { 16 };
            if payload.len() < header_len {
                return Err(truncated());
            }
            let flags = u16_at(payload, 8).ok_or_else(truncated)?;
            let environment_count = usize::from(u16_at(payload, 10).ok_or_else(truncated)?);
            let cwd_len = u32_at(payload, 12).ok_or_else(truncated)? as usize;
            let known = EXEC_CWD_PRESENT | EXEC_ENVIRONMENT_PRESENT | EXEC_INHERIT_DEFAULT_ENV;
            let cwd_valid = if flags & EXEC_CWD_PRESENT == 0 {
                cwd_len == 0
            } else {
                (1..=MAX_ARGUMENT_BYTES).contains(&cwd_len)
            };
            let environment_valid = flags & EXEC_ENVIRONMENT_PRESENT != 0
                || (environment_count == 0 && flags & EXEC_INHERIT_DEFAULT_ENV == 0);
            if flags & !known != 0
                || !cwd_valid
                || !environment_valid
                || environment_count > MAX_ENVIRONMENT
            {
                return Err(violation(
                    "the exec request has unknown flags or inconsistent fields",
                ));
            }
            let limits = if extension == EXEC_EXTENDED_V2 {
                ExecLimits {
                    mem_mb: u32_at(payload, 16).ok_or_else(truncated)?,
                    cpu_percent: u32_at(payload, 20).ok_or_else(truncated)?,
                    pids_max: u32_at(payload, 24).ok_or_else(truncated)?,
                }
            } else {
                ExecLimits::default()
            };
            if !limits.is_supported() {
                return Err(violation(
                    "the exec request asks for a resource limit outside the supported range",
                ));
            }
            (flags, environment_count, cwd_len, limits, header_len)
        }
        _ => return Err(violation("the exec request has an unknown extension")),
    };
    let mut argv = Vec::with_capacity(count);
    for _ in 0..count {
        argv.push(prefixed_text(payload, &mut offset, "arguments")?);
    }
    if !argv[0].starts_with('/') {
        return Err(violation("exec program must be an absolute guest path"));
    }
    let cwd = if flags & EXEC_CWD_PRESENT == 0 {
        None
    } else {
        let cwd = text_at(payload, offset, cwd_len, "working directory")?;
        offset += cwd_len;
        if !cwd.starts_with('/') {
            return Err(violation(
                "exec working directory must be an absolute guest path",
            ));
        }
        Some(cwd)
    };
    let mut environment = Vec::with_capacity(environment_count);
    let mut names = BTreeSet::new();
    for _ in 0..environment_count {
        let entry = prefixed_text(payload, &mut offset, "environment entries")?;
        // Like the guest agent, refuse entries without a name and repeated names.
        let Some((name, _)) = entry.split_once('=').filter(|(name, _)| !name.is_empty()) else {
            return Err(violation(
                "exec environment entries must be KEY=VALUE strings",
            ));
        };
        if !names.insert(name.to_owned()) {
            return Err(violation(format!(
                "exec environment names must be unique, but {name:?} repeats"
            )));
        }
        environment.push(entry);
    }
    if offset != payload.len() {
        return Err(violation("the exec request has trailing bytes"));
    }
    Ok(ExecPayload {
        timeout_ms,
        argv,
        cwd,
        environment: (flags & EXEC_ENVIRONMENT_PRESENT != 0).then_some(environment),
        inherit_default_env: flags & EXEC_ENVIRONMENT_PRESENT == 0
            || flags & EXEC_INHERIT_DEFAULT_ENV != 0,
        limits,
    })
}

/// Reads the text at `offset` that its `u32` length precedes, of 1 to [`MAX_ARGUMENT_BYTES`]
/// bytes, and advances `offset` past it.
fn prefixed_text(payload: &[u8], offset: &mut usize, what: &str) -> Result<String, ProtocolError> {
    let length = u32_at(payload, *offset)
        .ok_or_else(|| violation("the exec request is truncated"))? as usize;
    *offset += 4;
    if length == 0 || length > MAX_ARGUMENT_BYTES {
        return Err(violation(format!(
            "exec {what} must be 1 to {MAX_ARGUMENT_BYTES} bytes"
        )));
    }
    let text = text_at(payload, *offset, length, what)?;
    *offset += length;
    Ok(text)
}

/// Reads the `length` bytes at `offset` as text. Like the guest agent, refuses a NUL byte, which
/// it rejects in every argument, working directory, and environment entry.
fn text_at(
    payload: &[u8],
    offset: usize,
    length: usize,
    what: &str,
) -> Result<String, ProtocolError> {
    let bytes = offset
        .checked_add(length)
        .and_then(|end| payload.get(offset..end))
        .ok_or_else(|| violation("the exec request is truncated"))?;
    if bytes.contains(&0) {
        return Err(violation(format!(
            "exec {what} must not contain NUL characters"
        )));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| violation(format!("exec {what} must be valid UTF-8")))
}
