//! Test double for the `openvmm` executable.
//!
//! It emulates the part of OpenVMM that NVX hosts rely on, without running a VM: it validates the
//! managed microVM command line, reads the launch capability from standard input, serves the
//! authenticated control console on the requested Unix socket or named pipe, and runs scripted
//! workloads. Tests point the OpenVMM path of their launches at an executable whose `main` calls
//! [`main`], such as `nvx-fake-openvmm`. It speaks the [`protocol`](crate::protocol) of the host
//! and decodes requests with the guest agent's decoders, whose golden byte fixtures pin the wire
//! format independently.
//!
//! Workloads are `/bin/sh -c SCRIPT`, `/bin/echo ARGS...`, `/bin/pwd`, or a program named `env`
//! or `printenv` in any directory, which prints its environment. A script is a `;`-separated
//! list of commands: `echo TEXT`, `echoerr TEXT`, `sleep MS`, `exit CODE`, `signal NUMBER`,
//! `flood BYTES`, `write KEY VALUE`, `read KEY`, `mkdir DIRECTORY`, `env`, `printenv NAME`,
//! `pwd`, `timeout`, `fail`, and `launchfail`. Like `sh`, a script exits with the status of its
//! last command; `printenv NAME` prints nothing and fails with status 1 when `NAME` is unset.
//! Values written with `write` and directories made with `mkdir` live in memory until the VM
//! stops, like files in the guest's RAM root file system. A `CANCEL` request ends a sleeping
//! workload with the cancelled outcome, and a client that disconnects during an exec abandons it,
//! as the real guest agent does. `pwd` prints the working directory of the exec request, and
//! `timeout` its timeout in milliseconds. Like the guest agent, the fake refuses a working
//! directory that does not exist (any but `/`, `/tmp`, `/work`, a mapped directory, or a directory
//! made with `mkdir`), or that is a mapped regular file, with a diagnostic and the `cwd-failed`
//! category.
//!
//! Host paths are mapped as OpenVMM and the guest agent map them: the command line exports
//! numbered `--mount-child` directories, and files with the `file` flag, through
//! `--mount-aggregate`, the kernel command line announces the number of mappings with
//! `nvx_maps=`, and `MAPS` requests deliver the mapping table in order. The fake checks each
//! entry against the exported children, refuses workloads until the table is complete, and
//! records it in `fake-openvmm-<token>-maps.json` next to the kernel, where `<token>` is the name
//! of the directory that holds the outcome report.
//!
//! Each workload gets the environment that its exec request selects, in the order in which the
//! guest agent builds it. The default environment is the documented guest bootstrap environment:
//! `PATH`, `TERM`, and the `HOME`, `USER`, and `LOGNAME` of the workload account. The guest's
//! boot leaves a few more variables behind, and the guest agent points `PWD` at the working
//! directory; the fake omits both. Like BusyBox's `sh`, a script exports `SHLVL`, one higher
//! than the value that it received as an unsigned 32-bit integer that wraps around, and its
//! working directory as `PWD`, replacing entries with these names.
//!
//! Kernel command-line tokens adjust the emulation: `fake_exit_on_start=CODE` fails the launch,
//! `fake_boot_delay_ms=MS` delays the control endpoint, `fake_crash_after_ms=MS` makes the VM
//! die, `fake_ignore_stop=1` ignores stop requests, `fake_ignore_cancel=1` ignores cancellation,
//! `fake_guest_features=MASK` advertises the decimal feature mask `MASK` instead of the current
//! guest's, `fake_legacy_guest=1` refuses the features request like a guest agent that
//! predates it, and `fake_refuse_maps=1` fails every `MAPS` request like a guest that cannot
//! mount a mapped path. The command line is recorded in `fake-openvmm-<token>.json` next to the
//! kernel.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use crate::protocol::{
    APP_CANCEL, APP_ERROR, APP_EXEC, APP_EXIT, APP_FEATURES, APP_MAPS, APP_PING, APP_READY,
    APP_STDERR, APP_STDOUT, APP_STOP, APP_STOPPED, CAPABILITY_LEN, CWD_FAILED, ExitCategory,
    GuestFeatures, INVALID_REQUEST, LAUNCH_FAILED, MAPPING_FAILED, MAPPINGS_INCOMPLETE, MAPS_TOKEN,
    MAX_HOST_MAPPINGS, MAX_OUTPUT_BYTES, MapsPayload, OUTER_DATA, OUTER_ERROR, OUTER_HEADER_LEN,
    OUTER_HOST_ATTACH, OUTER_READY, OuterHeader, UNSUPPORTED_OPERATION, WORKLOAD_ACCOUNT_TOKEN,
    decode_app, decode_exec_payload, decode_maps_payload, decode_outer_header, encode_app,
    encode_outer,
};

/// Largest workload-output frame emitted by the fake guest.
const OUTPUT_CHUNK_BYTES: usize = 32 * 1024;

/// Control features of the current guest: cancellation, workload accounts, workload
/// containment, per-execution environments, working directories, and host path mapping tables.
/// Bit 1 is retired.
const GUEST_FEATURES: GuestFeatures = GuestFeatures::from_bits(
    GuestFeatures::CANCEL.bits()
        | GuestFeatures::WORKLOAD_ACCOUNT.bits()
        | GuestFeatures::EXEC_CGROUP.bits()
        | GuestFeatures::EXEC_ENVIRONMENT.bits()
        | GuestFeatures::EXEC_CWD.bits()
        | GuestFeatures::HOST_MAPPING_TABLE.bits(),
);

/// The guest directory at which the host mounts the aggregate export.
const GUEST_EXPORT: &str = "/run/nvx/hostfs/root";

/// `NAME=VALUE` variables in the order in which a workload's `environ` lists them.
type Environment = Vec<(String, String)>;

/// Sets `name` like `putenv`: in place when it exists, and at the end otherwise.
fn set_variable(environment: &mut Environment, name: &str, value: &str) {
    match environment
        .iter_mut()
        .find(|(existing, _)| existing == name)
    {
        Some(entry) => value.clone_into(&mut entry.1),
        None => environment.push((name.to_owned(), value.to_owned())),
    }
}

/// What BusyBox's `sh` does to the environment of everything that it starts: it raises `SHLVL`
/// and exports its working directory as `PWD`, replacing the values of the same names that it
/// received. It keeps every other variable.
fn start_shell(environment: &mut Environment, cwd: &str) {
    let level = environment
        .iter()
        .find(|(name, _)| name == "SHLVL")
        .map_or(0, |(_, value)| atoi(value));
    // BusyBox exports `atoi(SHLVL) + 1` as an unsigned integer, so `4294967295` and `-1`
    // become `0`, and `-3` becomes `4294967294`.
    set_variable(
        environment,
        "SHLVL",
        &level.wrapping_add(1).cast_unsigned().to_string(),
    );
    set_variable(environment, "PWD", cwd);
}

/// musl's `atoi`, which the guest's BusyBox uses: it skips leading whitespace, takes an
/// optional sign and the digits that follow, wraps around on overflow, and stops at the first
/// other character, so `7x` is 7 and a value without digits is 0.
fn atoi(value: &str) -> i32 {
    let value = value.trim_start_matches([' ', '\t', '\n', '\u{b}', '\u{c}', '\r']);
    let (negative, digits) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    let magnitude = digits
        .bytes()
        .take_while(u8::is_ascii_digit)
        .fold(0i32, |n, digit| {
            n.wrapping_mul(10).wrapping_add(i32::from(digit - b'0'))
        });
    if negative {
        magnitude.wrapping_neg()
    } else {
        magnitude
    }
}

/// Parsed OpenVMM-compatible command line and fake-specific test controls.
struct Options {
    /// Name of the executable, which prefixes the fake's diagnostics.
    program: String,
    /// Control endpoint at which the fake accepts host sessions.
    endpoint: String,
    /// Path to the synthetic OpenVMM outcome report.
    report: PathBuf,
    /// Backend name recorded in the synthetic report.
    hypervisor: String,
    /// Path that receives the parsed command-line dump.
    args_dump: PathBuf,
    /// Path that receives the mounted-host-path dump.
    maps_dump: PathBuf,
    /// Status with which to stop immediately after launch, when requested.
    exit_on_start: Option<u8>,
    /// Artificial delay before the fake guest becomes ready.
    boot_delay: Duration,
    /// Artificial delay before the fake OpenVMM crashes, when requested.
    crash_after: Option<Duration>,
    /// Whether stop requests are deliberately left unanswered.
    ignore_stop: bool,
    /// Whether cancellation requests are deliberately ignored.
    ignore_cancel: bool,
    /// Whether the guest omits feature negotiation like an older image.
    legacy_guest: bool,
    /// Whether host-mapping requests are deliberately refused.
    refuse_maps: bool,
    /// UID whose account and environment the fake guest models.
    workload_uid: u32,
    /// Feature mask returned during guest feature negotiation.
    guest_features: GuestFeatures,
    /// Host directories of the aggregate export, in child order.
    children: Vec<PathBuf>,
    /// Number of host mappings that the kernel command line announces.
    maps: usize,
}

/// A host path mapped into the guest.
#[derive(serde::Serialize)]
struct Mapped {
    /// Path relative to the guest's mount of the export.
    source: String,
    /// Guest path at which the host path appears.
    target: String,
    /// Whether the guest mounts it read-only.
    read_only: bool,
    /// Whether the host path is a directory rather than a regular file.
    directory: bool,
}

/// Runs the fake OpenVMM with the process's arguments and standard input, as an executable's
/// `main` does, and returns its exit status.
pub fn main() -> ExitCode {
    let program = program_name();
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let options = match parse(&program, &arguments) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{program}: {message}");
            return ExitCode::from(2);
        }
    };
    let _ = fs::write(
        &options.args_dump,
        serde_json::to_vec(&arguments).unwrap_or_default(),
    );
    if let Some(code) = options.exit_on_start {
        eprintln!("{program}: failing the launch as requested");
        return ExitCode::from(code);
    }
    let capability = match read_capability() {
        Ok(capability) => capability,
        Err(message) => {
            eprintln!("{program}: {message}");
            return ExitCode::from(2);
        }
    };
    thread::sleep(options.boot_delay);
    if let Some(after) = options.crash_after {
        thread::spawn(move || {
            thread::sleep(after);
            std::process::exit(3);
        });
    }
    match serve(&options, &capability) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{program}: {error}");
            ExitCode::from(1)
        }
    }
}

/// Returns the name of the running executable, such as `nvx-fake-openvmm`.
fn program_name() -> String {
    std::env::args_os()
        .next()
        .and_then(|path| {
            Path::new(&path)
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "nvx-fake-openvmm".to_owned())
}

/// Parses the OpenVMM command line plus fake controls, rejecting unsupported combinations.
fn parse(program: &str, arguments: &[String]) -> Result<Options, String> {
    const VALUED: [&str; 26] = [
        "--mount-aggregate",
        "--mount-child",
        "--mount-deny",
        "--mount-allow",
        "--mount-write",
        "--network-egress-allow",
        "--network-egress-deny",
        "--machine",
        "--microvm-workload-identity",
        "--microvm-lifecycle",
        "--hypervisor",
        "--memory",
        // The launcher chooses the guest CPU profile explicitly and passes the export channel the
        // VMM should serve; the fake serves the control protocol, so it accepts both and ignores
        // what it does not model. Without them every start fails with "unsupported argument".
        "--cpu-profile",
        "--microvm-virtiofs-control",
        "--kernel",
        "--initrd",
        "--cmdline",
        "--virtio-console",
        "--microvm-control-console",
        "--microvm-report",
        "--net",
        "--network-profile",
        "--network-egress",
        "--network-ingress",
        "--host-loopback",
        "--host-loopback-forward",
    ];
    let mut values: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut flags = BTreeSet::new();
    let mut iterator = arguments.iter();
    while let Some(argument) = iterator.next() {
        let name = argument.as_str();
        if name == "--single-process" || name == "--microvm-control-auth-stdin" {
            flags.insert(name);
        } else if VALUED.contains(&name) {
            let value = iterator
                .next()
                .ok_or_else(|| format!("{name} requires a value"))?;
            values.entry(name).or_default().push(value);
        } else {
            return Err(format!("unsupported argument {name}"));
        }
    }
    let single = |name: &str| -> Result<&str, String> {
        match values.get(name).map(Vec::as_slice) {
            Some([value]) => Ok(value),
            _ => Err(format!("{name} must be given exactly once")),
        }
    };
    let expect = |name: &str, expected: &str| -> Result<(), String> {
        let value = single(name)?;
        if value == expected {
            Ok(())
        } else {
            Err(format!("{name} must be {expected}, not {value}"))
        }
    };
    expect("--machine", "microvm")?;
    expect("--microvm-lifecycle", "managed")?;
    expect("--virtio-console", "none")?;
    for flag in ["--single-process", "--microvm-control-auth-stdin"] {
        if !flags.contains(flag) {
            return Err(format!("{flag} is required"));
        }
    }
    let hypervisor = single("--hypervisor")?;
    if !["kvm", "mshv", "whp"].contains(&hypervisor) {
        return Err(format!("unsupported hypervisor {hypervisor}"));
    }
    if !single("--memory")?.ends_with('M') {
        return Err("--memory must be given in MiB".to_owned());
    }
    let identity = single("--microvm-workload-identity")?;
    let workload_uid = identity
        .split_once(':')
        .and_then(|(uid, gid)| Some((uid.parse::<u32>().ok()?, gid.parse::<u32>().ok()?)))
        .filter(|&(uid, gid)| uid != 0 && gid != 0)
        .map(|(uid, _)| uid)
        .ok_or_else(|| format!("invalid workload identity {identity}"))?;
    let kernel = PathBuf::from(single("--kernel")?);
    for path in [&kernel, &PathBuf::from(single("--initrd")?)] {
        if !path.is_file() {
            return Err(format!("{} does not exist", path.display()));
        }
    }
    let endpoint = single("--microvm-control-console")?
        .strip_prefix("listen=")
        .ok_or("--microvm-control-console must use listen=")?
        .to_owned();
    let report = PathBuf::from(single("--microvm-report")?);
    if report.exists() {
        return Err(format!("report path {} already exists", report.display()));
    }
    let command_line = single("--cmdline")?;
    let tokens: Vec<&str> = command_line.split_whitespace().collect();
    if tokens.iter().any(|token| {
        token.starts_with("nvx_")
            && !token.starts_with(MAPS_TOKEN)
            && *token != WORKLOAD_ACCOUNT_TOKEN
    }) {
        return Err("the kernel command line must not select a sandbox".to_owned());
    }
    let maps = match tokens
        .iter()
        .filter_map(|token| token.strip_prefix(MAPS_TOKEN))
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => 0,
        [count] => count
            .parse::<usize>()
            .ok()
            .filter(|count| (1..=MAX_HOST_MAPPINGS).contains(count))
            .ok_or_else(|| format!("invalid {MAPS_TOKEN}{count}"))?,
        _ => return Err(format!("{MAPS_TOKEN} must be given at most once")),
    };
    let children = match values.get("--mount-aggregate").map(Vec::as_slice) {
        None if maps == 0 => Vec::new(),
        Some([GUEST_EXPORT]) if maps > 0 => {
            let mut children = Vec::new();
            for (index, child) in values
                .get("--mount-child")
                .into_iter()
                .flatten()
                .enumerate()
            {
                let invalid = || format!("invalid --mount-child {child}");
                let (name, rest) = child.split_once(',').ok_or_else(invalid)?;
                // Like OpenVMM, a child exposes a directory or, with the `file` flag, a regular
                // file, and refuses a host path of the other kind.
                let (rest, file) = match rest.strip_suffix(",file") {
                    Some(rest) => (rest, true),
                    None => (rest, false),
                };
                let (host, mode) = rest.rsplit_once(',').ok_or_else(invalid)?;
                let kind_matches = if file {
                    Path::new(host).is_file()
                } else {
                    Path::new(host).is_dir()
                };
                if name != index.to_string() || !kind_matches || !["ro", "rw"].contains(&mode) {
                    return Err(invalid());
                }
                children.push(PathBuf::from(host));
            }
            if children.is_empty() {
                return Err("--mount-aggregate requires --mount-child".to_owned());
            }
            children
        }
        _ => {
            return Err(format!("--mount-aggregate and {MAPS_TOKEN} must agree"));
        }
    };
    if children.is_empty() && values.contains_key("--mount-child") {
        return Err("--mount-child requires --mount-aggregate".to_owned());
    }
    for option in ["--mount-deny", "--mount-allow", "--mount-write"] {
        for path in values.get(option).into_iter().flatten() {
            let path = Path::new(path);
            // No policy path names a file child, which contains nothing.
            if !path.exists()
                || !children
                    .iter()
                    .any(|root| root.is_dir() && path.starts_with(root))
            {
                return Err(format!("invalid {option} {}", path.display()));
            }
        }
    }
    if (values.contains_key("--network-egress-allow")
        || values.contains_key("--network-egress-deny"))
        && !values.contains_key("--network-egress")
    {
        return Err("--network-egress is required with egress rules".to_owned());
    }
    if values.contains_key("--host-loopback-forward")
        && values.get("--host-loopback").map(Vec::as_slice) != Some(&["allow"][..])
    {
        return Err("--host-loopback-forward requires explicit --host-loopback allow".to_owned());
    }
    if !tokens.iter().any(|token| token.starts_with("hostname=")) {
        return Err("the kernel command line must set the hostname".to_owned());
    }
    if values.contains_key("--net") {
        expect("--network-profile", "portable")?;
    }
    let knob = |name: &str| {
        tokens
            .iter()
            .find_map(|token| token.strip_prefix(name)?.strip_prefix('='))
    };
    let millis = |name: &str| {
        knob(name)
            .and_then(|value| value.parse().ok())
            .map(Duration::from_millis)
    };
    let token = report
        .parent()
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(Options {
        program: program.to_owned(),
        endpoint,
        args_dump: kernel.with_file_name(format!("fake-openvmm-{token}.json")),
        maps_dump: kernel.with_file_name(format!("fake-openvmm-{token}-maps.json")),
        report,
        hypervisor: hypervisor.to_owned(),
        exit_on_start: knob("fake_exit_on_start").and_then(|value| value.parse().ok()),
        boot_delay: millis("fake_boot_delay_ms").unwrap_or_default(),
        crash_after: millis("fake_crash_after_ms"),
        ignore_stop: knob("fake_ignore_stop") == Some("1"),
        ignore_cancel: knob("fake_ignore_cancel") == Some("1"),
        legacy_guest: knob("fake_legacy_guest") == Some("1"),
        refuse_maps: knob("fake_refuse_maps") == Some("1"),
        workload_uid,
        guest_features: knob("fake_guest_features")
            .and_then(|value| value.parse().ok())
            .map_or(GUEST_FEATURES, GuestFeatures::from_bits),
        children,
        maps,
    })
}

/// Reads exactly one nonzero control capability from standard input.
fn read_capability() -> Result<[u8; CAPABILITY_LEN], String> {
    let mut stdin = io::stdin().lock();
    let mut capability = [0u8; CAPABILITY_LEN];
    stdin
        .read_exact(&mut capability)
        .map_err(|error| format!("cannot read the capability from stdin: {error}"))?;
    let mut extra = [0u8; 1];
    if stdin.read(&mut extra).map_err(|error| error.to_string())? != 0 {
        return Err("standard input carried more than the capability".to_owned());
    }
    if capability == [0; CAPABILITY_LEN] {
        return Err("the capability is all zero".to_owned());
    }
    Ok(capability)
}

/// Guest state that lives in memory until the VM stops.
struct Guest {
    /// Values exposed by the fake's scripted `get` and `set` commands.
    values: BTreeMap<String, String>,
    /// Environment that workloads inherit unless they replace it.
    default_environment: Environment,
    /// Directories a workload can enter.
    directories: BTreeSet<String>,
    /// Mapped regular files, which a workload cannot enter either.
    files: BTreeSet<String>,
    /// Entries of the host mapping table mounted so far.
    mapped: Vec<Mapped>,
}

impl Guest {
    /// Constructs the initial guest environment and filesystem model from `options`.
    fn new(options: &Options) -> Self {
        // The Alpine image resolves the default identity to `nobody`; for any other host-selected
        // identity, the managed init creates the `nvx` account homed in /tmp.
        let (user, home) = if options.workload_uid == 65534 {
            ("nobody", "/")
        } else {
            ("nvx", "/tmp")
        };
        let default_environment = [
            ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
            ("TERM", "linux"),
            ("HOME", home),
            ("USER", user),
            ("LOGNAME", user),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
        Self {
            values: BTreeMap::new(),
            default_environment,
            directories: ["/", "/tmp", "/work"].map(str::to_owned).into(),
            files: BTreeSet::new(),
            mapped: Vec::new(),
        }
    }

    /// Mounts the entries of a `MAPS` request, like the guest agent: in order, and only as many
    /// as the kernel command line announced. Returns the error number and category of a refusal.
    fn map(&mut self, options: &Options, payload: &[u8]) -> Result<(), (i32, &'static str)> {
        const INVALID: (i32, &str) = (22, INVALID_REQUEST);
        let Ok(MapsPayload { first, maps }) = decode_maps_payload(payload) else {
            return Err(INVALID);
        };
        let (first, count) = (first as usize, maps.len());
        if options.maps == 0
            || first != self.mapped.len()
            || count == 0
            || count > options.maps - first
        {
            return Err(INVALID);
        }
        if options.refuse_maps {
            return Err((13, MAPPING_FAILED));
        }
        for map in maps {
            let (child, relative) = map.source.split_once('/').unwrap_or((&map.source, ""));
            let Some(root) = child
                .parse::<usize>()
                .ok()
                .and_then(|child| options.children.get(child))
            else {
                return Err(INVALID);
            };
            let host = if relative.is_empty() {
                root.clone()
            } else {
                root.join(relative)
            };
            let directory = if host.is_dir() {
                self.directories.insert(map.target.clone());
                true
            } else if host.is_file() {
                self.files.insert(map.target.clone());
                false
            } else {
                return Err((2, MAPPING_FAILED));
            };
            self.mapped.push(Mapped {
                source: map.source,
                target: map.target,
                read_only: map.read_only,
                directory,
            });
        }
        let _ = fs::write(
            &options.maps_dump,
            serde_json::to_vec(&self.mapped).unwrap_or_default(),
        );
        Ok(())
    }
}

/// Whether the fake should accept another control session or terminate.
enum Flow {
    /// Keep the fake VM running after the current session.
    Continue,
    /// Stop the fake VM after a successful stop request.
    Exit,
}

/// Outcome of control traffic observed while a workload runs.
enum Interrupt {
    /// No control request is waiting.
    None,
    /// The workload's matching cancellation request arrived.
    Cancel,
    /// The host disconnected and abandoned the workload.
    Disconnected,
}

/// A control stream that can report whether input is waiting without consuming it.
trait Pending {
    /// Returns whether a read would make progress, including at end of stream.
    fn pending(&mut self) -> io::Result<bool>;
}

#[cfg(unix)]
impl Pending for std::os::unix::net::UnixStream {
    fn pending(&mut self) -> io::Result<bool> {
        use std::os::fd::AsRawFd;

        let mut descriptor = libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the descriptor array has one valid entry, and a zero timeout only polls.
        match unsafe { libc::poll(&mut descriptor, 1, 0) } {
            -1 => Err(io::Error::last_os_error()),
            ready => Ok(ready > 0),
        }
    }
}

#[cfg(windows)]
impl Pending for fs::File {
    fn pending(&mut self) -> io::Result<bool> {
        use std::os::windows::io::AsRawHandle;

        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;

        let mut available = 0u32;
        // SAFETY: the handle is a connected pipe, and only the byte count is requested.
        let peeked = unsafe {
            PeekNamedPipe(
                self.as_raw_handle() as HANDLE,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        // A failed peek means the client is gone; the next read reports end of stream.
        Ok(peeked == 0 || available > 0)
    }
}

/// Encodes an outer record without a payload, which the broker sends to answer an attach.
fn control_record(record_type: u8, instance: &[u8; 16], epoch: u64) -> Vec<u8> {
    encode_outer(record_type, instance, epoch, 0, &[]).expect("an empty payload fits a record")
}

/// Decoded outer header paired with its owned payload.
type Record = (OuterHeader, Vec<u8>);

/// Reads one outer record, returning `None` at end of stream.
fn read_record<S: Read>(stream: &mut S) -> io::Result<Option<Record>> {
    let mut header = [0u8; OUTER_HEADER_LEN];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let header = decode_outer_header(&header).map_err(io::Error::other)?;
    let mut payload = vec![0u8; header.length];
    stream.read_exact(&mut payload)?;
    Ok(Some((header, payload)))
}

/// One authenticated host session over a connected stream.
struct Session<'a, S> {
    /// Connected transport to the host.
    stream: &'a mut S,
    /// Executable name used to prefix diagnostics.
    program: &'a str,
    /// Random identity assigned to this attachment.
    instance: [u8; 16],
    /// Monotonic attachment epoch.
    epoch: u64,
    /// Sequence number of the next guest record.
    guest_sequence: u64,
    /// Sequence number expected from the next host record.
    host_sequence: u64,
    /// Whether matching cancellation requests are ignored for fault injection.
    ignore_cancel: bool,
    /// Requests that arrived while a workload ran.
    ///
    /// A host used to give each execution its own session, so the fake served one request at a
    /// time per connection and never met a second request mid-workload. Now one session carries
    /// several executions, so the fake queues what arrives and serves it once the current
    /// workload finishes. That keeps every request answered, in order, which is what the
    /// host-layer tests depend on; how concurrent executions overlap is proved against a real
    /// guest by `tools/nvxd/tests/parallel_exec.py`.
    deferred: VecDeque<(u8, u64, Vec<u8>)>,
}

impl<S: Read + Write + Pending> Session<'_, S> {
    /// Encodes and sends one sequenced guest application frame.
    fn send(&mut self, kind: u8, request_id: u64, status: i32, payload: &[u8]) -> io::Result<()> {
        let frame = encode_app(kind, request_id, status, payload);
        let record = encode_outer(
            OUTER_DATA,
            &self.instance,
            self.epoch,
            self.guest_sequence,
            &frame,
        )
        .map_err(io::Error::other)?;
        self.guest_sequence += 1;
        self.stream.write_all(&record)
    }

    /// Reads the next host request, returning `None` at end of stream.
    fn request(&mut self) -> io::Result<Option<(u8, u64, Vec<u8>)>> {
        let Some((header, frame)) = read_record(self.stream)? else {
            return Ok(None);
        };
        let valid = header.record_type == OUTER_DATA
            && header.instance_id == self.instance
            && header.epoch == self.epoch
            && header.sequence == self.host_sequence;
        let frame = decode_app(&frame)
            .ok()
            .filter(|_| valid)
            .ok_or_else(|| io::Error::other("invalid data record"))?;
        self.host_sequence += 1;
        Ok(Some((frame.kind, frame.request_id, frame.payload.to_vec())))
    }

    /// Serves requests until the host disconnects or asks the VM to stop.
    fn run(&mut self, options: &Options, guest: &mut Guest) -> io::Result<Flow> {
        loop {
            // Requests that arrived while a workload ran are served first, in arrival order.
            let next = match self.deferred.pop_front() {
                Some(request) => Some(request),
                None => self.request()?,
            };
            let Some((kind, request_id, payload)) = next else {
                return Ok(Flow::Continue);
            };
            match self.handle(kind, request_id, &payload, options, guest)? {
                Flow::Continue => {}
                other => return Ok(other),
            }
        }
    }

    /// Serves one request. Returns [`Flow::Exit`] when the guest should stop.
    fn handle(
        &mut self,
        kind: u8,
        request_id: u64,
        payload: &[u8],
        options: &Options,
        guest: &mut Guest,
    ) -> io::Result<Flow> {
        match kind {
            APP_PING => self.send(APP_READY, request_id, 0, &[])?,
            APP_FEATURES if !options.legacy_guest => {
                self.send(APP_READY, request_id, 0, &options.guest_features.encode())?;
            }
            APP_EXEC if guest.mapped.len() < options.maps => {
                self.send(APP_ERROR, request_id, 11, MAPPINGS_INCOMPLETE.as_bytes())?;
            }
            APP_EXEC => {
                if !self.exec(request_id, payload, guest)? {
                    return Ok(Flow::Continue);
                }
            }
            APP_MAPS => match guest.map(options, payload) {
                Ok(()) => self.send(APP_READY, request_id, 0, &[])?,
                Err((status, category)) => {
                    self.send(APP_ERROR, request_id, status, category.as_bytes())?;
                }
            },
            // The targeted workload already finished.
            APP_CANCEL => {}
            APP_STOP if options.ignore_stop => {}
            APP_STOP => {
                let _ = self.send(APP_STOPPED, request_id, 0, &[]);
                return Ok(Flow::Exit);
            }
            _ => self.send(APP_ERROR, request_id, 95, UNSUPPORTED_OPERATION)?,
        }
        Ok(Flow::Continue)
    }

    /// Handles control traffic that arrives while workload `request_id` runs.
    fn interrupt(&mut self, request_id: u64) -> io::Result<Interrupt> {
        while self.stream.pending()? {
            match self.request()? {
                None => return Ok(Interrupt::Disconnected),
                Some((APP_CANCEL, id, _)) if id == request_id && !self.ignore_cancel => {
                    return Ok(Interrupt::Cancel);
                }
                Some((APP_CANCEL, _, _)) => {}
                // A host used to give each execution its own session, so the fake never met a
                // second request mid-workload. Now one session carries several executions: queue
                // what arrives and serve it when this workload finishes, instead of refusing it.
                Some((kind, id, payload)) => self.deferred.push_back((kind, id, payload)),
            }
        }
        Ok(Interrupt::None)
    }

    /// Runs one workload. Returns `false` if the client disconnected and abandoned it.
    fn exec(&mut self, request_id: u64, payload: &[u8], guest: &mut Guest) -> io::Result<bool> {
        self.exec_script(request_id, payload, guest)
            .map(|outcome| outcome.is_some())
    }

    /// Interprets one fake-workload script and emits the same records a guest agent would.
    fn exec_script(
        &mut self,
        request_id: u64,
        payload: &[u8],
        guest: &mut Guest,
    ) -> io::Result<Option<()>> {
        let Ok(exec) = decode_exec_payload(payload) else {
            return self.send_some(APP_ERROR, request_id, 22, INVALID_REQUEST.as_bytes());
        };
        let mut environment = if exec.inherit_default_env {
            guest.default_environment.clone()
        } else {
            Environment::new()
        };
        for entry in exec.environment.iter().flatten() {
            let (name, value) = entry.split_once('=').unwrap();
            set_variable(&mut environment, name, value);
        }
        let cwd = exec.cwd.as_deref().unwrap_or("/");
        if !guest.directories.contains(cwd) {
            // The guest agent's refusal: a diagnostic, then the error number, before anything
            // runs.
            let (error, reason) = if guest.files.contains(cwd) {
                (20, "Not a directory") // ENOTDIR
            } else {
                (2, "No such file or directory") // ENOENT
            };
            let message =
                format!("nvx-managed-agent: cannot enter working directory {cwd}: {reason}\n");
            self.send(APP_STDERR, request_id, 0, message.as_bytes())?;
            return self.send_some(APP_ERROR, request_id, error, CWD_FAILED.as_bytes());
        }
        let timeout_ms = exec.timeout_ms;
        let program_name =
            |program: &str| program.rsplit('/').next().unwrap_or_default().to_owned();
        let script = match exec.argv.as_slice() {
            [shell, option, script] if shell == "/bin/sh" && option == "-c" => {
                start_shell(&mut environment, cwd);
                script.clone()
            }
            [program, words @ ..] if program == "/bin/echo" => format!("echo {}", words.join(" ")),
            [program] if program == "/bin/pwd" => "pwd".to_owned(),
            [program] if ["env", "printenv"].contains(&program_name(program).as_str()) => {
                "env".to_owned()
            }
            [program, name] if program_name(program) == "printenv" => format!("printenv {name}"),
            [program, ..] => {
                let message = format!("{}: {program}: not found\n", self.program);
                self.send(APP_STDERR, request_id, 0, message.as_bytes())?;
                return self.exit(request_id, 127, ExitCategory::Exit);
            }
            [] => return self.send_some(APP_ERROR, request_id, 22, INVALID_REQUEST.as_bytes()),
        };
        let started = Instant::now();
        let limit = (timeout_ms > 0).then(|| started + Duration::from_millis(timeout_ms.into()));
        let mut output = 0usize;
        let mut status = 0;
        for command in script
            .split(';')
            .map(str::trim)
            .filter(|command| !command.is_empty())
        {
            let (name, argument) = command
                .split_once(' ')
                .map_or((command, ""), |(name, argument)| (name, argument.trim()));
            status = 0;
            match name {
                "echo" | "echoerr" => {
                    let line = format!("{argument}\n");
                    let kind = if name == "echo" {
                        APP_STDOUT
                    } else {
                        APP_STDERR
                    };
                    if !self.forward(kind, request_id, &mut output, line.as_bytes())? {
                        return self.exit(request_id, 125, ExitCategory::OutputLimit);
                    }
                }
                "sleep" => {
                    let wake =
                        Instant::now() + Duration::from_millis(argument.parse().unwrap_or(0));
                    let end = limit.map_or(wake, |limit| wake.min(limit));
                    while Instant::now() < end {
                        match self.interrupt(request_id)? {
                            Interrupt::None => thread::sleep(
                                end.saturating_duration_since(Instant::now())
                                    .min(Duration::from_millis(5)),
                            ),
                            Interrupt::Cancel => {
                                return self.exit(request_id, 137, ExitCategory::Cancelled);
                            }
                            Interrupt::Disconnected => return Ok(None),
                        }
                    }
                    if wake > end {
                        return self.exit(request_id, 124, ExitCategory::Timeout);
                    }
                }
                "exit" => {
                    let status = argument.parse().unwrap_or(1);
                    return self.exit(request_id, status, ExitCategory::Exit);
                }
                "signal" => {
                    let signal: i32 = argument.parse().unwrap_or(9);
                    return self.exit(request_id, 128 + signal, ExitCategory::Signal);
                }
                "flood" => {
                    let mut remaining: usize = argument.parse().unwrap_or(0);
                    while remaining > 0 {
                        let chunk = remaining.min(OUTPUT_CHUNK_BYTES);
                        if !self.forward(APP_STDOUT, request_id, &mut output, &vec![b'x'; chunk])? {
                            return self.exit(request_id, 125, ExitCategory::OutputLimit);
                        }
                        remaining -= chunk;
                    }
                }
                "write" => {
                    let (key, value) = argument.split_once(' ').unwrap_or((argument, ""));
                    guest.values.insert(key.to_owned(), value.to_owned());
                }
                "read" => {
                    if let Some(value) = guest.values.get(argument).cloned() {
                        self.send(APP_STDOUT, request_id, 0, value.as_bytes())?;
                    }
                }
                "mkdir" => {
                    guest.directories.insert(argument.to_owned());
                }
                "env" => {
                    for (name, value) in &environment {
                        let line = format!("{name}={value}\n");
                        if !self.forward(APP_STDOUT, request_id, &mut output, line.as_bytes())? {
                            return self.exit(request_id, 125, ExitCategory::OutputLimit);
                        }
                    }
                }
                "printenv" => {
                    let value = environment
                        .iter()
                        .find(|(variable, _)| variable == argument)
                        .map(|(_, value)| format!("{value}\n"));
                    match value {
                        Some(line) => {
                            if !self.forward(
                                APP_STDOUT,
                                request_id,
                                &mut output,
                                line.as_bytes(),
                            )? {
                                return self.exit(request_id, 125, ExitCategory::OutputLimit);
                            }
                        }
                        None => status = 1,
                    }
                }
                "pwd" => {
                    let line = format!("{cwd}\n");
                    self.send(APP_STDOUT, request_id, 0, line.as_bytes())?;
                }
                "timeout" => {
                    let line = format!("{timeout_ms}\n");
                    self.send(APP_STDOUT, request_id, 0, line.as_bytes())?;
                }
                "fail" => return self.exit(request_id, 125, ExitCategory::Failed),
                "launchfail" => {
                    return self.send_some(APP_ERROR, request_id, 125, LAUNCH_FAILED.as_bytes());
                }
                _ => {
                    let message = format!("{}: unknown command {name}\n", self.program);
                    self.send(APP_STDERR, request_id, 0, message.as_bytes())?;
                    return self.exit(request_id, 127, ExitCategory::Exit);
                }
            }
        }
        self.exit(request_id, status, ExitCategory::Exit)
    }

    /// Sends one frame and adapts success to the optional value expected by script execution.
    fn send_some(
        &mut self,
        kind: u8,
        request_id: u64,
        status: i32,
        payload: &[u8],
    ) -> io::Result<Option<()>> {
        self.send(kind, request_id, status, payload).map(Some)
    }

    /// Ends workload `request_id` with `status` and `category`.
    fn exit(
        &mut self,
        request_id: u64,
        status: i32,
        category: ExitCategory,
    ) -> io::Result<Option<()>> {
        self.send_some(APP_EXIT, request_id, status, category.as_str().as_bytes())
    }

    /// Forwards workload output unless it would exceed the guest agent's output limit, and
    /// returns whether it did. A workload whose output was refused ends with `output-limit`.
    fn forward(
        &mut self,
        kind: u8,
        request_id: u64,
        forwarded: &mut usize,
        output: &[u8],
    ) -> io::Result<bool> {
        if *forwarded + output.len() > MAX_OUTPUT_BYTES {
            return Ok(false);
        }
        *forwarded += output.len();
        self.send(kind, request_id, 0, output)?;
        Ok(true)
    }
}

/// Authenticates one client and serves it until it disconnects or stops the VM.
fn serve_client<S: Read + Write + Pending>(
    stream: &mut S,
    options: &Options,
    capability: &[u8; CAPABILITY_LEN],
    epoch: u64,
    guest: &mut Guest,
) -> Flow {
    let Ok(Some((header, payload))) = read_record(stream) else {
        return Flow::Continue;
    };
    if header.record_type != OUTER_HOST_ATTACH || payload != capability {
        let _ = stream.write_all(&control_record(OUTER_ERROR, &[0; 16], 0));
        return Flow::Continue;
    }
    let mut instance = [0u8; 16];
    while instance == [0; 16] {
        if getrandom::fill(&mut instance).is_err() {
            return Flow::Continue;
        }
    }
    if stream
        .write_all(&control_record(OUTER_READY, &instance, epoch))
        .is_err()
    {
        return Flow::Continue;
    }
    let mut session = Session {
        stream,
        program: &options.program,
        instance,
        epoch,
        guest_sequence: 1,
        host_sequence: 0,
        ignore_cancel: options.ignore_cancel,
        deferred: VecDeque::new(),
    };
    match session.run(options, guest) {
        Ok(Flow::Exit) => {
            write_report(options);
            Flow::Exit
        }
        _ => Flow::Continue,
    }
}

/// Writes the successful synthetic OpenVMM outcome report if the destination is new.
fn write_report(options: &Options) {
    let report = serde_json::json!({
        "schema_version": 1,
        "backend": options.hypervisor,
        "outcome": { "operation": "managed", "category": "success", "status_code": 0 },
        "network_policy": { "status": "not-requested" },
        "teardown": { "workers": true, "memory": true },
    });
    if let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&options.report)
    {
        let _ = file.write_all(report.to_string().as_bytes());
    }
}

#[cfg(unix)]
/// Serves the fake control endpoint as a Unix-domain socket until a stop request.
fn serve(options: &Options, capability: &[u8; CAPABILITY_LEN]) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let listener = UnixListener::bind(&options.endpoint)?;
    fs::set_permissions(&options.endpoint, fs::Permissions::from_mode(0o600))?;
    let mut guest = Guest::new(options);
    let mut epoch = 0;
    for stream in listener.incoming() {
        let mut stream = stream?;
        epoch += 1;
        if let Flow::Exit = serve_client(&mut stream, options, capability, epoch, &mut guest) {
            let _ = fs::remove_file(&options.endpoint);
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(windows)]
/// Serves the fake control endpoint as a Windows named pipe until a stop request.
fn serve(options: &Options, capability: &[u8; CAPABILITY_LEN]) -> io::Result<()> {
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

    use windows_sys::Win32::Foundation::{
        ERROR_NO_DATA, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    let name: Vec<u16> = std::ffi::OsStr::new(&options.endpoint.replace('/', "\\"))
        .encode_wide()
        .chain([0])
        .collect();
    // Like OpenVMM, serve every client on one pipe instance, so the endpoint exists for as long
    // as the process runs.
    // SAFETY: the name is NUL-terminated and default security is allowed.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65_536,
            65_536,
            0,
            std::ptr::null(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateNamedPipeW returned a fresh handle that nothing else owns.
    let mut file = File::from(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) });
    let pipe = file.as_raw_handle() as HANDLE;
    let mut guest = Guest::new(options);
    let mut epoch = 0;
    loop {
        // SAFETY: the handle is a pipe server instance; a null OVERLAPPED waits synchronously.
        if unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) } == 0 {
            // SAFETY: GetLastError has no preconditions.
            match unsafe { GetLastError() } {
                ERROR_PIPE_CONNECTED => {}
                // The client left before the connection was accepted.
                ERROR_NO_DATA => {
                    // SAFETY: the handle is a pipe server instance.
                    unsafe { DisconnectNamedPipe(pipe) };
                    continue;
                }
                error => return Err(io::Error::from_raw_os_error(error as i32)),
            }
        }
        epoch += 1;
        let flow = serve_client(&mut file, options, capability, epoch, &mut guest);
        // Wait until the client has read every reply: disconnecting discards unread data.
        let _ = file.sync_all();
        // SAFETY: the handle is a connected pipe server instance.
        unsafe { DisconnectNamedPipe(pipe) };
        if let Flow::Exit = flow {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shells_raise_shlvl_like_busybox() {
        let level = |value: &str| {
            let mut environment = vec![("SHLVL".to_owned(), value.to_owned())];
            start_shell(&mut environment, "/work");
            assert_eq!(environment[1], ("PWD".to_owned(), "/work".to_owned()));
            environment.swap_remove(0).1
        };
        assert_eq!(level("1"), "2");
        assert_eq!(level("7x"), "8");
        assert_eq!(level(" +3"), "4");
        assert_eq!(level("nothing"), "1");
        assert_eq!(level("4294967295"), "0");
        assert_eq!(level("-1"), "0");
        assert_eq!(level("-3"), "4294967294");
        let mut fresh = Environment::new();
        start_shell(&mut fresh, "/");
        assert_eq!(fresh[0], ("SHLVL".to_owned(), "1".to_owned()));
    }

    #[test]
    fn the_current_guest_advertises_every_required_feature() {
        assert_eq!(GUEST_FEATURES, GuestFeatures::REQUIRED);
        assert!(GUEST_FEATURES.missing(GuestFeatures::REQUIRED).is_empty());
    }

    /// Every argument the launcher emits must be one this double accepts.
    ///
    /// The launcher grew `--cpu-profile` and `--microvirtiofs-control` while the fake still
    /// rejected them, so every start failed with "unsupported argument" and the suites that use
    /// the fake quietly stopped running. This test fails the moment the two drift apart, instead
    /// of waiting for somebody to run those suites.
    #[test]
    fn the_launcher_emits_only_arguments_the_fake_accepts() {
        let directory = std::env::temp_dir().join("nvx-fake-arguments");
        std::fs::create_dir_all(&directory).expect("a temporary directory");
        // The fake checks that the artifacts it was told about exist; the contents are never read.
        for name in ["openvmm.exe", "vmlinux", "initramfs.cpio.gz"] {
            std::fs::write(directory.join(name), b"").expect("an empty artifact");
        }
        let artifacts = crate::host::artifacts::Artifacts::new(
            directory.join("openvmm.exe"),
            directory.join("vmlinux"),
            directory.join("initramfs.cpio.gz"),
        );
        let mut spec = crate::host::launch::LaunchSpec::new(
            artifacts,
            crate::Hypervisor::platform_default().expect("tests run on Linux or Windows"),
        );
        // The families that changed last: an explicit CPU profile, an export channel, and a
        // kernel parameter the launcher passes through.
        spec.cpu_profile = crate::host::launch::CpuProfile::Host;
        spec.kernel_parameters = "quiet".to_owned();

        let arguments = spec
            .openvmm_arguments_with_control(
                "//./pipe/nvx-fake-arguments",
                &directory.join("report.json"),
                Some("//./pipe/nvx-fake-export"),
            )
            .expect("the launcher builds arguments for a default specification");
        let arguments: Vec<String> = arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();

        parse("nvx-fake-openvmm", &arguments).unwrap_or_else(|error| {
            panic!("the launcher emits an argument the fake rejects: {error} in {arguments:?}")
        });
    }
}
