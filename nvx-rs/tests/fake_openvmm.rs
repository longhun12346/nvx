//! Drives VM instances end to end against the `nvx-fake-openvmm` test double, which serves the
//! real control protocol without running a VM.
#![cfg(all(
    feature = "host",
    feature = "testing",
    any(target_os = "linux", windows)
))]

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use nvx::host::instance::{self, Instance, WorkloadOutcome};
use nvx::host::launch::{LaunchSpec, PROCESS_COMMAND_LINE_LIMIT};
use nvx::protocol::{Workload, WorkloadEnvironment};
use nvx::{Artifacts, ErrorKind, Hypervisor};

const TIMEOUT: Duration = Duration::from_secs(30);

/// Creates the fake guest artifacts and an instance directory below `directory`.
fn setup(directory: &Path) -> (LaunchSpec, Instance) {
    fs::write(directory.join("vmlinux"), b"kernel").unwrap();
    fs::write(directory.join("initramfs.cpio.gz"), b"initrd").unwrap();
    let artifacts = Artifacts::new(
        env!("CARGO_BIN_EXE_nvx-fake-openvmm"),
        directory.join("vmlinux"),
        directory.join("initramfs.cpio.gz"),
    );
    let hypervisor = Hypervisor::platform_default().expect("tests run on Linux or Windows");
    let state = directory.join("vm");
    instance::create_private_dir(&state).unwrap();
    (
        LaunchSpec::new(artifacts, hypervisor),
        Instance::new(state, "test"),
    )
}

fn workload(argv: &[&str]) -> Workload<'static> {
    Workload {
        argv: argv.iter().map(|argument| (*argument).to_owned()).collect(),
        timeout_ms: 0,
        cwd: None,
        environment: WorkloadEnvironment::Default,
        limits: nvx::protocol::ExecLimits::default(),
    }
}

struct Output {
    outcome: WorkloadOutcome,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(instance: &Instance, workload: &Workload<'_>, cancel: &AtomicBool) -> Output {
    let runtime = instance.runtime().unwrap().expect("the instance runs");
    let capability = instance.read_capability().unwrap();
    let execution = instance
        .exec(&runtime, &capability, workload, TIMEOUT, TIMEOUT)
        .unwrap();
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let outcome = execution
        .pump(
            &mut |chunk: &[u8]| {
                stdout.extend_from_slice(chunk);
                Ok(())
            },
            &mut |chunk: &[u8]| {
                stderr.extend_from_slice(chunk);
                Ok(())
            },
            cancel,
        )
        .unwrap();
    Output {
        outcome,
        stdout,
        stderr,
    }
}

#[test]
fn a_stop_after_the_guest_died_is_not_reported_as_forced() {
    let directory = tempfile::tempdir().unwrap();
    let (mut spec, instance) = setup(directory.path());
    spec.kernel_parameters = "fake_crash_after_ms=200".to_owned();
    let started = instance.start(&spec, TIMEOUT).unwrap();
    thread::sleep(Duration::from_secs(2));

    // The guest is gone, so the stop reaches nothing; that is not the same as a stop that had to
    // terminate a running VM, and the reported outcome says which one happened.
    let stopped = instance.stop(&started.runtime, TIMEOUT).unwrap();
    assert!(
        !stopped.forced,
        "a VM that had already exited was reported as forcibly stopped"
    );
}

#[test]
fn instances_start_run_workloads_and_stop() {
    let directory = tempfile::tempdir().unwrap();
    let (spec, instance) = setup(directory.path());
    assert_eq!(instance.reconcile().unwrap(), None);
    let started = instance.start(&spec, TIMEOUT).unwrap();
    assert_eq!(instance.reconcile().unwrap(), Some(started.runtime.clone()));
    // Only a running instance keeps a launch capability.
    assert!(instance.launch().unwrap().is_none());

    let idle = AtomicBool::new(false);
    let output = run(
        &instance,
        &workload(&["/bin/sh", "-c", "echo hello; echoerr warning; exit 3"]),
        &idle,
    );
    assert_eq!(output.outcome, WorkloadOutcome::Exited(3));
    assert_eq!(output.stdout, b"hello\n");
    assert_eq!(output.stderr, b"warning\n");
    let signaled = run(&instance, &workload(&["/bin/sh", "-c", "signal 15"]), &idle);
    assert_eq!(signaled.outcome, WorkloadOutcome::Signaled(15));
    let mut timed = workload(&["/bin/sh", "-c", "sleep 10000"]);
    timed.timeout_ms = 50;
    assert_eq!(
        run(&instance, &timed, &idle).outcome,
        WorkloadOutcome::TimedOut
    );
    let mut missing = workload(&["/bin/pwd"]);
    missing.cwd = Some("/missing");
    let refused = run(&instance, &missing, &idle);
    assert_eq!(refused.outcome, WorkloadOutcome::WorkingDirectory);
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("/missing"),
        "{:?}",
        refused.stderr
    );

    let stopped = instance.stop(&started.runtime, TIMEOUT).unwrap();
    assert!(!stopped.forced);
    let report = stopped.report.expect("the VM reports its outcome");
    assert_eq!(report.category.as_deref(), Some("success"));
    assert_eq!(report.teardown_complete, Some(true));
    assert_eq!(instance.reconcile().unwrap(), None);
    assert!(instance.read_capability().is_err());
}

#[test]
fn timeouts_are_checked_before_they_are_used() {
    let directory = tempfile::tempdir().unwrap();
    let (spec, instance) = setup(directory.path());
    for timeout in [Duration::ZERO, Duration::MAX] {
        let error = instance.start(&spec, timeout).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unsupported, "{error}");
        // Nothing was launched.
        assert!(instance.launch().unwrap().is_none());
        assert!(instance.runtime().unwrap().is_none());
    }
    let started = instance.start(&spec, TIMEOUT).unwrap();
    let capability = instance.read_capability().unwrap();
    let echo = workload(&["/bin/echo", "hello"]);
    for (control_timeout, response_grace) in [
        (Duration::ZERO, TIMEOUT),
        (Duration::MAX, TIMEOUT),
        (TIMEOUT, Duration::MAX),
    ] {
        let Err(error) = instance.exec(
            &started.runtime,
            &capability,
            &echo,
            control_timeout,
            response_grace,
        ) else {
            panic!("exec accepted {control_timeout:?} and {response_grace:?}");
        };
        assert_eq!(error.kind(), ErrorKind::Unsupported, "{error}");
    }
    for timeout in [Duration::ZERO, Duration::MAX] {
        let error = instance.stop(&started.runtime, timeout).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unsupported, "{error}");
    }
    // The refused requests left the VM running.
    let idle = AtomicBool::new(false);
    let output = run(&instance, &echo, &idle);
    assert_eq!(output.outcome, WorkloadOutcome::Exited(0));
    assert_eq!(output.stdout, b"hello\n");
    instance.stop(&started.runtime, TIMEOUT).unwrap();
}

#[test]
fn launches_beyond_the_process_command_line_limit_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let (mut spec, instance) = setup(directory.path());
    // The program's path counts toward the command line, which every host holds to the limit.
    spec.openvmm = directory
        .path()
        .join("o".repeat(PROCESS_COMMAND_LINE_LIMIT));
    let error = instance.start(&spec, TIMEOUT).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unsupported, "{error}");
    // Nothing was launched or recorded.
    assert!(instance.launch().unwrap().is_none());
    assert!(instance.runtime().unwrap().is_none());
    assert!(instance.read_capability().is_err());
}

#[test]
fn cancellation_ends_a_running_workload() {
    let directory = tempfile::tempdir().unwrap();
    let (spec, instance) = setup(directory.path());
    let started = instance.start(&spec, TIMEOUT).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let canceller = thread::spawn({
        let cancel = Arc::clone(&cancel);
        move || {
            thread::sleep(Duration::from_millis(200));
            cancel.store(true, Ordering::Release);
        }
    });
    let output = run(
        &instance,
        &workload(&["/bin/sh", "-c", "echo started; sleep 60000"]),
        &cancel,
    );
    canceller.join().unwrap();
    assert_eq!(output.outcome, WorkloadOutcome::Cancelled);
    assert_eq!(output.stdout, b"started\n");
    instance.stop(&started.runtime, TIMEOUT).unwrap();
}

#[test]
fn guests_without_required_features_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let (mut spec, instance) = setup(directory.path());
    // Cancellation alone.
    spec.kernel_parameters = "fake_guest_features=1".to_owned();
    let error = instance.start(&spec, TIMEOUT).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unavailable);
    assert!(
        error.message().contains("lacks control features"),
        "{error}"
    );
    assert!(error.message().contains("sandbox test failed to start"));
    // The rejected VM is gone and leaves no runtime state behind.
    assert_eq!(instance.reconcile().unwrap(), None);
    assert!(instance.runtime().unwrap().is_none());
}

#[test]
fn launches_that_exit_fail_to_start() {
    let directory = tempfile::tempdir().unwrap();
    let (mut spec, instance) = setup(directory.path());
    spec.kernel_parameters = "fake_exit_on_start=4".to_owned();
    let error = instance.start(&spec, TIMEOUT).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Exited, "{error}");
    assert!(
        error
            .message()
            .contains(&instance.log_path().display().to_string()),
        "{error}"
    );
    assert_eq!(instance.reconcile().unwrap(), None);
}
