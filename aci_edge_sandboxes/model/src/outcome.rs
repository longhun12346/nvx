//! Terminal outcomes of executions.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Terminal outcome of an execution.
///
/// It serializes as `{"exited": 0}`, `{"signaled": 9}`, `"timedOut"`, `"cancelled"`, or
/// `{"failed": "launchFailed"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum ExecOutcome {
    /// The workload exited with this status code.
    Exited(i32),
    /// The workload was terminated by this signal number.
    Signaled(i32),
    /// The workload was killed for memory, with the signal number that ended it.
    ///
    /// `vm_wide` distinguishes VM-wide pressure from hitting the execution's own limit.
    /// The victim may also have caused the global pressure; this is not a retry guarantee.
    /// Ordinary external signals remain [`Signaled`](Self::Signaled).
    OutOfMemory {
        /// The signal that ended the workload.
        signal: i32,
        /// True when the whole VM ran out of memory.
        vm_wide: bool,
    },
    /// The workload overran `process.timeout` and is no longer running.
    TimedOut,
    /// The workload was cancelled at the caller's request and is no longer running.
    Cancelled,
    /// The workload could not run to completion.
    Failed(ExecFailure),
}

impl ExecOutcome {
    /// Returns whether the workload exited with status zero.
    pub fn success(self) -> bool {
        self == Self::Exited(0)
    }

    /// Returns the exit status of an [`ExecOutcome::Exited`] workload.
    pub fn exit_code(self) -> Option<i32> {
        match self {
            Self::Exited(code) => Some(code),
            _ => None,
        }
    }
}

impl fmt::Display for ExecOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exited(code) => write!(formatter, "exited with status {code}"),
            Self::Signaled(signal) => write!(formatter, "terminated by signal {signal}"),
            Self::OutOfMemory { signal, vm_wide: false } => {
                write!(formatter, "killed by its own memory limit (signal {signal})")
            }
            Self::OutOfMemory { signal, vm_wide: true } => {
                write!(formatter, "killed by the VM running out of memory (signal {signal})")
            }
            Self::TimedOut => formatter.write_str("timed out"),
            Self::Cancelled => formatter.write_str("cancelled"),
            Self::Failed(failure) => write!(formatter, "failed: {failure}"),
        }
    }
}

/// Reason an execution failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum ExecFailure {
    /// The sandbox could not launch the workload.
    LaunchFailed,
    /// The workload's working directory (`process.cwd`, or the backend's default) does not exist,
    /// is not a directory, or is not accessible to the workload, so the workload did not run.
    WorkingDirectory,
    /// The workload exceeded the backend's output limit and was terminated.
    OutputLimitExceeded,
    /// The sandbox lost track of the workload's exit status.
    Workload,
}

impl fmt::Display for ExecFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LaunchFailed => "the workload could not be launched",
            Self::WorkingDirectory => {
                "the workload's working directory does not exist, is not a directory, or is not \
                 accessible to the workload"
            }
            Self::OutputLimitExceeded => "the workload exceeded the output limit",
            Self::Workload => "the workload's exit status could not be determined",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_round_trip_through_their_wire_spelling() {
        for (outcome, json) in [
            (ExecOutcome::Exited(7), r#"{"exited":7}"#),
            (ExecOutcome::Signaled(9), r#"{"signaled":9}"#),
            (ExecOutcome::TimedOut, r#""timedOut""#),
            (ExecOutcome::Cancelled, r#""cancelled""#),
            (
                ExecOutcome::Failed(ExecFailure::WorkingDirectory),
                r#"{"failed":"workingDirectory"}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&outcome).unwrap(), json);
            assert_eq!(serde_json::from_str::<ExecOutcome>(json).unwrap(), outcome);
        }
    }
}
