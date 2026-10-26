"""Validate the target-guest P8 probe report as a mandatory gate input.

The kernel probe is executed by the product verification harness because it needs a diagnostic
initrd. This companion test keeps the result in the same required-case accounting as the
sidecar suites and rejects an old, partial, or failed report.
"""

from __future__ import annotations

import argparse
import json
import pathlib


REQUIRED_CHECKS = {
    "requires-root",
    "disposable-agent-state",
    "workspace-fixtures",
    "session-wire",
    "unknown-network-policy-refused",
    "workspace-symlink-refused",
    "agent-secret-fd",
    "create-a",
    "create-b",
    "production-scheduler-two-by-two-cgroups",
    "identity-proc-capabilities-fds",
    "a-private-state",
    "same-session-state",
    "cross-session-state",
    "same-session-sysv-ipc",
    "cross-session-sysv-ipc-denied",
    "late-mount-fixtures",
    "same-target-in-independent-sessions",
    "late-mount-write-isolated",
    "foreign-source-denied",
    "mount-traversal-denied",
    "recursive-readonly-enforced",
    "private-unmount-preserves-other-authorized-view",
    "b-mount-survives-a-unmount",
    "all-private-directory-mounts-revoked",
    "file-source",
    "file-bind-and-strict-unmount",
    "busy-revoke-fixture",
    "busy-revoke-holder",
    "busy-revoke-escalates-group-failure",
    "scoped-mount-matrix",
    "a-loopback-server",
    "cross-session-loopback-denied",
    "same-session-loopback",
    "agent-descriptors-preserved",
    "close-a",
    "b-survives-a-close",
    "id-reuse-refused",
    "reopen-new-id",
    "private-state-reset-authorized-workspace-persists",
    "cleanup-all",
    "session-directories-removed",
    "legacy-migration-refused",
    "fault-injection-session",
    "fault-injection-kill-keeper",
    "fault-injection-reap-keeper",
    "keeper-loss-escalates-group-failure",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if not args.report.is_file():
        raise RuntimeError(f"guest probe report is missing: {args.report}")
    report = json.loads(args.report.read_text(encoding="utf-8"))
    if report.get("passed") is not True or report.get("exitCode") != 0:
        raise RuntimeError(f"guest probe did not pass: {report}")
    scope = report.get("scope", "")
    if "guest session lifecycle" not in scope.lower():
        raise RuntimeError(f"guest probe scope is not a session lifecycle report: {scope!r}")
    checks = set(report.get("checks") or [])
    missing = sorted(REQUIRED_CHECKS - checks)
    if missing:
        raise RuntimeError(f"guest probe report is missing checks: {missing}")
    print("CASE p8.guest_probe.target_negative_matrix PASS", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        raise SystemExit(f"guest probe report validation failed: {error!r}")
