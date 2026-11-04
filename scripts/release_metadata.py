"""Create release metadata at publication time; consumers need no Git checkout."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def generate(repo, revision, binaries, guest):
    def git(*args, directory=repo):
        return subprocess.check_output(["git", "-C", str(directory), *args])

    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Expected a full commit hash")
    openvmm = git("ls-tree", revision, "openvmm").decode().split()[2]
    sources = {}
    for name, directory, sha in [("nvx", repo, revision), ("openvmm", repo / "openvmm", openvmm)]:
        sources[name] = {"revision": sha, "treeDigest": git("rev-parse", sha + "^{tree}", directory=directory).decode().strip()}
    files = {}
    for group, root in [("bin", binaries), ("guest", guest)]:
        for file in sorted(root.iterdir()):
            if file.is_file() and file.name != "SHA256SUMS":
                files[f"{group}/{file.name}"] = hashlib.sha256(file.read_bytes()).hexdigest()
    for root in [binaries, guest]:
        for line in (root / "SHA256SUMS").read_text().splitlines():
            digest, name = line.split(maxsplit=1)
            if hashlib.sha256((root / name.lstrip("*")).read_bytes()).hexdigest() != digest:
                raise ValueError("Artifact checksum mismatch")
    for root, name in [(binaries, "BUILD-INFO.txt"), (guest, "GUEST-INFO.txt")]:
        info = dict(line.split("=", 1) for line in (root / name).read_text().splitlines() if "=" in line)
        if info.get("nvx_revision") != revision or (root == binaries and info.get("openvmm_revision") != openvmm):
            raise ValueError("Artifact revision mismatch")
    cargo = git("show", revision + ":tools/nvxd/Cargo.toml").decode()
    return {
        "schemaVersion": 1,
        "version": git("show", revision + ":VERSION").decode().strip(),
        "nvxdVersion": re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.M).group(1),
        "sources": sources,
        "ubuntuPackagesLockSha256": hashlib.sha256(git("show", revision + ":ubuntu/packages.lock.json")).hexdigest(),
        "files": files,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--revision", required=True)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--guest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    metadata = generate(args.repo, args.revision, args.binaries, args.guest)
    args.output.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(metadata, indent=2) + "\n").encode()
    (args.output / "nvx-release-metadata.json").write_bytes(data)
    (args.output / "nvx-release-metadata.sha256").write_text(
        hashlib.sha256(data).hexdigest() + "  nvx-release-metadata.json\n", encoding="utf-8")
