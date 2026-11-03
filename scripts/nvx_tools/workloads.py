"""Locked, offline-installed document and data tooling for the Ubuntu guest."""

from __future__ import annotations

import compileall
import concurrent.futures
import base64
import csv
import hashlib
import json
import os
from pathlib import Path
import py_compile
import re
import shutil
import subprocess
import sys
import tarfile
from urllib.parse import unquote, urlparse

from .build_constants import BuildConstants
from .common import ScriptError, cache_root, download_verified

LOCK = BuildConstants.REPO_ROOT / "ubuntu" / "workloads.lock.json"
REQUIREMENTS = BuildConstants.REPO_ROOT / "ubuntu" / "workloads.requirements.txt"


def load_lock() -> dict:
    document = json.loads(LOCK.read_text(encoding="utf-8"))
    if (document.get("format"), document.get("python"), document.get("architecture")) != (1, "3.14", "x86_64"):
        raise ScriptError("unsupported Ubuntu workload lock")
    names = set()
    for package in document["packages"]:
        name = re.sub(r"[-_.]+", "-", package["name"]).lower()
        if name in names or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
            raise ScriptError("duplicate or invalid Python workload name")
        names.add(name)
        url = urlparse(package["url"])
        if url.scheme != "https" or url.netloc != "files.pythonhosted.org" or not url.path.endswith(".whl"):
            raise ScriptError("Python workloads must be locked PyPI wheels")
        if not re.fullmatch(r"[0-9a-f]{64}", package["sha256"]):
            raise ScriptError("invalid workload SHA-256")
    npm = document["npm"]
    if npm["url"] != f"https://registry.npmjs.org/npm/-/npm-{npm['version']}.tgz":
        raise ScriptError("npm must come from the official registry")
    if not re.fullmatch(r"[0-9a-f]{64}", npm["sha256"]):
        raise ScriptError("invalid npm SHA-256")
    return document


def install(root: Path) -> None:
    """Install verified wheels without network resolution, scripts or source builds."""
    if sys.version_info[:2] != (3, 14):
        raise ScriptError("Ubuntu workloads require a Python 3.14 build interpreter")
    lock = load_lock()
    downloads = cache_root() / "downloads" / "workloads"
    downloads.mkdir(parents=True, exist_ok=True)

    def fetch(package: dict) -> Path:
        filename = unquote(urlparse(package["url"]).path.rsplit("/", 1)[-1])
        if Path(filename).name != filename:
            raise ScriptError("invalid workload filename")
        path = downloads / filename
        download_verified(package["url"], path, package["sha256"])
        return path

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        wheels = list(pool.map(fetch, lock["packages"]))
    pip_wheel = wheels[next(i for i, p in enumerate(lock["packages"]) if p["name"].lower() == "pip")]
    requirements = downloads / "requirements.lock.txt"
    requirements.write_text("".join(
        f"{wheel.as_uri()} --hash=sha256:{package['sha256']}\n"
        for package, wheel in zip(lock["packages"], wheels, strict=True)
    ), encoding="utf-8")
    target = root / "usr/local/lib/python3.14/dist-packages"
    target.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONPATH=str(pip_wheel), PIP_CONFIG_FILE=os.devnull,
               PIP_DISABLE_PIP_VERSION_CHECK="1", PYTHONNOUSERSITE="1")
    subprocess.run([
        sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
        "--require-hashes", "--no-compile", "--no-cache-dir",
        "--target", str(target), "-r", str(requirements),
    ], env=env, check=True)
    binaries = root / "usr/local/bin"
    binaries.mkdir(parents=True, exist_ok=True)
    for script in (target / "bin").iterdir():
        data = script.read_bytes()
        if data.startswith(b"#!"):
            data = b"#!/usr/bin/python3\n" + data.split(b"\n", 1)[1]
        destination = binaries / script.name
        destination.write_bytes(data)
        destination.chmod(0o755)
    shutil.rmtree(target / "bin")
    # pip otherwise records absolute build-cache URLs in the installed metadata.
    for direct in target.glob("*.dist-info/direct_url.json"):
        direct.unlink()
    if not compileall.compile_dir(str(target), ddir="/usr/local/lib/python3.14/dist-packages",
                                 quiet=1, force=True, optimize=0, workers=1,
                                 invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH):
        raise ScriptError("failed to byte-compile workload packages")

    # npm's registry archive includes its own dependencies. No install hooks are executed.
    archive = fetch(lock["npm"])
    npm_root = root / "usr/local/lib/node_modules/npm"
    npm_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as source:
        members = source.getmembers()
        for member in members:
            if not member.name.startswith("package/"):
                raise ScriptError("unexpected npm archive layout")
            member.name = member.name[len("package/"):]
            if not member.name or member.issym() or member.islnk():
                raise ScriptError("unexpected npm archive link or empty entry")
        source.extractall(npm_root, members=members, filter="data")
    for name in ("npm", "npx"):
        (binaries / name).symlink_to(f"../lib/node_modules/npm/bin/{name}-cli.js")
    # Font selection is explicit so charts with Chinese labels work without task-specific setup.
    mpl = target / "matplotlib/mpl-data/matplotlibrc"
    settings = {"backend": "Agg", "font.family": "sans-serif",
                "font.sans-serif": "WenQuanYi Micro Hei, Noto Sans CJK JP, DejaVu Sans",
                "axes.unicode_minus": "False"}
    text = mpl.read_text(encoding="utf-8")
    for key, value in settings.items():
        text, count = re.subn(r"(?m)^#*\s*" + re.escape(key) + r":[^\n]*",
                             f"{key}: {value}", text)
        if count != 1:
            raise ScriptError(f"unexpected matplotlib default setting: {key}")
    mpl.write_text(text, encoding="utf-8")
    # Keep RECORD portable and consistent after relocating scripts and removing local URLs.
    for record in target.glob("*.dist-info/RECORD"):
        rows = []
        with record.open(newline="", encoding="utf-8") as source:
            for name, _, _ in csv.reader(source):
                if name.endswith("/direct_url.json"):
                    continue
                if name.startswith("../../bin/"):
                    name = "../" + name
                elif name.startswith("../../"):
                    # --target retains wheel data/headers below the target directory.
                    name = name[len("../../"):]
                path = target / name
                if path == record:
                    rows.append((name, "", ""))
                elif path.is_file():
                    data = path.read_bytes()
                    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
                    rows.append((name, "sha256=" + digest, str(len(data))))
                else:
                    raise ScriptError(f"missing installed workload file: {name}")
        with record.open("w", newline="", encoding="utf-8") as destination:
            csv.writer(destination, lineterminator="\n").writerows(rows)
    manifest = root / "usr/share/nvx/workloads.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")


def configure_trust(root: Path) -> None:
    """Reproduce the certificate-package setup without running maintainer scripts."""
    certificates = sorted((root / "usr/share/ca-certificates").rglob("*.crt"))
    if not certificates:
        raise ScriptError("the Ubuntu guest has no trust certificates")
    output = root / "etc/ssl/certs"
    output.mkdir(parents=True, exist_ok=True)
    (output / "ca-certificates.crt").write_bytes(b"".join(
        path.read_bytes().rstrip() + b"\n" for path in certificates
    ))
    (root / "etc/ca-certificates.conf").write_text("".join(
        path.relative_to(root / "usr/share/ca-certificates").as_posix() + "\n" for path in certificates
    ), encoding="utf-8")
    for certificate in certificates:
        name = certificate.stem + ".pem"
        (output / name).symlink_to(os.path.relpath(certificate, output))
        subject = subprocess.check_output(
            ["openssl", "x509", "-hash", "-noout", "-in", str(certificate)], text=True
        ).strip()
        if not re.fullmatch(r"[0-9a-f]{8}", subject):
            raise ScriptError("invalid certificate subject hash")
        index = 0
        while (output / f"{subject}.{index}").is_symlink():
            index += 1
        (output / f"{subject}.{index}").symlink_to(name)
    # Debian's OpenSSL default paths are reached through /usr/lib/ssl.
    ssl = root / "usr/lib/ssl"
    if not ssl.exists() and not ssl.is_symlink():
        ssl.symlink_to("../../etc/ssl")
    (root / "etc/ssl/cert.pem").symlink_to("certs/ca-certificates.crt")
