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
import tempfile
from urllib.parse import unquote, urlparse

from .build_constants import BuildConstants
from .common import ScriptError, cache_root, download_verified

LOCK = BuildConstants.REPO_ROOT / "ubuntu" / "workloads.lock.json"
REQUIREMENTS = BuildConstants.REPO_ROOT / "ubuntu" / "workloads.requirements.txt"
NODE_PROJECT = BuildConstants.REPO_ROOT / "ubuntu" / "workloads-node"
NODE_MANIFEST = NODE_PROJECT / "package.json"
NODE_LOCK = NODE_PROJECT / "package-lock.json"
CHECK = Path(__file__).with_name("workload_check.py")


def requirements() -> list[str]:
    return [line.strip() for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def load_lock() -> dict:
    document = json.loads(LOCK.read_text(encoding="utf-8"))
    if (document.get("format"), document.get("python"), document.get("architecture")) != (1, "3.14", "x86_64"):
        raise ScriptError("unsupported Ubuntu workload lock")
    if document.get("requirements") != requirements():
        raise ScriptError("Python workload requirements differ from the resolved lock")
    names = set()
    for package in document["packages"]:
        name = re.sub(r"[-_.]+", "-", package["name"]).lower()
        if name in names or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
            raise ScriptError("duplicate or invalid Python workload name")
        names.add(name)
        url = urlparse(package["url"])
        suffix = ".tar.gz" if "wheel" in package else ".whl"
        if url.scheme != "https" or url.netloc != "files.pythonhosted.org" or not url.path.endswith(suffix):
            raise ScriptError("Python workloads must be locked PyPI artifacts")
        if not re.fullmatch(r"[0-9a-f]{64}", package["sha256"]):
            raise ScriptError("invalid workload SHA-256")
        if "wheel" in package:
            for item in (package["wheel"], package["buildWheel"]):
                if (Path(item["filename"]).name != item["filename"]
                        or not item["filename"].endswith(".whl")
                        or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
                    raise ScriptError("invalid source-build wheel lock")
    npm = document["npm"]
    if npm["url"] != f"https://registry.npmjs.org/npm/-/npm-{npm['version']}.tgz":
        raise ScriptError("npm must come from the official registry")
    if not re.fullmatch(r"[0-9a-f]{64}", npm["sha256"]):
        raise ScriptError("invalid npm SHA-256")
    node = json.loads(NODE_MANIFEST.read_text(encoding="utf-8"))
    node_lock = json.loads(NODE_LOCK.read_text(encoding="utf-8"))
    if (document.get("node", {}).get("dependencies") != node["dependencies"]
            or node_lock.get("lockfileVersion") != 3
            or node_lock["packages"][""]["dependencies"] != node["dependencies"]
            or document["node"].get("lockSha256") != hashlib.sha256(NODE_LOCK.read_bytes()).hexdigest()):
        raise ScriptError("Node workload manifest differs from the resolved lock")
    for name, package in node_lock["packages"].items():
        if not name:
            continue
        url = urlparse(package.get("resolved", ""))
        if (url.scheme != "https" or url.netloc != "registry.npmjs.org"
                or not re.fullmatch(r"sha512-[A-Za-z0-9+/]+={0,2}", package.get("integrity", ""))):
            raise ScriptError(f"Node workload lacks a registry URL or SHA-512 integrity: {name}")
    return document


def build_source_wheel(root: Path, package: dict, source: Path, pip_wheel: Path) -> Path:
    """Build the explicitly pinned pure-Python sdist using the locked distro build wheel."""
    backend = root / "usr/share/python-wheels" / package["buildWheel"]["filename"]
    if hashlib.sha256(backend.read_bytes()).hexdigest() != package["buildWheel"]["sha256"]:
        raise ScriptError("source-build backend differs from its lock")
    output = source.parent / package["wheel"]["filename"]
    with tempfile.TemporaryDirectory(prefix="nvx-wheel-") as temporary:
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(map(str, (pip_wheel, backend))),
                   PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK="1",
                   PYTHONNOUSERSITE="1", SOURCE_DATE_EPOCH="0", PYTHONHASHSEED="0")
        subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps",
                        "--no-build-isolation", "--no-index", "--no-cache-dir",
                        "--wheel-dir", temporary, str(source)], env=env, check=True)
        wheel = Path(temporary) / package["wheel"]["filename"]
        if hashlib.sha256(wheel.read_bytes()).hexdigest() != package["wheel"]["sha256"]:
            raise ScriptError("source-built workload wheel differs from its lock")
        shutil.copyfile(wheel, output)
    return output


def install_node(root: Path, npm_root: Path, binaries: Path) -> None:
    node = shutil.which("node")
    if node is None:
        raise ScriptError("Node.js 22 is required to build the Ubuntu Node workloads")
    version = subprocess.check_output([node, "--version"], text=True).strip()
    if not version.startswith("v22."):
        raise ScriptError("Node workload installation requires Node.js 22")
    project = root / "usr/local/lib/nvx-workloads"
    project.mkdir(parents=True, exist_ok=True)
    for source in (NODE_MANIFEST, NODE_LOCK):
        shutil.copyfile(source, project / source.name)
    lock = json.loads(NODE_LOCK.read_text(encoding="utf-8"))
    urls = []
    for name, package in lock["packages"].items():
        if not name:
            continue
        if any(key in package and expected not in package[key]
               for key, expected in (("os", "linux"), ("cpu", "x64"), ("libc", "glibc"))):
            continue
        urls.append(package["resolved"])
    with tempfile.TemporaryDirectory(prefix="nvx-npm-") as temporary:
        # Do not inherit host npm configuration, caches or lifecycle hooks.
        env = {key: value for key, value in os.environ.items()
               if not key.lower().startswith("npm_config_")}
        for name in ("user.npmrc", "global.npmrc"):
            (Path(temporary) / name).touch()
        env.update(HOME=temporary, npm_config_userconfig=str(Path(temporary) / "user.npmrc"),
                   npm_config_globalconfig=str(Path(temporary) / "global.npmrc"), npm_config_cache=temporary,
                   npm_config_ignore_scripts="true")
        command = [node, str(npm_root / "bin/npm-cli.js"),
                   "--ignore-scripts", "--no-audit", "--fund=false",
                   "--os=linux", "--cpu=x64", "--libc=glibc"]
        # Fetch only the locked target-platform tarballs. ci validates their SRI before
        # extraction; no dependency resolution or network access occurs during installation.
        subprocess.run([*command, "cache", "add", *sorted(set(urls))], env=env, check=True)
        subprocess.run([*command, "ci", "--offline", "--omit=dev", "--include=optional"],
                       cwd=project, env=env, check=True)
    # Ancestor lookup supports both require() and ESM import from /workspace and /tmp.
    # A task's own node_modules still takes precedence.
    (root / "node_modules").symlink_to("usr/local/lib/nvx-workloads/node_modules")
    for entry in (project / "node_modules/.bin").iterdir():
        destination = binaries / entry.name
        if destination.exists() or destination.is_symlink():
            raise ScriptError(f"Node workload command conflicts with a runtime command: {entry.name}")
        destination.symlink_to(os.path.relpath(entry, binaries))


def install(root: Path) -> None:
    """Install locked workloads without floating resolution or npm lifecycle hooks."""
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
    for i, package in enumerate(lock["packages"]):
        if "wheel" in package:
            wheels[i] = build_source_wheel(root, package, wheels[i], pip_wheel)
    requirements = downloads / "requirements.lock.txt"
    requirements.write_text("".join(
        f"{wheel.as_uri()} --hash=sha256:{package.get('wheel', package)['sha256']}\n"
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
    subprocess.run([sys.executable, str(CHECK), str(target), str(LOCK)],
                   env=env, check=True)
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
    install_node(root, npm_root, binaries)
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
