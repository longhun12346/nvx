# Ubuntu workload profile

The Ubuntu EROFS layer includes Python 3.14 and Node.js, a CA trust store, GNU wget,
curl, zip/unzip, fontconfig, Noto CJK and WenQuanYi Micro Hei fonts. Python packages
cover document, spreadsheet, presentation, PDF, chart and data-processing work.
The Playwright Python API is included; browser executables are not included.
Python wrappers such as pytesseract and pdf2image do not imply that their optional
external programs (Tesseract and Poppler) are installed.

`packages.lock.json` pins the supplemental Ubuntu packages, including their
source identities, licenses, download URLs and SHA-256 values. Builds extract
these packages without running maintainer scripts. The certificate bundle and
OpenSSL hash links are generated explicitly from the locked CA package. Fontconfig
can build its user cache on first use.

`workloads.requirements.txt` describes the workload capability baseline.
`workloads.lock.json` records the exact Python 3.14 / Linux x86_64 artifacts and
the bundled npm distribution. Every download is verified, and pip installs offline
with `--require-hashes --no-deps --no-index`. Plotille remains within the declared
`>=5,<6` range: its pinned 5.0.0 source archive is built offline using the pinned
setuptools wheel already supplied by the distro, and the resulting wheel must
match its locked hash. Build tooling is not added to the runtime package set.
The build checks every declared version range, the complete dependency closure
and the absence of unrelated Python packages (pip is runtime infrastructure).

`workloads-node/package.json` defines the eight direct Node workloads; its
`package-lock.json` pins their transitive dependencies with registry URLs and
SHA-512 integrity. A Node.js 22 build host downloads only Linux x64/glibc-compatible
tarballs, then runs `npm ci --offline --ignore-scripts`. No lifecycle hooks, source
compilation, browser downloads or additional top-level packages run or appear
during installation. Sharp uses its locked Linux x64 native packages.
Release builds never resolve floating ranges. Updating either profile requires
reviewing the lock and rerunning `tools/nvxd/tests/workloads.py` on a real VM.

Installed wheel metadata and licenses remain in
`/usr/local/lib/python3.14/dist-packages`; npm and its bundled dependencies remain
in `/usr/local/lib/node_modules/npm`. Node workloads live in
`/usr/local/lib/nvx-workloads/node_modules`; `/node_modules` points to that directory,
so CommonJS and ESM scripts in `/workspace` and `/tmp` find the supplied packages.
Task-local packages take precedence. Workload CLI links, including `omm`, are in
`/usr/local/bin`. `/usr/share/nvx/workloads.json` and the EROFS manifest record the
workload lock. Build-cache paths are removed from installed
metadata and script shebangs. Standard library and workload bytecode use guest
paths and hash invalidation.

Package-specific loading rules still apply. In particular, the locked G2 package's
ESM entry targets bundlers; native Node scripts use its CommonJS entry, or
`createRequire(import.meta.url)` from ESM. The profile does not add a bundler.

The system Python remains externally managed. For additional dependencies, create
a session-local environment, for example:

```sh
python3 -m venv --system-site-packages /home/session/task-env
/home/session/task-env/bin/python -m pip install PACKAGE
```

This environment and its download caches count toward the session's temporary
storage quota. Persist results in the authorized `/workspace`. npm's normal
per-user cache is likewise temporary. Network access remains subject to the
session's network policy; installing tooling does not grant network permission.

Matplotlib defaults to the headless Agg backend and a CJK-capable font. ReportLab
can use `/usr/share/fonts/truetype/wqy/wqy-microhei.ttc` as a TrueType font.

See `tools/nvxd-guest/ISOLATION.md` for the shared memory-backed filesystem budget.
`tools/nvxd/tests/workloads.py` checks low-memory quotas, ENOSPC/recovery, session
isolation, verified HTTPS, package imports, venv creation, and document/chart
generation. Run it with explicit release assets using the existing `NVX_*`
artifact environment variables.
