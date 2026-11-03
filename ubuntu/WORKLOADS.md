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
`workloads.lock.json` is the resolved Python 3.14 / Linux x86_64 wheel set and the
bundled npm distribution. Every download is verified, and pip installs offline
with `--require-hashes --no-deps --no-index`. Release builds do not resolve version
ranges or build source distributions. Plotille uses the 6.x wheel distribution;
its older 5.x releases have no wheel. Updating the lock requires reviewing the
new versions and rerunning `tools/nvxd/tests/workloads.py` on a real VM.

Installed wheel metadata and licenses remain in
`/usr/local/lib/python3.14/dist-packages`; npm and its bundled dependencies remain
in `/usr/local/lib/node_modules/npm`. `/usr/share/nvx/workloads.json` and the EROFS
manifest record the workload lock. Build-cache paths are removed from installed
metadata and script shebangs. Standard library and workload bytecode use guest
paths and hash invalidation.

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
