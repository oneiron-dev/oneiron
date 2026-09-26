# Linux seal reader matrix

This is an opt-in interoperability harness, not a Cargo test. It installs tools only below
`/mnt/wd16/w8-build/seal-interop` (override with `SEAL_INTEROP_HOME`) and never uses sudo.

## Install and run

```bash
scripts/seal-interop/install.sh
scripts/seal-interop/run.sh /path/to/sealed.pdf
# One reader, suitable for the `oneiron-seal` oracle test:
scripts/seal-interop/run.sh --reader pdfbox /path/to/sealed.pdf
# Configure the opt-in Cargo oracle legs. The source test remains unchanged unless these are set.
ROOT=/mnt/wd16/w8-build/seal-interop
source "$ROOT/reader-env.sh"
cargo test --locked -p oneiron-seal --features seal-oracle --test oracle
```

The retained two-revision fixtures exercise the wrappers against a valid earlier
signature and a corrupt later signature. After installation, run
`SEAL_INTEROP_INTEGRATION=1 python3 -m unittest discover -s scripts/seal-interop -p test_readers.py -v`.
To regenerate these fixtures with the pinned pyHanko environment, run
`ROOT="${SEAL_INTEROP_HOME:-/mnt/wd16/w8-build/seal-interop}"; "$ROOT/venv/bin/python" scripts/seal-interop/make_multisig_fixture.py`.

The full runner prints TSV with `reader`, `version`, `os_proxy`, `mode`, `status`, and `detail`.
Each per-reader wrapper prints one JSON object with `reader`, `version`, `mode`, and `status`;
optional `detail` and `os_proxy` fields add context. A single-reader run exits 0 for a completed check (including a reported qpdf warning), 1 for failure, or 77 when unavailable. The full matrix exits 77 if **no reader ran**, 1 if any reader failed, and 0 if the available readers passed; a partially available matrix prints `PARTIAL-MATRIX` to stderr and is **not full reader coverage**. Each unavailable row remains visible. qpdf warning rows retain `status=warning` and are not clean structural passes.

## Evidence meaning

- **Verification**: Poppler `pdfsig`, PDFBox + Bouncy Castle, EU DSS, and pyHanko check the
  cryptographic PDF signature. A certificate trust warning is reported separately and is not
  treated as cryptographic signature corruption. These tools do not establish a production trust
  policy, remote timestamp validity, or long-term validation.
- **Parse only**: PDFium parses signature objects and checks each signature object's `/ByteRange` reaches the end of its own signed PDF revision, excluding exactly that object's hex `/Contents` bytes. The pinned pyHanko parser supplies the signature object's xref location for this source-span check; PDFium still does the signature-object parse. An unsupported source encoding does not establish coverage. It separately reports final-document coverage; it does not assess whether later changes are permitted. pdf.js opens the document and finds signature fields. Its public field API does not expose the associated `/V` dictionary, so **pdf.js makes no ByteRange coverage claim**; scanning unrelated PDF text for `/ByteRange` would give false results. Neither engine check verifies CMS or certificate trust.
- **Check**: qpdf runs `--check`; warnings are preserved in `detail`. It is a structural check, not
  signature verification.
- **OS proxy** uses the detected host architecture, e.g. `linux-x86_64/<distro>` or `linux-aarch64/<distro>`: results use Linux builds or Linux wheels,
  not macOS/iOS native PDF frameworks. Poppler rows are version-pinned. They do not substitute for
  native platform testing.

Poppler versions: 22.02.0 is built from checksummed upstream source because conda-forge has no
Linux package for that exact version. All four rows pin exact versions. In this run, 25.02.0 and
26.05.0 are conda-forge builds under the task root, while 24.02.0 reuses the preinstalled
exact-version binary at `/home/lexi/w8-opus/poppler-2402/bin/pdfsig`. They are Linux builds and
version proxies for distro viewers, not direct runs on Ubuntu or Debian.
Other pins: DSS 6.5, PDFBox 3.0.6, pyHanko 0.35.2 (the crate oracle lock), pypdfium2 4.30.0,
pdfjs-dist 5.4.394, qpdf 12.3.2, Bouncy Castle 1.80 (PDFBox) / 1.85 (EU DSS). For Poppler 24/26, install.sh reuses an exact-version preinstalled host binary when present and otherwise installs the exact conda-forge package under the root. `reader-env.sh` sets `PDFSIG_EXTRA_BINARIES` to full executable paths (not directories) and omits unavailable versions. `pins.json` is the machine-readable list.

## macOS PDFKit parse probe

On a Mac with Swift/PDFKit, run `swift scripts/seal-interop/pdfkit.swift before.pdf after.pdf`.
It exercises PDFDocument loading, page access, and signature-widget enumeration only. It is not
CMS/PAdES verification, trust/revocation, signed-byte integrity, rendering, Preview qualification,
or writer round-trip evidence.
