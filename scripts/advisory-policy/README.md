# Exact maintenance-risk acceptance (ONE-335)

These are **accepted maintenance risks, not fixes**. The 2026-09-07 owner grant
and standing-authority extension cover only the **19** advisory ID / package /
locked-version triples in `exceptions.json` and `check.py`'s `AUTHORIZED` set:
the original 16 plus `bitmaps 2.1.0` / `RUSTSEC-2026-0247`, `im 15.1.0` /
`RUSTSEC-2026-0248`, and `sized-chunks 0.6.5` / `RUSTSEC-2026-0251`.
No new vulnerability exception is granted. Required Linux support remains in
the all-features, unfiltered dependency graph. [POSTWAVE.md](POSTWAVE.md) banks
the fresh evidence, required Loro chain, no-supported-safe-upgrade rationale,
and standing delegation for post-wave review.

## Deadline and review

- Acceptance ends at **2026-10-07T00:00:00Z**, or the post-wave context-pack
  discussion, whichever comes first. The expiry boundary itself is blocked.
- The owner must record the discussion time in `review.post_wave_at` as a UTC
  timestamp ending in `Z` as soon as it is scheduled (or at its start if it was
  not scheduled). `null` means the discussion has not been scheduled/recorded;
  it does **not** mean review was completed. There is no external calendar feed:
  the guard enforces the recorded event and the unconditional expiry, but cannot
  detect an unrecorded meeting.
- At that time, retire these acceptances and review the maintenance risks. A
  completed discussion is not permission to clear its timestamp or extend the
  grant. **No automatic renewal.** Renewal or materially different risk needs
  new owner authority and a separately reviewed policy change, not a date bump.
- Within the unchanged window, the standing delegation lets the current ticket
  owner add inspected equivalent informational-unmaintained cases without
  per-ID owner/Board approval. Each needs an explicit ID/package/version entry
  in code and data, exact dependency context, and a record of why no supported
  safe upgrade is available. There is **no runtime blanket autoallow**; fresh unlisted
  findings remain blocking until an explicit qualifying policy change is reviewed.
- Re-evaluate on package/version/source changes, changed direct dependency
  parents, the `tauri-utils -> urlpattern` and
  `loro 1.13.9 -> loro-internal 1.13.9 -> im 15.1.0` contexts, or advisory
  classification / affected-version changes. Package removal also blocks until
  the obsolete exception is retired through review. Other relevant dependency
  changes must be reviewed, even when they do not change the recorded direct-parent
  context.

## Effective command

Use Python 3.11+ (standard library only) and cargo-deny **0.19.4**:

```sh
python3 scripts/advisory-policy/check.py
# Local cached evidence only; no network and no lockfile update:
python3 scripts/advisory-policy/check.py --offline
```

The existing CI deny job runs the tests and the first command on manual
`workflow_dispatch` runs. Its matching job condition keeps the checks reachable
under the existing manual-only workflow policy. This extension does not change
workflows, triggers, job conditions, or runner platforms. The guard still checks
advisories, licenses, bans, and sources.

The wrapper:

1. Checks the owner grant, UTC deadline/review, all locked occurrences and sources
   of each accepted package, and recorded dependency context. It refuses extra
   permanent ignores, graph pruning, broad informational settings, or a changed
   tool version.
2. Fetches the configured RustSec DB into a private temporary cache. Offline
   mode instead snapshots the configured local cache; it is not fresh-DB evidence.
3. Reads each accepted advisory from that same cache. Only its exact ID/package,
   `informational = "unmaintained"`, and unchanged all-versions affected scope
   qualify. Missing/duplicate/moved/malformed records, vulnerability classification,
   CVSS/alias/affected metadata, withdrawal, and version-range changes block.
4. Adds only the 19 IDs to a **temporary** copy of `deny.toml` and invokes:
   `cargo deny --locked check --disable-fetch --config <temporary-config>` without
   CLI lint-level overrides. Pinned cargo-deny 0.19.4 makes non-ignored vulnerability,
   unmaintained, notice, and unsound findings errors. Ignored IDs emit notes with
   their original advisory code; `--deny <code>` would promote even those notes
   back to errors, breaking both temporary and pre-existing exceptions. The tool
   version guard prevents silently adopting changed defaults.
   Offline mode also passes `--offline`. No output filtering or nonzero-exit
   suppression occurs. The guard checks time and lockfile integrity again before
   and after the check, and removes the temporary configuration on exit.

The permanent `deny.toml` deliberately does **not** contain these 19 ignores.
A plain `cargo deny check` remains stricter; it cannot accidentally use expired
acceptances. Existing atomic-polyfill, bincode, smallstr, and rsa decisions are
preserved separately and are not renewed by this grant. In particular, the
pre-existing rsa vulnerability exception is not a new ONE-335 waiver.

## Inspection and validation handoff

Prior read-only inspection found installed `cargo-deny 0.19.4`. Its `--help`,
`check --help`, `fetch --help`, and embedded config describe advisory exceptions
as IDs with optional reasons, not package/version/classification/expiry guards.
The local cache for the configured RustSec URL uses
`advisory-db-3157b0e258782691`; the real-command fixture pins that observed layout
along with the tool version. A changed layout/tool must fail, not skip tests.

The current `Cargo.lock` was read, not recreated: SHA-256
`1d31f3cdb3ac79e9fb610c8a76cb7349949caba096cb9a7918018ecfadc84ad6`.
All 19 versions match the original grant and exact3 extension; chacha20 is
already 0.10.2. The old baseline packet's lock hash is not a required lockfile
image.

Controller validation commands (not executed by the author):

```sh
python3 -m unittest discover -s scripts/advisory-policy -p 'test_*.py' -v
# Fresh network-backed validation when authorized (also the CI command):
python3 scripts/advisory-policy/check.py
# Optional cached diagnostic only; the old offline DB lacks the three new IDs:
python3 scripts/advisory-policy/check.py --offline
```

The old offline DB must fail for missing records; it cannot validate the exact3
extension. Use a fresh DB for the later current-candidate validation. Do not
skip missing advisories or loosen classification to make that old cache pass.
The fresh disposition records prior-candidate evidence, not a successful check
of this extension on the current candidate.

A standard-library regression pins the manual-only trigger and the deny job's
matching condition, with no upstream job dependency that could skip it. The
original 23 tests and their assertions are retained, with count-sensitive
expectations updated to 19 temporary / 23 effective exceptions. Two exact3
regressions bring the total to 25: required Loro links and every direct-parent
edge must stay intact, and missing new advisory records must fail closed.

The deterministic suite includes all 19 exact entries, version/source/context
changes, extra/new/unlisted IDs, vulnerabilities, classification changes,
expiry boundaries, earlier review, no renewal, command exit propagation, and
private-config cleanup. Real cargo-deny tests create a temporary local Git
advisory DB and supply synthetic cargo metadata. They do not compile Rust or
fetch data. They isolate the advisory behavior by disabling only the synthetic
fixture's unrelated yanked-index check; production retains `yanked = "deny"`.
They demonstrate why naked ID ignores are unsafe for version/classification
changes, then require the guard to block them. Missing tools or fixture/tool
incompatibility are failures, not skipped coverage. Authoring these tests is
not a claim that they passed; controller execution and review remain required.
