# Mac mini live fixture matrix — ONE-2531

## Current passing run (post-review)

- Source commit: `08111200` (private staged-snapshot identity checked before
  opening, package checks bound to that snapshot, and tagged dialog inputs).
- Command: `python3 scripts/office/run_fixture_matrix.py
  scripts/office/fixtures/.runs/mac-mini-009` from the Mac mini clone.
- Result: **5/5 passed** — clean, failed-open, damaged-candidate, timeout and
  repair-prompt. See [matrix.json](mac-mini-009/matrix.json), the per-case
  receipts and the clean PDF/PNG/save-back. The copied files match all receipt
  SHA-256 values and byte counts. No cleanup warnings, open presentations,
  PowerPoint process or staging directories remained.
- The observed Mac/renderer pin matches [`environment.json`](../environment.json)
  exactly. The 100 PPTArena cases remain an offline manifest/classifier scope;
  their binaries were not opened.

The earlier [mac-mini-008](mac-mini-008/matrix.json) post-review run also passed
5/5 at oracle commit `7084af94`. The current run rechecks the source snapshot
and observer-format changes on the actual Mac.

## Earlier passing baseline

- Host: dedicated Mac mini; PowerPoint for Mac 16.113.2, macOS 27.0 (26A428),
  PDFKit 27.0; observer: System Events; raster scale: 2.
- Branch source: `w8/one-2531` at `1684a843`.
- Command, from `/Users/olety/w8-office/lin-2531`:
  `python3 scripts/office/run_fixture_matrix.py scripts/office/fixtures/.runs/mac-mini-006`
- Result: **5/5 passed**. See [matrix.json](mac-mini-006/matrix.json) and the
  per-case `receipt.json` files for hashed inputs, outputs, and environment.

| Fixture | Observed | Result |
|---|---|---|
| clean | PDF export, one checked PNG, valid save-back | pass |
| failed-open | Repair alert on non-ZIP input; cancelled and refused | pass (`failed`) |
| damaged-candidate | Repair alert on malformed presentation XML; cancelled and refused | pass (`failed`) |
| timeout | One-second deadline during a valid open | pass (`timed_out`) |
| repair-prompt | Repair alert on valid ZIP with missing slide; cancelled, not repaired | pass (`repaired`) |

`repaired` means PowerPoint offered repair. The harness did **not** accept it.
PowerPoint ended with no open documents, no remaining staging directory, and no
cleanup warnings. All copied output bytes match the SHA-256 and size in the
clean receipt. The pinned 100-case PPTArena manifest was classified offline;
corpus files were not downloaded or opened in this live fixture run.

Earlier `mac-mini-001` through `mac-mini-005` runs exposed and resolved Mac-only
AppleScript empty-list and Accessibility-text handling defects. They are
noncanonical diagnostics, not part of this passing evidence set.
