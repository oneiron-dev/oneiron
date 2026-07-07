# @oneiron/xlsx-viewer

OF-336 **xlsx viewer instrument** — the D8 lens from
[`OF-368` (artifact edit lens)](../../../../fable-queue/oneiron/designs/OF-368-artifact-edit-lens-DESIGN.md).
A view-only spreadsheet grid that a human anchors Google-Docs-style comments on,
so an agent can implement the requested change and have every edit versioned,
consented, and receipted.

This is the first format in the D9 ladder (xlsx → docx → pptx).

## What it does

- **Import bridge (SheetJS CE → Univer `IWorkbookData`).** SheetJS parses the
  blob **in a Web Worker**, **lazily per sheet**, so a >25MB workbook never sits
  fully parsed in memory — only the mounted sheet is materialised.
- **View-only, cached values, no recalculation.** Cells carry the workbook's
  cached values; the bridge never emits a live `ICellData.f`, so Univer's
  formula engine has nothing to recompute. Formula *text* is preserved under
  `custom.oneironFormula` for read-only display.
- **No export path.** Round-tripping happens agent-side on the original blob
  (OF-368 D5). This is what lets us skip the Univer-Pro import/export packages —
  there are **zero `@univerjs-pro/*` imports** (guarded by a test).
- **Comment overlay (ARTL-2 seam).** Threads are `anchored_annotation` claims
  read/written through a thin engine client — **never viewer-local** (OF-368 D3).
  The viewer holds zero comment state of its own.
- **Version scrubber + manifest-op diff (ARTL-3 seam, D7).** The diff between
  versions is rendered from the edit-manifest ops **only** — the viewer never
  re-parses two binaries.

## Placement call

There is **no JS/TS instrument host anywhere in the repo yet**. The ONE-1434
generative-UI wire format (`crates/oneiron/src/lens.rs`) is a *closed, lightweight
atom vocabulary* interpreted by a trusted renderer — it has no `Instrument` /
embed atom, so a heavyweight Univer grid cannot ride the atom wire. Per OF-368 D8
the grid is a **host-mounted instrument region**, parallel to `render_instrument`,
with the affordances around it (comment threads, receipts, scrubber) as ordinary
atom-kit lenses.

The eventual runtime home is the private `oneiron-cloud` app (Phase C, not yet
built). This package is placed as a **self-contained package in the engine repo**
because (1) OF-368 D10 explicitly permits the Univer fork + SheetJS CE in-repo
(both Apache-2.0), and (2) OF-368 blesses an engine-optional standalone MVP whose
shapes (anchors / manifests / receipts) are format-stable, so it folds into the
`oneiron-cloud` host without a rewrite when that host materialises.

## Fork-vs-dependency call

**Pinned upstream dependencies, no vendored fork.** The community `@univerjs/*`
packages (grid / styles / formula / thread-comments, all Apache-2.0) plus SheetJS
CE satisfy "no Pro imports, no export tax" with plugin configuration alone. Nothing
needs patching for a view-only grid, so nothing is vendored. Univer is pinned to
`0.25.1`; SheetJS CE to the CDN tarball `xlsx-0.20.3` (SheetJS's own distribution).

## Reconciliation seams (post-merge wiring)

- **ARTL-2 (ONE-1552, not merged):** `src/annotations/` mirrors the
  `anchored_annotation` claim + anchor shapes. Bind `AnnotationClient` to the
  engine (napi/FFI) when ONE-1552 lands. `InMemoryAnnotationClient` stands in.
- **ARTL-3 (ONE-1553, PR #394):** `src/manifest/types.ts` mirrors the
  `EditManifest` op vocabulary. Re-derive against the generated bindings on merge.
- **Univer comment model ↔ ARTL-2:** the Univer thread-comment plugin provides
  the on-grid affordance only; the store of record is ARTL-2. Syncing the two is
  a follow-up.

## Run

```bash
bun install
bun run typecheck      # tsc --noEmit (strict)
bun test               # unit + acceptance suite
bun run audit:licenses # dependency license audit
bun run check          # typecheck + test
```

## License

Apache-2.0. Every runtime dependency is Apache/MIT-class — see
`scripts/license-audit.ts` (enforced by `tests/license-audit.test.ts`). Per
OF-368 D10, no literal or structurally-copied code from non-Apache/MIT sources
(OnlyOffice/Collabora etc.) lives here.
