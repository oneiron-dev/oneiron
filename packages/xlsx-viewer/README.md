# @oneiron/xlsx-viewer

A view-only spreadsheet grid that a person anchors comments on, so an agent can
make the requested change with every edit versioned, consented and receipted.
The design lives in the document-engine canon (ARCH-0075) in the docs repo.

## What it does

- **Import bridge (SheetJS CE → Univer `IWorkbookData`).** SheetJS parses the
  blob **in a Web Worker**, **lazily per sheet**, so a >25MB workbook never sits
  fully parsed in memory — only the mounted sheet is materialised.
- **View-only, cached values, no recalculation.** Cells carry the workbook's
  cached values; the bridge never emits a live `ICellData.f`, so Univer's
  formula engine has nothing to recompute. Formula *text* is preserved under
  `custom.oneironFormula` for read-only display.
- **No export path.** Round trips happen agent-side on the original blob, so
  the package needs none of the Univer Pro import/export packages: there are
  **zero `@univerjs-pro/*` imports**.
- **Comment overlay.** Threads are `anchored_annotation` claims read and
  written through an `AnnotationClient`. The viewer holds no comment state of
  its own.
- **Version scrubber and manifest-op diff.** The diff between versions is
  rendered from the edit-manifest ops **only**; the viewer never re-parses two
  binaries.

## Engine seams

- `src/annotations/` mirrors the `anchored_annotation` claim and anchor shapes.
  The engine has native threads (`open_annotation_thread`,
  `add_annotation_comment` and `annotation_threads_for_artifact` in
  `crates/oneiron/src/anchored_annotation/threads.rs`), but no binding exposes
  them to this package yet. `InMemoryAnnotationClient` stands in for the
  engine.
- `src/manifest/types.ts` mirrors the edit-manifest op vocabulary by hand.
- The Univer thread-comment plugin supplies the on-grid affordance only; the
  store of record is the `AnnotationClient`. Univer's comment model is not
  synced to it.

## Dependencies

Pinned upstream packages, no vendored fork: the community `@univerjs/*`
packages (grid, styles, formula, thread-comments; all Apache-2.0) at `0.25.1`,
and SheetJS CE from its own CDN tarball, `xlsx-0.20.3`. Nothing is patched.

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
`scripts/license-audit.ts`. No literal or structurally-copied code from
non-Apache/MIT sources (OnlyOffice/Collabora etc.) lives here.
