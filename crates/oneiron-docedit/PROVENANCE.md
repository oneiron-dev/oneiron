# Stemma fork provenance (ONE-2522)

The source under `vendor/stemma-engine` and `vendor/stemma-diff` was copied from
[stemma-sh/stemma](https://github.com/stemma-sh/stemma), commit
`ad1e70deac0a828d5162ac3b3f2186c2bb0c075e` (2026-09-26 snapshot).
The upstream work is dual-licensed MIT OR Apache-2.0. We elect Apache-2.0;
the original `LICENSE-APACHE` and `LICENSE-MIT` are retained here and in both
upstream crate roots, along with original source headers and attribution.

Changes from that commit: the first import copied upstream `src/`, tests,
and fixtures unchanged. ONE-2522 later changed `vendor/stemma-engine/src/normalize.rs`,
`src/tracked_model.rs`, and `src/resolution_rules.rs`: on Word-oracled rejection,
a plain paragraph before an inserted-row table is absorbed into that row and
removed with it, not rejoined past the table. The second review fix changes
`vendor/stemma-engine/src/docx.rs`: `read_with_limits` accepts data-only
workload limits and bounds actual inflated bytes per part and in total before
any XML linker sees caller-supplied output. The vault owns policy resolution;
the fork has no dependency on Oneiron. The old synthetic assertions
were corrected in the two paragraph-join suite files. Actual Word-for-Mac
saved outputs were added under `testdata/word-oracle/` as reference fixtures;
see `docs/docx-oracle/word-mini-20260927.json` for their digests and custody.
We omit upstream's MCP, API server, CLI, and session runtimes (separate crates).
The `oneiron-docedit` wrapper adds a stateless caller-facing Word revision
entry and blocking export-linker check. The upstream engine's `runtime.rs`
remains because its stateless serialization helpers and error types back the
pure `api::Document` facade; the wrapper does not expose a session store.
Upstream packages are not separately published by this workspace.
ONE-2701 ported the fork's quick-xml readers (`src/word_xml.rs`, `src/normalize.rs`, three test
files) from 0.37 to the workspace's `=0.42.0` pin, clearing RUSTSEC-2026-0194 and -0195.
The comment-occurrence change (2026-10-16) touches `src/edit/verbs/comments.rs`, `src/edit/mod.rs`,
`src/edit_v4.rs`, `src/edit_v4/catalog.rs`, `src/runtime.rs` and `src/api.rs`. `comment_create` takes an
optional 1-based `occurrence` that anchors the n-th copy of a repeated quote, counted over the
paragraph's visible text the way `set_format` counts its targets. An out-of-range copy is refused. Without
`occurrence` the first-copy anchor is unchanged. A quote that matches more than one copy now yields a
typed `EditNote` with the copy count and the anchored copy, which `apply_with_notes` returns (the
value-only `apply` drops it).
The set_format-occurrence change (2026-10-17) touches `src/edit/verbs/run_formatting.rs`, `src/edit/mod.rs`
and `src/edit_v4.rs`. `set_format` takes an optional 1-based `occurrence` that formats the n-th copy of a
repeated `expect`, counted the way the ambiguity check counts its matches. A copy the paragraph does not
hold reads as an expect mismatch. Without `occurrence` a repeated `expect` still refuses. The suite's
`EditStep::SetRunFormatting` literals do not carry the new field; the suite is outside the workspace.
