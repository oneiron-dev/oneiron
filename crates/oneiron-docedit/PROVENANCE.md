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
The DOCX parse-budget change (2026-10-20, scan C005) adds `src/parse_budget.rs` and touches `src/docx.rs`,
`src/lib.rs`, `src/runtime.rs`, `src/import.rs`, `src/docx_validate.rs` and `src/redline_extract.rs`. Before any
reader builds a tree, one pass streams every XML part of the package and charges what the tree builders keep:
nodes (elements, attributes, namespace bindings, text runs, CDATA, comments, processing instructions) up to
`MAX_DOCX_XML_NODES` = 10,000,000, and decoded bytes with each resolved namespace URI up to
`MAX_DOCX_XML_EXPANDED_BYTES` = 500 MiB. The counters run across all parts. A package over either is refused as
`DocxError::ParseLimitExceeded` and `ErrorCode::ParseLimitExceeded`, naming the bound; `validate_docx` reports
it as I-PKG-000 and `extract_redline` as a ZIP error. Packages under both bounds read as before.
The comment-anchor allocation change (2026-10-20, scan C060) touches `src/edit/verbs/comments.rs` only.
`comment_create` tries the single-run fast path first and builds the per-visible-char map only when an
`occurrence` is given or the fast path misses; the copies of the quote are counted as `match_indices`
streams past (total, the chosen copy's start, the fast hit's copy number) instead of collected into a
vector. Marker placement, the `RepeatedCommentQuote` note, refusals and their order are unchanged.
The DOCX admission change (2026-10-22, Rule 5, FIX 8570, 8763, 5354) adds `src/admission.rs` and touches
`src/docx.rs`, `src/parse_budget.rs`, `src/lib.rs`, `src/runtime.rs`, `src/import.rs`, `src/docx_validate.rs` and
`src/redline_extract.rs`. A host hands its memory port in through a thread-scoped `admission::Operation` (the
scoped pair import re-enters it on both threads). The archive reader reserves each entry's record, name and
bytes before it allocates them, and parse admission reserves what the trees cost: node overhead as an
estimate, decoded bytes as measured. The entry count and the node count are observations, never refusals,
and `MAX_DOCX_XML_NODES`, `MAX_DOCX_XML_EXPANDED_BYTES`, `ParseBound` and `ParseLimitExceeded` are gone.
`ArchiveLimits::is_valid` no longer bounds any dimension by `DEFAULT`, and `DocxArchive::read` uses the
operation's limits. A byte ceiling hit is `DocxError::Capacity` (`ErrorCode::CapacityExceeded`), a memory or
deadline refusal is `DocxError::Resource` (`ErrorCode::ResourceRefused`), and both carry typed details. The
writer refuses a package past classic ZIP's widths (65,534 entries, 0xFFFFFFFE bytes) as that format's limit.
