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
The non-body story read change (FIX 594, 2026-11-05) adds one public projection in
`src/view.rs`. It reuses the existing block/segment/table/guard projection for a story's
local blocks with no body-role lookup: story ids can collide with body ids, and the
body vocabulary does not assign roles to story paragraphs. No writer or parser changes.
The default comment-anchor boundary change (2026-11-05, FIX 4) touches
`src/edit/verbs/comments.rs`. A default cross-segment anchor now opens on the
text node holding its resolved quote's first character, after preceding breaks,
bookmarks or comment markers, as the chosen-occurrence path already does. Quote
selection, single-run placement, range ends and tracked-container widening are
unchanged.

The non-final tracked-deletion change (2026-11-05) touches `src/edit/mod.rs` and
`src/tracked_model.rs`. The tracked delete verb can preserve earlier inline
revisions in an ordinary non-final, unmoved paragraph by lowering its runs
individually instead of flattening them under one block deletion. Empty,
numbered, section-bearing and tracked-final paragraphs keep the existing
validation path, as do moves, replacements and direct edits. The wrapper
recognizes only its own fully deleted paragraph marks in accepted order;
imported revisions keep their existing visibility. An unwitnessed surviving physical
final mark that fails the shared body's order comparison uses the existing
whole-window default-author projection, not a relaxed order check.

The final-carrier section change (2026-11-05, FIX 13798) touches
`src/tracked_model.rs`. After a tracked final-paragraph delete carries its
predecessor's accepted formatting onto the surviving final-mark carrier, it
clears the copied paragraph section break and section-property revision on that
carrier. The original predecessor and the document body's final section remain
unchanged. This prevents a duplicate section boundary and copied revision from
being serialized on the carrier; no Word-runtime comparison is claimed.

The wrapper's terminal final-deletion change (2026-11-05) preserves sequential
actor attribution for one last-group paragraph delete when the only extra
native id is its physical final-mark carrier. The existing snapshot and view
must show unmoved, unsplit text-only paragraphs with no literal prefixes,
exact live-id order and accepted text, and one deleted break on the immediate
physical predecessor. The fork's existing merge concatenates that predecessor
with the empty carrier without a separator or another block. No fork code or
revision mark changes; all other shapes retain the existing fallback.

The move-deletion pairing change (2026-11-05, FIX 13294) touches `src/tracked_model.rs`.
Within one tracked move range, each destination paragraph's inner deletions are
paired with the source block at the same position, rather than always using the
first source paragraph. The count includes siblings without inner deletions,
non-paragraph blocks, and the matching insertion/deletion layer of stacked
inserted-then-deleted siblings. The final source eligibility gate is unchanged.
Existing move and deletion gates, resolution order, and
serialization are unchanged.
The same pack (FIX 13299) advances the text-overlay cursor over the
existing hard-break and opaque-inline placeholders, matching `extract_inlines_text`.
The non-text inline nodes themselves are preserved unchanged.

The empty header/footer expect change (2026-11-05, FIX 594) touches
`src/edit_v4.rs` only. The `edit_header` / `edit_footer` schema arms admit a
blank `expect` when the existing `semantic_hash` is supplied. Native `expect`
matching is substring-based, so an unguarded blank retains its prior refusal;
the projection sends the actual story paragraph's current guard. All previously
admitted nonblank expectations, required string fields, part-name checks and
apply-time guard/expect checks stay unchanged. No wire shape, error code or
default changes.

The header/footer exact-run change (2026-11-05, FIX 14300 / FIX 594) touches
`src/edit_v4.rs`, `src/edit/mod.rs` and `src/edit/verbs/headers_footers.rs`.
The opt-in `exact_marks` edit mode treats replacement text's six marks as a set,
including empty sets and same-text replacements. The shared segment materializer
is unchanged: after it builds the tracked replacement, only its new Inserted
text nodes receive exact bold/italic/underline/subscript/superscript/strike and
explicit authored OFF values for absent marks. Deleted source runs, opaque
anchors, unrelated run properties and revision metadata remain as built. Direct
mode resolves the same tracked replacement after applying these marks. Ordinary
header/footer edits without the mode retain their current inheritance, identity
checks and word-diff dispatch. No new serializer, format reader, version constant,
refusal, default or cap is added.

The complex-script exact-run correction (2026-11-05, FIX 14300 R2) touches
`src/edit/verbs/headers_footers.rs` only. The same new Inserted text nodes now
set `bold_cs` / `italic_cs` and their authored flags to the requested bold /
italic values, with explicit OFF for absence. Word uses these complex-script
slots instead of `b` / `i` when `cs` or `rtl` is enabled. Those script selectors,
fonts and deleted source history remain unchanged; the shared materializer and
all ordinary edits remain unchanged.

The exact-run parser registration correction (2026-11-05, FIX 14300) adds
`exact_marks` to both header/footer entries in `src/edit_v4.rs::OP_FIELDS`.
`deserialize_ops` checks that allowlist before deserializing the typed operation,
so the setting must be registered there as well as on the enum. Other fields,
tags, unknown-field checks and schema validation stay unchanged.

The marked note-runs change (2026-11-05, FIX 594) adds the native
`edit_note_runs` op (`src/edit_v4.rs`, `src/edit_v4/catalog.rs`,
`src/edit/mod.rs`, `src/edit/verbs/footnotes.rs`) and opens the wrapper
`SetStoryRuns` footnote/endnote arms (`docx_body/projection.rs`). The new op
edits one paragraph within the actual footnote/endnote `w:id` story as a
whole-paragraph tracked redline with the exact six marks, paragraph-scoped
across multi-paragraph notes. It reuses the shared segment builder, the exact
post-pass (moved whole from `headers_footers.rs` to a parent-private helper
with no visibility change), the header/footer guard/expect/opaque law, and the
shared structural-marker offset law for bookmarks, comment ranges, and foreign
markers; the auto-number glyph stays a leading Normal run. Existing `EditNote`
plaintext behavior is byte-unchanged. No contract schema bump, no new error,
format, default, cap, or Loro change.

The marked comment-runs change (2026-11-05, FIX 594) adds the native
`edit_comment_runs` op (`src/edit_v4.rs`, `src/edit_v4/catalog.rs`,
`src/edit/mod.rs`, `src/edit/verbs/comments.rs`) and opens the wrapper
`SetStoryText`/`SetStoryRuns` comment arms (`docx_body/projection.rs`,
`docx_body.rs`). The new op edits one paragraph within the actual comment `w:id`
story with the exact six marks, paragraph-scoped across multi-paragraph comments,
one op serving both plain-text and marked content. It reuses the shared segment
builder, the parent-private exact-marks post-pass, the header/footer
guard/expect/opaque law, and the shared structural-marker offset law (opaque
`CommentReference` atoms excluded, already preserved); comments carry no
auto-number glyph. The fresh tracked pair settles to Normal annotation text in
both outer modes via a text-only settle that flips the fresh `Inserted` segment
and drops the `Deleted` tombstone, leaving paragraph formatting/change metadata,
`para_id`, author/date, threading/resolve sidecar, all other blocks, and body
anchors verbatim; no `w:ins`/`w:del` is authored into comments.xml, and the
edited comment's full content hash is recomputed. An empty replacement drops its
markers with its tombstone, the same full-deletion law as the note path. Existing
create/reply/delete behavior, the shared builder, and the exact-marks helper are
byte-unchanged. No contract schema bump, no new error, format, default, cap, or
Loro change. No Word-runtime comparison is claimed.

The shared-Loro story paragraph change (2026-11-05, FIX 594) adds the engine-side
story slice (`crates/oneiron/src/office_body/docx/stories.rs`, schema 2): scoped
story paragraph import, three story ops, typed read, fork review entries and
export of every changed paragraph as its full `SetStoryRuns`, reusing the native
story verbs above with no native change. It works once this chain integrates;
story structure/table ops and story ask pinning remain unbuilt.

The story table-cell change (2026-11-05, FIX 594) adds the native
`edit_story_cell` op (`src/edit_v4.rs`, `src/edit_v4/catalog.rs`,
`src/edit/mod.rs`, new `src/edit/verbs/story_cells.rs`) and opens the wrapper
`DocxChange::SetStoryCell` arm (`docx_body.rs`, `docx_body/projection.rs`). One
strict wire op with a tagged scope object (the same shape as `DocxStoryScope`)
serves all five story families; the existing body cell core is factored onto
`&mut BlockNode` unchanged and reused, so the logical-grid, vMerge, effective
structural status with same-transaction own-insert, opaque, no-op, revision and
Direct law is identical for body and story cells. The op rewrites the cell's
FIRST paragraph only (the body law, `apply_set_cell_text_in_place`); any later
cell paragraphs are untouched, and a shared import caller must not treat the
read view's joined multi-paragraph cell text as that first paragraph. Header,
footer, and note cells land tracked; comment cells land as Normal annotation
text in both outer modes via a text-only settle of the target paragraph only,
with the note/comment whole-story hash recomputed. Story structure
insert/delete stays unbuilt; no whole-594 claim. The native contract moves
from 4 to 5 because `set_story_cell` extends the typed `docx.project` arguments;
it serves only the current version, with no old reader or migration. Nested
transaction and Loro versions stay unchanged. No new error, default, cap or
Word-runtime comparison is claimed.

The story cell-paragraph extension (2026-11-05, FIX 594) adds required ordered
`DocxCell.paragraphs` from the canonical cell blocks: ids, guards, accepted inline
text and exact target locks. It does not split the joined redline read or reuse
lossy render segments. `edit_story_cell` and `SetStoryCell` accept an optional
exact paragraph id inside the selected cell; absent retains FIRST-paragraph
intent, including every body cell call. Scope and transaction-base table guards
are unchanged. The common cell core narrows Direct settlement to the edited
paragraph, so sibling history stays pending, and distinguishes a joined redline
identity from a genuine edit of the accepted text. It does not change the shared
materializer. The private cell projection helpers move whole into
`docx_body/projection/story_cells.rs` before the parent crosses 800 lines.

The same still-pending schema-2 Loro body now imports story tables as independent
plain cell paragraphs, with scoped set/splice operations, typed reads, masked
public views, table-level fork review and exact-selector native export. No rich
cell marks, nested-table structure or story live-unit pinning is claimed. Native
contract 5 and inner DOCX schema 2 are extended before this same PR lands; this
is not an old-format reader, default or migration. A later change after they
land requires fresh current versions. No numeric ceiling, default, dependency,
error kind, test or runtime/Word proof is added by this extension.

The scoped paragraph-question extension (2026-11-06, FIX 14487) carries an optional
actual native story through `comment_create`'s strict wire schema, EditStep and
paragraph lookup. Absent scope keeps the existing body path; present scope never
falls back to body ids. The existing marker splice, global comment identities,
comment body writer, reply/resolve/delete and per-part serializers are reused.
Note anchors refresh their entire note's content hash. Comment content ranges
return the existing UnsupportedEdit code through a new typed error because
ISO/IEC 29500-1 section 17.13.4 makes those markers non-conformant there. Header
and footer lookup retains exact part, band and authored-story identity; Word
honor of file-authored header/footer ranges is not proved. The public scoped
block reader retains the old BODY read when scope is absent. Engine judgments,
carry/withdraw/re-ask and standing selectors keep the same actual scope, native
version quote and live frontier. Top-level paragraphs only; cell ParagraphAsk,
comment-story alternatives and full FIX 14487 remain open. No numeric constant,
cap, default, schema integer, dependency, old reader, migration, test or runtime
proof is added.

The direct story-cell paragraph-question extension (2026-11-06, FIX 14487) adds
native paragraph-id lookup inside direct cells of the exact selected story.
It keeps BODY's original top-level lookup and the existing kind, tracked-status,
paragraph semantic-guard, quote and marker-splice checks. Named-story reads
append the existing native per-cell paragraph projections and their locks,
including the enclosing table lock. Engine live-head and scoped change reads
use those same native paragraph ids, lock and text at the whole-document pin.
Carry and standing questions reuse the scoped reader without a new identity or
wire shape. Marker scan, reply, removal and serialization already descend into
table cells; their bodies are unchanged. The earlier top-level-only limit is
therefore lifted for direct cells in named stories, not BODY or nested cells.
Comment-content alternatives, structural history and full FIX 14487 remain open.
No numeric constant, cap, default, schema integer, dependency, old reader,
migration, test, compiler result or runtime/Word proof is added.


## Nested native story-cell comment targets (FIX 14487)

Named-story `CommentCreate` can resolve an imported paragraph id inside nested
table cells. Existing top-level matches and all existing direct-cell matches keep
their lookup priority. Deeper lookup visits native table/cell blocks in order,
keeps the first non-Normal ancestor status, and skips vertical-merge continuation
cells at every level. The existing block guard, quoted-range selection, visible
text, marker insertion, comment identity, and reply/delete maintenance are
unchanged. Body lookup stays top-level only. This is native target lookup, not a
claim of nested ParagraphAsk inventory, live-pin, or whole FIX 14487 support.

The styled structural-marker carrier change (2026-11-06, FIX 14354) touches
`src/edit/mod.rs`. Whole-paragraph segment replacement leaves each existing
Decoration or comment range/reference marker in one carrier at its original
inline position and status, instead of consuming it into the old text's deletion.
Normal markers stay current, and prior inserted/deleted markers keep their own
revision. Rejection restores the original current range; acceptance collapses removed old
text before the inserted replacement. No marker identity is duplicated or
inferred from replacement prose. The same predicate now serves marker presence,
stripping and this carrier. Native wire/schema versions and marker-free
replacement semantics are unchanged; no Word-runtime comparison is claimed.


The nested-table identity change (2026-11-07, FIX 21302) touches `src/import.rs`.
Rows, cells and content-control-wrapped cells pass the existing body/story
`table_counter` into nested tables instead of resetting it in each cell.
The existing `tbl_N` mint and derived row/cell names therefore identify every
nested table within that parse scope without colliding with an ancestor or a
table in another cell. Each story keeps its own counter; these are not global
identities. A later outer table can receive a different native id after an
earlier nested table. No old-id reader, new address field or format version is
added. Paragraph counters, XML content, tracking, formatting, materialization
and the direct-only story-cell editing surface are unchanged. This fixes the
native producer identity only; it does not add nested story-cell editing.


## Nested story paragraph reads (FIX 14487, 2026-11-07)

`src/docx_body/stories.rs` now appends native nested-cell paragraphs to the
existing named-story scoped read, after every old top-level and direct-cell
result. Each new block carries its actual paragraph id and accepted inline
text. It is not a replacement target for the enclosing cell. The shared
paragraph reader keeps the existing tracked, literal-prefix and inline-anchor
locks, with tracked block/row/cell and vertical-merge continuation ancestry
carried through every nested level. Locked descendants remain readable.

The all-story read is factored without changing its results. A scoped call
still parses once inside the caller's archive/resource context and reads all
stories before selecting the exact scope. Missing stories stay empty; omitted
scope still calls the unchanged body-only reader. Public types, native edit
verbs, first-direct paragraph selection, materialization and core live-unit
handling are unchanged. This is the native scoped-reader slice only, not whole
nested ParagraphAsk/live-pin/projection or FIX 14487 closure. No test, compiler
or runtime/Word result is claimed.

## Nested named-story table identities and cell edits

Named-story `read_docx_body` results append actual nested table blocks after all
previous story blocks. Each table keeps its native story-local id and direct
cell paragraph ids. The existing core story-table model imports those blocks;
no separate path field or shadow table store is added. The body read and scoped
paragraph read keep their previous results and ordering.

Story-cell projection and transaction-base/live resolution find the actual
nested table inside the exact named story. Old top-level ids keep priority.
Every enclosing row/cell tracking state and vertical-merge continuation is
checked before the existing leaf edit. A same-transaction enclosing insertion
uses the existing plain-text insertion branch, without exempting a foreign
tracked target cell. An absent paragraph selector still means the first direct
paragraph. Direct and comment settlement still touch only that paragraph.

This is retained source work for FIX 14487/594. It does not claim parent PRs
merged, a production compile, Word behavior, or complete story/live-unit closure.
