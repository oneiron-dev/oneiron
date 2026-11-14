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
edited comment's full content hash is recomputed. An empty replacement retains
its Normal structural markers while removing the old text. Existing
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
The normalized final-move deletion change (2026-11-06, FIX 13301 partial)
touches `src/tracked_model.rs`. A document-final move destination whose pilcrow
was normalized to Normal retains its actual move revision on the block. Its
inner deletions use the same paired source and positional character ranges only
when the reconstructed original text equals the full source text. Nonaligned
normalized destinations stay unchanged; they never use substring matching.
The existing Inserted-pilcrow path and deletion cascade stay unchanged, including
revision identities, authors, and the final Normal pilcrow. This also covers a
second selective resolution after an unrelated revision normalized the final
mark. Reimported move destinations continue through the existing Inserted path.

The exact move-deletion range change (2026-11-05, FIX 13300 partial) touches
`src/tracked_model.rs`. Eligible destination clones reconstruct their original
moved text using actual revision identities. When it equals the full paired
source text, inner deletions retain their character ranges instead of searching
for unique substrings. Repeated text maps to its own occurrence; empty material
ranges leave the source unchanged. Hard breaks and opaque inlines retain their
nodes and receive the deletion status when their one-character span is selected.
Empty material deletions also leave nonaligned sources unchanged, matching the
exact-range no-op; destination revision repair still runs. Nonempty nonaligned
clones keep the existing unique-text mapping, including its non-text statuses.
Move eligibility, pairing, marker repair and resolution order are unchanged;
nonaligned ambiguity and suppressed destination pilcrows remain open.

The table-cell fallback change (2026-11-06, FIX 17480) touches
`src/native_patch/table.rs`. When retained text mapping and the field-aware cut
cannot apply, the existing rebuild keeps the first paragraph's terminal run
properties and the namespace bindings of copied paragraph and run properties.
If no ordinary run exists, it carries the first field's explicit run properties.
The outcome names the actual typed fields removed by that rebuild. Expected-text
checks, grid/merge checks, first-match table selection and the retained/cut paths
are unchanged. This is a source-level correction, not a PowerPoint fidelity proof.
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

The note/comment run marker correction (2026-11-07) repositions each retained
Normal marker once between the old and replacement text readings, using the
existing offset-placement helper only to plan the target positions. The planning
copies are discarded, so accepted, rejected and unresolved output retain one
marker identity rather than emitting both originals and replacement copies.
The exact-marks pass still runs before any replacement text is split; the shared
segment builder, marker offset law and note auto-number behavior are unchanged.
The comment-cell text settle also retains structural markers from a deleted
text segment as Normal markers, including when the replacement is empty. It
adds no refusal and does not change any other paragraph or cell.

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

## Native deck transaction graphic ceilings (FIX 10653)

A deck transaction may carry `graphics` with the existing `svg_bytes`,
`raster_bytes`, and `raster_pixels` ceilings. Every `set_picture` step uses that
same setting through `Picture.limits`. An absent setting uses the unchanged
`GraphicLimits::default()` values and is omitted from canonical serialization.
An explicit setting stays in the canonical transaction and therefore the existing
handoff hash and settlement replay. The asset identity/hash checks, factual-use
and provenance rules, resource admission, capacity errors, candidate part-diff
checks, and reports are unchanged. Native deck creation and live export retain
their existing defaults; this is only the transaction slice of FIX 10653.


### Native live deck export graphic settings (FIX 10653)

The live deck export profile accepts optional `GraphicLimits`. The projector resolves
those settings once and passes them to both new-picture creation and bound-picture
replacement. Existing held-media paths do not re-admit their bytes. Omitting the
settings keeps the existing numeric defaults and the old profile/key serialization.
An explicit setting is part of `ExportKey`, so a memo for another setting cannot
stand in for it. The projector signature and export gate remain unchanged.


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

The multi-level native series change (2026-11-06, FIX 18217;
FIX 9163 remainder) touches `src/native_patch/chart.rs` and `chart/cache.rs`.
A direct category write uses the leaf-first, level-major cell order already
returned by the native reader. Direct and overlapping writes splice the retained
`c:lvl` point values without inserting a point count inside a level or rewriting
the outer count, formulas, level order or unrelated XML. An unchanged level,
including a self-closed one, retains its bytes. Single-level caches keep their
existing count and point-splice path. Length, kind, date, workbook and fresh
read-back checks remain unchanged. No native wire/schema version changes;
source qualification is not a compiler, runtime or PowerPoint fidelity proof.

The same chart pack (FIX 18236) removes every direct cached point at an
index written as Missing, including duplicate indices. Deletion spans are
collected in the existing point-index pass; nonmissing writes and insertion
anchors keep their last-wins map and prior byte-preserving behavior. The fresh
cache/workbook read-back remains the landing check.

The ideographic-space estimate change (2026-11-06, FIX 16557) touches
`src/design_plan/capability.rs`. `Metrics::lines_in` measures a complete nonempty
U+0020/U+3000 run through the same advance and greedy wrap at leading, trailing,
and internal separators; other whitespace keeps its existing fallback. Advance,
words, height, and emission are unchanged; no renderer comparison is claimed.

The same-count later-paragraph fallback (2026-11-06, FIX 17480) touches
`src/native_patch/table.rs`. When the rebuilt line count matches the original
paragraph count, later lines reuse the same-index paragraph's properties;
new replacement text uses its first run's (else first field's, else the global
run's) properties. A later-template error falls back to the first paragraph's
template. New replacement text in the first line of a same-count rebuild
and in paired middle lines of a count-changing rebuild keeps the existing
global-run template; unpaired added lines keep the first-paragraph template.
Field-removal receipts, expected-text checks and the retained/cut paths are
unchanged.

The same-count later-paragraph run carry (2026-11-06, FIX 17480) keeps the
common character prefix and suffix in their actual source run or field's
explicit run properties and namespace bindings. It emits only static runs,
including text kept from a field, so every field the rebuild reports removed
is still removed. The replacement middle keeps the existing first-run
template. Unknown text coverage or unreadable copied properties retain the
existing one-template rebuild rather than refusing the write. This is a
source-level text-diff assignment, not canonical text identity or a
PowerPoint rendering proof; count-changing formatting remains partial.

The count-changing outer-paragraph carry (2026-11-06, FIX 17480) maps an
unchanged common whole-paragraph text prefix and suffix back to their actual
original paragraphs, using nonoverlapping text equality as the retained
mapping does. These paragraphs keep their own paragraph, terminal and run
properties through the static-run renderer, including field text converted
to ordinary runs. Paired middle paragraphs use their actual pPr, endParaRPr
and prefix/suffix run properties, but the replacement middle keeps the global
run template; unpaired added paragraphs still use the existing first-paragraph
template. Unknown coverage or copied-property errors fall back directly to that
same template. No field wrapper survives the rebuild,
and its field-removal receipts are unchanged. This is a deterministic current
text assignment, not canonical paragraph identity or a PowerPoint proof.

The same-count first-paragraph run carry (2026-11-06, FIX 17480) also keeps
the first line's common character prefix and suffix in their actual source
run or field properties, as static runs. Its replacement middle still uses
the original global first-ordinary-run (else first-field) template, even when
that run belongs to a later paragraph. Unsupported coverage or copied
properties keep the original first-template render. Later same-count and
count-changing paths, all static-run primitives and all field-removal receipts
are unchanged. This does not assign canonical identity or claim PowerPoint
rendering fidelity.

The count-changing paired-middle carry (2026-11-06, FIX 17480) pairs new middle
lines head..head+paired with the original paragraphs at the same positions,
reusing the deterministic native positional assignment, not canonical identity,
history or nearest-style inference. Each paired line keeps its actual paragraph
properties and prefix/suffix runs as static runs; its replacement middle keeps
the global run template, with direct first-template fallback on unknown coverage
or copied-property errors. Unpaired added lines keep the first template. Static
field conversion, fallbacks and field-removal receipts are unchanged. This is a
source-only correction, not a PowerPoint fidelity proof.

The rebuilt-break serialization (2026-11-06, FIX 17480) writes each requested
U+000B in a rebuilt fallback line as a qualified DrawingML `br` carrying the
same selected static run's `rPr` and namespace bindings, with surrounding
nonempty text as static `r`/`t` runs with those same properties. Empty and
BREAK-free text keep their exact previous bytes, and consecutive, leading or
trailing breaks emit each `br` with no empty run. No field wrapper survives and
field-removal receipts are unchanged. This serializes only the requested break,
not the original break's properties, and claims no PowerPoint or global
fidelity proof.

The original-break property carry (2026-11-06, FIX 17480) keeps a common
retained direct DrawingML `br` in its actual source `rPr` and namespace
bindings through the existing static `br` serializer. Requested new breaks
still use the selected template's properties, and an omitted BREAK still drops
the source `br`. Unknown text coverage still falls back to the existing
one-template render, and field-removal receipts are unchanged. This is a
source-only common-span correction, not full 17480, whole OF-509 or PowerPoint
fidelity proof, and no Office runtime comparison is claimed.

The count-changing requested-break alignment (2026-11-06, FIX 17480) counts
an original direct DrawingML `br` as U+000B when matching a requested outer
paragraph that explicitly contains a break. BREAK-free requested lines keep
the prior t-only matches and paragraph-property carry; omitted breaks still
drop. Exact matched outer paragraphs reuse the existing static run and break
property serializer. Paragraph pairing, replacement defaults, unsupported
coverage fallback and field-removal receipts are unchanged. This is a source
correction, not a PowerPoint or full table-fidelity proof.

The whole opaque retained-segment carry (2026-11-06, FIX 17480) keeps a
wholly retained field-free unknown direct child with nonempty descendant
DrawingML `t` as its entire original XML with namespace bindings, instead of
dropping its wrapper to the one-template static render. Only whole-interval
prefix/suffix retention qualifies; partial, edited, middle, field-holding or
unknown-coverage cases keep the existing fallback. Known `r`/`fld`/`br` bytes,
static serializers, alignment and field-removal receipts are unchanged. This is
a source-only retained-span correction, not full 17480, whole OF-509 or
PowerPoint fidelity proof, and no Office runtime comparison is claimed.

The whole unchanged field-free paragraph carry (2026-11-06, FIX 17480) keeps a
rebuilt line's original paragraph span bytes when its full native text, counting
each direct DrawingML `br` as U+000B, exactly equals the requested line and the
paragraph holds zero descendant DrawingML `fld`. The keep returns the original
span in place under the same direct text body with its own attributes, run
wrappers, inter-child bytes and namespace bindings unchanged, so no binding
materialization is added. Changed text, partial or unknown coverage, any field
and omitted BREAK lines keep the existing prefix/suffix, render and fallback
bytes; nonempty opaque retained segments and field-removal receipts are
unchanged. This is a source-only whole-paragraph correction, not full 17480,
whole OF-509 or PowerPoint fidelity proof, and no Office runtime, full-feature
or build comparison is claimed.

The same-count field-free inter-paragraph gap carry (2026-11-06, FIX 17480) keeps
each original gap's exact bytes between same-count rebuilt lines when zero DrawingML
`fld` nodes sit wholly inside that gap, using the existing source spans and body scope.
Gaps holding any direct or nested field keep the existing drop so the existing
field-removal receipts stay truthful, and count-changing output keeps its exact previous
bytes. Paragraph gates, rendering, alignment, defaults, opaque/static carries, cut paths
and receipts are unchanged. This is a source-only same-count gap correction, part of the
existing 17480/residual 18510 pack, not full 17480, full-feature, whole OF-509 or
PowerPoint fidelity proof, and no Office runtime comparison is claimed.

The count-changing outer field-free gap carry (2026-11-06, FIX 17480) extends
the same-count gap carry with one shared original-gap block: same-count lines keep
their exact existing gap bytes and predicate, and count-changing lines additionally
keep only gaps wholly between two original matched head paragraphs or two original
matched tail paragraphs under the same field-free gate and body scope. Gaps holding
any direct or nested field and all middle, boundary, added, removed or unmatched gaps
keep the existing drop so field-removal receipts stay truthful. Rendering, alignment,
BREAK handling, opaque/static carries, cut paths and receipts are unchanged. This is a
source-only outer-gap correction, part of the existing 17480/residual 18510 pack, not
full 17480, full-feature, whole OF-509/OF-510 or PowerPoint fidelity proof, and no
Office runtime comparison is claimed.

The count-changing paired-prefix field-free gap carry (2026-11-06, FIX 17480) widens
the one shared original-gap predicate from `index < head` to `index < head + paired`,
so count-changing lines additionally keep contiguous head+paired prefix gaps wholly
between two original prefix paragraphs under the same field-free gate and body scope.
Same-count gaps keep their exact bytes and strict matched tail gaps are unchanged;
head+paired stays within old-tail and new-tail so prefix, tail and added ranges do not
overlap and no count-changed middle-tail gap carries. Gaps holding any direct or nested
field, crossing added lines or nonconsecutive original paragraphs, and other unmatched
gaps keep the existing drop so field-removal receipts stay truthful. Native partial-field 2->3
(head 0, tail 0, paired 2) field-free gap 0->1 now carries; pairing, styled fallback,
rendering, BREAK, cut paths and receipts are unchanged. This is a source-only
paired-prefix gap correction, part of the existing 17480/residual 18510 pack, not full
17480, full-feature, whole OF-509/OF-510 or PowerPoint fidelity proof, and no Office
runtime comparison is claimed.

The zero-text direct-child raw carry (2026-11-06, FIX 17480) keeps every direct child
except `pPr`/`endParaRPr` in segments, including zero-char ones, with the existing `br`
special case unchanged; the unknown overlap/refusal gate runs only for nonempty text, so a
newly recorded zero-char unknown in the edited middle keeps the existing drop. One new raw
branch in the shared retained loop carries a zero-text child strictly inside a retained
head/tail interval (`from < position < to`) with zero actual DrawingML `fld` (own root
check plus no descendant `fld`) as its original span bytes as-is under the same rebuilt
paragraph qualified tag with its own `xmlns`/default-undeclare bindings and the same body
ancestors, with no binding materialization into a self-closing tag. Old nonempty static and
opaque bytes are unchanged; edited, internal-boundary or field-holding empties keep
the existing drop. In this interior branch, known empty `r` qualifies under the same strict
internal field-free rule; leading/trailing clusters follow the boundary extension below.
Empty `fld` is never raw-restored, and same-position multiple zero children preserve
original order once. No paragraph-wide field refusal, matching map, default, cap, API, DTO,
schema, authority, config, dependency, BC, policy or deploy changes. Raw comment/PI/whitespace
gaps are not implemented in this slice. This is a source-only direct-child correction, part of
the existing 17480/residual 18510 pack, not full 17480, full-feature, whole OF-509/OF-510 or
PowerPoint fidelity proof, and no compiler, runtime, Office runtime or build comparison is claimed.

## Original intra-paragraph gaps on retained table-cell text

When native PPTX table-cell fallback rebuilds a changed paragraph, it now
keeps the original raw bytes between consecutive direct children inside the
same unchanged character prefix or suffix. Original child ordinals exclude
gaps crossing paragraph properties that the fallback places separately.
The gap-facing ends of both children must stay in that retained interval;
comments, processing instructions and whitespace there keep their byte order.
Zero-text children use the existing strict retained-interval carry. A paragraph
with any actual DrawingML field keeps the previous gap behavior, so field
flattening and its cut receipts do not change. Edited, leading, trailing and
nonconsecutive gaps still use the previous fallback behavior. This does not
claim full paragraph fidelity or change retained-mapping selection.

## Attributes of actual reused table-cell paragraphs

The native fallback's styled path now carries every original attribute of
its actual reused paragraph, not just namespace declarations. Raw attribute
spans keep qualified names, quotes and entity spellings under the same
paragraph and ancestor namespace context. The reconstructed open/close tag
also handles an originally self-closing paragraph. Each actual paragraph is
selected at most once across the same-count, outer and paired paths.
The generic first-paragraph template renderer is unchanged: newly added
paragraphs do not acquire arbitrary identity attributes from that template.
Same-count actual fallback renders now keep their own wrapper attributes, as
described below; cloned template fallbacks still do not acquire them.
Run serialization, retained text mapping and field-cut receipts are unchanged.
This is source preservation, not full native or PowerPoint fidelity proof.


## Native table paragraph boundary gaps

The table-cell fallback keeps original raw non-node bytes at the edges of an
actually reused field-free paragraph. A leading or trailing gap beside a text
segment carries when the first or last nonempty direct segment contributes the
first retained prefix character or last retained suffix character. Consecutive
zero-text children before or after that segment and their intervening gaps now
carry their original bytes too. The other neighbor is the original paragraph
edge, or the already copied first `a:pPr` or last `a:endParaRPr`; skipped direct
children still block bridges. The exterior gaps before that first `a:pPr` and
after that last `a:endParaRPr` also keep their original bytes. Raw gaps exclude
node spans; the whole retained edge stays under the same original paragraph
attributes and body ancestors. Field-containing paragraphs, unknown-coverage
fallback, template selection, run/break text serialization, matching and
field-removal receipts are unchanged. The property-template identity handling
for the newly carried edge sources is described below. The complete
fallback helper moves to `native_patch/table/rebuilt.rs` without changing its
parent caller. This is source-only retention work, not proof of Office fidelity
or completion of the full table-cell fallback or OF-509/OF-510.


## Wholly retained native table runs and breaks

In an actually reused field-free paragraph, a nonempty ordinary `a:r` or direct
`a:br` whose complete existing text interval lies in the retained common prefix
or suffix now keeps its original XML span. This retains its own attributes,
original text XML and other child XML under the same original paragraph and
body ancestors. A direct break contributes its existing U+000B character. The
disjoint prefix/suffix intervals select each such whole nonempty span at most
once; no raw run or break is copied into added paragraphs or the replacement
template. Partial runs keep the prior static serialization. Empty segments,
field-containing paragraphs (including conversion of fields to static text),
unknown opaque segments, gap selection, matching and field-removal receipts
keep their prior paths. This remains source-only work; full table-cell fallback,
OF-509/OF-510 and Office fidelity are not claimed complete.


## Attributes of one retained partial native table run

In an actually reused field-free paragraph, a partial ordinary `a:r` that
contributes text to exactly one retained common prefix or suffix now keeps its
own non-namespace attributes in that one existing static run wrapper. Original
attribute spans keep qualified names, quotes and entity spellings. The existing
serializer still supplies the same inherited and own namespace declarations,
run properties and escaped retained text. XML parsing rejects U+000B in text
nodes, so a partial ordinary run's retained text produces one run, not multiple
break-separated wrappers. A source run intersecting both retained intervals
keeps its own wrapper on the head containing its original start, as described
below; the tail stays static, so those attributes are not copied twice.
The whole-run raw path, fields and their
receipts, breaks, empty/opaque segments, gaps, added-paragraph and replacement
templates, and retained-mapping selection are unchanged. This is source-only
retention work, not full table-cell fallback, OF-509/OF-510 or Office fidelity
proof.


## Original XML of one retained partial native table run

The same field-free, single-retained-piece partial run now keeps its original
XML when it has exactly one descendant DrawingML `a:t` and that text element is
a direct child of the run. The existing native `replace_text` helper rewrites
only that element's direct character-data spans; the existing splice helper
applies those edits relative to the original run span. Run and text-element
attributes, lexical qualified names, properties, unknown child XML and raw gaps
remain under the same original paragraph and body ancestors, once. Comments
and processing instructions keep their original bytes and order; replacement
text goes into the first character-data span and later text spans disappear,
so their position relative to that replacement text is not claimed unchanged.
Replaced CDATA and entity text uses the native helper's escaped text spelling.
The prior static serializer still succeeds first, keeping its property/error
selection. A native helper that cannot produce the text splice keeps the
previous static attribute path; the extended text shapes are described below.
The dual-piece extension is described below. Fields, breaks, whole-run raw
copies, empty/opaque segments, gaps, templates, matching and receipts are
unchanged. This is source retention work, not full table-cell fallback,
OF-509/OF-510, runtime or Office fidelity proof.


## Original text-element ownership within one partial native table run

The same field-free, single-retained-piece path now keeps the original run XML
with multiple or non-direct DrawingML `a:t` elements too. Its retained interval
is measured in original run characters. Text elements are visited in the same
native descendant order used to read that run; each contributes only its own
direct text. Each changed element keeps exactly its intersection with that
interval, or empty text when outside it. Fully retained and originally empty
text elements keep their lexical bytes. No inserted replacement text is assigned
to an arbitrary original text element; it still uses the existing template.
The existing `replace_text` helper edits only each element's direct character
data, so edits of a parent text element and a nested text element do not overlap.
One native splice applies those edits to the original run span, keeping run and
text attributes, wrappers, unknown child XML, comments, processing instructions
and gaps once under the same ancestors. Changed character data still uses the
native helper's escaped text spelling and first-character-data placement.
The prior serializer still succeeds first; a failed native text splice keeps
the same static attribute path. The dual-piece extension is described below;
fields, breaks, templates, matching and receipts are unchanged. This remains source-only
preservation, not full table-cell fallback, OF-509/OF-510 or Office fidelity proof.


## XML identity of newly retained table-cell boundary sources

The fallback records original identity source intervals from successful
field-free styled output: retained edge clusters, whole unchanged paragraphs,
wholly retained nonempty ordinary runs or direct breaks, and owning partial
ordinary-run pieces whose native `partial_run` preserves the original XML. Native text
splices change only character data, leaving original identity attribute spans
unchanged. Retained-loop source ranges stay local until both retained intervals
and the replacement succeed; a
whole-paragraph source is recorded only after its original XML string is ready.
Failed styled attempts record no ownership. If such intervals exist, a second
render uses that same original tree, text and interval plan. Property-template
source selection and every fallback condition depend on unchanged original nodes
and text, not the cloned attributes.

When a selected `a:rPr` lies wholly inside a recorded original source interval,
its original identity attributes survive there unchanged. Fresh copies of that subtree in any
replacement run, requested break or added/fallback paragraph omit only attributes
whose expanded name is XML-namespace `id`. Qualified attribute names resolve
through the original nearest namespace declarations and the reserved `xml` binding.
Only those parsed attribute byte spans are omitted; all remaining property bytes,
styles, namespace declarations, relationship `r:id` references, unqualified `id`
and unknown metadata stay. The original attributes and identities are never removed
from the retained source. This distinguishes an original element from a new style
copy without assigning new identities or choosing a different style template.

Fresh paragraph-template copies of `pPr` and `endParaRPr` use that same original
source check and XML-namespace identity omission. A whole retained paragraph
already owns both property sources. In a changed paragraph, the successful
styled path also records its own original property spans, but only after the
head, middle and tail all succeed. This includes field-containing paragraphs:
their own paragraph properties are still copied as original bytes even though
their runs and fields use the existing static conversion. The styled path keeps
those original property bytes unchanged. Added or fallback lines borrowing that
paragraph's properties then keep the same style without copying identities still
carried by the original paragraph. Failed styled attempts record no such sources.
With no retained original source,
the first successful fresh property copy keeps its identity; later copies of that
same property source omit only the XML-namespace `id` attributes.

The leading-empty-run source case can therefore retain its original `rPr xml:id`
once at the original edge while the inserted middle keeps the same style without
copying that identity. The plan covers cross-paragraph copies of the global run
source as well as its own middle. A first ordinary run retained wholly in the
common prefix likewise owns its original property identity when the middle uses
that same style source. A whole unchanged paragraph owns its property identities
when later paired or added lines borrow its global template. The disjoint
prefix/suffix selection and actual paragraph selection still emit each such
original span at most once. A successful single-piece native partial run owns
its unchanged identity attributes in the same way; the prior serializer still
succeeds first, and unsupported native edits keep the same static attribute path.
A run spanning both retained pieces owns its original wrapper on the head
containing its original start; the tail stays static, as described below.
In a field-free paragraph, a successful raw copy of a zero-text
child strictly inside a retained interval also owns its original property identities.
A wholly retained opaque child owns the identities of its nested properties: its
original bytes stay intact, apart from the existing insertion of inherited namespace
bindings on its opening tag. Both source spans stay local until the head, middle
and tail all render successfully. A later template copy can then omit only the
same-source XML-namespace `id` attributes without changing the original opaque
or zero-text child. Static fallback and other source sites are not added to this
ledger, and arbitrary schema-specific identity attributes are not interpreted.
Internal-boundary empties, field-containing paragraphs, matching and field-cut
receipts keep their prior behavior. This is source-only work in the existing
17480/18510 pack, not full table-cell fallback, OF-509/OF-510, compiler, runtime or
Office fidelity proof.


## Same-source identities across fresh table-cell property copies

A rebuilt cell also tracks the exact original property spans used by successful
fresh outputs in document order. When no retained original owns the property,
the first fresh copy keeps its original bytes, including XML-namespace `id`.
Later copies from that same property span omit only those identity attributes
through the existing namespace-aware property copier. The original-source plan
still takes precedence when the second render knows a retained original survives.
This covers global run-template sharing across changed and added lines even
when no original run property survives, and applies the same rule to fresh
paragraph property copies. Distinct property sources are not deduplicated.

The reservation is per emitted run or break, not per `run_xml` call: each
nonempty text piece and requested break chooses its own property copy in output
order. Empty text reserves nothing. Styled and fallback paragraph attempts stage
fresh reservations locally and publish them only after the whole attempt succeeds.
A temporary static run replaced by the existing native partial-run serializer
also releases its fresh reservation; its original source owns that identity.
Selection, original raw and native-partial bytes, styles, namespace bindings,
relationship references, errors and field-removal receipts keep their prior paths.
No identities are minted and no style source is replaced or dropped. This is
source-only work in the existing 17480/18510/20096 pack; it is not a global
identity, compiler, runtime or Office fidelity certificate.


## Original table-cell paragraph properties beside converted fields

A successful styled paragraph owns its exact original `pPr` and `endParaRPr`
subtrees even when it contains fields. Their raw property bytes are emitted
unchanged; only the successful head/middle/tail completion publishes those spans.
A later added or fallback line borrowing the same paragraph template then omits
only XML-namespace identities already carried by that original property source.
Field-containing paragraphs gain no original run, field, empty-child, opaque or
gap ownership from this change. Their static conversion, field-removal receipts,
selection and error paths remain unchanged. Failed styled attempts still publish
nothing. This is the excluded field cohort of the same source-only identity work,
not full table-cell, compiler, runtime or Office fidelity proof.


## Source-start wrapper of a dual-piece native table run

A field-free ordinary run spanning both common retained intervals now keeps its
original wrapper once on the head piece containing that run's original start.
The tail keeps the existing static style wrapper. For `ABCD` changed to `ABQD`,
the original wrapper owns `AB`, the replacement keeps the existing template for
`Q`, and the tail remains a static `D` with the original run's style. This also
applies when another paragraph's partial field edit forced whole-body fallback.

The existing native partial-run serializer still runs only after static rendering
succeeds. Its successful head preserves original wrapper attributes, unknown
children, text-element attributes and gaps once, while trimming each text slot
to the head interval. Only native success records that original run span for the
existing second-pass property-copy identity handling. If native trimming cannot
produce the splice, the head instead uses the old own-attribute insertion path;
it does not claim that the original property subtree survived. The tail never
copies the original wrapper attributes or unknown children, so it cannot duplicate
that wrapper's XML identity. Fresh property identities still use the existing
same-source original/fresh-copy ledger.

Single-piece native and attribute-only fallback paths are unchanged. Paragraph
and run selection, text, style templates, namespaces, fields and their removal
receipts, errors, gaps and other retained-source classes keep their prior paths.
This is source-only work in the existing 17480/18510 pack, not full table-cell
fallback, OF-509/OF-510, compiler, runtime or Office fidelity proof.


## Actual same-count paragraph wrapper after unsupported text coverage

When a same-count native table-cell write reaches the fallback renderer, its
same-index original paragraph now keeps every own attribute, not just namespace
declarations, even if the styled path declined text coverage. One native case
is a direct opaque child holding `ABCD` changed to `ABQD`: retained mapping and
field-aware cutting decline a partial opaque edit, styled retention also declines,
and the successful fallback previously dropped the original paragraph's `xml:id`
and other wrapper attributes.

Only the actual index-zero fallback and the first actual same-index fallback for
later paragraphs carry those original attribute spans. Each original paragraph
maps to that one output line. The later-paragraph retry using the first/global
template and added lines keep the namespace-only wrapper. Count-changing
original wrappers are handled by the following extension. They never copy another paragraph's identity. The same
private renderer still selects paragraph properties, run style and end properties
and stages fresh-copy reservations in the same order; its errors and retries stay
unchanged. Attribute-only wrapper preservation does not record a full original
paragraph source interval or claim the opaque child survived.

This same-count preservation changes no styled success, field conversion or
removal receipt, text mapping, run retention, gap selection or added-line template.
It is source-only preservation in the existing 17480/18510 pack, not full native
fallback, OF-509/OF-510, compiler, runtime or Office fidelity proof.


## Actual count-changing paragraph wrappers under the global style

A count-changing fallback now keeps each mapped original paragraph's own qualified
name and attribute spans even when styled retention declines. This applies to the
matched outer paragraphs and paired middle paragraphs, using their existing
one-to-one mapping. Added lines and the same-count global retry remain
namespace-only template copies; they never borrow an original wrapper's identity.
One source case is an opaque child holding `ABCD` changed to `ABQD`, paired with
a partial field edit in another paragraph and an added line. Retained mapping,
field-aware cutting and styled retention decline the partial opaque coverage,
so successful fallback must preserve the wrapper independently of that child.

The fallback still takes paragraph and end properties from the first paragraph,
and run style from the same global source. Under a different original wrapper,
each moved property carries its own effective source namespace bindings locally,
so the wrapper's declarations cannot change property names or QName-valued content.
An absent source default namespace is explicitly kept absent when the destination
would otherwise introduce one; the same applies to generated runs and breaks
using a selected source. With no selected run, generated child names follow the
actual wrapper's DrawingML spelling. The actual wrapper remains in its original
body scope, including all its own attributes and namespace bindings.

Property identities still use the same original/fresh-copy ledger and reservation
order. Attribute-only wrapper preservation records no whole paragraph source.
Text, retained styled output, fields and removal receipts, gap mapping, errors,
retries and added-line style stay on their existing paths. No identities are
minted and no original paragraph is mapped twice. This is source-only work in the
existing 17480/18510 pack, not full native fallback, OF-509/OF-510, compiler,
runtime, Office or global identity proof.


## Styled run copies preserve an absent source default namespace

Styled native table-cell output now passes its actual paragraph's effective
nonempty-default context to both static run writers. A selected global run can
come from another paragraph: when that source has no default namespace, its
unprefixed property descendants must not acquire the destination paragraph's
default namespace. The existing run writer emits `xmlns=""` on each generated
run or break only in that case. Explicit empty and nonempty source defaults
already travel with source bindings; a missing selected run still follows the
actual paragraph's DrawingML names without a copied run property.

This uses the actual source and destination scopes, not an unconditional clear.
Same-paragraph retained runs, native raw and partial-run retention, wrapper
selection, text, style, property identity reservations, field conversion and
removal receipts, errors and gaps keep their existing paths. No original source
span or authority is added. This is source-only namespace preservation within
the existing 17480/18510 pack, not a compiler, runtime or Office certificate.


## Namespace scope keyed by prefix (FIX STEMMA-NS-PREFIX-SCAN, 2026-11-13)

`src/word_xml.rs` only. Each start tag's namespace frame keys its declarations
by prefix, keeping the declared order for the element's `namespaces` map, and
the tree builders' scope keeps an index from each prefix to the open frames that
bind it, as `src/parse_budget.rs`'s `Scope` does. Resolving the element name,
each prefixed attribute and each `mc:Choice` `Requires` token now costs one
hash, not a scan of the tag's declarations and of every open frame: one tag with
d declarations and a prefixed attributes cost O(a*d). The innermost binding
still wins, and the built tree, the refusals and their order are unchanged.
