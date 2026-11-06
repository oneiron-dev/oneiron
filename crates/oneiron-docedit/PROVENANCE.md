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

The table-cell fallback change (2026-11-06, FIX 17480) touches
`src/native_patch/table.rs`. When retained text mapping and the field-aware cut
cannot apply, the existing rebuild keeps the first paragraph's terminal run
properties and the namespace bindings of copied paragraph and run properties.
If no ordinary run exists, it carries the first field's explicit run properties.
The outcome names the actual typed fields removed by that rebuild. Expected-text
checks, grid/merge checks, first-match table selection and the retained/cut paths
are unchanged. This is a source-level correction, not a PowerPoint fidelity proof.

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
keeps the previous static wrappers; arbitrary identity attributes are not copied
twice or assigned to a guessed side. The whole-run raw path, fields and their
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
Runs contributing to both retained intervals, fields, breaks, whole-run raw
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
the same static attribute path. Runs intersecting both retained pieces, fields,
breaks, templates, matching and receipts are unchanged. This remains source-only
preservation, not full table-cell fallback, OF-509/OF-510 or Office fidelity proof.


## XML identity of newly retained table-cell boundary sources

The fallback first records exact original raw edge intervals only after the
styled paragraph, including both retained intervals and its replacement, succeeds.
Failed styled attempts and existing whole-paragraph copies record no new edge
ownership. If such intervals exist, a second render uses that same original tree,
text and interval plan. Property-template source selection and every fallback
condition depend on unchanged original nodes and text, not the cloned attributes.

When a selected `a:rPr` lies wholly inside a newly retained raw interval, its
original subtree survives verbatim there. Fresh copies of that subtree in any
replacement run, requested break or added/fallback paragraph omit only attributes
whose expanded name is XML-namespace `id`. Qualified attribute names resolve
through the original nearest namespace declarations and the reserved `xml` binding.
Only those parsed attribute byte spans are omitted; all remaining property bytes,
styles, namespace declarations, relationship `r:id` references, unqualified `id`
and unknown metadata stay. The original attributes and identities are never removed
from the retained source. This distinguishes an original element from a new style
copy without assigning new identities or choosing a different style template.

The leading-empty-run source case can therefore retain its original `rPr xml:id`
once at the original edge while the inserted middle keeps the same style without
copying that identity. The plan covers cross-paragraph copies of the global run
source as well as its own middle. It does not change unrelated existing template
copies or establish identity semantics for arbitrary schema-specific attributes.
Internal-boundary empties, field-containing paragraphs, matching and field-cut
receipts keep their prior behavior. This is source-only work in the existing
17480/18510 pack, not full table-cell fallback, OF-509/OF-510, compiler, runtime or
Office fidelity proof.
