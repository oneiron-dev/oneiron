# Documents API handoff

The document engine is sold as two parts (ARCH-0075 section 2, ruling `docengine:business`). The
first is one OSS crate under the workspace licence: `oneiron-docedit`, with `oneiron-xlsx-formula`
for recalculation. The second is one paid hosted documents API in oneiron-cloud. This page is the
handoff between them. It says what the crate's contract serves, and what the cloud service owns.

Documents edit in-engine through docedit and the formula engine. They need no organ process
(owner ruling, 2026-10-17). The engine and the hosted API call the same contract,
`oneiron_docedit::contract`, in process.

## Who owns what

| The crate (`oneiron_docedit::contract`) | The cloud service (oneiron-cloud) |
|---|---|
| The op table, its version (`CONTRACT_SCHEMA = 5`), and the call, reply and error JSON schemas | Authentication, accounts and API keys |
| Every native read, edit, check and projection | Metering and billing units |
| Refusals with a closed code and bounded detail | Hosting, scaling, timeouts, queues and async jobs |
| The checks that every op runs against the caller's limits | Per-plan limits: the values it passes in each call |
| Determinism: pinned dates, seeds and handoff hashes | Uploads, storage, ids, retention and expiry of inputs and outputs |
| Nothing else. No session or handle store, no clock read beyond a missing DOCX revision date, no network, no writes | Session images: LibreOffice, the precision fallback for workbooks the native engine refuses, and openpyxl. They never enter a repo (D10) |
| | The HTTP shape: routes, status codes, multipart or upload handles, retries |

An op only proposes bytes. The caller decides what lands. A refusal changes nothing and returns
no output. In the vault, the engine keeps every write and runs the policy check (ARCH-0075,
"The engine keeps every write"). In the hosted API, the customer's own system keeps them.

## The call

```rust
use oneiron_docedit::contract::{Ports, execute_json};
use oneiron_xlsx_formula::engine::FormualizerEngine;

let engine = FormualizerEngine::new();
let done = execute_json(call_json, &[&docx_bytes], Ports { recalc: Some(&engine) })?;
let manifest = done.manifest(); // name, media type, size and BLAKE3 of each output
```

- **A call** is `{"schema": 5, "op": "<name>", "args": {...}}`, plus a list of byte inputs. The
  args name each input by its index in that list. The hosted API maps its multipart parts or
  upload handles to that list, in order.
- **A reply** is `Done { reply, outputs }`. `reply` is a typed `Reply`, tagged by `"reply"`.
  `outputs` holds the named byte outputs, each with its media type. `Done::manifest()` lists each
  output's name, media type, size and BLAKE3 hash, for the JSON body beside the bytes.
- **`execute_json`** reads `schema` before anything else. A call that names another schema
  refuses as `unsupported_schema`, even when its op is unknown.
- **`contract.describe`** returns the op table: each op's inputs, accepted media types, outputs
  and port. It also returns `call_schema`, `reply_schema` and `error_schema`, generated with
  schemars 0.8. The hosted API serves this reply as its discovery document.

## Ops, schema 5

| Op | Inputs | Args besides inputs | Reply | Output | Native door |
|---|---|---|---|---|---|
| `contract.describe` | none | none | `described` | none | `contract::describe` |
| `docx.read` | `document` | `limits` (DOCX) | `docx_blocks`: body `blocks` (id, kind, role, text, runs, cells, lock) and scoped `stories` | none | `read_docx_body` |
| `docx.revise` | `document` | `transaction` (stemma tracked-change grammar), `limits` | `docx_revised`: the transaction with its date pinned, notes | `document` | `prepare_revision_transaction`, `revise_with_notes` |
| `docx.validate` | `document` | optional `transaction`, `limits` | `checked` | none | `validate_revision_transaction`, `validate_blocking_with_limits` |
| `docx.project` | `source` | `changes` (set_text, set_runs, set_cell, move, insert, delete; set_story_text, set_story_runs and set_story_cell for header/footer/footnote/endnote/comment stories with an explicit scope; set_story_cell replaces the addressed cell's first paragraph by default, or its exact in-cell paragraph id when `paragraph` is supplied; a mark change on kept body text lands as a tracked formatting change, header/footer runs land as one whole-paragraph redline, note and comment runs land paragraph-scoped the same way, comments as Normal annotation text), `revision` (author, RFC 3339 date, group), `limits` | `written` | `document` | `project_docx` |
| `xlsx.read` | `workbook` | `limits` (package) | `xlsx_book`: sheets, cells, names, styles, locks | none | `read_xlsx_cells` |
| `xlsx.project` | `source` | `changes` (cell, set_name, delete_name, conditional_formats: a range, a cell-value or formula rule, and the differential look written to `dxfs`), `limits`, optional `location` (directory, file_name: an external link naming it is the workbook's own and follows a sheet rename or deletion) | `written` | `workbook` | `project_xlsx` |
| `xlsx.mark_full_calc` | `workbook` | `limits` | `written` | `workbook` | `mark_full_calc` |
| `xlsx.recalc` | `workbook` | `clock` (now_ms, utc_offset_minutes, seed), optional `location` (directory, file_name), `limits` | `recalculated`: engine, version, formula count | `workbook` | the host's `RecalcPort`; `FormualizerEngine::recalculate_xlsx` |
| `deck.read` | `deck` | `limits` | `deck`: editability, id marks, slides, shapes (id, kind, slide-space position, extent, text, fingerprint), ambiguities | none | `Package::open`, `DeckView::read` |
| `deck.transaction` | `deck`, `assets[].input` | `transaction` (deck transaction schema 1), `assets` (artifact, version, media, origin, provenance, rights), `limits` | `deck_transaction`: the report (candidate hash, part diff, step effects, marks, handoff hash) | `deck` | `run_transaction` |
| `deck.create` | `brief.input`, `template`, `fonts`, `assets.*.input` | `brief` (version, optional kept hash), `assets` keyed by brief asset id, `names`, `limits` | `deck_ask` (pages no layout could hold) or `deck_created` (hash, slides, write set, omitted, fit-unverified units) | `deck` | `compile_with_fonts`, `emit` |
| `pptx.comments` | `deck` | `edits` (author, thread and comment GUIDs, time, and an add with its slide or shape target, a reply, or a resolve), optional `slide_creation_ids`, `seed`, `limits` (comments) | `pptx_comments`: touched parts, the slide creation IDs minted, each new thread's anchor | `deck` | `pptx_comments::comment_patch` |
| `pptx.comments.inspect` | `deck` | `limits` (comments) | `pptx_comments_inspected`: slides (number, part, id, creation ID, fingerprint, shapes with creation GUID, fingerprint and slide-space position), signature parts, threads with an unknown anchor | none | `pptx_comments::inspect_pptx`, `unknown_anchor_threads` |

`docx.read` returns authored header/footer parts, footnotes, endnotes and comment stories
beside the main body. Each story carries its native scope and its own ordered local blocks;
Story paragraph ids such as `story_p1` are local to their story; table ids such as `tbl_1`
can also occur in the body and in other stories. Header/footer scopes include the source band
(default, first or even). Synthetic render-time blank bands are not authored package parts
and are not listed. Story roles are absent: body role tokens cannot be looked up by colliding
story-local ids. The same text/run/cell/lock projection is used for both. Each cell also has a
required ordered `paragraphs` list with native ids, guards, accepted inline text
and exact target locks. Unlike the flat cell `text`, paragraph text excludes
pending deleted tombstones. Nested table and opaque sibling blocks remain in
the source package; their presence does not lock otherwise editable paragraphs.

`docx.project` writes story text statelessly through the same native tracked
transaction: `set_story_text` covers authored headers/footers plus footnote/endnote
bodies plus one paragraph within a comment story, `set_story_runs` covers authored
headers/footers plus one paragraph within a footnote/endnote story plus one paragraph
within a comment story. Each change names its
explicit story scope and its story-local block id; a story's local id never addresses
the body or another story. Header/footer runs land as one whole-paragraph tracked
redline with exactly the requested six text marks, including empty mark sets and
same-text edits. Absent marks are explicitly off on new runs, including the
complex-script bold/italic slots; script selectors, source deletion history and
unrelated run properties remain intact. Ordinary `set_story_text`
keeps native formatting inheritance, except comment text which lands as Normal
annotation text in both outer modes. This is not the body's granular formatting
pass. Note runs are paragraph-scoped: the addressed note paragraph lands as one
whole-paragraph tracked redline with exactly the requested six marks, later
note paragraphs included, while the old note plain mode (`set_story_text`
first-paragraph body) is unchanged. Comment runs are paragraph-scoped the same
way and land as Normal annotation text with exactly the requested six marks,
later comment paragraphs included; one op serves both comment text and runs.
Author/date, paragraph `para_id`, threading/resolve metadata, all other blocks,
and body anchors stay intact; the edited comment's full content hash is recomputed.
`set_story_cell` projects through the native `edit_story_cell` op, naming the
actual story scope, its local table id and a logical row/column. Like the body
cell writer, absent `paragraph` it replaces only the cell's first paragraph.
With `paragraph` it resolves that exact direct paragraph inside the selected
cell, never another cell, nested table, story or body. Other cell paragraphs,
table geometry and other cells stay intact. Header/footer and note cell text
lands tracked; comment cell text lands as Normal annotation text in both outer
modes, without accepting other cells' history. The native story table guard
pins the table in the same transaction base as sibling steps. There is no bare
story-to-body table-id fallback.

Story move/insert/delete ops do not exist. Shared-Loro story paragraph import,
scoped text/splice/mark ops, read, fork review and export (each changed paragraph
as its full runs) are implemented on this chain and work once it integrates.
Shared-Loro story tables import each direct cell paragraph independently,
never the joined redline cell text. `set_story_cell_paragraph` and
`splice_story_cell_paragraph` carry scope, local table id, logical row/column
and exact paragraph id; the model stores plain text, not rich marks. Every
changed paragraph exports with the explicit native selector. Read, fork review
and masked views include these cells; fork review uses the existing table-level
Cells granularity. Scope, table/cell/paragraph membership, order and target locks
must still match the imported source. Existing native restrictions on structural
cell revisions, comment redlines, literal prefixes and inline anchors remain
local to their actual targets. Header/footer and note cell text can layer tracked
revisions through the native cell materializer; reading accepted text does not
resolve their source history. Direct settlement touches only the edited
paragraph, not other cells' pending changes. Story structure, rich cell marks
and story ask pinning remain unbuilt engineering scope. Filling an
empty header/footer paragraph supplies its actual semantic guard with an empty
`expect`. Native expectations are substring matches; a blank expectation without
a guard retains its prior refusal.

A deck step targets a shape by its slide part, its `p:cNvPr` id and its content fingerprint. All
three come from `deck.read`. A transaction's `base` is the BLAKE3 hash of the deck input.

A comment targets a slide by its number and p14 creation ID, and a shape by its `a16:creationId`
GUID and fingerprint, all from `pptx.comments.inspect`. Only the comment, author, slide extension,
relationship and content-type parts it declares may change; any other part diff refuses. A
comment's text is written whole: the contract bounds no comment's length.

## Media types

| Input or output | Media type |
|---|---|
| DOCX | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` |
| XLSX | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` |
| PPTX | `application/vnd.openxmlformats-officedocument.presentationml.presentation` |
| A deck brief | `application/json` |
| Deck assets | `image/png`, `image/jpeg`, `image/svg+xml` (the closed SVG subset, compiled to native shapes) |
| Fonts for measuring text | sfnt: `font/ttf`, `font/otf`, `font/sfnt` |

The contract does not sniff bytes: a deck asset's `media` field names its type.

## Limits

The crate holds no fallback numbers. Every op that reads a package takes the caller's ceilings.
DOCX ops take `{max_entries, max_part_bytes, max_total_bytes}`, checked across every entry before
any XML parser runs. XLSX and PPTX ops take
`{archive_bytes, entries, part_bytes, expanded_bytes, xml_depth, xml_nodes}`, checked before
decompression and again after it. A package over a ceiling refuses as `invalid_document`.
The PPTX comment ops take one `{max_archive_bytes, max_entries, max_part_bytes,
max_expanded_bytes, max_xml_bytes, max_xml_attributes, max_xml_namespaces, max_xml_depth,
max_xml_nodes}`: the package's ceilings, then each XML part's. A comment author's name has no
bound of its own; it is attribute text inside those.
How many edits one call carries is not bounded here. The vault measures a comment proposal's
edits against its `[limits] pptx_comment_patches` row (10,000), asks past it, and serves the
proposal whole.

For reference, the vault ships these values:

- **Packages** (`crates/oneiron/src/gate/default_manifest.rs`): 512 MiB archive, 10,000 entries,
  64 MiB per part, 512 MiB expanded, XML depth 256, 1,000,000 XML nodes.
- **DOCX** (`ArchiveLimits::DEFAULT`): 1,000 entries, 200 MiB per part, 500 MiB in total.

The hosted API picks its own values for each plan. Error detail is capped at 512 bytes
(`MAX_DETAIL_BYTES`), the same cap as an organ's error detail.

## Errors and refusals

A failed call returns `ContractError {code, detail}` and no output. Treat `detail` as untrusted
text: it can quote ids or text from the caller's own transaction.

| Code | Meaning | What the hosted API does |
|---|---|---|
| `bad_request` | The call does not parse, an op's args fail its schema, or the args name a missing input | Return it to the caller |
| `unsupported_schema` | The call names a contract schema this build does not serve | Return it, with the served schema from `contract.describe` |
| `invalid_document` | An input is not a package the op reads within the limits | Return it |
| `stale` | The input moved since it was read: a base hash, a staleness guard, a changed shape, or a kept brief that no longer matches | Return it; the caller reads again |
| `refused` | The native writer refuses the edit for the reason the detail names | Return it |
| `not_editable` | The package is signed, or its metadata cannot be inspected | Return it; never retry |
| `needs_fallback` | The native formula engine refuses this workbook | Run the LibreOffice session image if the plan includes it; otherwise return it |
| `unavailable` | The op needs a host port the caller did not supply (`xlsx.recalc` without `RecalcPort`) | A hosting bug: wire the port |
| `internal` | A broken invariant inside the crate | Log it and return it |

The HTTP status for each code is the cloud service's choice.

## Waits

The contract has none. Every op is synchronous and CPU-bound, and it either finishes or refuses.
Queues, deadlines and async jobs belong to the cloud service. `needs_fallback` is the only point
where work moves to another runtime, and that runtime (the session image) is the cloud's.

## Replay and determinism

- **`docx.revise`** returns its transaction with the revision date pinned. Replaying that
  transaction gives the same edit. A transaction without a date takes the host clock's time once,
  and the reply records it.
- **`deck.transaction`**: its `seed` derives every id that a step mints. The report's `handoff`
  hash binds the candidate bytes, the base, the write set and the report.
- **`xlsx.recalc`**: the same `clock` and `seed` recalculate the same values.
- **`deck.create`**: `brief.kept_hash` binds the deck to the kept brief. If the brief's bytes no
  longer hash to it, the call refuses as `stale`.
- **`pptx.comments`**: a commented slide without a p14 creation ID gets one drawn from `seed`, and
  the reply lists it. Passing those back as `slide_creation_ids` replays the same bytes; a mint the
  edits do not need, or one they need and the list lacks, refuses as `bad_request`.

## Vault DOCX revision attribution

A shared DOCX body's default-author export keeps one native revision per consecutive actor group
when the package can represent it. A terminal group that only deletes the final paragraph can
keep those revisions when the native view proves the exact live text and order, with one empty
physical final-mark carrier. This slice requires unmoved, unsplit text-only paragraphs, no
literal prefixes, and exactly one deleted break on the carrier's immediate physical predecessor.
Earlier groups' text revisions keep their own marks and authors. This is a read-only witness;
it does not resolve revisions or rewrite the package's identities.

Every unproved final-deletion shape keeps the existing whole-window default-author projection.
This includes nonterminal or mixed-operation groups, moves, inserted blocks, nontext content,
labels, and an empty live body. The stateless `docx.project` call and all contract schemas are
unchanged.

## Not on schema 5

- **Live office bodies:** the shared Loro bodies, forks, landing and export projection (OF-505,
  OF-510). They are vault state, not a stateless file op.
- **Slide review and managed comment threads:** review runs on the engine's decision ladder
  (`crates/oneiron/src/edit_roundtrip/slides_review.rs`), and the annotation threads a comment
  proposal settles into are vault state (`crates/oneiron/src/anchored_annotation`). The comment
  writer and inspector themselves are the `pptx.comments` ops.
- **Generated-image deck assets:** their adapter receipts stay engine-side.
- **The Office oracle:** live Word, Excel and PowerPoint runs are Phase 2.

## Versioning

The crate serves exactly one contract schema. Changing an op's args or reply means a new schema
number, and there is no compatibility path. Two nested grammars carry their own versions: the
deck transaction (`schema: 1`, `crates/oneiron-docedit/src/edit/transaction.rs`) and the stemma
tracked-change transaction (`crates/oneiron-docedit/vendor/stemma-engine`).

Source: `crates/oneiron-docedit/src/contract/mod.rs` (the types and the op table) and
`contract/run.rs` (the handlers and the refusal mapping). The recalculation port is
`crates/oneiron-xlsx-formula/src/contract_port.rs`.


### Native live deck export graphic settings (FIX 10653)

`vault.artifacts.body.deck.export` accepts optional `graphics`, with the existing
`svg_bytes`, `raster_bytes` and `raster_pixels` fields. The request passes the same
`GraphicLimits` to the native export profile. The projector resolves the existing
default once when the field is absent, then uses that value for both newly compiled
live pictures and replaced picture payloads. This does not re-admit held media or
unchanged retained pictures. The default-only internal export caller passes `None`.

Explicit settings are part of the export key; even an explicit default is distinct
from an omitted setting. With no setting, the old serialized profile/key fields,
order and hash remain unchanged. Numeric defaults, profile-name gates, asset and
package admission, actor/rights/secret checks, and land/propose/rebind ordering are
unchanged. The generated SDK carries the optional request field.
