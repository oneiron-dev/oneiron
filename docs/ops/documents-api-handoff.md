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
| The op table, its version (`CONTRACT_SCHEMA = 1`), and the call, reply and error JSON schemas | Authentication, accounts and API keys |
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

- **A call** is `{"schema": 1, "op": "<name>", "args": {...}}`, plus a list of byte inputs. The
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

## Ops, schema 1

| Op | Inputs | Args besides inputs | Reply | Output | Native door |
|---|---|---|---|---|---|
| `contract.describe` | none | none | `described` | none | `contract::describe` |
| `docx.read` | `document` | `limits` (DOCX) | `docx_blocks`: id, kind, role, text, cells, lock | none | `read_docx_blocks` |
| `docx.revise` | `document` | `transaction` (stemma tracked-change grammar), `limits` | `docx_revised`: the transaction with its date pinned, notes | `document` | `prepare_revision_transaction`, `revise_with_notes` |
| `docx.validate` | `document` | optional `transaction`, `limits` | `checked` | none | `validate_revision_transaction`, `validate_blocking_with_limits` |
| `docx.project` | `source` | `changes` (set_text, set_cell, move, insert, delete), `revision` (author, RFC 3339 date, group), `limits` | `written` | `document` | `project_docx` |
| `xlsx.read` | `workbook` | `limits` (package) | `xlsx_book`: sheets, cells, names, styles, locks | none | `read_xlsx_cells` |
| `xlsx.project` | `source` | `changes` (cell, set_name, delete_name), `limits` | `written` | `workbook` | `project_xlsx` |
| `xlsx.mark_full_calc` | `workbook` | `limits` | `written` | `workbook` | `mark_full_calc` |
| `xlsx.recalc` | `workbook` | `clock` (now_ms, utc_offset_minutes, seed), optional `location` (directory, file_name), `limits` | `recalculated`: engine, version, formula count | `workbook` | the host's `RecalcPort`; `FormualizerEngine::recalculate_xlsx` |
| `deck.read` | `deck` | `limits` | `deck`: editability, id marks, slides, shapes (id, kind, slide-space position, extent, text, fingerprint), ambiguities | none | `Package::open`, `DeckView::read` |
| `deck.transaction` | `deck`, `assets[].input` | `transaction` (deck transaction schema 1), `assets` (artifact, version, media, origin, provenance, rights), `limits` | `deck_transaction`: the report (candidate hash, part diff, step effects, marks, handoff hash) | `deck` | `run_transaction` |
| `deck.create` | `brief.input`, `template`, `fonts`, `assets.*.input` | `brief` (version, optional kept hash), `assets` keyed by brief asset id, `names`, `limits` | `deck_ask` (pages no layout could hold) or `deck_created` (hash, slides, write set, omitted, fit-unverified units) | `deck` | `compile_with_fonts`, `emit` |

A deck step targets a shape by its slide part, its `p:cNvPr` id and its content fingerprint. All
three come from `deck.read`. A transaction's `base` is the BLAKE3 hash of the deck input.

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

## Not on schema 1

- **Live office bodies:** the shared Loro bodies, forks, landing and export projection (OF-505,
  OF-510). They are vault state, not a stateless file op.
- **PPTX modern comments and slide review:** they live in the core crate
  (`crates/oneiron/src/edit_roundtrip/pptx`, `slides_review.rs`), and review runs on the engine's
  decision ladder.
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
