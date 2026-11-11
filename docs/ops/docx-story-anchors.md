# DOCX story annotation locators

`vault.artifacts.units` lists top-level paragraphs and direct table-cell
paragraphs in authored headers, footers, footnotes, endnotes and comment bodies
as `format: "docx_story"`.
Copy the returned locator when pinning or opening a thread. Its `scope` is the
native `DocxStoryScope`; `para_path` is local to that scope. Never use a body
paragraph id, infer a part name, or stringify a scope into an id.

The new story locator's character offsets count Unicode scalar values in the
current accepted-inline reading. Native deleted blocks and deleted inline text
are excluded. Top-level paragraph labels use the existing native read rule.
A direct cell paragraph uses its native per-paragraph text, not the flat cell's
joined redline text. Its native paragraph id and optional `w14:paraId` remain
intact; the engine does not turn a table address into a paragraph id. Deleted
tables, rows and cells and vertical-merge continuation cells are absent from
the new native anchor inventory. Existing body `format: "docx"` locators and native `DocxRead` keep their original
reading and coordinates. The new reader uses a local clone; it does not accept
revisions or alter the stored file.

The same locator flows through units, pinning, thread records, assignment,
views, native version re-anchoring and explicit reattachment. The legacy blob
artifact HTTP offers also return and accept its typed `docx_story` shape.
All existing file sight, annotation rights and author/provenance checks remain.

A body anchor is stamped only from actual version bytes and the body frontier
recorded for that version. It requires the same native story, local paragraph
id and exact text. It follows the paragraph's text edits and shrinks a partially
deleted span. Deleting the spot detaches the comment; its task keeps the existing
Unattached hold. Export landing checks the actual exported bytes at the recorded
export frontier. A missing read or an unmatched text keeps the version pin;
there is no nearby-text or body fallback.

Across versions, the existing Word paragraph pairing and span rules run inside
one unique native story, using actual `w14:paraId` values where present. Exact
words returning produce explicit reattachment offers only. Undo/restore still
uses stored identity and evidence; the engine does not auto-attach a guess.

## Remaining scope

This covers top-level and direct story-table cell paragraphs. Body-cell and
nested-table locators and story paragraph-question judgments/hashes remain
unbuilt. Story structure and tracked
paragraph-mark merge handling remain separate work. A locked imported story with
pre-existing redlines can remain version-only when its stored live text differs
from the new native accepted-inline reading. No body mapping is fabricated.

The change is current-format only. It adds no migration, old-format reader,
quota, timeout, authority grant or operation-level refusal. Matching engine,
server and generated clients are required when this source and its whole native
story foundation are actually released. Source inspection and SDK generation
are not compile, runtime, Word or global anchor-correctness proof.
