# PERSON values in one code run's stored output

When an authorized PERSON reveal delivers a value to a bound code run, that
same execution's later result bodies replace matching bytes with the existing
bare `pr…` handle. The queue's string run label, task attempt, payer and session
are not the execution identity. An unbound reveal keeps its existing behavior.

The PERSON delivery keeps a keyed, value-free print beside its existing reveal
collection. It uses the known-value index's native custody master without adding
a global custody holder or retaining the PERSON value. A PERSON-only vault can
mint that master in the delivery transaction even when no custody value has been
indexed. A committed missing master is never replaced with a new one.

Each output frame and final tail reread this execution's delivered prints. The
source exists before the first delivery, so a reveal collected after the first
output frame is included. The custody entries, PERSON prints and matching share
one snapshot under the custody read guard. Prints, entries and matcher keys are
wiped before that pass releases the guard.

Matching uses the existing non-empty substring and encoded-form rules, including
short names, only for that execution. Custody matches are computed independently
and keep priority on overlap; their existing `[secret sc…]` text and genuine
custody IDs do not change. PERSON replacements use the native bare `pr…` grammar.
Other runs and global mark writers do not load these PERSON prints.

Canonical and session-bound executor output sinks use the same matching path for
streamed console, finish, stored values and files, and runtime-returned step
bodies. A model reply's evidence copy also replaces PERSON values, but only in
typed `ContentPart::Text.text`, before JSON encoding. It borrows every unchanged
part and leaves the live reply used for execution untouched. Each text pass reads
current run prints. Custody overlap uses the selected matches in the complete
native reply serialization, not an independently encoded Text scalar: an earlier
match can start in a field boundary and suppress a later overlapping custody hit.
Borrowed typed content/Text positions and the native decoded-byte source map place
each PERSON hit in those exact serialized bytes. The temporary full encoding is
wiped on return or error. Custody bytes remain for the evidence sink's original
custody sweep rather than being replaced twice. This is not a claim that all
encoded-form context remains unchanged after PERSON substitutions, or that PERSON
matching applies to arbitrary control-JSON or untyped fields.

Serialized executor control records and source maps keep the existing
custody-only path. Reply evidence preserves role/kind tags, reasoning and its
signatures, tool-call IDs/names and untyped JSON, and media fields. PERSON
substring matching must not rewrite JSON keys, status tags or identifiers.
Oversized verb replies and Query spills still use their original custody-only
sinks: their arbitrary JSON has no typed payload/identifier distinction. No
recursive string-value or field-name heuristic is applied. Stored programs and
executed JavaScript stay byte-exact and unswept. Existing output publication,
provenance, taint, input-row and final-sweep behavior stay in place.

The value reread lease is not the matching lifetime. A delivered value can be
echoed after its lease ends, so output matching does not expire at that boundary.
Erasing the asking actor clears its retained output print in the existing erase
transaction. Merely anonymizing the owner who answered does not clear another
actor's print. This is not a claim that all PERSON source/run erasure paths or
other model-output pipelines have run-local matching.

No new setting, limit, word boundary, minimum length, timer, refusal or transport
is introduced. Deploy the matching engine revision to use this behavior; no
configuration or data migration is required.
