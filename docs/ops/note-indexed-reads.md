# Indexed NOTE reads

`vault.notes.read` still reads live NOTE text by default. Its existing
`NoteVersion` input and edit-head rules are unchanged.

Use `vault.notes.read_indexed` to select the NOTE frontier already published to
its text and vector indexes. It takes `NoteIndexedReadRequest`:

```json
{
  "note_ref": "<NOTE reference>",
  "reason": "<the caller's reason, when required>",
  "spans": [{"start": 0, "end": 5}]
}
```

`spans` is optional. The answer is the existing scoped `NoteReadView`. Its
markdown, title, version, head id and anchors all come from the selected stored
frontier. The indexed head can differ from the current live head. This new read
does not change the existing exact-version or edit-head rules.

The door uses the same credential, row admission, room view, private/diary gate
and lifted-view handling as an ordinary NOTE read. It does not fetch another
copy or treat a revision, head id or content hash as authority. A room NOTE read
uses that room's content snapshot and scan accounting, not a fresh base-vault
read. `source` still describes where the read obtained its content; it is not a
live/indexed selector.

## Publication

The first structural persist publishes the actual stored NOTE snapshot. Later
edits advance the live frontier and keep the indexed frontier until the existing
configured idle publication runs. There is no new debounce default or limit.

A mask, citation scrub or explicit history purge can remove history that an old
indexed frontier needs. In that same write transaction, publication then selects
the clean stored frontier and updates text and phonetic postings. Vectors for
another source body are removed and the existing refill path is scheduled. A
source-identical vector is retained. An activated native binding with a missing
slot or frontier does not silently read today's live document instead.

Before a native NOTE binding exists, the new door preserves the existing NOTE
read path. Lightweight NOTE births therefore do not require an extra stored
snapshot just to be read.

## Retained references and checkpoints

Native revision entries name an actual NOTE document slot, its retained frontier
and the exact physical-row revision supplying its metadata. Generic physical
history and common-document revisions retain their existing reference and cursor
namespaces. Native activation does not keep another raw NOTE body or author copy.
A native history cut does not imply a selective erase of separate generic
physical history.

Checkpoint restore validates native entries after NOTE slots and all revision
rows have landed in the same restore transaction. A native ledger can have no
generic revision document; that is not evidence that its bindings can be skipped.
The restored slot/frontier, physical-row reference, reverse bindings, state and
staged inputs must agree. Generic and common-document checks remain in place.
The checkpoint's existing actor projection and unclassified-row rules are
unchanged. This is a current-format change, with no migration or old-format
reader.
