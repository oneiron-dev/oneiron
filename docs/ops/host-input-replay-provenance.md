# Host input replay provenance

`commit_host_inputs` stores each input's actual source rows in the existing
`CodeRunRawOutput.input_rows` field beside its first published body. A loan
for an already-stored path uses that occurrence's stored source set, not a
new caller's label for the same bytes. `None` stays unknown; `Some([])` stays
known empty. Staged outputs still keep an unknown input set.

The source set is carried by the native output codec and replay record.
`replay_owners` includes these exact source ids in the owners of the single
checkpoint replay-response image. This uses the existing image erasure rule:
an erase of any source may retire that image's response instance, while its
native erased stub preserves call and output metadata.

This is not live parent-run ownership. It adds no owner row, body descriptor,
independent hold, source index, or run-wide live erase. Unrelated live outputs,
shared bytes, normal actor erasure, grants and loan admission stay unchanged.

FIX9348 remains partial. Explicit source-TURN erasure still needs the native
per-occurrence release path for live host-input bodies. This checkpoint-image
slice does not claim that release, generic source closure, or runtime proof.
There is no new format, default, cap, migration or old-format reader.

## Atomic live publication

Each new host input or staged host output commits its owned body, replay
membership, and existing erase-fence result in one write transaction. Bodies
finish and stay pinned before that writer opens. The writer reads the current
parent record and preserves all of its other outputs, rather than replacing it
with the caller's earlier snapshot. Host actors are stamped before the native
replay fence; staged outputs keep their existing actor stamp.

A reused path keeps its first stored output and source rows. Its unused caller
bytes are not scanned or finished. An empty first input commit still creates the
host's stamped record, but never overwrites a concurrent publication. Separate
inputs can commit separately; this is not an all-or-fail batch transaction.
Returned output metadata comes from the stored, post-fence record, including an
erased preview when the native fence erased it.

This closes the publication-to-membership gap for these two host APIs. It does
not prove that every newly captured source was still live at publication, and it
does not add a hard-versus-soft source-deletion predicate or complete source-erase
coverage for other publishers.
