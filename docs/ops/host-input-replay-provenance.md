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
