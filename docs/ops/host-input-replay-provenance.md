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

## Live persisted occurrences

A hard source erase now scans the native replay manifests in the erase's
accepted writer. For each output whose stored `input_rows` names that exact
source, it withdraws only the actual run/path occurrence, replaces only its
preview text with the native erased preview, releases that occurrence's own
marks and body descriptor, and stages the native body erasure with the actual
digest captured before release. Another holder keeps shared bytes; native
custody, hold, deferred retirement and receipt rules still apply. The parent
response owner, its bridge replies and unrelated outputs are unchanged.

The occurrence uses the existing stale status, not a new format or body-owner
row. Owned result taint/secret projections and the explicit host/finding readers
honour that exact occurrence status. Privileged raw shared-byte APIs do not gain
an occurrence authority or a content-hash-wide withdrawal. Later replay writes
of the same withdrawn occurrence cannot restore its preview or body hold.

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
not complete source-erase coverage for other publishers.

FIX9348 remains partial. The source-erase path covers decodable, already-persisted
manifests. An occurrence first captured after the erase meets the same retirement
in its publishing writer's replay fence: when a source in its frozen `input_rows`
has the native hard-delete marker, the fence stages that occurrence's stale mark
and retires it as above. A soft delete, a missing row or a pending erasure does
not count; a pending erasure meets the occurrence in its own accepted writer. This
slice does not claim unknown sources, generic source closure, or runtime proof.
There is no new format, default, cap, migration or old-format reader.
