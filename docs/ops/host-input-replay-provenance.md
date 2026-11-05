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

FIX9348 remains partial. This covers decodable, already-persisted manifests.
`commit_host_inputs` still publishes a body before its final replay-record write
in a separate transaction. An erase during that gap, a publication that never
links its record, and a new late capture after the erase remain open; this slice
does not claim a cohort that was never persisted. It also does not claim generic
source closure or runtime proof. There is no new format, default, cap, migration
or old-format reader.
