# Code-run result archives

A whole-vault archive carries a run's released result bodies, output manifests,
and result-name bindings. It does not carry a complete deterministic execution:
bridge calls, step checkpoints, live leases and callable read sets are outside
this result round trip.

Each `Run` row must include `bindings` and `determinism`. A binding includes its
name, handle and occurrence path. The handle and path identify one occurrence;
another occurrence of the same bytes cannot supply its release decision.
Withheld occurrences keep the binding's name, path and reason, but no handle.
Names with no matching occurrence are not exported.

`determinism: null` means the frozen clock and RNG seed are unknown. An explicit
clock of zero and an all-zero seed are known values, not an unknown marker.
Import stores that distinction in the replay record, and re-export retains it.
Missing fields are malformed input; there is no old-format reader or migration.

Import validates run IDs before staging bodies. Two `Run` rows with the same ID
are rejected rather than allowing the later row to replace the earlier row's
output manifests. Restored names resolve against the original archived handle
and exact path, then bind the restored occurrence. A secret scan can change the
restored body's handle without losing this association.

Output occurrences, names and the rebuilt replay record land in the same import
transaction. A pre-existing record is skipped only when its archived inputs,
outputs and bindings agree; divergent facts abort the import. The receipt counts
bound, unresolved and withheld names and rebuilt or skipped records.

An imported record with unknown determinism still supports its result readers.
Execution, continuation or shadow replay that needs the clock and seed reports
those inputs as unavailable instead of inventing them. A present clock and seed
alone do not prove full replayability of an imported result archive.
