# Code-run result archives

A whole-vault archive carries a run's released result bodies, output manifests,
and result-name bindings. It does not carry a complete deterministic execution:
bridge calls, step checkpoints, live leases and callable read sets are outside
this result round trip.

Each `Run` row must include `bindings`, `determinism` and `birth_world`. A binding
includes its name, handle and occurrence path. The handle and path identify one occurrence;
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
outputs, bindings and birth world agree; divergent facts abort the import. The
receipt counts bound, unresolved and withheld names and rebuilt or skipped records.

An imported record with unknown determinism still supports its result readers.
Execution, continuation or shadow replay that needs the clock and seed reports
those inputs as unavailable instead of inventing them. A present clock and seed
alone do not prove full replayability of an imported result archive.

## World privacy

Replay schema 3 and archive manifest version 5 carry a required nullable
`birth_world`. MCP code runs take it from the connector's accepted write
placement. Explicit default placement records the base-world ID. An entry with
no proved placement records `null`; requested read worlds are not birth worlds.
A continuation retains its source record's actual birth field. Other entry
producers remain unknown until they thread their own accepted placement.

On-device whole-vault archives still carry every run that their existing
occurrence checks release. Off-device whole-vault archives use the same snapshot
and machine-specific device-local world settings as the other archived rows.
When no world is held for that destination, those settings withhold no run.
Otherwise a run needs a known birth outside the held worlds and complete,
closed served-world capture. Captured historical worlds and each captured row's
ordinary source/withdrawal world judgment must also permit release. Unknown or
open capture keeps the previous off-device omission; known-empty capture is not
unknown and does not erase the birth-world check. Secret, taint, erase and
serializer credential checks still apply to each occurrence.

Record-scoped and OKF exports still carry no run results. Birth metadata is not
residence or read authority. Import preserves it but does not create a captured
execution; any stale same-ID capture is marked incomplete when a result record
is newly restored. Import never substitutes birth for missing read evidence.

## Heal evidence body reads

A heal's evidence context reads a code run's full output bodies through the reader's own
scoped lane, in the same snapshot as the replay record that names them: each body is
admitted against the complete source rows its occurrence and its run record, and withheld
by the occurrence's secret mark, taint or erase, as an outside-run result read withholds
one. An unavailable body keeps its manifest and recorded preview, with only its reason
recorded. The replay record's bridge calls, checkpoints and bindings stay owner-gated as
before, and the owner's result doors are unchanged.
