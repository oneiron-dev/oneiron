# Pack script output reservation

Pack admission keeps an immutable source snapshot and reserves the output file
independently. Source bytes do not reduce the existing `MAX_FILE_BYTES` output
reservation. The combined workspace shape still checks path collisions and byte
overflow. This applies to admission and runtime qualification of script packs.

An otherwise valid source snapshot at or above 16 MiB no longer fails because its
output reservation becomes zero. The adapter program, injected grants, pack fit,
source screening and installation checks remain unchanged.

The output must still be one new `/mnt/workspace/adapter-output.json` file. Its
existing 1 MiB bound, empty base hash, exact path and whole-file edit checks still
apply. The guest's file-write limit also remains unchanged. Output must pass JSON
and granted-connector validation. `PackScriptOutputBytes` and
`PackScriptOutputRows` remain measured through the existing `[limits]` path.

This change does not alter guest memory, fuel, tmpfs or framing limits, snapshot
streaming, proposal spooling, disk floors or cancellation. It needs no guest,
rootfs, container-agent or protocol change.
