# Code-run read-world capture

The run's ledger records worlds and row scopes from the reads that served them.
It does not reconstruct an earlier answer from a later row lookup. Capture errors
never fail the memory read. They leave the ledger unknown instead.

## Native `vault.get`

A live canonical executor call plants a private capture in its `HostWriteOrigin`.
The Memory point-view producer derives a candidate from the actual admitted row's
kind and body, the lane's store view, and the same read transaction. It records the
candidate only after the original projection, including short refs, repo-body
handling, lifted-key masking and birth metadata, succeeds.

The dispatcher joins this evidence with every row the answer and its observations
release. A released row without evidence, or an unproved world, keeps the ledger
unknown. Missing scope evidence leaves that row's scope unproved; it does not erase
proved worlds. Successful ledger writes are tied to the live call's bridge sequence.

The row's pre-hook context carries the same capture into its post chain. An admitted
Redact outcome, even one whose paths match nothing, or a blocking read hook that
hides the result prevents a complete capture. This is conservative. Hook decisions,
returned values, and public hook APIs do not change.

## Limits of this slice

This covers live native `vault.get` calls through the canonical host and MCP doors.
It does not make other AgentVerb reads, room dispatcher reads, or settled replay
answers complete. An absent capture or an empty capture keeps their existing
unknown behavior. The answer format and stored replay codec are unchanged.

This is source instrumentation, not runtime or whole-run closure proof. A prior
unknown cause still makes the run's ledger incomplete. Deploy matching engine and
server binaries; no configuration, guest image or data migration is required.
