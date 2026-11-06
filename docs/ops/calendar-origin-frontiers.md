# Calendar origin frontier observations

`Memory::calendar_create` records observed source frontiers on the existing
`calendar.origin` claim. Its existing same-writer evidence-read check comes
first. The projector then validates the original actor and every evidence
TURN before reading any frontier in that same writer.

The claim's existing `evid` map keeps `kind`, `write_class`, and `actor`. Its
`source_frontier_observations` entry contains one `{turn, frontier}` map per
admitted evidence TURN. `frontier` is the native incarnation-qualified binary
value, or Nil when that TURN has no document head. A MESSAGE or SUMMARY
frontier is never substituted for the evidence TURN.

These are observed facts, not validation of the caller's `sourceFrontiers`
strings, proof of frontier membership, source authority, or retention rights.
The public input and EVENT body remain unchanged. The raw Vault projector and
Imported admission do not gain capture or a new refusal.

The bytes travel with the existing claim row and its normal codec, lifecycle,
archive, and restore paths. There is no new side table, dependency, citation
floor, public schema, migration, or source-erasure policy. Full typed caller
frontier validation remains separate work.
