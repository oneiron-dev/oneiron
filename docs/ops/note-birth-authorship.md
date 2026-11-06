# NOTE birth authorship in native documents

A newly generated native NOTE birth record stores `actor: "erased"` in
its Loro authorship map. Its operation id, ledger class, empty grant and
original body hash stay unchanged. The original NOTE core remains the
birth-author record. Later admitted operations still store their writer's
stamp token, not the actor id.

Admitted document, history and receipt reads bind the birth author from
that same NOTE core in the read transaction. Room history uses the core
already admitted from the room view, not the vault's base row. An erased
core author reads as no one. This binding grants no operation authority.

Canonical recovery values still carry the actual core-bound birth author.
Capture fills only an existing live birth record; it creates no provenance
record and gives non-live values no authorship. The existing canonical
birth validator is unchanged. Reconstruction removes the birth-author
literal before inserting records into native Loro history. Recovery compares
the target's native representation before its existing ErasedWins check.

This changes local birth and canonical reconstruction, including room
births that use the same native producer. It does not rewrite existing
snapshots, implement native proposal Merge, or scrub all retained history.
Authority-to-replica imports still keep the authenticated authority's
bytes. Matching engine and server versions must be used; no migration or
old-format reader is provided. Stamp-token retention and held-token
handling are unchanged.
