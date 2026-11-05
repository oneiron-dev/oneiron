# Blocked capture ownership witnesses

Blocked reports retain replay sources under receipt keys. Durable steps retain captured
requests under full attempt, step, lease and call keys. Both use the existing
`coach:blocked_source_owner:v1:` inventory to keep their actual owners apart from their
source values.

A receipt write records its final stored reporter in the same transaction, including the
requestless fallback after a kept-request savepoint fails. Replacing that receipt clears
its previous reporter witnesses, even if its old source row is already absent. A step's
actor, subject and terminal-claim witnesses keep their existing encoding and behavior.
The inventory does not grant read or erase authority.

An actor erase unions decoded sources with exact witnessed keys. It can therefore take a
prospectively witnessed receipt whose source value no longer decodes. For a present row,
it revokes the native side-row custody under the erase's existing act before deleting the
row. It removes that receipt's witnesses even when the source is already gone. A hard
non-erase entity delete still leaves receipt sources alone.

Checkpoint response ownership uses these same witnesses. The existing response binding
pass records and journals owner obligations before a checkpoint carries a response.
Erasing an owner retires the retained body instances those obligations name; an empty
witness value alone is not evidence that any body was retired. Getter 16 carries canonical
step and receipt witnesses under each witness owner's content compartment. Unknown roles,
partial keys and role/key-kind mismatches do not prove an owner.

This is prospective. There is no backfill or reconstruction from damaged source bodies.
A source without an intact canonical owner witness still depends on its decodable owner
fields; pre-witness, unowned and damaged-witness cases remain outside this repair. This
change does not establish whole-vault erasure or external process termination.
