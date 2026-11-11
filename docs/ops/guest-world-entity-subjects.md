# Guest claims about WORLD entities

A guest CLAIM whose `ClaimSubject::Entity` names a proven WORLD uses that
WORLD's foreign-copy id. The source namespace and sender WORLD id determine
the foreign id, as for the existing WORLD-row and world-edge routing.

The admitted update must carry that subject as a WORLD row, or, when it
carries no row at that id, the vault must already store its source-derived
foreign copy as a WORLD. A carried PERSON, CLAIM or any other non-WORLD kind
keeps the Entity subject unchanged, even if an older foreign WORLD or another
edge uses the same sender id. An edge's typed WORLD target alone is not proof
for this Entity-subject rewrite. Unproven Entity subjects stay unchanged.

The rewrite runs before the existing claim-admission gate and encoding. It
does not grant standing or change source-trust grading, member handling,
withholding, edge containment, update parts or their order. Admission without
a source namespace still performs no guest-world rewrite.

This rule changes only Entity subjects. The existing InWorld and SetIn edge
subject rules remain in place.

## Typed WORLD references in AGENT_DEF and SavedQuery rows

A guest AGENT_DEF scoped `AgentScope::World(w)` and each WORLD `w` a guest
SavedQuery declares in its scope use `w`'s foreign-copy id (FIX 3892). The
SavedQuery kind is the one this vault's registry assigned to the CRM pack's
`sq` prefix. The rewrite reads the same foreign WORLD map the InWorld and
SetIn edges use: a WORLD row the update carries, an edge's typed WORLD
target, or a foreign copy this vault already stores as a WORLD. A `w` the
update carries as a non-WORLD row adds no stored-copy proof. A `w` the map
does not hold stays unchanged, as an unproven Entity subject does.

The body is decoded, renamed and re-encoded by its own codec. The row keeps
its id and metadata header. The rewrite runs before the existing body
validation and the peer agent-definition widening check, so those checks
judge the bytes that land. A body that does not decode lands as it came, and
the existing checks judge it. Member sync, admission without a source
namespace, and signed grant and control records are not rewritten.
