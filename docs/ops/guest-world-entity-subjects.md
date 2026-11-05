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
subject rules remain in place. It does not rewrite `AgentScope::World` in
AGENT_DEF records or a SavedQuery's declared worlds.
