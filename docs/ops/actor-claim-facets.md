# Actor claim facet stamps

Native actor claims keep the PERSON actor's substrate facet. AGENT_DEF and MACHINE actors do not create a PERSON substrate facet. Their native claims use the actor's stored birth facet when it names a stored FACET, otherwise the vault's existing default facet. The writer resolves this in the same transaction as the claim.

Resident-dream craft candidates use the same rule. An owner-approved or rejected verdict keeps the reviewed candidate's stored facet. A change to the vault default between proposal and review does not move that verdict into another facet.

This changes only the facet stamp. Evidence, source lineage, owner review, approval, cardinality, deduplication and supersession still use their existing native checks. The FACET validation remains enabled; no facet is created to satisfy an invalid derived identifier. Existing PERSON stamps are unchanged.

Deploy the matching engine binaries through the normal release process when authorized. No configuration, model worker, migration, VM or data conversion is required. This source change does not claim runtime proof or repair existing malformed claims.
