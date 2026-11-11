//! The side tables `identity_topology` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// An identity-topology author carrier this vault wrote itself: a blake3 digest of the
    /// carrier row's body (32 bytes). Local truth that never replicates. Key: hex32 (carrier
    /// entity id).
    IDENTITY_TOPOLOGY_AUTHORED_HERE: SyncState b"it:authored:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Digest of which install keys counted as mine-machine signers when an authority write last
    /// reconciled the identity-topology shell edges (32 bytes). Local only. Key: ().
    IDENTITY_TOPOLOGY_MINE_SIGNERS: SyncState b"it:mine_signers" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One proposing actor's opaque ramp-scope handle on this vault (FIX 9870): 32 random bytes.
    /// Local and erasable; never replicates, never restored from an image. Key: hex32 (actor
    /// entity id).
    IDENTITY_TOPOLOGY_PROPOSER_SCOPE: SyncState b"it:proposer-scope:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// An identity-topology admission seal this vault wrote itself: the signer key and signature (96
    /// bytes) of the fact row. Local truth that never replicates. Key: hex32 (fact entity id).
    IDENTITY_TOPOLOGY_SEALED_HERE: SyncState b"it:sealed:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One local `Auto` merge, split or facet's post-hoc review candidate, kept in its decision's
    /// own writer (FIX 7817): ids, digests and its ramp-shaped scope, never claim or evidence
    /// text. Local review state, never replicated authority. Key: hash32 (audit id).
    COACH_TOPOLOGY_AUDIT_INTENT: VaultMeta b"coach:topology_audit_intent:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::identity_topology::erase_topology_audit_actor_in_txn;
    /// The one result of a reviewed topology-audit candidate, append-only, with the Coach's
    /// correction of a concern (FIX 7817). Key: hash32 (audit id).
    COACH_TOPOLOGY_AUDIT_RESULT: VaultMeta b"coach:topology_audit_result:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::identity_topology::erase_topology_audit_actor_in_txn;
    /// The first selection of a topology-audit candidate, kept before any review: the pinned
    /// recipe and revision that selected it (FIX 7817). Key: hash32 (audit id).
    COACH_TOPOLOGY_AUDIT_SELECTION: VaultMeta b"coach:topology_audit_selection:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::identity_topology::erase_topology_audit_actor_in_txn;
    /// Engine-stamped monotonic causality sequence for identity-topology ledger events. Key: ().
    IDENTITY_TOPOLOGY_SEQ: VaultMeta b"m:identity_topology_seq" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Conservative marker that a zero-head split has ever been recorded, gating an expensive ledger
    /// fold. Key: ().
    IDENTITY_TOPOLOGY_ZERO_HEAD_SEEN: VaultMeta b"m:identity_topology_zero_head_seen" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Split/facet claim-reassignment row keyed by the origin entity, event, and claim; the only
    /// record of a SPLIT assignment. Key: id16 (origin) + id16 (event) + id16 (claim).
    REASSIGNMENT_ORIGIN: VaultMeta b"reassign:v1:o:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Same reassignment inverted by destination head, so claims_assigned_to can prefix-scan by head
    /// instead of origin. Key: id16 (target head) + id16 (event) + id16 (claim).
    REASSIGNMENT_TARGET: VaultMeta b"reassign:v1:t:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
