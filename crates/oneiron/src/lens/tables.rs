//! The side tables `lens` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Vault-scoped authored lens prompt keyed by the lens entity id16.
    LENS_INTENT: VaultMeta b"lens/intent/v1\0" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One proposed pack lens: its frozen compiled tree, the pack/skill slot and pack content
    /// hash it is bound to, and who proposed it. It mounts only once the owner selects it. Key:
    /// id16 (lens).
    LENS_PROPOSAL: VaultMeta b"lens/proposal/v1\0" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::lens::erase_proposal_actor_in_txn;
    /// The owner's consented selection of one proposed lens revision for a pack/skill slot.
    /// Key: string (pack name "\0" skill id hex).
    LENS_SLOT: VaultMeta b"lens/slot/v1\0" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::lens::erase_slot_actor_in_txn;
}
