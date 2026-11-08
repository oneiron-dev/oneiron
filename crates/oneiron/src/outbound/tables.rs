//! The side tables `outbound` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Index from a principal reference to every standing outbound grant naming it. Key: u16be(len) +
    /// string(principal_ref) + id16.
    OUTBOUND_GRANT_PRINCIPAL_INDEX: VaultMeta b"outbound_grant/principal/v1\0" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// The owner's override of where one reader's weave digest is sent (FIX 1262): off, or
    /// another of the vault's channel identities the reader has a live contact on. Absent means
    /// the send is on, to the reader's primary route. Key: id16 (reader).
    WEAVE_DIGEST_CHANNEL_OVERRIDE: VaultMeta b"weave:digest_channel_override:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::outbound::erase_weave_digest_channel_override_actor_in_txn;
}
