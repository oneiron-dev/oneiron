//! The side tables `channel_identity_lifecycle` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One channel-identity lifecycle request, kept by its ref before its ask (FIX 6424 part 3):
    /// the actor, the verb, its input's or request's digest, the identity it was given and when
    /// that was requested and, once applied, the receipt it answered, the identity's body and
    /// facts (an address among them) as that apply committed them. Dropped with the identity's
    /// erase or retirement and by its actor's erase. Key: id16 (request ref).
    CHANNEL_IDENTITY_LIFECYCLE_REQUEST: VaultMeta b"channel_identity_lifecycle_request:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::channel_identity_lifecycle::erase_lifecycle_request_actor_in_txn;
}
