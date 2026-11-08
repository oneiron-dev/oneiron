//! The side tables `provenance` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// This device's cache of an actor's opaque stamp token (FIX 10930): the id of its
    /// `actor.stamp_token` claim, which a commit message names in place of the actor; an erase
    /// of the actor drops it. Key: id16 (actor); value: id16 (token).
    PROVENANCE_ACTOR_STAMP_TOKEN: VaultMeta b"provenance:actor_stamp_token:v1:" Raw
        // Restore class: A cached stamp token follows the image's token claims (FIX 10930): the
        // restore's actor sweep drops an erased actor's again, and a writer checks its claim on
        // each read.
        // Payload family: An actor's stamp token is two ids, no payload (FIX 10930), and so is a
        // token-use row (FIX 11965).
        [restore: content] [family: structure] [tier: canonical]
        => crate::provenance::erase_actor_stamp_cache_in_txn;
    /// Which records' documents name a stamp token (FIX 11965), so an actor erase's hold check
    /// finds a held record's tokens without a history walk; a record's erase drops its rows.
    /// Key: id16 (record) + id16 (token); value: empty.
    PROVENANCE_ACTOR_STAMP_TOKEN_USE: VaultMeta b"provenance:actor_stamp_token_use:v1:" Raw
        // Restore class: A token-use row follows the image's documents (FIX 11965): it names a
        // token a restored document's history names.
        // Payload family: An actor's stamp token is two ids, no payload (FIX 10930), and so is a
        // token-use row (FIX 11965).
        [restore: content] [family: structure] [tier: canonical];
}
