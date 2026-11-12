//! The side tables `phone_line` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Quarantined arrival metadata or an erased marker, keyed by line/call digest32.
    CHANNEL_IDENTITY_PHONE_ARRIVAL: VaultMeta b"channel_identity_phone_arrival:v1:" Named Authored [accepts: crate::phone_line::arrival_accepts_masked]
        // Restore class: An erased arrival stays erased: an image never brings back the private
        // metadata an erase replaced with its marker (ARCH-0038).
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::phone_line::erase_arrival_actor_in_txn;
    /// Owner-enabled line settings, keyed by ChannelIdentity id16. No read grant is minted.
    CHANNEL_IDENTITY_PHONE_LINE: VaultMeta b"channel_identity_phone_line:v1:" Named Engine
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::phone_line::erase_line_actor_in_txn;
}
