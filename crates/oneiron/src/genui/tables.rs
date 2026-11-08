//! The side tables `genui` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Durable journal record of one prepared/applied/failed git ref, stage, or worktree effect. Key:
    /// hex64(repo identity) ":" hex64(record key).
    /// Owner-confirmed voice disclosure grant offer. Key: hex64 nonce.
    GENUI_VOICE_GRANT_OFFER: VaultMeta b"genui.voice_grant_offer.v1:" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::genui::erase_voice_offer_actor_in_txn;
}
