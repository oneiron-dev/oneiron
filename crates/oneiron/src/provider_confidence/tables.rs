//! The side tables `provider_confidence` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Disposable cache: which PERSON actor currently represents one provider key. Key: bytes32
    /// (sha256 of provider key).
    PROVIDER_ACTOR_INDEX: VaultMeta b"provider_confidence/actor/v1\0" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Disposable cache: the newest active actor.confidence_prior claim id for one provider key. Key:
    /// bytes32 (sha256 of provider key).
    PROVIDER_PRIOR_HEAD_INDEX: VaultMeta b"provider_confidence/prior_head/v1\0" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
}
