//! The side tables `consent` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Standing consent grant. Key: hex64.
    CONSENT_STANDING_GRANT: VaultMeta b"consent.grant.v1:" Raw
        [restore: refuse "standing consent grants"] [family: unclassified] [tier: canonical];
    /// Approve-once marker. Key: bytes32.
    CONSENT_APPROVE_ONCE_MARKER: VaultMeta b"consent.once.v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner-reason rule behind a derived standing grant. Key: string (grant ref) ":" id16 (rule
    /// decision id).
    CONSENT_OWNER_REASON_RULE: VaultMeta b"consent.owner_reason.v1:" Named
        [restore: refuse "standing consent grants"] [family: unclassified] [tier: canonical];
    /// Settled contact-disclosure offers by (contact, verdict). Key: id16 + verdict byte + hex64.
    CONSENT_WIDEN_CONTACT_VERDICT_INDEX: VaultMeta b"consent.widen.contact_verdict.v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Completeness flag of the contact-verdict index above (u64 version). Key: ().
    CONSENT_WIDEN_CONTACT_VERDICT_STATE: VaultMeta b"consent.widen.contact_verdict_state.v1" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Parked authority-widening request. Key: hex64.
    CONSENT_WIDEN_PROPOSAL: VaultMeta b"consent.widen.v1:" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// OF-365: the owner's disclosure-mode knob (always_ask / auto / always_yes; absent means
    /// auto). Value: the mode's ASCII name. Key: ().
    DISCLOSURE_OFFER_MODE: VaultMeta b"settings:disclosure:v1:offer_mode" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
