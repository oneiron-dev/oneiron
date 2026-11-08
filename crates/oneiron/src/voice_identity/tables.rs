//! The side tables `voice_identity` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Voice consent decision event. Key: id16 + digest16.
    VOICE_IDENTITY_CONSENT: VaultMeta b"voice_identity.consent.v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Voice print records and the active-space pointer per subject. Key: id16 [+ digest16].
    VOICE_IDENTITY_PRINT: VaultMeta b"voice_identity.print.v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Resolved session speaker roster. Key: digest16.
    VOICE_IDENTITY_ROSTER: VaultMeta b"voice_identity.roster.v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Enrollment sample row. Key: digest16.
    VOICE_IDENTITY_SAMPLE: VaultMeta b"voice_identity.sample.v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
