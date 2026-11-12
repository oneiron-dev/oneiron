//! The side tables `campaign` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The currently active campaign compliance rule pack. Key: ().
    CAMPAIGN_COMPLIANCE_ACTIVE: VaultMeta b"campaign:compliance:active:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Durable UTF-8 activation notice for one compliance-pack version, one row per version. Key:
    /// u32be.
    CAMPAIGN_COMPLIANCE_NOTICE: VaultMeta b"campaign:compliance:notice:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// One staged compliance-pack amendment proposal awaiting an owner stamp. Key: ().
    CAMPAIGN_COMPLIANCE_PENDING: VaultMeta b"campaign:compliance:pending:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Caller-bound compliance amendment, owner decision or verification receipt. Key: id16.
    CAMPAIGN_COMPLIANCE_RECEIPT: VaultMeta b"campaign:compliance:receipt:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// One campaign body version's copy review (ARCH-0059 #copy-review): whether it follows
    /// the voice guide, the judge's reason class, the guide and its text digest, and the
    /// answering providers; no body text. Key: id16(campaign) + the body's 32-byte digest.
    CAMPAIGN_COPY_REVIEW_VERDICT: VaultMeta b"campaign:copy_review_verdict:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// One campaign enrollment outbound call's retained request and optional current hold:
    /// original ids/digests, actual attempt provenance and frozen-envelope digest, and its
    /// owner-ask/redrive refs; no address or message body. Key: id16(consequence) + u64be(call
    /// seq) + the request's 32-byte digest.
    CAMPAIGN_ENROLLMENT_ASK: VaultMeta b"campaign:enrollment_ask:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::campaign::enrollment::erase_enrollment_ask_actor_in_txn;
    /// Per-saved-query baseline (definition version + scope digest) a campaign enrollment detection
    /// re-derives against. Key: id16.
    CAMPAIGN_ENROLLMENT_BASELINE: VaultMeta b"campaign:enrollment_baseline:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// One persisted campaign membership-transition detection event awaiting its consequence. Key:
    /// id16.
    CAMPAIGN_ENROLLMENT_EVENT: VaultMeta b"campaign:enrollment_event:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Campaign-local MACRO home-node election result. Key: ().
    CAMPAIGN_HOME_NODE_MACRO: VaultMeta b"campaign:home_node_macro:v1" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Persisted binding from a campaign program to the campaign it belongs to. Key: id16.
    CAMPAIGN_PROGRAM: VaultMeta b"campaign:program:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// One step of a campaign program: channel/consent/sender binding and optional outward call,
    /// keyed by program then step. Key: id16 + id16.
    CAMPAIGN_PROGRAM_STEP: VaultMeta b"campaign:program_step:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
}
