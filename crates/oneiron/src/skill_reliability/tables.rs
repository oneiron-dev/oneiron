//! The side tables `skill_reliability` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Owner-set posterior-lower-bound floor below which a skill's reliability triggers a quarantine
    /// proposal. Key: ().
    SKILL_RELIABILITY_FLOOR: VaultMeta b"settings:skill:v1:reliability_floor" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The amendment verdict replacing one attempt's outcome row (MessagePack map: amendment
    /// receipt, `skill_defect` share, event time). Key: the outcome row's full stored key, table
    /// prefix included.
    SKILL_RELIABILITY_AMENDED: VaultMeta b"skill_reliability:amended:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Lease-bound callable invocation witness of one caller step (MessagePack map: executor,
    /// version, success, result digest). Key: id16 (skill) + u16be length + receipt string +
    /// u64be step seq.
    SKILL_RELIABILITY_CALL_INVOCATION: VaultMeta b"skill_reliability:call_invocation:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Marker (MessagePack map naming the displaced and replacement judge revisions) that one
    /// outcome row's weight is superseded. Key: the outcome row's full stored key, table prefix
    /// included.
    SKILL_RELIABILITY_DISPLACED_JUDGE: VaultMeta b"skill_reliability:displaced_judge:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable per-(skill, receipt) attributed-outcome ledger row, keyed so a re-run over the same
    /// judgment cannot double-count. Key: id16 + string.
    SKILL_RELIABILITY_OUTCOME: VaultMeta b"skill_reliability:outcome:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The same outcome row for a named executor's arm. Key: id16 + u16be length + executor string +
    /// receipt string.
    SKILL_RELIABILITY_PAIRED_OUTCOME: VaultMeta b"skill_reliability:outcome:v2:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
