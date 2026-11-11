// Declared `vault_meta` tables whose prefix starts with `a` or `b`, in prefix order.

side_tables! {
    /// Pending context-widen proposal record, keyed by a hash of the dedupe key or full intent. Key:
    /// hash32.
    AGENT_DISPATCH_WIDEN_INTENT: VaultMeta b"agent.dispatch.widen.v1\0" LegacyJson Authored
        [refs: WIDEN_INTENT_REFS] [accepts: crate::agent_dispatch::agent_dispatch_widen_intent_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable saved-composition record for one inert multi-step workflow wrapper attempt. Key: id16.
    AGENT_WORKFLOW_RECORD: VaultMeta b"agent.workflow.record.v1\0" LegacyJson Authored
        [refs: WORKFLOW_RECORD_REFS] [accepts: crate::agent_dispatch::agent_workflow_record_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// This store's backup incarnation: 16 random bytes minted at its first backup, which a
    /// backup watermark carries so a restored or recreated store never compares equal to an
    /// older one. Runtime-tier: no image carries it. Key: ().
    BACKUP_INCARNATION: VaultMeta b"backup:incarnation:v1" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Actual in-flight native hard purges, emptied before commit. Key: entity16.
    BYOA_EXHAUST_ACTIVE_PURGE: VaultMeta b"byoa:exhaust_active_purge:v1:" Named
        [restore: live] [family: not_imaged] [tier: canonical];
    /// An accepted exhaust erase's sources, inventory and owed retirements. Key: attempt16.
    BYOA_EXHAUST_ERASE: VaultMeta b"byoa:exhaust_erase:v1:" Named
        [restore: live] [family: structure] [tier: canonical];
}
