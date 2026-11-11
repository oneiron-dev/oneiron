//! The side tables `claim` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A destructive claim action (supersede/decay/weaken/stale) parked behind unresolved gate
    /// consent. Key: id16.
    CLAIM_DEFERRED: VaultMeta b"claim.deferred.v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Immutable before/after revision binding for an accepted supersession. Key: old id16 + new id16.
    CLAIM_SUPERSESSION_DIFF: VaultMeta b"claim.supersession_diff.v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A host re-root's carry of one MACHINE claim's signed history: the carried birth digest
    /// (32 bytes), then the content hash (32 bytes) of the handoff packet the move signed for it.
    /// Written by that move only; retired with the history on delete. Key: id16 (target claim).
    CLAIM_MACHINE_HISTORY_CARRY: VaultMeta b"claim:machine-history-carry:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The memoized gate verdict over one MACHINE claim's history (FIX 12374): the seal
    /// (40 bytes), the pin's content hash (32 bytes), the gate sequence (u64 BE) and the
    /// settled verdict (1 byte) the carrier loop proved. Key: id16 (target claim).
    CLAIM_MACHINE_HISTORY_GATE_FINGERPRINT: VaultMeta b"claim:machine-history-gate-fingerprint:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The vault-wide gate sequence (FIX 12374): how many gate writes landed since the
    /// last clear. Key: ().
    CLAIM_MACHINE_HISTORY_GATE_SEQUENCE: VaultMeta b"claim:machine-history-gate-sequence:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The pinned signed handoff (encoded `ClaimHistoryHandoff`) that roots one MACHINE claim's
    /// signed birth and transition history. Key: id16 (target claim).
    CLAIM_MACHINE_HISTORY_PIN: VaultMeta b"claim:machine-history-pin:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The running seal over every control put one MACHINE claim's history index took (FIX
    /// 4296): the put count (u64 BE), then a chained digest (32 bytes). Key: id16 (target claim).
    CLAIM_MACHINE_HISTORY_SEAL: VaultMeta b"claim:machine-history-seal:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Empty marker indexing one MACHINE claim's signed history control rows under their target.
    /// Key: id16 (target claim) + id16 (control).
    CLAIM_MACHINE_HISTORY_TARGET: VaultMeta b"claim:machine-history-target:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Binding proof tying a restored foreign expression-preference claim to the exact local row it
    /// reconstructed. Key: id16.
    EXPRESSION_ARCHIVE_BINDING: VaultMeta b"expression/archive-binding/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One admitted anchored outcome for a `learning.*` cell; its pack context is cleared once it
    /// names an erased entity. Key: cell digest + receipt string.
    LEARNING_EVIDENCE: VaultMeta b"learning:evidence:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::learning::erase_learning_pack_context_in_txn;
    /// An owner's own behaviour with one period of his digest, for the Coach's digest settings
    /// rule (FIX 5495): when its due notice reached him and when he first opened it, no digest
    /// text. Key: id16 (owner) + u64be (scheduled_for).
    WEAVE_DIGEST_BEHAVIOUR: VaultMeta b"weave:digest_behaviour:v1:" Named
        // Restore class: The owner's digest settings and their change history are his content, as
        // the digest schedule is (FIX 5495).
        [restore: content] [family: unclassified] [tier: canonical];
    /// One Coach change to an owner's digest rhythm or section order (FIX 5495): proposed,
    /// applied under his Grant, answered or undone, with the settings before and after. Key: id16
    /// (owner) + id16 (change).
    WEAVE_DIGEST_SETTING_CHANGE: VaultMeta b"weave:digest_setting_change:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// An owner's digest settings generation, the Coach's last evaluation of him and his own
    /// feedback (FIX 5495). Key: id16 (owner).
    WEAVE_DIGEST_SETTINGS: VaultMeta b"weave:digest_settings:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Weave digest schedule of one reader. Key: reader kind byte + id16.
    WEAVE_DIGEST_SCHEDULE: VaultMeta b"weave:schedule:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One immutable wrong-item label filed from a live weave report. Key: family byte
    /// (0 entity, 1 gate decision) + native id16 + id16 (label receipt id).
    WEAVE_WRONG_ITEM_LABEL: VaultMeta b"weave:wrong-item:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One immutable wrong-link label filed from a live weave report. Key: edge ref (33 bytes) +
    /// id16 (label receipt id).
    WEAVE_WRONG_LINK_LABEL: VaultMeta b"weave:wrong-link:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
