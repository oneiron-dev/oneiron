//! The side tables `edit_distance` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One compiled acting revision (a charter or brief revision compiled from one principal's
    /// approved preferences) and its answer. Key: string (revision id, 64 hex).
    EDIT_DISTANCE_ACTING_REVISION: VaultMeta b"edit_distance/acting_revision/v1\0" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Amendment cause rows by the attempt receipt they name, so the nightly agent-health pass
    /// looks them up instead of scanning (FIX 11639). Key: id32 + id32 + string.
    EDIT_DISTANCE_AMENDMENT_ATTEMPT: VaultMeta b"edit_distance/amendment_attempt/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One amendment judgment's labels kept write-once per receipt and judge revision (FIX 11638);
    /// a project's erase re-keys the project it names. Key: id32 + string.
    EDIT_DISTANCE_AMENDMENT_CAUSE: VaultMeta b"edit_distance/amendment_cause/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::edit_distance::attribution::erase_amendment_project_in_txn;
    /// Write-once Δ side-ledger row for one receipt: a captured edit-distance measurement (canonical
    /// JSON), or the literal marker "uncaptured" when capture was attempted and failed. Key: string.
    EDIT_DISTANCE_AMENDMENT_DELTA: VaultMeta b"edit_distance/amendment_delta/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Recorded routing/attribution evidence for one amendment receipt; a project's erase re-keys
    /// the project it names (FIX 6038). Key: string.
    EDIT_DISTANCE_AMENDMENT_EVIDENCE: VaultMeta b"edit_distance/amendment_evidence/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::edit_distance::attribution::erase_amendment_project_in_txn;
    /// Judge-routed classification of one amendment's edit distance/preference class; a project's
    /// erase re-keys the project it names (FIX 6038). Key: string.
    EDIT_DISTANCE_AMENDMENT_JUDGMENT: VaultMeta b"edit_distance/amendment_judgment/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::edit_distance::attribution::erase_amendment_project_in_txn;
    /// Uncaptured-amendment counters per door (FIX 11542): how many store-row
    /// and inbox amendments measured nothing. Key: string (door).
    EDIT_DISTANCE_AMENDMENT_UNCAPTURED_COUNT: VaultMeta b"edit_distance/amendment_uncaptured_count/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Live edit-cost head for a (predicate, subject, scope) tuple; the retraction ledger for re-
    /// judged receipts. Key: string "\x00" hex32 "\x00" string.
    EDIT_DISTANCE_EDIT_COST_TARGET: VaultMeta b"edit_distance/edit_cost_target/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Append-only ruled-escalation ledger row, scope-major (scope digest then UUIDv7 row id) so one
    /// scope's history is a contiguous range. Key: id16 + id16.
    EDIT_DISTANCE_ESCALATION: VaultMeta b"edit_distance/escalation/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::edit_distance::escalation::erase_escalation_scope_in_txn;
    /// Standing escalation policy for one (scope, trigger) pair, keyed by what the row governs. Key:
    /// id16 + u8.
    EDIT_DISTANCE_ESCALATION_POLICY: VaultMeta b"edit_distance/escalation_policy/v1\0" Raw
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::edit_distance::escalation::erase_escalation_scope_in_txn;
    /// Publisher digest-interview session state, keyed by the digest artifact id. Key: id16.
    EDIT_DISTANCE_INTERVIEW_SESSION: VaultMeta b"edit_distance/interview_session/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Stored publisher issue-signature (category, artifact, version, model, counts, content hash).
    /// Key: id16.
    EDIT_DISTANCE_ISSUE_SIGNATURE: VaultMeta b"edit_distance/issue_signature/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Send-state token (pending/sent/etc) for a publisher issue signature. Key: id16.
    EDIT_DISTANCE_ISSUE_SIGNATURE_SEND: VaultMeta b"edit_distance/issue_signature_send/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Persisted amendment-judge audit report (total/passed/abstained), ordered oldest-first by (at,
    /// sequence). Key: u64be + u64be.
    EDIT_DISTANCE_JUDGE_AUDIT: VaultMeta b"edit_distance/judge_audit/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Monotonic counter behind EDIT_DISTANCE_JUDGE_AUDIT's sequence half. Key: ().
    EDIT_DISTANCE_JUDGE_AUDIT_SEQUENCE: VaultMeta b"edit_distance/judge_audit_sequence/v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Claim-to-receipt index bounding the teaching-copy erase (FIX 11347): the receipt ids taught
    /// on one claim. Key: id16.
    EDIT_DISTANCE_MINER_CLAIM_RECEIPTS: VaultMeta b"edit_distance/miner_claim_receipts/v1\0" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Mint-mark preventing a re-mint of the same substitution cluster, keyed by cluster handle. Key:
    /// hash32.
    EDIT_DISTANCE_MINER_MINT_MARK: VaultMeta b"edit_distance/miner_mint_mark/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Mined skill-edit proposal awaiting owner decision, keyed by proposal id. Key: id16.
    EDIT_DISTANCE_MINER_SKILL_EDIT: VaultMeta b"edit_distance/miner_skill_edit/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Global work-gate watermark for the substitution-miner pass. Key: ().
    EDIT_DISTANCE_MINER_WATERMARK: VaultMeta b"edit_distance/miner_watermark/v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Minted phrasing/preference proposal born from a judged amendment. Key: string.
    EDIT_DISTANCE_PREFERENCE_PROPOSAL: VaultMeta b"edit_distance/preference_proposal/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Immutable owner-bound decision on an inbox/amendment intake item, keyed by receipt id. Key:
    /// string.
    EDIT_DISTANCE_PRINCIPAL_DECISION: VaultMeta b"edit_distance/principal_decision/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::edit_distance::miner::erase_principal_decision_entity_in_txn;
    /// Finalized proposal-text artifact (span attributions, actor/class per span, the head of its
    /// document on the entity-document plane), write-once keyed by artifact ref. Key: id16.
    EDIT_DISTANCE_PROPOSAL_ARTIFACT: VaultMeta b"edit_distance/proposal_artifact/v1\0" Raw Authored [accepts: crate::edit_distance::edit_distance_proposal_artifact_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::edit_distance::erase_proposal_texts_in_txn;
    /// Rebuildable training-reservoir candidate index row, keyed by the proposal artifact's entity
    /// id. Key: id16.
    EDIT_DISTANCE_RESERVOIR_CANDIDATE: VaultMeta b"edit_distance/reservoir_candidate/v1\0" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Training-reservoir export-receipt ledger row. Key: id16.
    EDIT_DISTANCE_RESERVOIR_EXPORT: VaultMeta b"edit_distance/reservoir_export/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Per-(task class, model version) routing score aggregate. Key: string "\x00" string.
    EDIT_DISTANCE_ROUTING_AGGREGATE: VaultMeta b"edit_distance/routing_aggregate/v1\0" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Run-to-generation membership binding, keyed by receipt id. Key: string.
    EDIT_DISTANCE_ROUTING_MEMBER: VaultMeta b"edit_distance/routing_member/v1\0" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// The owner-anchored outcome of one judged amendment's rework (FIX 11706):
    /// `undone` for a Keep later undone, `merged` for a fork later merged.
    /// Key: string (the delta receipt id).
    EDIT_DISTANCE_ROUTING_OUTCOME: VaultMeta b"edit_distance/routing_outcome/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Per-task-class rollout rung state. Key: string.
    EDIT_DISTANCE_ROUTING_RUNG: VaultMeta b"edit_distance/routing_rung/v1\0" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Model-version stamp new routing folds are recorded against. Key: ().
    EDIT_DISTANCE_ROUTING_SERVING_MODEL: VaultMeta b"edit_distance/routing_serving_model/v1" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Append-only offer-answer log for consent-graduation ramps, scope-major then UUIDv7 row id.
    /// Key: id16 + id16.
    EDIT_DISTANCE_GRADUATION_ANSWER: VaultMeta b"graduation_answer:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Runtime consent-graduation threshold override for one ramp pattern, keyed by a digest of the
    /// pattern text. Key: id16.
    EDIT_DISTANCE_GRADUATION_THRESHOLD: VaultMeta b"graduation_threshold:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Publisher share dial: explicit owner-set enabled/disabled token. Key: ().
    EDIT_DISTANCE_PUBLISHER_ENABLED: VaultMeta b"settings:publisher:v1:enabled" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Install-profile default for the publisher share dial. Key: ().
    EDIT_DISTANCE_PUBLISHER_INSTALL_DEFAULT: VaultMeta b"settings:publisher:v1:install_default" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
