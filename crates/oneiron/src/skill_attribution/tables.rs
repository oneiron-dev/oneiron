//! The side tables `skill_attribution` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Persisted audit report of a judge run against the held-out fixture set, keyed by run time then
    /// evidence sequence. Key: u64be + u64be.
    SKILL_ATTRIBUTION_AUDIT: VaultMeta b"skill_attribution:audit:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One run's matched-fork contribution checks for one experiment (its outcome, goal revision,
    /// axis and target: a loaded skill or a used edge): the measured verdict and the pair it was
    /// read from (both fork receipts and results, the anchor, the axis, the edge), and each pair
    /// recorded unmatched, with why. Key: string (attempt receipt "\0" target hex "\0" identity
    /// digest); a row naming an erased entity names it nil and moves to its attempt receipt
    /// "\0" "erased:" a fresh ULID.
    SKILL_ATTRIBUTION_CONTRIBUTION_CHECK: VaultMeta b"skill_attribution:contribution_check:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::skill_attribution::erase_contribution_checks_in_txn;
    /// Each sealed late-credit receipt's frozen credit_decay (FIX 10107) and its immutable
    /// adjustments (FIX 3241, FIX 10108): the base receipt, the adjustment before it, the checks
    /// and late landed uses the effective credit joins (each end nil once erased), its direct
    /// subjects and shares with their used chains, and when. Key: string (the credit receipt id
    /// "\0" "decay", or "\0" a zero-padded index); an erase moves an adjustment naming the erased
    /// entity to "erased" "\0" a fresh ULID, and where the base receipt's run or outcome reference
    /// spells it, also drops the adjustment's base links and the frozen decay.
    SKILL_ATTRIBUTION_CREDIT_ADJUSTMENT: VaultMeta b"skill_attribution:credit_adjustment:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::skill_attribution::erase_credit_adjustments_in_txn;
    /// Highest evidence sequence (u64be) the attribution projector has already routed. Key: ().
    SKILL_ATTRIBUTION_CURSOR: VaultMeta b"skill_attribution:cursor:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The receipts of the decisions that gave one attempt-lane judgment, in hunk order, kept once
    /// beside it (FIX 11512); an erased entity's evidence pins go, and a row with a receipt decided
    /// for it goes whole. Key: u64be (the judgment's evidence sequence).
    SKILL_ATTRIBUTION_DECISION_RECEIPTS: VaultMeta b"skill_attribution:decision_receipts:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::skill_attribution::erase_decision_receipts_entity_in_txn;
    /// A leased run's derivation witnesses (FIX 3103): each exact DerivedFrom edge a write of the
    /// run left stored, with its producer, whether the run's lease held as it landed and when
    /// (each end nil once erased); beside them, each scope summary a run asked for, with its lease
    /// owner. Key: "d" + id16 (run attempt) + u32be (lease generation) + hash32 (the edge pair),
    /// or "r" + id16 (summary attempt) + id16 (asking run's attempt) + u32be (its generation).
    /// An erase moves a scrubbed edge's row to a fresh ULID in place of the pair (or to "e" +
    /// ULID once its run is erased) and drops a request that names the erased entity.
    SKILL_ATTRIBUTION_DERIVATION_WITNESS: VaultMeta b"skill_attribution:derivation_witness:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::skill_attribution::erase_derivation_witness_in_txn;
    /// Replacement judge revision (UTF-8) marking one routed judgment as displaced. Key: u64be
    /// (evidence sequence).
    SKILL_ATTRIBUTION_DISPLACED_JUDGE: VaultMeta b"skill_attribution:displaced_judge:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Fence on a displaced attribution judge revision: its replacement revision (UTF-8). Key:
    /// string (the displaced revision).
    SKILL_ATTRIBUTION_DISPLACED_REVISION: VaultMeta b"skill_attribution:displaced_revision:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Monotonic counter (u64be) minting the next evidence sequence number. Key: ().
    SKILL_ATTRIBUTION_EVIDENCE_SEQUENCE: VaultMeta b"skill_attribution:evidence_sequence:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Judge revision (UTF-8) that routed one judgment, stamped once. Key: u64be (evidence
    /// sequence).
    SKILL_ATTRIBUTION_JUDGE_REVISION: VaultMeta b"skill_attribution:judge_revision:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Frozen anchored pack outcome, eligible used lineage chains and shares; an erased entity's
    /// id is redacted where it is named. Key: credit receipt id.
    SKILL_ATTRIBUTION_LATE_CREDIT: VaultMeta b"skill_attribution:late_credit:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::skill_attribution::erase_late_credit_in_txn;
    /// The highest attribution evidence sequence the positive lane has read. Key: ().
    SKILL_ATTRIBUTION_POSITIVE_CURSOR: VaultMeta b"skill_attribution:positive_cursor:v1" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Highest judgment sequence (u64be) the sweep has already applied to skill-reliability/actor-
    /// claim projections. Key: ().
    SKILL_ATTRIBUTION_SWEEP_APPLIED_CURSOR: VaultMeta b"skill_attribution:sweep_applied:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Idempotency marker (single byte) recording that a receipt's attribution evidence has already
    /// been captured. Key: string.
    SKILL_ATTRIBUTION_SWEEP_RECEIPT_CAPTURED: VaultMeta b"skill_attribution:sweep_receipt:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Resume cursor (receipt-id text bytes) for the in-progress task-attribution receipt-page scan.
    /// Key: ().
    SKILL_ATTRIBUTION_SWEEP_SCAN_CURSOR: VaultMeta b"skill_attribution:sweep_scan:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One outcome the attribution judge left `unclear`, with each unclear hunk's reason, share and
    /// note, and the context frozen with them (FIX 7824): actor, skill, scope, project, task type,
    /// attempt receipt, judge revision and model, and the rows the judge read; awaiting Dreamer
    /// clustering. A row whose context names an erased entity goes whole. Key: string (lane ":"
    /// reference).
    SKILL_ATTRIBUTION_UNCLEAR: VaultMeta b"skill_attribution:unclear:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::skill_attribution::erase_unclear_entity_in_txn;
}
