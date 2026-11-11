//! The side tables `self_heal` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One wire call's lasting receipt (OF-538): who called on which credential, which verb, how
    /// it ended, and digests of what was asked and answered; never the bodies. Key: id16.
    CALL_RECEIPT: VaultMeta b"call_receipt:v1:" Named Authored [accepts: crate::dreamer_runner::call_receipt_accepts_masked]
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::Vault::erase_call_receipt_actor_in_txn;
    /// An agent's `self.report_blocked` receipt waiting for the Coach's Issues job. Key: id16 of
    /// the receipt.
    COACH_BLOCKED_ISSUE: VaultMeta b"coach:blocked_issue:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One `self.report_blocked` receipt a durable run filed, and when, kept after the Coach
    /// settles it, so a failing attempt's ladder case carries its own reports (OF-418). Key: id16
    /// of the run, then id16 of the receipt.
    COACH_BLOCKED_RUN: VaultMeta b"coach:blocked_run:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The source a `self.report_blocked` receipt's code fix replays (FIX 2343): the instructions,
    /// briefing and task of the model request the run's host bound before the call, whole, or
    /// none for a caller that gave this engine no request, with the run, reporter and scope.
    /// Kept after the Coach settles the report. Key: id16 of the receipt. FIX 1662: the same
    /// table keeps the request a code fix replays exactly: a receipt row names it by its hash and
    /// keeps it whole when no replay capsule of the run holds it, and a step row keeps a durable
    /// step's request, masked, before its call. Key: b's', id16 of the attempt, the step's hash,
    /// be64 of the lease generation, be32 of the call.
    COACH_BLOCKED_SOURCE: VaultMeta b"coach:blocked_source:v1:" Named Authored [accepts: crate::self_heal::blocked_reports::coach_blocked_source_accepts_masked]
        // Payload family: A blocked report's captured requests (FIX 6708), a wait's deliveries
        // (FIX 6588) and a conversation check's gate material (FIX 5040); the wait index stays
        // unclassified, as only its settled rows hold a reply, which [`class_for_row`] places row
        // by row (FIX 9179).
        [restore: content] [family: dispatch Response] [tier: canonical]
        => crate::self_heal::blocked_reports::erase_blocked_source_actor_in_txn;
    /// One durable step capture's owner witness (FIX 6734): the owner an erase takes the
    /// capture for, its role in the step, and the capture's full step key. Written with the
    /// capture and rebound with its terminal claim; the capture eraser drops every witness
    /// of a capture it takes, so no own scrub. Key: id16 of the owner, one role byte, then
    /// the capture's step key.
    COACH_BLOCKED_SOURCE_OWNER: VaultMeta b"coach:blocked_source_owner:v1:" Raw
        // Payload family: Canonical owner witnesses survive an undecodable captured request.
        [restore: content] [family: owner BlockedSourceOwner] [tier: canonical];
    /// The Coach's issue for one positive model finding (OF-418 L3): its DIAGNOSTIC, tier,
    /// family, class and recipe revision, its exact ordered runs with their replay hashes, the
    /// decision receipts that raised it, the gate decisions its results link, the producer its
    /// recorded links prove, its recurrence key and its retries. Kept after the Coach files it;
    /// it waits while no `COACH_ISSUE_SETTLED` row names it. Key: id16 of the issue.
    COACH_DIAGNOSTIC_ISSUE: VaultMeta b"coach:diagnostic_issue:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Each COACH_DIAGNOSTIC_ISSUE under its recurrence key, written with it (FIX 7343). Key:
    /// the key's 32 bytes, then id16 of the issue.
    COACH_DIAGNOSTIC_ISSUE_BY_KEY: VaultMeta b"coach:diagnostic_issue_by_key:v1:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// What was observed of a model finding's issue (OF-418 L3), append-only: an owner's closed
    /// answer to its proposal, as the claim's gate row records it. Key: id16 of the issue, then
    /// hash32 of the fact.
    COACH_ISSUE_EVIDENCE: VaultMeta b"coach:issue_evidence:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The proposed heal the Coach filed for a blocked report, a failure-ladder case or a model
    /// finding's issue, so a replay files none twice. Key: id16 of the receipt, the case or the
    /// issue.
    COACH_ISSUE_SETTLED: VaultMeta b"coach:issue_settled:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Per-actor healer-submission counter and burst-check flag. Key: id16 (actor).
    SELF_HEAL_HEALER_COUNT: VaultMeta b"healer:count:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// An external healer's repair proposal record and its review state. Key: id16.
    SELF_HEAL_HEALER_PROPOSAL: VaultMeta b"healer:proposal:" Named Authored [accepts: crate::self_heal::self_heal_healer_proposal_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// A human-ratified patch pull-request record for a released healer proposal. Key: id16.
    SELF_HEAL_HEALER_RELEASE: VaultMeta b"healer:release:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Per-actor per-run healer receipt: submitted proposals and reversal state. Key: id16 + bytes32
    /// (actor then blake3 hash of run name).
    SELF_HEAL_HEALER_RUN: VaultMeta b"healer:run:" Named Authored [accepts: crate::self_heal::self_heal_healer_run_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// When a host detector graded one telemetry window under one wording. Key: bytes32
    /// (blake3 of the tier, the detector policy and the window's run ids).
    SELF_HEAL_DETECTOR_WINDOW: VaultMeta b"self_heal:detector_window:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Owner-reviewed T3 finding by family string, colon and diagnostic id16.
    SELF_HEAL_DISTILL: VaultMeta b"self_heal:distill:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The T2 the host's detector pass registered for one family from its reviewed T3 findings,
    /// with the closed-form T1 that graduated it (OF-418). Key: the family string.
    SELF_HEAL_MINTED: VaultMeta b"self_heal:minted:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Immutable attempt confession, audit draw and independently checked findings. Key: id16.
    SELF_HEAL_ATTEMPT_SEAL: VaultMeta b"self_heal:seal:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// (diagnostic event id).
    SELF_HEAL_SIGNED_EVENT: VaultMeta b"self_heal:signed:v2:event:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// A host-signed scheduled detector run receipt, keyed by its content digest. Key: bytes32
    /// (blake3 digest of the signed detector run).
    SELF_HEAL_SIGNED_RUN: VaultMeta b"self_heal:signed:v2:run:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
}
