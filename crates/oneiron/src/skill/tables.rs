//! The side tables `skill` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The serve skill judge (OF-495): its typed-decision journal, and person-time on receipts.
    /// Key: "decision:" hex32 (row id) | "minutes:" string (receipt id) "|" hex32 (row id).
    SKILL_JUDGE: SyncState b"skill:judge:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The frozen callable cases by what they were made from, so an erase reads only the cases
    /// naming its row (FIX 12180). Key: b'S' + source id16 + case key, or, when the sources are
    /// unknown, b'R' + u16be receipt length + receipt string + case key. Value: empty.
    SKILL_CALLABLE_CASE_INDEX: VaultMeta b"skill:callable_case_index:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A callable helper's standing promotion verdict (Self-Harness splits, reliability check,
    /// the exact content hash it scored). Key: id16 (skill entity).
    SKILL_CALLABLE_GATE: VaultMeta b"skill:callable_gate:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Append-only history of shared-skill merge receipts, keyed by receipt id. Key: string.
    SKILL_HUB_SHARED_MERGE_HISTORY: VaultMeta b"skill_hub/shared-merge-history/v1\0" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Latest shared-skill merge receipt for one candidate entity. Key: id16.
    SKILL_HUB_SHARED_MERGE_RECEIPT: VaultMeta b"skill_hub/shared-merge-receipt/v1\0" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Portable goal-axis identity of a skill under optimization. Key: id16.
    SKILL_OPTIMIZE_GOAL: VaultMeta b"skill_optimize/goal/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A proposal's live goal-axis report, bound to its bodies, evidence and plan (MessagePack
    /// named map). Key: id16 (proposal).
    SKILL_OPTIMIZE_LIVE_AXES: VaultMeta b"skill_optimize/live_axes/v2\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A skill goal's join to a project's goal record (MessagePack named map). Key: id16 (goal).
    SKILL_OPTIMIZE_PROJECT_GOAL: VaultMeta b"skill_optimize/project_goal/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A vault owner's dismissal of one learned goal-revision proposal under the goal claim in
    /// force (MessagePack named map). Key: id16 (project) + question digest (64 hex).
    SKILL_OPTIMIZE_PROJECT_GOAL_DISMISSED: VaultMeta b"skill_optimize/project_goal_dismissed/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A learned preference proposed for a project's goal record (MessagePack named map). Key:
    /// id16 (project) + id16 (row).
    SKILL_OPTIMIZE_PROJECT_GOAL_PROPOSAL: VaultMeta b"skill_optimize/project_goal_proposal/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One pending skill-edit tradeoff ask (MessagePack named map: pending proposal, question, bound
    /// Jev verdict). Key: id16 (proposal).
    SKILL_OPTIMIZE_TRADEOFF_ASK: VaultMeta b"skill_optimize/tradeoff_ask/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Learned owner tradeoff preferences of one goal (MessagePack named map). Key: id16 (goal).
    SKILL_OPTIMIZE_TRADEOFF_PREFERENCES: VaultMeta b"skill_optimize/tradeoff_preferences/v1\0" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One date-cut sealed eval cohort (MessagePack named map). Key: id16 (cohort).
    SKILL_OPTIMIZE_EVAL_COHORT: VaultMeta b"skill_optimize:eval_cohort:v1:" Raw
        // Restore class: A restore cannot make a spent cohort fresh: cut, audit, retirement and
        // every serving stand as the live vault holds them.
        [restore: live] [family: unclassified] [tier: canonical];
    /// One counted serving of a sealed eval cohort (MessagePack named map). Key: id16 (cohort) +
    /// id16 (exposure).
    SKILL_OPTIMIZE_EVAL_EXPOSURE: VaultMeta b"skill_optimize:eval_exposure:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// One eval source family and its purpose (MessagePack named map). Key: id16 (family).
    SKILL_OPTIMIZE_EVAL_FAMILY: VaultMeta b"skill_optimize:eval_family:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// One owner-label ask a waiting decision put (MessagePack named map). Key: sha256 of the
    /// decision and the case.
    SKILL_OPTIMIZE_EVAL_LABEL_ASK: VaultMeta b"skill_optimize:eval_label_ask:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The eval family a source root belongs to, per seat. Key: seat token + NUL + root; value:
    /// id16 (family).
    SKILL_OPTIMIZE_EVAL_ROOT: VaultMeta b"skill_optimize:eval_root:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Imported (alpha, beta) reliability base this vault's own outcome ledger cannot reproduce,
    /// node-local and never synced. Key: id16.
    SKILL_RELIABILITY_IMPORTED_BASE: VaultMeta b"skill_reliability:imported_base:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The imported reliability base of one named executor's arm. Key: id16 + u16be length +
    /// executor string.
    SKILL_RELIABILITY_PAIRED_IMPORTED_BASE: VaultMeta b"skill_reliability:imported_base:v2:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
