//! The side tables `learning` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A `learning.*` cell's key, estimate form and what counted; a project's erase takes every
    /// cell scoped to it, with its index, evidence and prior, and re-keys its heads (FIX 6038).
    /// Key: cell digest (32 bytes).
    LEARNING_CELL: VaultMeta b"learning:cell:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::learning::erase_learning_scope_in_txn;
    /// Subject index over `learning.*` cells (value: the member). Key: subject id16 + cell digest.
    LEARNING_CELL_SUBJECT: VaultMeta b"learning:cell_subject:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A team's derived coordination cost (wait by reason, reuse delay, duplicate work): a
    /// diagnostic, never a score. Key: string (team reference).
    LEARNING_COORDINATION: VaultMeta b"learning:coordination:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// An audit's label that two pieces of one team's work duplicated each other. Key: string
    /// (team reference "\0" first "\0" second).
    LEARNING_DUPLICATE_LABEL: VaultMeta b"learning:duplicate_label:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A judge swap's fitted score map, applied as a projection. Key: string (old judge revision).
    LEARNING_JUDGE_CONVERSION: VaultMeta b"learning:judge_conversion:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A `learning.*` cell's engine-written prior (origin, value, weight in runs). Key: cell digest.
    LEARNING_PRIOR: VaultMeta b"learning:prior:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A `learning.setting` fit, cached beside its claim for hot readers. Key: string (setting key,
    /// then its project, subject and type node as they apply); a project's erase deletes its keys.
    LEARNING_SETTING_FIT: VaultMeta b"learning:setting_fit:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Index from a review verdict claim id back to its CRITIC_REVIEW_RESULT row key. Key: id16.
    CRITIC_REVIEW_RESULT_ID: VaultMeta b"review:result_id:v2:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
