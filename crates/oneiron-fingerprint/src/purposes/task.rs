//! Purposes of tasks (`crates/oneiron/src/task_verb`, `task_type`, `campaign`).

purposes! {}

legacy_purposes! {
    /// The key a wave plan's seal and per-task rows are kept under
    /// (`task_verb::wave_port::index_key`): plain BLAKE3, no tag, then the plan ref as a u64
    /// big-endian length and its bytes, then the local name's bytes, unframed (the plan's
    /// length fixes the boundary).
    WAVE_PLAN_INDEX_KEY = (Blake3, NotHashed, "oneiron.task.wave_plan_index_key.v1");

    /// The key a wave plan's frozen statement is kept under
    /// (`task_verb::wave_port::statement_key`): BLAKE3 derive-key with this context, then the
    /// plan ref's bytes.
    WAVE_PLAN_STATEMENT_KEY = (Blake3, DeriveKeyContext, "oneiron wave plan statement v1");

    /// The idempotency index of a policy change's human follow-up TASK
    /// (`task_verb::policy_change_followup`): plain BLAKE3, the tag's bytes, then the receipt
    /// id as a u64 big-endian length and its bytes, then the recipient's 16 bytes. The key is
    /// the tag's bytes followed by the 32-byte digest.
    POLICY_CHANGE_FOLLOWUP_INDEX_KEY = (Blake3, HashedFirst, "task.policy_change_followup.v1:");
}
