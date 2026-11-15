//! Purposes of agent dispatch (`crates/oneiron/src/agent_dispatch`).

purposes! {}

legacy_purposes! {
    /// The key a workflow wrapper's dedupe index is kept under
    /// (`agent_dispatch::workflow_record::dedupe_key_hash`): plain BLAKE3 of the dedupe key's
    /// bytes, with no tag. Today the same bytes as `learning::SKILL_CAUSE_RECEIPT_KEY` and
    /// `learning::AMENDMENT_CAUSE_RECEIPT_KEY` for one string; the three tables are never read
    /// together.
    WORKFLOW_DEDUPE_KEY = (Blake3, NotHashed, "oneiron.agent.workflow_dedupe_key.v1");
}
