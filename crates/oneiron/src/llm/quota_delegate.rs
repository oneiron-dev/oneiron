//! Whether an agent may answer a spent-quota question (restriction wave 11):
//! the owner's per-answer key `models.quota.agent_may_answer`, read at the
//! asking agent.

use crate::llm::setting_keys::MODELS_QUOTA_AGENT_MAY_ANSWER;
use crate::setting::SettingScope;
use crate::{EntityId, Vault};

impl Vault {
    /// Whether `agent` may give the `choice` answer to a spent-quota
    /// question: the value in force of `models.quota.agent_may_answer` for
    /// that answer at that agent. Off by default: only the owner answers.
    /// An agent's own row wins over the vault row. An unknown answer is
    /// refused, never panicked on.
    pub fn agent_may_answer_quota(&self, agent: EntityId, choice: &str) -> crate::Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(MODELS_QUOTA_AGENT_MAY_ANSWER
            .read_in_txn(self, &txn, &[SettingScope::Agent(agent)], Some(choice))?
            .value)
    }
}
