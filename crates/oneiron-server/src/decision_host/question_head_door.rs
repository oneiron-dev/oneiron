//! Doors for `tests/question_head_host.rs` (FIX 23586, 23587): a test seat in
//! one of the ladder's slots, and the Local slot fronted by the owner's
//! question heads as `SyncServer::with_decision_config` fronts it.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use std::sync::Arc;

use oneiron::llm::decision::{DecisionProvider, DecisionRung};
use oneiron::{Error, Vault};

use super::DecisionHost;
use crate::ai_host::training_pack::QuestionHeadRung;

impl DecisionHost {
    /// This host with `seat` in the ladder's `rung` slot, where a configured
    /// seat of that rung sits.
    ///
    /// # Errors
    ///
    /// The Human rung: it is the owner's ask queue, never a seat.
    pub(crate) fn with_test_seat(
        mut self,
        rung: DecisionRung,
        seat: Arc<dyn DecisionProvider>,
    ) -> oneiron::Result<Self> {
        let slot = match rung {
            DecisionRung::Rule => &mut self.ladder.rule,
            DecisionRung::Local => &mut self.ladder.local,
            DecisionRung::SystemOne => &mut self.ladder.system_one,
            DecisionRung::Escalation => &mut self.ladder.escalation,
            DecisionRung::Big => &mut self.ladder.big,
            DecisionRung::Human => {
                return Err(Error::InvalidConfig(
                    "the Human rung is the owner's ask queue, not a seat".to_owned(),
                ));
            }
        };
        *slot = Some(seat);
        Ok(self)
    }

    /// This host with the owner's question heads in front of whatever its
    /// Local slot holds, as `SyncServer::with_decision_config` puts them
    /// there.
    pub(crate) fn with_test_question_heads(self, vault: &Arc<Vault>) -> Self {
        self.with_question_heads(vault)
    }

    /// The question heads in front of the Local slot, when they are there.
    pub(crate) fn test_question_heads(&self) -> Option<&Arc<QuestionHeadRung>> {
        self.question_heads.as_ref()
    }
}
