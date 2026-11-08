use crate::Vault;
use crate::attempt_queue::AttemptId;

/// Actual changes carried from an erase writer to its commit owner.
#[derive(Default)]
pub(crate) struct ErasureEffects {
    pub(crate) cancelled: Vec<(AttemptId, u32)>,
    pub(crate) decision_answers: Vec<u64>,
}

impl ErasureEffects {
    pub(crate) fn extend(&mut self, other: Self) {
        self.cancelled.extend(other.cancelled);
        self.decision_answers.extend(other.decision_answers);
    }

    /// Only a raw writer's successful root commit may publish these changes.
    /// Grouped writers use their existing transaction-keyed decision drain.
    pub(crate) fn committed(self, vault: &Vault) {
        crate::attempt_queue::AttemptQueue::new(vault)
            .erased_payload_cancellations_committed(&self.cancelled);
        for seq in self.decision_answers {
            vault.signal_decision_answer(seq);
        }
    }
}
