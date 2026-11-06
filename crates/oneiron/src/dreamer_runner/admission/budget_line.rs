//! The original line established by a successful native admission.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::error::{Error, Result};

/// Accounting provenance, not an execution grant or a paid receipt.
#[derive(Debug, Clone)]
pub(crate) struct AdmittedBudgetLine {
    attempt_id: AttemptId,
    generation: u32,
    budget_id: String,
    next_invocation: Arc<AtomicU64>,
}

/// One invocation of the original admission, and one of its corrective calls.
/// Transport retries keep the same coordinate. It certifies no payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdmittedCallId {
    pub(crate) attempt_id: AttemptId,
    pub(crate) generation: u32,
    pub(crate) invocation: u64,
    pub(crate) ordinal: u32,
}

impl PartialEq for AdmittedBudgetLine {
    fn eq(&self, other: &Self) -> bool {
        self.attempt_id == other.attempt_id
            && self.generation == other.generation
            && self.budget_id == other.budget_id
    }
}

impl Eq for AdmittedBudgetLine {}

impl AdmittedBudgetLine {
    pub(super) fn new(attempt_id: AttemptId, generation: u32, budget_id: String) -> Self {
        Self {
            attempt_id,
            generation,
            budget_id,
            next_invocation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn for_attempt(&self, attempt_id: AttemptId) -> Option<&str> {
        (self.attempt_id == attempt_id).then_some(self.budget_id.as_str())
    }

    pub(crate) fn next_call(&self, attempt_id: AttemptId) -> Result<Option<AdmittedCallId>> {
        if self.attempt_id != attempt_id {
            return Ok(None);
        }
        let invocation = self
            .next_invocation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| Error::ArithmeticOverflow("dreamer admitted invocation sequence"))?;
        Ok(Some(AdmittedCallId {
            attempt_id: self.attempt_id,
            generation: self.generation,
            invocation,
            ordinal: 0,
        }))
    }
}

impl DreamerAdmittedAttempt {
    pub(crate) fn admitted_budget_line(&self) -> &AdmittedBudgetLine {
        &self.admitted_budget_line
    }
}
