//! Read-only native task context and the model evidence a fresh seat consumes.

use std::collections::BTreeMap;

use crate::agent_dispatch::{MeasuredRate, seat_model_rates_in_txn};
use crate::llm::ModelId;
use crate::task_type::TaskTypeRef;
use crate::{EntityId, Vault};

/// The frozen dispatch inputs that qualify a task seat's measured model reads.
/// This is selection context only: it grants no authority, changes no pin
/// identity and never substitutes a payer or guest-provided project label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatLearningContext {
    pub project: EntityId,
    pub agent: EntityId,
    pub type_ref: TaskTypeRef,
}

/// Optional evidence never prevents an otherwise eligible seat from being
/// born. A failed read is reported, not presented as an empty measurement.
pub(crate) fn learned_models(
    vault: &Vault,
    context: Option<&SeatLearningContext>,
    models: impl Iterator<Item = ModelId>,
) -> BTreeMap<ModelId, MeasuredRate> {
    let Some(context) = context else {
        return BTreeMap::new();
    };
    let models: Vec<_> = models.collect();
    let read = (|| {
        let txn = vault.store.env.read_txn()?;
        seat_model_rates_in_txn(
            vault,
            &txn,
            context.project,
            context.agent,
            &context.type_ref,
            &models,
        )
    })();
    match read {
        Ok(rates) => rates,
        Err(error) => {
            tracing::warn!(%error, "a task seat's measured model evidence is unavailable");
            BTreeMap::new()
        }
    }
}
