//! Read-only native task context and the model evidence a fresh seat consumes.

use std::collections::BTreeMap;

use crate::agent_dispatch::{MeasuredRate, seat_model_rates_in_txn};
use crate::llm::ModelId;
use crate::task_type::TaskTypeRef;
use crate::{EntityId, Vault};

/// The actual task context for owner rows and, when identified, measured model reads.
/// This is selection context only: it grants no authority, changes no pin
/// identity and never substitutes a payer or guest-provided project label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatLearningContext {
    pub project: Option<EntityId>,
    /// The actual executor definition, absent for a generic reader.
    pub agent: Option<EntityId>,
    /// The actual placed task type, absent for an untyped reader job.
    pub type_ref: Option<TaskTypeRef>,
    /// The actual direct call's model-choice mode, even when marked unapplied.
    /// Call pins bypass owner rows; call seeds keep owner seeds from applying.
    pub call_model_choice: Option<crate::learning_setting::SettingMode>,
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
    let (Some(project), Some(agent), Some(type_ref)) =
        (context.project, context.agent, context.type_ref.as_ref())
    else {
        return BTreeMap::new();
    };
    let models: Vec<_> = models.collect();
    let read = (|| {
        let txn = vault.store.env.read_txn()?;
        seat_model_rates_in_txn(vault, &txn, project, agent, type_ref, &models)
    })();
    match read {
        Ok(rates) => rates,
        Err(error) => {
            tracing::warn!(%error, "a task seat's measured model evidence is unavailable");
            BTreeMap::new()
        }
    }
}

/// The owner model rows for a fresh native task, using its actual scopes.
pub(super) fn owner_model_choices(
    vault: &Vault,
    context: Option<&SeatLearningContext>,
) -> crate::Result<crate::learning_setting_choice::OwnerSpawnModelChoices> {
    let Some(context) = context else {
        return Ok(Default::default());
    };
    if context.call_model_choice == Some(crate::learning_setting::SettingMode::Pin) {
        return Ok(Default::default());
    }
    let txn = vault.store.env.read_txn()?;
    let type_ref = context
        .type_ref
        .as_ref()
        .map(crate::learning::TypeRef::from);
    let scopes = crate::learning_setting::read_scopes_in_txn(
        vault,
        &txn,
        context.project,
        type_ref.as_ref(),
    )?;
    let mut choices = crate::learning_setting_choice::owner_spawn_model_choices_in_txn(
        &vault.store,
        &txn,
        &scopes,
    )?;
    if context.call_model_choice == Some(crate::learning_setting::SettingMode::Seed) {
        choices.seeds.clear();
    }
    Ok(choices)
}
