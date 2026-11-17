//! L8-07 door: a scripted local model for the task-brief composer, and the
//! brief a parked post holds.

use std::sync::{Arc, Mutex, PoisonError};

use crate::entity_id::EntityId;
use crate::llm::ModelLocality;
use crate::memory::MemoryResult;
use crate::task_verb::{
    QueueTaskBrief, TaskBriefDraftRequest, TaskBriefModel, TaskBriefModelBinding,
};
use crate::{Result, Vault};

/// One draft call as the scripted model received it.
#[derive(Debug, Clone)]
pub struct DraftCall {
    pub instruction: String,
    pub input: String,
    pub schema: serde_json::Value,
}

/// A model that answers every draft with one fixed reply and records each
/// call.
pub struct ScriptedBriefModel {
    model: String,
    locality: ModelLocality,
    reply: String,
    calls: Mutex<Vec<DraftCall>>,
}

impl ScriptedBriefModel {
    /// Every draft call so far, in order.
    pub fn calls(&self) -> Vec<DraftCall> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl TaskBriefModel for ScriptedBriefModel {
    fn binding(&self) -> TaskBriefModelBinding {
        TaskBriefModelBinding {
            model: self.model.clone(),
            locality: self.locality,
        }
    }

    fn draft(&self, request: &TaskBriefDraftRequest<'_>) -> MemoryResult<String> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(DraftCall {
                instruction: request.instruction.to_owned(),
                input: request.input.to_owned(),
                schema: request.schema.clone(),
            });
        Ok(self.reply.clone())
    }
}

/// Installs on `vault` a model named `model` at `locality` that answers
/// every draft with `reply`, and returns it to read its calls.
pub fn install_scripted_brief_model(
    vault: &Vault,
    model: &str,
    locality: ModelLocality,
    reply: &str,
) -> Arc<ScriptedBriefModel> {
    let scripted = Arc::new(ScriptedBriefModel {
        model: model.to_owned(),
        locality,
        reply: reply.to_owned(),
        calls: Mutex::new(Vec::new()),
    });
    let installed: Arc<dyn TaskBriefModel> = scripted.clone();
    assert!(
        vault.install_task_brief_model(installed).is_ok(),
        "one task-brief model per vault"
    );
    scripted
}

/// The brief parked post proposal `proposal_ref` carries, its composer
/// stamp included; `None` when the claim is no parked post.
pub fn parked_post_brief(vault: &Vault, proposal_ref: EntityId) -> Result<Option<QueueTaskBrief>> {
    crate::task_verb::parked_post_brief(vault, proposal_ref)
}
