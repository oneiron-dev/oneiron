//! L8-07 door, red pin: main has no task-brief composer, so the scripted
//! model installs nothing and records nothing, and no parked brief reads.

use std::sync::Arc;

use crate::entity_id::EntityId;
use crate::llm::ModelLocality;
use crate::task_verb::QueueTaskBrief;
use crate::{Result, Vault};

/// One draft call as the scripted model received it.
#[derive(Debug, Clone)]
pub struct DraftCall {
    pub instruction: String,
    pub input: String,
    pub schema: serde_json::Value,
}

/// The red pin's model: nothing calls it.
pub struct ScriptedBriefModel;

impl ScriptedBriefModel {
    /// Every draft call so far: none on main.
    pub fn calls(&self) -> Vec<DraftCall> {
        Vec::new()
    }
}

/// Installs nothing: main has no seam to install a model on.
pub fn install_scripted_brief_model(
    _vault: &Vault,
    _model: &str,
    _locality: ModelLocality,
    _reply: &str,
) -> Arc<ScriptedBriefModel> {
    Arc::new(ScriptedBriefModel)
}

/// No parked brief reads on main.
pub fn parked_post_brief(
    _vault: &Vault,
    _proposal_ref: EntityId,
) -> Result<Option<QueueTaskBrief>> {
    Ok(None)
}
