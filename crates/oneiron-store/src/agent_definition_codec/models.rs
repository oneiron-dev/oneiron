//! The AGENT_DEF `models` list and `compaction_model` codec (FIX 4472): the
//! strict decode, the pinned-key encode and the list rules every encode and
//! decode holds.

use oneiron_model::llm::ModelId;
use rmpv::Value;

use crate::agent_model::AgentModel;
use crate::agent_record::AGENT_DESC_MAX_BYTES;
use crate::agent_record::AGENT_MODEL_TIER_MAX_BYTES;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

pub const MODEL_REF_TEXT: &str = "model entry model_ref must be a provider/name@revision model id";
pub const WHEN_TEXT: &str = "model entry when must be a non-empty UTF-8 string";
pub const COMPACTION_MODEL_TEXT: &str =
    "compaction_model must be a provider/name@revision model id";

pub fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDefBody(reason))
}
