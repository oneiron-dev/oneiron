//! Durable model-step identity frozen into outbound effects.

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::model_step_error::DurableStepResult;
use oneiron_model::llm::LlmRequest;

/// Exact durable-step identity frozen beside an outbound payload. This is a
/// correlation key, never a caller-authored permission bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StepEffectBinding {
    pub(crate) attempt_id: AttemptId,
    pub(crate) step_hash: [u8; 32],
}

impl StepEffectBinding {
    pub(crate) fn for_request(
        attempt_id: AttemptId,
        request: &LlmRequest,
    ) -> DurableStepResult<Self> {
        Ok(Self {
            attempt_id,
            step_hash: request.canonical_hash()?,
        })
    }

    pub(crate) fn frozen_value(self) -> serde_json::Value {
        serde_json::json!({
            "attempt_id": crate::entity_id::bytes_to_hex_lower(self.attempt_id.as_bytes()),
            "step_hash": crate::entity_id::bytes_to_hex_lower(&self.step_hash),
        })
    }

    /// No key means an ordinary non-step effect. A present but malformed key
    /// refuses rather than dropping the step restriction.
    pub(crate) fn from_frozen_payload(payload: &[u8]) -> Result<Option<Self>, Error> {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
            return Ok(None);
        };
        let Some(value) = value.get("dreamer_step") else {
            return Ok(None);
        };
        let invalid = || Error::InvalidClaimBody("invalid frozen dreamer step binding");
        let object = value.as_object().ok_or_else(invalid)?;
        if object.len() != 2 {
            return Err(invalid());
        }
        let attempt_hex = object
            .get("attempt_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?;
        let hash_hex = object
            .get("step_hash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?;
        if attempt_hex.len() != 32 || hash_hex.len() != 64 {
            return Err(invalid());
        }
        let attempt_ref = EntityId::from_hex(attempt_hex).map_err(|_| invalid())?;
        let attempt_id = AttemptId::from_bytes(attempt_ref.as_bytes()).map_err(|_| invalid())?;
        let hash = blake3::Hash::from_hex(hash_hex).map_err(|_| invalid())?;
        if crate::entity_id::bytes_to_hex_lower(attempt_id.as_bytes()) != attempt_hex
            || crate::entity_id::bytes_to_hex_lower(hash.as_bytes()) != hash_hex
        {
            return Err(invalid());
        }
        Ok(Some(Self {
            attempt_id,
            step_hash: *hash.as_bytes(),
        }))
    }
}
