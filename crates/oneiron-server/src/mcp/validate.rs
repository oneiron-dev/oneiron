//! Validation of the actor and consent metadata every MCP tool call carries.

use super::args::{McpActorMetadata, McpConsentMetadata, McpToolScope};
use super::tool_catalog::McpToolValidationError;
use super::validators::{
    validate_entity_ref, validate_nonblank, validate_optional_entity_ref,
    validate_optional_nonblank,
};

impl McpActorMetadata {
    pub(super) fn validate(&self, tool: &'static str) -> Result<(), McpToolValidationError> {
        validate_entity_ref(tool, "actor.actor_ref", &self.actor_ref)?;
        validate_entity_ref(tool, "actor.gate_actor_ref", &self.gate_actor_ref)?;
        if self.actor_class != self.gate_actor_class {
            return Err(McpToolValidationError::field(
                tool,
                "actor.gate_actor_class",
                "must match actor_class for foreign MCP clients",
            ));
        }
        self.scope.validate(tool)
    }
}

impl McpToolScope {
    fn validate(&self, tool: &'static str) -> Result<(), McpToolValidationError> {
        validate_optional_entity_ref(tool, "actor.scope.world_ref", self.world_ref.as_deref())?;
        validate_optional_entity_ref(tool, "actor.scope.facet_ref", self.facet_ref.as_deref())
    }
}

impl McpConsentMetadata {
    pub(super) fn validate(&self, tool: &'static str) -> Result<(), McpToolValidationError> {
        validate_nonblank(tool, "consent.policy_ref", &self.policy_ref)?;
        validate_nonblank(tool, "consent.purpose", &self.purpose)?;
        validate_optional_nonblank(tool, "consent.approval_ref", self.approval_ref.as_deref())?;
        validate_optional_nonblank(
            tool,
            "consent.consent_receipt_ref",
            self.consent_receipt_ref.as_deref(),
        )
    }
}
