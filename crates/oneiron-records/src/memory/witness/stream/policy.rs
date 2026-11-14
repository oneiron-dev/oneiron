//! Moved from `crates/oneiron/src/memory/witness/stream/policy.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::witness::stream::*;
use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

impl MessageStreamPolicy {
    fn validate(&self) -> MessageStreamResult<()> {
        if self.idle_timeout_ms == 0 {
            return Err(MessageStreamError::InvalidRequest(
                "idle timeout must be positive",
            ));
        }
        self.default_mode.validate()?;
        for mode in self.agent_overrides.values() {
            mode.validate()?;
        }
        Ok(())
    }

    pub fn resolve(
        &self,
        actor: &EntityId,
        explicit: Option<MessageWriteMode>,
    ) -> MessageWriteMode {
        explicit
            .or_else(|| self.agent_overrides.get(actor).copied())
            .unwrap_or(self.default_mode)
    }
}
