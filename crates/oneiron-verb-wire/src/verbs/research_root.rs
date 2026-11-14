//! Moved from `crates/oneiron/src/verbs/research_root.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::config::context_spec::CONTEXT_SPEC_MAX_TEXT_BYTES;
use serde::Deserialize;
use serde::Serialize;

/// Byte cap on an intent key: the campaign record's bound on a ref.
pub const INTENT_KEY_MAX_BYTES: usize = 256;

/// `vault.research.create_root`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchRootWire {
    /// The dispatchable agent definition the root attempt runs.
    pub agent: EntityId,
    /// The caller's name for this root: a repeat while the root is still
    /// pending returns that root and its run.
    pub intent_key: String,
    /// The root's brief, carried as its context briefing.
    pub briefing: String,
}

impl ResearchRootWire {
    /// Refuses a blank or over-long intent key or brief.
    ///
    /// # Errors
    ///
    /// BAD_REQUEST naming the field and its bound.
    pub fn validate(&self) -> MemoryResult<()> {
        if self.intent_key.trim().is_empty() || self.intent_key.len() > INTENT_KEY_MAX_BYTES {
            return Err(MemoryError::bad_request(format!(
                "a research root's intent_key is 1 to {INTENT_KEY_MAX_BYTES} bytes and not blank"
            )));
        }
        if self.briefing.trim().is_empty() || self.briefing.len() > CONTEXT_SPEC_MAX_TEXT_BYTES {
            return Err(MemoryError::bad_request(format!(
                "a research root's briefing is 1 to {CONTEXT_SPEC_MAX_TEXT_BYTES} bytes and not blank"
            )));
        }
        Ok(())
    }
}

/// The root a `vault.research.create_root` call enqueued or found pending.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchRootReceipt {
    /// The queued root attempt: bind a campaign to it with `vault.research.bind`.
    pub root: EntityId,
    /// The run the root carries.
    pub run_id: String,
    /// False when the call returned the pending root an earlier call with the
    /// same intent enqueued.
    pub enqueued: bool,
}
