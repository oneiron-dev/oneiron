//! Moved from `crates/oneiron/src/mail_pack/local_sync.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::mail_pack::importer::MailSyncBudget;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;

/// The most bodies one step of `vault.mail.sources.sync` fills in.
pub const MAX_BODIES_PER_STEP: u32 = 500;

/// `vault.mail.sources.sync`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceSyncRequest {
    /// The mail or calendar source, 32-hex.
    pub source_ref: String,
    /// The bodies a mailbox step fills in; 50 when absent, at most 500.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bodies: Option<u32>,
}

impl MailSourceSyncRequest {
    /// The source this request names and the step's budget.
    ///
    /// # Errors
    ///
    /// A source ref that is not 32-hex.
    pub fn step(&self) -> MemoryResult<(EntityId, MailSyncBudget)> {
        let source = EntityId::from_hex(&self.source_ref)?;
        let mut budget = MailSyncBudget::default();
        if let Some(bodies) = self.bodies {
            budget.bodies = bodies.min(MAX_BODIES_PER_STEP);
        }
        Ok((source, budget))
    }
}
