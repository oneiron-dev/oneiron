//! Moved from `crates/oneiron/src/connector_key/slate_revision.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::connector_key::slate_revision::ConnectorRevisionDeferral;
use oneiron_verb_wire::connector_key::slate_scope_signal::ConnectorScopeExceed;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Why a slate revises its prior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlateRevisionCause {
    /// The connector's declaration drifted (a delta draft).
    ManifestDrift,
    /// The owner's rulings on repeated scope exceeds earned an offer to
    /// widen one row's grant.
    ScopeExceed {
        signal_ref: EntityId,
        key_ref: EntityId,
        actor: String,
        generation: [u8; 32],
        tool: String,
        exceed: ConnectorScopeExceed,
    },
    /// A credential binding answers for a new issuer: every row that
    /// depended on the old one goes back to the owner.
    CredentialIssuerChanged {
        binding_ref: EntityId,
        expected_generation: u64,
        old_issuer: String,
        new_issuer: String,
        proposed_credential_ref: String,
        dependent_rows: BTreeSet<String>,
    },
}
