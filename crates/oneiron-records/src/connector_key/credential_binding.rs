//! Moved from `crates/oneiron/src/connector_key/credential_binding.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::connector_key::credential_binding::ConnectorIssuerHaltView;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// One key, or one row of it, that depends on a credential binding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorBindingDependent {
    pub key_ref: EntityId,
    /// The row's key (a tool, or the elicitation row); `None`: every row the
    /// key calls.
    pub tool: Option<String>,
}

/// Where an issuer change stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorIssuerTransitionState {
    /// Recorded; its forced re-ask is not drafted yet.
    Detected,
    /// Its forced re-ask waits on the owner's stamp.
    Drafted { slate_ref: EntityId },
    /// The owner stamped it: the binding answers for the new issuer.
    Accepted { slate_ref: EntityId },
}

/// One observed issuer change on a binding, kept after acceptance as its
/// evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorIssuerTransition {
    pub old_issuer: String,
    pub new_issuer: String,
    /// The custody pointer the new issuer's credential presents.
    pub proposed_credential_ref: String,
    /// What the observer saw, in its own words: never a credential.
    pub witness: String,
    pub detected_at: u64,
    /// The binding generation it was detected at; acceptance names it.
    pub expected_generation: u64,
    /// The rows it halts.
    pub dependents: BTreeSet<ConnectorBindingDependent>,
    pub state: ConnectorIssuerTransitionState,
}

impl ConnectorIssuerTransition {
    /// Whether it still waits on the owner, halting its dependents.
    #[must_use]
    pub fn halts(&self) -> bool {
        !matches!(self.state, ConnectorIssuerTransitionState::Accepted { .. })
    }
}

/// One catalog connector credential slot's durable binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorCredentialBinding {
    pub binding_ref: EntityId,
    /// The catalog connector, normalized.
    pub connector: String,
    pub catalog_key: EntityId,
    /// The credential slot: the route's own, or a custody record's name.
    pub slot: String,
    /// The accepted issuer.
    pub issuer: String,
    /// The accepted custody pointer or fingerprint, never a value.
    pub credential_ref: String,
    pub generation: u64,
    pub dependents: BTreeSet<ConnectorBindingDependent>,
    /// The latest issuer change, open or accepted.
    pub transition: Option<ConnectorIssuerTransition>,
}
