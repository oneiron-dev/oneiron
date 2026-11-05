//! Owner-editable principal set and the legal-reality-gated D6 action dial.
use crate::blob_artifact::esign::model::invalid;
use crate::blob_artifact::esign::model::reference;
use crate::side_table::key::HexId;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::limit_ask::EngineLimit;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningAutonomy {
    ScopedRead,
    Draft,
    SendWithApproval,
    AutonomousInEnvelope,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningPrincipal {
    pub principal_ref: String,
    pub autonomy: SigningAutonomy,
    /// Defaults closed. This is a legal-reality dial, not a fixed safety ban.
    pub automated_sign_action: bool,
}
