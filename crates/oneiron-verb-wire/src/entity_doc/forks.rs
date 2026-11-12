//! Moved from `crates/oneiron/src/entity_doc/forks.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::consent_bound::ActionClass;
use oneiron_store::consent_bound::ActionEnvelope;
use oneiron_store::consent_bound::ActorBound;
use oneiron_store::consent_bound::GrantBound;
use oneiron_store::entity_doc::side_keys::HexPair;
use oneiron_store::side_table::key::HexId;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// A consume-once fork's durable state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum ForkStatus {
    Pending,
    Merged,
    Switched,
    Rejected,
}

/// Explicit settle verbs. Only SWITCH has a stale-base refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum SettleVerb {
    Merge,
    Switch,
    Reject,
}
