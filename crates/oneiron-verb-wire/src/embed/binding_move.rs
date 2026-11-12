//! Moved from `crates/oneiron/src/embed/binding_move.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::embed::space_move::NotWorse;
use crate::embed::space_move::SpaceMove;
use crate::embed::space_move::SpaceMoveState;
use crate::embed::space_move::SpaceRef;
use heed::RoTxn;
use heed::RwTxn;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::model_binding::ModelBinding;
use oneiron_model::model_binding::ModelRole;
use oneiron_store::embedding::EmbeddingSpace;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The space move that re-embeds for a binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BindingMoveLink {
    pub candidate: String,
    pub incumbent: SpaceRef,
    /// The move's `started_at`: which move to that candidate it is.
    pub started_at: u64,
}

/// Why a staged binding never applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BindingNotApplied {
    /// The owner undid the switch before it applied.
    Cancelled,
    /// The binding it expects to replace, or its trained run, changed since it was staged.
    Stale,
    /// The manifest's own checks refused it at the swap: its validation, or the teacher's
    /// probe approval.
    Refused { reason: String },
}
