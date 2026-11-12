//! Moved from `crates/oneiron/src/embed/binding_move.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::embed::space_move::NotWorse;
use crate::embed::space_move::SpaceRef;
use crate::skill_optimize::offer_switch::SwitchOwner;
use heed::RoTxn;
use heed::RwTxn;
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

/// Where a staged binding stands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BindingMoveState {
    /// No declared space pins its model yet, or the slots it moves move elsewhere; the old
    /// binding serves.
    Waiting,
    /// Its move's candidate fills while the old binding and slots serve.
    Filling,
    /// The manifest binds it. `verdict` is its move's last check reading, kept beside the
    /// owner's yes; `None` when no check ran.
    Applied { at: u64, verdict: Option<NotWorse> },
    /// It never applied.
    NotApplied { at: u64, why: BindingNotApplied },
    /// The owner undid it after it applied: the binding it replaced serves again.
    Undone { at: u64, owner: SwitchOwner },
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
