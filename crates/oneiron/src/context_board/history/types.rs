//! Typed board history requests and exact-fold results.

use crate::vault::RevisionRef;
use crate::{EntityId, error::Error};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Planner-resolved, agent-free selection. Index-only candidates are separate
/// and never become persistent activated claims or reconstruction rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoardSelection {
    pub allowed: BTreeSet<EntityId>,
    pub default_on: BTreeSet<EntityId>,
    pub active: BTreeSet<EntityId>,
    pub pinned: BTreeSet<EntityId>,
    pub top_snippet: BTreeSet<EntityId>,
    pub index_only: BTreeSet<EntityId>,
}

/// Turn order is strict within one board owner. `at` is the valid-time axis;
/// `learned_at` on the writer is the independent transaction-time axis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardTurn {
    pub turn: EntityId,
    pub owner: EntityId,
    pub at: u64,
    pub selection: BoardSelection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct TurnAnchor {
    #[serde(with = "entity_id_codec")]
    pub owner: EntityId,
    pub at: u64,
    pub learned_at: u64,
    pub source_revision_ref: RevisionRef,
    pub frontier: Vec<u8>,
}

/// Claims written by this turn. Empty on an unchanged selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardTurnReceipt {
    pub turn: EntityId,
    pub source_revision_ref: RevisionRef,
    pub changed_claims: Vec<EntityId>,
}

/// Reconstructed facts, not an opaque stored board snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructedBoard {
    pub turn: EntityId,
    pub owner: EntityId,
    pub at: u64,
    pub source_revision_ref: RevisionRef,
    pub selection: BoardSelection,
    /// Exact body bytes at the frontier recorded by this turn.
    pub documents: BTreeMap<EntityId, Vec<u8>>,
}

/// History cannot fall back to the current board or to an older checkpoint.
#[derive(Debug, thiserror::Error)]
pub enum BoardHistoryError {
    #[error("turn {turn:?} predates board retention horizon {retained_from}")]
    BeyondCompactionHorizon { turn: EntityId, retained_from: u64 },
    #[error("board turn {0:?} has no frontier anchor")]
    UnknownTurn(EntityId),
    #[error("board owner {0:?} is no longer live")]
    UnknownOwner(EntityId),
    #[error("board frontier is missing or invalid")]
    MissingFrontier,
    #[error("board document {0:?} is not currently readable by its owner")]
    UnreadableDocument(EntityId),
    #[error("invalid board selection: {0}")]
    InvalidSelection(&'static str),
    #[error(transparent)]
    Storage(#[from] Error),
    #[error(transparent)]
    Database(#[from] heed::Error),
}

mod entity_id_codec {
    use super::*;
    pub(super) fn serialize<S: serde::Serializer>(
        value: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.as_bytes().serialize(serializer)
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let bytes = <[u8; 16]>::deserialize(deserializer)?;
        EntityId::from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}
