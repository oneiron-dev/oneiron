//! Citation floors: a derived record that quotes an entity document keeps the
//! history it quoted. The citing write records the frontier it read (or the
//! birth state, when the entity had no document yet) in its own transaction.
//! An owner purge never drops history past the floor of a live citer, and a
//! value-only recovery that would rebuild the document under a fresh
//! incarnation refuses while one exists. Unlike a `CitationPin`, a floor is
//! not a quote the recovery artifact must carry, so canonical capture stays
//! available.

use crate::entity_doc::side_keys::HexPair;
use crate::side_table::key::HexId;
use heed::{RoTxn, RwTxn};
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// What one citer quoted of one entity document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CitationFloor {
    /// Every incarnation-qualified frontier the citer named.
    pub frontiers: Vec<Vec<u8>>,
    /// The citer quoted the entity before it had a document: its birth state.
    pub birth: bool,
}

/// Hex incarnation id leading every qualified frontier.
pub const INCARNATION_LEN: usize = 32;

pub fn entity_prefix(entity: &EntityId) -> Vec<u8> {
    format!("{}:", entity.to_hex()).into_bytes()
}
