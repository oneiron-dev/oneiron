//! The checkpoint getter of the entity and edge rows (KS7-2): each raw
//! entity row by its own entity tree, and each edge read with the strict
//! edge codec. The rows are the raw ones, never a materialized live read, so
//! retained and deleted rows are captured as they stand.
//!
//! A kind another custody client seals is handed to it, never sealed here:
//! SECRET_CUSTODY to KS-6, WORLD_KEY_PAD to KS-5, ASSET bytes to KS-2, and a
//! dreamer step's CLAIM, which holds a model response, to KS-2B. An
//! `authored_by` edge names its actor, so it is the authored entity's
//! actor-keyed row; every other edge is structure that holds while both its
//! ends do. A NOTE core names its author (FIX 6072): one that names no one
//! is its tree's as it stands, and one with a live author stays under the
//! vault-wide seal until a restore derives its raw-derived refs again
//! (`crate::note::checkpoint::CORE_RAW_REFS`); the join that puts an opened
//! author back is NOTE's own. A sync copy of a CLAIM or NOTE row, in a window
//! or a thin cache, is placed by the same rule from its own bytes
//! ([`entity_row_placement`], FIX 10279). Nothing calls this until KS7-5,
//! and only once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

use crate::checkpoint_payload::rows;
use crate::write_envelope::claim_body::decode_claim_body;
use oneiron_base::edge::EdgeKind;
use oneiron_base::edge::parse_strict_edge_record;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_ASSET;
use oneiron_base::registry::ENTITY_TYPE_CLAIM;
use oneiron_base::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT;
use oneiron_base::registry::ENTITY_TYPE_NOTE;
use oneiron_base::registry::ENTITY_TYPE_SECRET_CUSTODY;
use oneiron_base::registry::ENTITY_TYPE_WORLD_KEY_PAD;
use oneiron_base::registry::entity_type_registry_entry;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::record_layout::EntityMetadataHeader;

/// The carrier an identity op's row is: its body names the actors it
/// stamps, and the live erase rewrites it in place (`IDENTITY_OPS`).
pub const IDENTITY_OP_ACTORS: &str = "identity op body names its actors";

/// The carrier an origin claim is: its body names its actor, and the live
/// erase rewrites it in place (`ORIGIN_CLAIMS`).
pub const ORIGIN_CLAIM_ACTORS: &str = "origin claim body names its actor";

/// Whether `value` is a NOTE's entity row.
pub fn is_note(value: &[u8]) -> bool {
    EntityMetadataHeader::parse(value).is_some_and(|header| header.entity_type == ENTITY_TYPE_NOTE)
}

pub fn entity_key(key: &[u8]) -> Option<EntityId> {
    EntityId::from_bytes(key.try_into().ok()?).ok()
}
