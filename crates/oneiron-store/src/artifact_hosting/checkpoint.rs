//! The checkpoint getter of artifact hosting rows (FIX 10436): each blob
//! artifact's channel pointers, publish admissions and serving descriptors
//! under the artifact's own entity tree. A pointer or a serving descriptor
//! names no actor and goes byte-exact; an admission's actor is an actor
//! part, as a version's is. A code fork's pointer, or a blob row whose key
//! does not name its artifact, has no proved owner and stays unclassified.
//! Nothing calls this until KS7-5, and only once
//! CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::RoTxn;

use crate::artifact_hosting::vocabulary::ArtifactExportRef;
use crate::checkpoint_payload::rows;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The field the publish's actor fills.
pub const ACTOR: &str = "actor";
