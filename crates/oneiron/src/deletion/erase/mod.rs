use std::collections::BTreeSet;

use crate::Vault;
use crate::affect::VadAnnotationCleanup;
use crate::affect::delete_vad_annotation_metadata_for_type_in_txn;
use crate::affect::delete_vad_annotation_metadata_in_txn;
use crate::affect::vad_annotation_delete_scope_exists_in_txn;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::deindex_entity;
use crate::batch::deindex_lexical_query_hints_for_target;
use crate::claim::ClaimSubject;
use crate::edge::EdgeConfirmationStatus;
use crate::edge::EdgeProvenanceFlags;
use crate::entity_id::EntityId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::ports::{RetrievalIndexMaintenance, ShortIdStoreMaintenance};
use crate::ppr;
use crate::provenance::EdgeRef;
use crate::provenance::PREDICATE_EDGE_PROVENANCE;
use crate::provenance::ProvenancePrecedence;
use crate::provenance::StoredProvenanceClaim;
use crate::provenance::decode_edge_provenance_body;
use crate::provenance::downgrade_edge_to_bare;
use crate::provenance::restamp_edge_flags;
use crate::provenance::winner_index;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::GateDecisionId;

use super::receipt::{RedactionReceiptInput, RedactionScope};
use super::sweep_queue::HardEraseSweepExtras;
use super::tombstone;
use super::tombstone::{ReplayedTombstoneOutcome, decode_tombstone_value, local_hard_delete_key};
use super::topology_delete_intent::{
    clear_own_topology_delete_in_txn, guard_topology_delete_request_in_txn,
    settled_topology_delete_in_txn,
};
use crate::error::{ClaimError, RegistryError};

/// ARCH-0038 delete-interplay refs captured from an `edge.provenance` Claim
/// BEFORE its body is purged or SoftErased: the subject EdgeRef whose cached
/// flags must be refreshed post-purge (D16), and the opaque refs the queued
/// historical-carrier sweep rides on (the ONE-1091 executor's seam).
pub(super) struct CapturedProvenanceDelete {
    pub(super) subject: EdgeRef,
    source_revision_ref: Option<[u8; 16]>,
    body_snapshot_ref: Option<[u8; 16]>,
}

/// Builds the queued sweep row's delete-interplay extras from a pre-purge
/// provenance capture: opaque lowercase-hex identifiers only — never content
/// or predicate strings. Empty for non-provenance deletes, so their queued
/// row shape gains nothing.
pub(super) fn sweep_extras(captured: Option<&CapturedProvenanceDelete>) -> HardEraseSweepExtras {
    let Some(captured) = captured else {
        return HardEraseSweepExtras::default();
    };
    HardEraseSweepExtras {
        revision_ids: captured
            .source_revision_ref
            .iter()
            .map(|reference| bytes_to_hex_lower(reference))
            .collect(),
        body_snapshot_refs: captured
            .body_snapshot_ref
            .iter()
            .map(|reference| bytes_to_hex_lower(reference))
            .collect(),
    }
}

mod active_store;
mod markers;
mod provenance;
mod redirect_shells;
mod replay;
