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
use crate::identity_topology::{
    StoredIdentityOpAction, decode_identity_topology_event_body,
    encode_identity_topology_event_body,
};
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
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT};
use crate::store::GateDecisionId;

use super::receipt::{RedactionReceiptInput, RedactionScope};
use super::sweep_queue::HardEraseSweepExtras;
use super::tombstone;
use super::tombstone::{ReplayedTombstoneOutcome, decode_tombstone_value, local_hard_delete_key};
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

/// Whether a stored type-76 action names any of `touched` in the redirect
/// topology it declares — the exact reach of the ARCH-0055 §9 erase walk.
///
/// ONLY the two shell-edge families answer yes: merge and split are the ops
/// the redirect walk reads, so they are the ops whose payloads it touches.
/// Facet, assert_distinct, undo and proposal resolution are outside that
/// reach and stay untouched, which is what keeps the author-stamp rider from
/// becoming a family-wide sweep.
fn identity_op_event_touches(
    action: &StoredIdentityOpAction,
    touched: &BTreeSet<EntityId>,
) -> bool {
    match action {
        StoredIdentityOpAction::Merge { sources, survivor } => {
            touched.contains(survivor) || sources.iter().any(|source| touched.contains(source))
        }
        StoredIdentityOpAction::Split { entity, heads, .. } => {
            touched.contains(entity) || heads.iter().any(|head| touched.contains(head))
        }
        StoredIdentityOpAction::Facet { .. }
        | StoredIdentityOpAction::AssertDistinct { .. }
        | StoredIdentityOpAction::Undo { .. }
        | StoredIdentityOpAction::ProposalResolution { .. } => false,
    }
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
