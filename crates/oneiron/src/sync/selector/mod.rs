//! Grant-backed closed-subgraph sync selectors.
//!
//! Existing full-window sync exports opaque Loro deltas from the canonical
//! window doc. Those bytes cannot be redacted safely after export, so selector
//! sync builds a synthetic window doc containing only the authorized closed
//! subgraph and exports from that doc instead.

mod admission;
pub(crate) use admission::admit_federated_entity_blob;
mod authorize;
mod born_with;
mod codec;
mod document_admission;
mod epoch_egress;
pub(in crate::sync) use document_admission::{
    admit_document_read_in_txn, admit_document_write_in_txn, admit_promoted_entity_write_in_txn,
};
#[cfg(feature = "sync")]
mod edge;
mod guest_document;
pub use guest_document::{export_guest_document_for_guest, share_guest_document_as_owner};
mod held_retire;
mod machine_history;
pub(in crate::sync) use machine_history::machine_history_controls;
mod note_admission;
mod peer_confidence;
mod scope;
// FIX 7608 slice 4: the masked copy a sync peer gets of a marked repo item.
pub(crate) mod secret_projection;
pub use secret_projection::{
    RepoCopyAliases, RepoSyncAdmission, admit_repo_sync_frame, prepare_repo_sync_frame,
    prepare_repo_sync_frame_for_home, repo_copy_generation, repo_document_copy_vector,
    repo_document_lineage_edit, repo_document_source,
};
mod text_egress;
// FIX 10161: the tombstones a narrower grant's export carries.
mod tombstones;
// FIX 10162: the admission validators that read in the caller's txn.
#[cfg(feature = "sync")]
mod validators;
pub(crate) use note_admission::admit_note_in_txn;
pub(in crate::sync) use text_egress::document_sources_readable_in_txn;
#[cfg(test)]
mod tests;

// Anchor for the unchanged `super::bridge` / `super::loro_support` body paths
// in edge.rs and scope.rs:
use super::bridge;
use super::loro_support;

#[cfg(test)]
pub(in crate::sync) use self::admission::admit_peer_window_update;
#[cfg(feature = "test-hooks")]
pub use self::admission::put_selector_test_federation_grant;
#[cfg(feature = "sync")]
pub(in crate::sync) use self::admission::validate_sync_identity_body;
pub(crate) use self::admission::{AdmittedUpdate, admit_staged_window_update};
pub use self::admission::{FederationAdmissionRole, admit_federated_window_update};
pub(in crate::sync) use self::admission::{
    admit_peer_window_update_as, revalidate_admitted_facet_stamps,
    revalidate_admitted_federated_claims, staged_births,
};
pub use self::authorize::authorize_sync_selector;
pub(in crate::sync) use self::authorize::authorize_sync_selector_in_txn;
pub(crate) use self::born_with::{
    carried_born_with, carried_born_with_in_txn, erase_carried_born_with_in_txn,
};
pub(in crate::sync) use self::codec::granted_window_doc;
pub use self::codec::{
    RequestedAxis, SYNC_SELECTOR_SCHEMA_VERSION, SelectorVvRequest, SyncSelector,
    SyncSelectorWorld, decode_selector_vv_request, decode_sync_selector,
    encode_selector_vv_request, encode_sync_selector, filtered_window_doc, filtered_window_doc_for,
    filtered_window_doc_for_peer, guest_share_envelope, guest_share_envelope_body,
};
pub(crate) use self::edge::ReleasedStamps;
pub(crate) use self::held_retire::retire_held_facet_stamps;
pub use self::peer_confidence::{DEFAULT_FEDERATED_CONFIDENCE_SCALE, PeerConfidence};
pub use crate::share_travel::GrantTravel;

#[cfg(test)]
use self::{authorize::*, codec::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::authority::{AuthorityOp, authority_log_entity_id, genesis_vault_id};
#[cfg(test)]
use crate::batch::EntityMetadataHeader;
#[cfg(test)]
use crate::edge::EdgeKind;
#[cfg(test)]
use crate::entity_id::{EntityId, LocalWorldId};
#[cfg(test)]
use crate::error::{Error, SyncProtocolValidation, SyncSelectorValidation as SelectorError};
#[cfg(test)]
use crate::federation::SelectorRange;
#[cfg(test)]
use crate::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CLAIM, ENTITY_TYPE_FEDERATION_GRANT};
#[cfg(test)]
use crate::sync::bridge::parse_edge_key;
#[cfg(test)]
use crate::sync::loro_support::{
    map_for_each_tombstone_value, map_for_each_value_bytes, map_insert_bytes,
};
#[cfg(test)]
use crate::sync::schema::create_window_doc;
#[cfg(test)]
use crate::sync::types::WindowKey;
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::io::Cursor;
