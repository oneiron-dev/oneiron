//! Grant-backed closed-subgraph sync selectors.
//!
//! Existing full-window sync exports opaque Loro deltas from the canonical
//! window doc. Those bytes cannot be redacted safely after export, so selector
//! sync builds a synthetic window doc containing only the authorized closed
//! subgraph and exports from that doc instead.

mod admission;
pub(crate) use admission::admit_federated_entity_blob;
mod authorize;
mod codec;
mod document_admission;
mod epoch_egress;
pub(in crate::sync) use document_admission::{
    admit_document_read_in_txn, admit_document_write_in_txn, admit_promoted_entity_write_in_txn,
};
#[cfg(feature = "sync")]
mod edge;
mod held_retire;
mod machine_history;
mod note_admission;
mod peer_confidence;
mod scope;
mod text_egress;
pub(crate) use note_admission::admit_note_in_txn;
pub(in crate::sync) use text_egress::document_sources_readable_in_txn;
#[cfg(test)]
mod tests;

// Anchor for the unchanged `super::bridge` / `super::loro_support` body paths
// in edge.rs and scope.rs:
use super::bridge;
use super::loro_support;

#[cfg(feature = "test-hooks")]
pub use self::admission::put_selector_test_federation_grant;
#[cfg(feature = "sync")]
pub(in crate::sync) use self::admission::validate_sync_identity_body;
pub(crate) use self::admission::{AdmittedUpdate, admit_staged_window_update};
pub use self::admission::{FederationAdmissionRole, admit_federated_window_update};
pub(in crate::sync) use self::admission::{
    admit_peer_window_update, revalidate_admitted_facet_stamps,
    revalidate_admitted_federated_claims, staged_births,
};
pub use self::authorize::authorize_sync_selector;
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
