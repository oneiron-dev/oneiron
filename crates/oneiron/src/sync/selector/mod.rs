//! Grant-backed closed-subgraph sync selectors.
//!
//! Existing full-window sync exports opaque Loro deltas from the canonical
//! window doc. Those bytes cannot be redacted safely after export, so selector
//! sync builds a synthetic window doc containing only the authorized closed
//! subgraph and exports from that doc instead.

mod admission;
mod authorize;
mod codec;
#[cfg(feature = "sync")]
mod edge;
mod scope;
#[cfg(test)]
mod tests;

// Anchor for the unchanged `super::bridge` / `super::loro_support` body paths
// in edge.rs and scope.rs:
use super::bridge;
use super::loro_support;

#[cfg(feature = "test-hooks")]
pub use self::admission::put_selector_test_federation_grant;
pub(crate) use self::admission::revalidate_admitted_federated_claims;
pub use self::admission::{FederationAdmissionRole, admit_federated_window_update};
pub use self::authorize::authorize_sync_selector;
pub use self::codec::{
    SYNC_SELECTOR_SCHEMA_VERSION, SelectorVvRequest, SyncSelector, SyncSelectorWorld,
    decode_selector_vv_request, decode_sync_selector, encode_selector_vv_request,
    encode_sync_selector, filtered_window_doc, guest_share_envelope, guest_share_envelope_body,
};

#[cfg(test)]
use self::{authorize::*, codec::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::authority::{AuthorityOp, authority_log_entity_id, genesis_vault_id};
#[cfg(test)]
use crate::batch::EntityMetadataHeader;
#[cfg(test)]
use crate::companion::CompanionExportClassification;
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
