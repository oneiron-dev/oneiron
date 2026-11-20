//! The scope a deleted record held, kept as content-free evidence bound to its
//! delete request, so a selector export can carry the tombstone to a grant
//! that reads that scope once the row is gone (FIX 10161). The facets the
//! record was stamped into go with it, because a selector narrowed to some
//! facets selects a row by those stamps and the delete sweeps them out of the
//! window (SELECTOR-FACET-EXPORT-DROPS-BODYLESS-TOMBSTONES).
//!
//! A capture never fails, delays or rolls back the delete it runs in: an error
//! is logged, and the tombstone is then not exported to a narrower grant.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::RelationshipRead;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::side_table::{self, HexId, Named, SideTable};
use crate::store::{ManifestDbs, Store};
use oneiron_authority::federation::{Scope, ScopeId};

#[cfg(feature = "sync")]
use super::tombstone::TombstoneValueV2;
use super::tombstone::decode_tombstone_value;

/// The scope one deleted record held, and the delete request it is bound to.
/// Ids and levels only (worlds, facets, bands, audience, verbs, sensitivity),
/// never content.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeletedRecordScope {
    pub(crate) scope: Scope,
    pub(crate) request: Option<[u8; 16]>,
    /// The relationship read the record's labels gave it: its kind, the
    /// relationships it was scoped to, whether it was private, and its record
    /// position (OPUS-LEAKS, SELECTOR-TOMBSTONE-LABEL). A selector's member
    /// takes the tombstone only where this read admits it. A capture written
    /// before the field existed has none, and its tombstone travels as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) relationship_read: Option<RelationshipRead>,
    /// The FACETs the record's stored `FacetOf` edges named, each only where
    /// both ends sit on the ONE-1645 table by their stored types, as the
    /// selector's read mirror honors a stamp
    /// (`sync/selector/scope.rs` `facet_scope_by_source`). A selector narrowed
    /// to some facets takes the tombstone only where it selects every one of
    /// them, as it keeps a live row (SELECTOR-FACET-EXPORT-DROPS-BODYLESS-
    /// TOMBSTONES). A capture written before the field existed has none, and
    /// its tombstone stays off such a selector, as before.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(crate) facet_of: BTreeSet<ScopeId>,
}

/// One deleted record's captured scope. Key: hex32 (entity id).
const TOMBSTONE_SCOPE: SideTable<HexId, DeletedRecordScope, Named> =
    SideTable::new(&side_table::FEDERATION_TOMBSTONE_SCOPE);

/// Captures `id`'s scope in the delete's own transaction, before its row is
/// torn down. `request` binds it; an unbound capture keeps the request a row
/// is already bound to.
pub(crate) fn capture_deleted_scope_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    request: Option<&[u8; 16]>,
) {
    capture_deleted_scope_in_store_txn(&vault.store, txn, id, request);
}

/// [`capture_deleted_scope_in_txn`] for a writer that holds the store alone,
/// as a Grant's withdrawal does (FIX 11780): the same capture, never failing
/// the delete it runs in.
pub(crate) fn capture_deleted_scope_in_store_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    request: Option<&[u8; 16]>,
) {
    if let Err(error) = capture_in_txn(store, txn, id, request) {
        warn_uncaptured(id, &error);
    }
}

/// [`capture_deleted_scope_in_txn`] in a writer of its own, for the publish
/// path, which holds no transaction where it captures.
#[cfg(feature = "sync")]
pub(crate) fn capture_deleted_scope(vault: &Vault, id: &EntityId, tombstone: &TombstoneValueV2) {
    let request = Some(&tombstone.request_id);
    if let Err(error) =
        vault.with_write_txn_grouped(|txn| capture_in_txn(&vault.store, txn, id, request))
    {
        warn_uncaptured(id, &error);
    }
}

/// A tombstone a peer sent: the scope of the row it removes here, bound to the
/// request id its value carries.
pub(crate) fn capture_received_scope_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    raw_value: &[u8],
) {
    let request = decode_tombstone_value(raw_value).request_id;
    capture_deleted_scope_in_txn(vault, txn, id, request.as_ref());
}

/// [`capture_received_scope_in_txn`] in a writer of its own, for a replay that
/// opens its own transaction.
pub(crate) fn capture_received_scope(vault: &Vault, id: &EntityId, raw_value: &[u8]) {
    let request = decode_tombstone_value(raw_value).request_id;
    if let Err(error) =
        vault.with_write_txn_grouped(|txn| capture_in_txn(&vault.store, txn, id, request.as_ref()))
    {
        warn_uncaptured(id, &error);
    }
}

/// What `id` held when delete `request` took it. Only a row bound to that
/// request answers.
pub(crate) fn deleted_record_scope_in(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    request: &[u8; 16],
) -> Result<Option<DeletedRecordScope>> {
    Ok(TOMBSTONE_SCOPE
        .get(store, txn, &HexId(*id))?
        .filter(|row| row.request.as_ref() == Some(request)))
}

/// The scope `id` held when delete `request` took it. Only a row bound to that
/// request answers.
pub(crate) fn deleted_scope_in(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    request: &[u8; 16],
) -> Result<Option<Scope>> {
    Ok(deleted_record_scope_in(store, txn, id, request)?.map(|row| row.scope))
}

/// The relationship read `id` held when delete `request` took it. Only a row
/// bound to that request answers: `None` when no row is, `Some(None)` for a
/// row captured before the read existed (an older delete).
pub(crate) fn deleted_relationship_read_in(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    request: &[u8; 16],
) -> Result<Option<Option<RelationshipRead>>> {
    Ok(deleted_record_scope_in(store, txn, id, request)?.map(|row| row.relationship_read))
}

/// A live row's scope is written. With no live row (none, or a deleted
/// shell), a held row is rebound to `request` whenever `request` is some and
/// differs from the row's; nothing else changes.
fn capture_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    request: Option<&[u8; 16]>,
) -> Result<()> {
    let key = HexId(*id);
    let held = TOMBSTONE_SCOPE.get(store, txn, &key)?;
    let live = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
        .filter(|raw| raw.len() > ENTITY_METADATA_HEADER_LEN);
    let captured = match live {
        Some(raw) => {
            crate::federation::record_scope::scope_for_blob(store, txn, *id, &raw)?.map(|scope| {
                (
                    scope,
                    live_relationship_read(store, txn, id, &raw),
                    live_facet_stamps(store, txn, id, &raw),
                )
            })
        }
        None => None,
    };
    let row = match (captured, held) {
        (Some((scope, relationship_read, facet_of)), held) => DeletedRecordScope {
            scope,
            request: request.copied().or(held.and_then(|row| row.request)),
            relationship_read: Some(relationship_read),
            facet_of,
        },
        (None, Some(held)) => {
            if request.is_none() || request == held.request.as_ref() {
                return Ok(());
            }
            DeletedRecordScope {
                scope: held.scope,
                request: request.copied(),
                relationship_read: held.relationship_read,
                facet_of: held.facet_of,
            }
        }
        (None, None) => return Ok(()),
    };
    TOMBSTONE_SCOPE.put(store, txn, &key, &row)
}

/// The live row `raw`'s relationship read, as a selector judges its member's
/// rows ([`crate::claim::relationship_label_read`]). A read that fails (a
/// CLAIM body that does not decode, a failed store read) is read by no
/// member, and the capture still lands.
fn live_relationship_read(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> RelationshipRead {
    crate::claim::relationship_label_read(store, txn, id, raw)
        .unwrap_or(RelationshipRead::Decided(false))
}

/// The FACETs the live row `raw` is stamped into: each target of its stored
/// `FacetOf` edges whose pair of stored types sits on the ONE-1645 table
/// ([`crate::batch::facet_of_endpoint_types_on_table`]), the stamps a
/// selector's read mirror honors. A stamp whose target has no stored row is
/// unknowable here, and a read that fails proves nothing: either stamps the
/// row into no facet, so its tombstone stays off a facet-narrowed selector,
/// and the capture still lands.
fn live_facet_stamps(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> BTreeSet<ScopeId> {
    facet_stamps(store, txn, id, raw).unwrap_or_else(|error| {
        tracing::warn!(
            %error,
            entity = %id.to_hex(),
            "deleted record's facet stamps not captured; its tombstone stays off facet-narrowed selectors"
        );
        BTreeSet::new()
    })
}

fn facet_stamps(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<BTreeSet<ScopeId>> {
    let source_type = EntityMetadataHeader::parse(raw)
        .ok_or(Error::CorruptedIndex("record header"))?
        .entity_type;
    let targets = store
        .port_edges(txn, id, EdgeDirection::Out, Some(EdgeKind::FacetOf), None)?
        .map(|edge| edge.map(|edge| edge.target))
        .collect::<Result<Vec<_>>>()?;
    let mut stamps = BTreeSet::new();
    for target in targets {
        match crate::batch::stored_entity_type(store, txn, &target)? {
            Some(target_type)
                if crate::batch::facet_of_endpoint_types_on_table(source_type, target_type) =>
            {
                stamps.insert(ScopeId(target));
            }
            // Off the table by stored types: inert, as the read mirror reads it.
            Some(_) => {}
            None => return Ok(BTreeSet::new()),
        }
    }
    Ok(stamps)
}

fn warn_uncaptured(id: &EntityId, error: &Error) {
    tracing::warn!(
        %error,
        entity = %id.to_hex(),
        "deleted record's scope not captured; its tombstone stays off narrower grants"
    );
}
