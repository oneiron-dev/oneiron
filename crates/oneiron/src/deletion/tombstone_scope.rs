//! The scope a deleted record held, kept as content-free evidence bound to its
//! delete request, so a selector export can carry the tombstone to a grant
//! that reads that scope once the row is gone (FIX 10161). The facets the
//! record was stamped into go with it, because a selector narrowed to some
//! facets selects a row by those stamps and the delete sweeps them out of the
//! window (SELECTOR-FACET-EXPORT-DROPS-BODYLESS-TOMBSTONES). So do the
//! worlds whose words it carried, because the delete takes the edges and
//! sources the device-only check reads them by (REVIEW-10024). So does every
//! world a row that takes its worlds from live edges sat in, because the
//! captured scope holds base reality alone of base and another world, and a
//! grant that reads only that world held the live row there (REVIEW-10042).
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
use crate::federation::record_scope::note_world;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::settings::CarriedWorlds;
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
    /// The type byte of the record's header, which a selector narrowed to
    /// some bands judges a kept row by. The scope's band axis is the record's
    /// disclosure position, which need not be its own type (a scoped touch
    /// names CLAIM), so it cannot stand in for it
    /// (SELECTOR-FACET-BAND-EXPORT-DROPS-BODYLESS-TOMBSTONES, REVIEW-10010
    /// round 2). A capture written before the field existed has none, and its
    /// tombstone stays off such a selector, as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) entity_type: Option<u8>,
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
    /// The worlds whose words the record carried, its sources' among them,
    /// as the device-only check reads a live row
    /// ([`crate::settings::carried_worlds_in`]). The delete takes the row's
    /// `InWorld` edges and sources with it, so an export judges the
    /// tombstone of a purged row against the worlds it keeps off its
    /// destination by these (REVIEW-10024). A read that failed is unknown,
    /// which keeps the tombstone home while any world is flagged. A capture
    /// written before the field existed has none, and its tombstone is
    /// judged as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) carried_worlds: Option<CarriedWorlds>,
    /// Every world a record whose kind takes its worlds from live edges (a
    /// NOTE, an ASSET, a caption; [`note_world::takes_live_worlds`]) sat in,
    /// base reality by its own id ([`note_world::live_worlds_in`]). The scope's
    /// world axis is its one position ([`note_world::NoteWorlds::axis`]),
    /// which keeps base reality alone of base and another world, so it cannot
    /// say where a grant that reads only that other world held the live row
    /// (REVIEW-10042). `None` for any other kind, for edges that did not read
    /// (the scope's axis then says every world), and for a capture written
    /// before the field existed, whose tombstone is judged by the scope as
    /// before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) live_worlds: Option<BTreeSet<ScopeId>>,
}

/// One deleted record's captured scope. Key: hex32 (entity id).
const TOMBSTONE_SCOPE: SideTable<HexId, DeletedRecordScope, Named> =
    SideTable::new(&side_table::FEDERATION_TOMBSTONE_SCOPE);

/// Whether the scope `id` held when a delete took it, whichever request the
/// capture is bound to, names a WORLD of the received foreign range: the
/// erased row was a foreign copy. Ids alone answer, never content; the
/// foreign-copy guards read it once the row is gone (L7-02).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn deleted_scope_names_foreign_world_in(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(TOMBSTONE_SCOPE
        .get(store, txn, &HexId(*id))?
        .is_some_and(|row| match &row.scope.worlds {
            oneiron_authority::federation::ScopeAxis::Some(worlds) => worlds
                .iter()
                .any(|world| crate::entity_id::is_foreign_world_id_range(world.0)),
            _ => false,
        }))
}

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
                let entity_type =
                    EntityMetadataHeader::parse(&raw).map(|header| header.entity_type);
                (
                    scope,
                    live_relationship_read(store, txn, id, &raw),
                    entity_type,
                    live_facet_stamps(store, txn, id, &raw),
                    live_carried_worlds(store, txn, id),
                    entity_type.and_then(|kind| live_worlds(store, txn, id, kind)),
                )
            })
        }
        None => None,
    };
    let row = match (captured, held) {
        (
            Some((scope, relationship_read, entity_type, facet_of, carried_worlds, live_worlds)),
            held,
        ) => DeletedRecordScope {
            scope,
            request: request.copied().or(held.and_then(|row| row.request)),
            relationship_read: Some(relationship_read),
            entity_type,
            facet_of,
            carried_worlds: Some(carried_worlds),
            live_worlds,
        },
        (None, Some(held)) => {
            if request.is_none() || request == held.request.as_ref() {
                return Ok(());
            }
            DeletedRecordScope {
                scope: held.scope,
                request: request.copied(),
                relationship_read: held.relationship_read,
                entity_type: held.entity_type,
                facet_of: held.facet_of,
                carried_worlds: held.carried_worlds,
                live_worlds: held.live_worlds,
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

/// The worlds whose words the live row `id` carries, its sources' among them
/// ([`crate::settings::carried_worlds_in`]). A read that fails names no
/// world: unknown, so the tombstone stays home while any world is flagged,
/// and the capture still lands.
fn live_carried_worlds(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> CarriedWorlds {
    crate::settings::carried_worlds_in(store, txn, id).unwrap_or_else(|error| {
        tracing::warn!(
            %error,
            entity = %id.to_hex(),
            "deleted record's worlds not captured; its tombstone stays home while any world is device-only"
        );
        CarriedWorlds {
            worlds: BTreeSet::new(),
            unknown: true,
        }
    })
}

/// Every world the live row `id` of `kind` sits in when its kind takes its
/// worlds from live edges ([`note_world::note_worlds_of`]), base reality by
/// its own id. `None` for any other kind, and where its edges did not read:
/// the captured scope's world axis then says every world, which holds it as
/// before.
fn live_worlds(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    kind: u8,
) -> Option<BTreeSet<ScopeId>> {
    match note_world::note_worlds_of(store, txn, *id, kind)? {
        note_world::NoteWorlds::In(worlds) => Some(worlds),
        note_world::NoteWorlds::NoSingleWorld => None,
    }
}

fn warn_uncaptured(id: &EntityId, error: &Error) {
    tracing::warn!(
        %error,
        entity = %id.to_hex(),
        "deleted record's scope not captured; its tombstone stays off narrower grants"
    );
}
