//! The scope a deleted record held, kept as content-free evidence bound to its
//! delete request, so a selector export can carry the tombstone to a grant
//! that reads that scope once the row is gone (FIX 10161).
//!
//! A capture never fails, delays or rolls back the delete it runs in: an error
//! is logged, and the tombstone is then not exported to a narrower grant.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::RelationshipRead;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, HexId, Named, SideTable};
use crate::store::{ManifestDbs, Store};
use oneiron_authority::federation::Scope;

#[cfg(feature = "sync")]
use super::tombstone::TombstoneValueV2;
use super::tombstone::decode_tombstone_value;

/// The scope one deleted record held, and the delete request it is bound to.
/// Ids and levels only (worlds, facets, bands, audience, verbs, sensitivity),
/// never content.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeletedRecordScope {
    /// `None` for a row the record-scope rules do not place: one born without
    /// its same-transaction FacetOf, or a local put of a replicated row, so it
    /// has no stamp. Such a row is captured for its relationship read alone
    /// (OPUS-LEAKS, SELECTOR-TOMBSTONE-UNSCOPED-ROW-NO-CAPTURE), and a
    /// narrower grant takes its tombstone no more than before (FIX 10161).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) scope: Option<Scope>,
    pub(crate) request: Option<[u8; 16]>,
    /// The relationship read the record's labels gave it: its kind, the
    /// relationships it was scoped to, whether it was private, and its record
    /// position (OPUS-LEAKS, SELECTOR-TOMBSTONE-LABEL). A selector's member
    /// takes the tombstone only where this read admits it. A capture written
    /// before the field existed has none, and its tombstone travels as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) relationship_read: Option<RelationshipRead>,
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

/// The scope `id` held when delete `request` took it. Only a row bound to that
/// request answers, and only with a scope: a row captured with none answers
/// as no row does.
pub(crate) fn deleted_scope_in(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    request: &[u8; 16],
) -> Result<Option<Scope>> {
    Ok(TOMBSTONE_SCOPE
        .get(store, txn, &HexId(*id))?
        .filter(|row| row.request.as_ref() == Some(request))
        .and_then(|row| row.scope))
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
    Ok(TOMBSTONE_SCOPE
        .get(store, txn, &HexId(*id))?
        .filter(|row| row.request.as_ref() == Some(request))
        .map(|row| row.relationship_read))
}

/// A live row with a scope has its scope and its relationship read written.
/// Otherwise a held row is rebound to `request` whenever `request` is some and
/// differs from the row's, and nothing else changes: with no live row (none,
/// or a deleted shell), or with a live row whose stamp is gone, the held read
/// was taken from the stamped row. A live row with no scope and no held row
/// has its relationship read written alone (OPUS-LEAKS,
/// SELECTOR-TOMBSTONE-UNSCOPED-ROW-NO-CAPTURE): an unstamped row the
/// relationship gate withholds keeps its tombstone off the same members.
fn capture_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    request: Option<&[u8; 16]>,
) -> Result<()> {
    #[cfg(oneiron_test_support)]
    if failing_capture(id) {
        return Err(Error::CorruptedIndex("tombstone capture fault (test door)"));
    }
    let key = HexId(*id);
    let held = TOMBSTONE_SCOPE.get(store, txn, &key)?;
    let live = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
        .filter(|raw| raw.len() > ENTITY_METADATA_HEADER_LEN);
    let live_scope = match &live {
        Some(raw) => crate::federation::record_scope::scope_for_blob(store, txn, *id, raw)?,
        None => None,
    };
    let row = match (live, live_scope, held) {
        (Some(raw), Some(scope), held) => DeletedRecordScope {
            scope: Some(scope),
            request: request.copied().or(held.and_then(|row| row.request)),
            relationship_read: Some(live_relationship_read(store, txn, id, &raw)),
        },
        (_, _, Some(held)) => {
            if request.is_none() || request == held.request.as_ref() {
                return Ok(());
            }
            DeletedRecordScope {
                request: request.copied(),
                ..held
            }
        }
        (Some(raw), None, None) => DeletedRecordScope {
            scope: None,
            request: request.copied(),
            relationship_read: Some(live_relationship_read(store, txn, id, &raw)),
        },
        (None, _, None) => return Ok(()),
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

fn warn_uncaptured(id: &EntityId, error: &Error) {
    tracing::warn!(
        %error,
        entity = %id.to_hex(),
        "deleted record's scope not captured; its tombstone stays off narrower grants"
    );
}

/// The rows whose every capture fails, for the test door
/// `test_doors::label_writers::fail_tombstone_captures_of`.
#[cfg(oneiron_test_support)]
static FAILING_CAPTURES: std::sync::Mutex<Vec<EntityId>> = std::sync::Mutex::new(Vec::new());

/// Makes every later capture of `id` fail before it reads the row, as a
/// store read that errors would.
#[cfg(oneiron_test_support)]
pub(crate) fn fail_captures_of(id: EntityId) {
    FAILING_CAPTURES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(id);
}

#[cfg(oneiron_test_support)]
fn failing_capture(id: &EntityId) -> bool {
    FAILING_CAPTURES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(id)
}
