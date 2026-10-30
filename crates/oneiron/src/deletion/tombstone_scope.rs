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
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::Scope;
use crate::side_table::{self, HexId, Named, SideTable};
use crate::store::ManifestDbs;

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
    if let Err(error) = capture_in_txn(vault, txn, id, request) {
        warn_uncaptured(id, &error);
    }
}

/// [`capture_deleted_scope_in_txn`] in a writer of its own, for the publish
/// path, which holds no transaction where it captures.
#[cfg(feature = "sync")]
pub(crate) fn capture_deleted_scope(vault: &Vault, id: &EntityId, tombstone: &TombstoneValueV2) {
    let request = Some(&tombstone.request_id);
    if let Err(error) = vault.with_write_txn_grouped(|txn| capture_in_txn(vault, txn, id, request))
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
        vault.with_write_txn_grouped(|txn| capture_in_txn(vault, txn, id, request.as_ref()))
    {
        warn_uncaptured(id, &error);
    }
}

/// The scope `id` held when delete `request` took it. Only a row bound to that
/// request answers.
pub(crate) fn deleted_scope_in(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    request: &[u8; 16],
) -> Result<Option<Scope>> {
    Ok(TOMBSTONE_SCOPE
        .get(store, txn, &HexId(*id))?
        .filter(|row| row.request.as_ref() == Some(request))
        .map(|row| row.scope))
}

/// A live row's scope is written. With no live row (none, or a deleted
/// shell), a held row is rebound to `request` whenever `request` is some and
/// differs from the row's; nothing else changes.
fn capture_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    request: Option<&[u8; 16]>,
) -> Result<()> {
    let key = HexId(*id);
    let held = TOMBSTONE_SCOPE.get(&vault.store, txn, &key)?;
    let live = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
        .filter(|raw| raw.len() > ENTITY_METADATA_HEADER_LEN);
    let scope = match live {
        Some(raw) => crate::federation::record_scope::scope_for_blob(&vault.store, txn, *id, &raw)?,
        None => None,
    };
    let row = match (scope, held) {
        (Some(scope), held) => DeletedRecordScope {
            scope,
            request: request.copied().or(held.and_then(|row| row.request)),
        },
        (None, Some(held)) => {
            if request.is_none() || request == held.request.as_ref() {
                return Ok(());
            }
            DeletedRecordScope {
                scope: held.scope,
                request: request.copied(),
            }
        }
        (None, None) => return Ok(()),
    };
    TOMBSTONE_SCOPE.put(&vault.store, txn, &key, &row)
}

fn warn_uncaptured(id: &EntityId, error: &Error) {
    tracing::warn!(
        %error,
        entity = %id.to_hex(),
        "deleted record's scope not captured; its tombstone stays off narrower grants"
    );
}
