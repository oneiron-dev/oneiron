//! The MACHINE rows by the endpoint key their mesh address names
//! (ARCH-0044 H336, census L3-28B). A lookup by endpoint key used to read
//! every MACHINE row's body, so the lookup any endpoint key can make refused
//! once the vault held more than [`super::MAX_LOOKUP_MACHINES`] of them, and
//! the owner's bind read them all. This derived index names, per endpoint
//! key, the MACHINE rows whose body is a valid address envelope for it.
//!
//! It is a prefilter only: every hit is re-read in the caller's snapshot,
//! and any doubt (flag unset, a read error, a hit the MACHINE type index
//! does not hold) falls back to the walk in [`super`], which answers (or
//! errors) exactly as it does today. Every entity body write passes the
//! body stage (`batch::put_apply::stage_entity_body_row`), which moves the
//! row's key here, and every entity row removal drops it. A key a path left
//! behind by rewriting a body in place (a scrub to a shell) re-reads as no
//! address for that key and is skipped, as the walk skips that row.

use super::{MeshMachineAddress, invalid_authority, parse_address};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::side_table::{self, Raw, SideTable};
use crate::store::{ManifestDbs, Store};

/// Keys are `(endpoint key, MACHINE id)`; the value is an empty marker.
const ENDPOINT_INDEX: SideTable<([u8; 32], EntityId), (), Raw> =
    SideTable::new(&side_table::AUTHORITY_MESH_MACHINE_ENDPOINT_INDEX);

/// `Some(1)` once a whole rebuild of the index has committed.
const INDEX_STATE: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::AUTHORITY_MESH_MACHINE_ENDPOINT_INDEX_STATE);

const INDEX_VERSION: u64 = 1;

fn index_complete_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> bool {
    matches!(INDEX_STATE.get(store, txn, &()), Ok(Some(INDEX_VERSION)))
}

/// The endpoint key a `kind` row holding `body` is indexed under: only a
/// MACHINE row whose body is a valid address envelope has one.
fn indexed_endpoint_key(kind: u8, body: &[u8]) -> Option<[u8; 32]> {
    if kind != ENTITY_TYPE_MACHINE {
        return None;
    }
    parse_address(body).map(|address| address.endpoint_key)
}

/// Moves entity `id`'s index key from its stored row to `replacement` (the
/// kind and body about to be stored), in the writing transaction; `None`
/// removes the row. Runs before the row itself is written or removed, as
/// the identity hint and named-entity indexes beside it do.
///
/// # Errors
///
/// The `entities` read's and the index write's own store errors.
pub(crate) fn reindex_mesh_machine_endpoint(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    replacement: Option<(u8, &[u8])>,
) -> Result<()> {
    let prior = store.entities().get(txn, id.as_bytes())?.and_then(|raw| {
        let header = EntityMetadataHeader::parse(raw)?;
        indexed_endpoint_key(header.entity_type, raw.get(ENTITY_METADATA_HEADER_LEN..)?)
    });
    let next = replacement.and_then(|(kind, body)| indexed_endpoint_key(kind, body));
    if let Some(key) = prior
        && prior != next
    {
        ENDPOINT_INDEX.delete(store, txn, &(key, *id))?;
    }
    if let Some(key) = next {
        ENDPOINT_INDEX.put(store, txn, &(key, *id), &())?;
    }
    Ok(())
}

impl Vault {
    /// Rebuilds the endpoint index from the MACHINE rows when it is missing
    /// or stale, in one write transaction (a crash leaves nothing or
    /// everything). Runs at writable open and after a checkpoint restore
    /// (`force`); a complete index is left alone.
    ///
    /// # Errors
    ///
    /// At open (`force` false) none: a failed rebuild of this Derived index
    /// never refuses the open; the flag stays unset and the lookups keep the
    /// walk. The restore rebuild (`force`) propagates its store errors like
    /// its sibling backfills.
    pub(crate) fn backfill_mesh_machine_endpoint_index(&self, force: bool) -> Result<()> {
        match self.rebuild_mesh_machine_endpoint_index(force) {
            Err(error) if !force => {
                tracing::warn!(
                    %error,
                    "mesh machine endpoint index rebuild failed; endpoint lookups keep the walk"
                );
                Ok(())
            }
            other => other,
        }
    }

    fn rebuild_mesh_machine_endpoint_index(&self, force: bool) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if !force && index_complete_in_txn(&self.store, &wtxn) {
            return Ok(());
        }
        let ids = EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            &wtxn,
            ENTITY_TYPE_MACHINE,
            None,
        )?
        .collect::<Result<Vec<_>>>()?;
        let mut keys = Vec::new();
        for id in ids {
            let Some(row) = EntityStoreRead::port_entity_record(&self.store, &wtxn, &id)? else {
                continue;
            };
            if let Some(key) = indexed_endpoint_key(row.entity_type, &row.body) {
                keys.push((key, id));
            }
        }
        ENDPOINT_INDEX.delete_from(&self.store, &mut wtxn, &[])?;
        for key in &keys {
            ENDPOINT_INDEX.put(&self.store, &mut wtxn, key, &())?;
        }
        INDEX_STATE.put(&self.store, &mut wtxn, &(), &INDEX_VERSION)?;
        wtxn.commit()?;
        Ok(())
    }
}

/// The MACHINE whose address names endpoint `key`, from the index when it
/// is complete, re-read in `txn`: `Some(Ok(None))` when no MACHINE names
/// it, `Some(Err(..))` when two do (the walk's refusal). `None` means any
/// doubt at all: the caller walks every MACHINE row.
pub(super) fn indexed_machine_by_endpoint_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: [u8; 32],
) -> Option<Result<Option<(EntityId, MeshMachineAddress)>>> {
    if !index_complete_in_txn(&vault.store, txn) {
        return None;
    }
    let keys = ENDPOINT_INDEX.scan_keys(&vault.store, txn, &key).ok()?;
    let mut found = None;
    for (indexed_key, id) in keys {
        if indexed_key != key {
            return None;
        }
        // The walk reads the MACHINE type index: a hit it does not hold is
        // doubt, never an answer the walk would not give.
        if !EntityStoreRead::port_entity_type_indexed(&vault.store, txn, ENTITY_TYPE_MACHINE, &id)
            .ok()?
        {
            return None;
        }
        let Some(address) = vault.mesh_machine_in_txn(txn, id).ok()? else {
            continue;
        };
        if address.endpoint_key != key {
            continue;
        }
        if found.is_some() {
            return Some(Err(invalid_authority()));
        }
        found = Some((id, address));
    }
    Some(Ok(found))
}

/// The door `authority::tests::machine_identity` and
/// `tests/mesh_machine_endpoint_index.rs` both use.
#[cfg(any(test, oneiron_test_support))]
impl Vault {
    /// Drops the index and its completeness flag, as a vault older than the
    /// index holds them, so the lookups walk until the next open rebuilds it.
    pub(crate) fn drop_mesh_machine_endpoint_index_for_test(&self) -> Result<()> {
        self.with_write_txn(|wtxn| {
            ENDPOINT_INDEX.delete_from(&self.store, wtxn, &[])?;
            INDEX_STATE.delete(&self.store, wtxn, &())?;
            Ok(())
        })
    }
}

/// Doors for `tests/mesh_machine_endpoint_index.rs`.
#[cfg(oneiron_test_support)]
impl Vault {
    /// Whether the index is complete.
    pub(crate) fn mesh_machine_endpoint_index_complete_for_test(&self) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(index_complete_in_txn(&self.store, &rtxn))
    }

    /// The MACHINE naming endpoint `key` as the index answers: `None` when
    /// the lookup would fall back to the walk.
    pub(crate) fn indexed_mesh_machine_by_endpoint_for_test(
        &self,
        key: [u8; 32],
    ) -> Result<Option<Result<Option<EntityId>>>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(indexed_machine_by_endpoint_in_txn(self, &rtxn, key)
            .map(|answer| answer.map(|found| found.map(|(id, _)| id))))
    }

    /// The MACHINE naming endpoint `key` as the walk of every MACHINE row
    /// answers, bounded as a stranger's lookup is.
    pub(crate) fn walked_mesh_machine_by_endpoint_for_test(
        &self,
        key: [u8; 32],
    ) -> Result<Option<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(self
            .walk_machines_by_endpoint_in_txn(&rtxn, key, None)?
            .map(|(id, _)| id))
    }
}
