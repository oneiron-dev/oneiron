//! The companion profile grants by principal and PERSON (ARCH-0044 H424,
//! census L3-28E). The companion grant reads (the persona list, the
//! profile admission and the gate's grant lookup) used to read every
//! ACCESS_GRANT row of the vault to find the few that name one principal
//! and one PERSON. This derived index names, per (principal, PERSON), the
//! ACCESS_GRANT rows whose body is a live grant of CompanionProfile scope,
//! whatever their status.
//!
//! It is a prefilter only: the reads run their own per-row checks on each
//! hit, in the grant id order the type index walk visits, so the first
//! grant that admits a read is the walk's first. Any doubt (flag unset, an
//! undecodable grant body stored anywhere, a read error, a hit the type
//! index does not hold) makes the reads walk every ACCESS_GRANT row, which
//! answers (or fails closed) exactly as it does today. Every entity body
//! write passes the body stage (`batch::put_apply::stage_entity_body_row`),
//! which moves the row's key here (an erased principal's inert history
//! too), every in-place scrub to a shell
//! (`EntityStoreMaintenance::port_entity_scrub`, which every erase runs)
//! drops it, and every entity row removal drops it.
//!
//! [`INDEX_VERSION`] is the decoder's version too: a change to what the
//! grant body decoder accepts bumps it, so the next open rebuilds the index
//! and its undecodable rows under the new decoder.

use super::decode_live_access_grant_body;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EntityStoreRead, PortRows};
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::side_table::{self, Raw, SideTable};
use crate::store::{ManifestDbs, Store};

/// Keys are `(principal, PERSON, grant)`; the value is an empty marker.
const GRANT_INDEX: SideTable<(EntityId, EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::ACCESS_GRANT_COMPANION_INDEX);

/// The ACCESS_GRANT ids whose stored body no grant decoder reads.
const UNDECODABLE: SideTable<EntityId, (), Raw> =
    SideTable::new(&side_table::ACCESS_GRANT_COMPANION_INDEX_UNDECODABLE);

/// `Some(INDEX_VERSION)` once a whole rebuild of the index has committed.
const INDEX_STATE: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::ACCESS_GRANT_COMPANION_INDEX_STATE);

const INDEX_VERSION: u64 = 1;

/// What the index holds for one stored row.
#[derive(Clone, Copy, PartialEq, Eq)]
enum IndexedRow {
    /// A live grant of CompanionProfile scope: its principal and PERSON.
    Companion {
        principal: EntityId,
        person: EntityId,
    },
    /// An ACCESS_GRANT body the walks fail closed on.
    Undecodable,
    /// Anything else: another kind, a shell, inert history, another scope.
    Outside,
}

/// The index entry of a `kind` row holding `body`. A header-only body is a
/// shell, which every walk skips while its row is deleted.
fn indexed_row(kind: u8, body: &[u8]) -> IndexedRow {
    if kind != ENTITY_TYPE_ACCESS_GRANT || body.is_empty() {
        return IndexedRow::Outside;
    }
    match decode_live_access_grant_body(body) {
        Ok(Some(grant)) => {
            grant
                .scope
                .companion_profile_refs()
                .map_or(IndexedRow::Outside, |(person, _)| IndexedRow::Companion {
                    principal: grant.principal_ref,
                    person,
                })
        }
        Ok(None) => IndexedRow::Outside,
        Err(_) => IndexedRow::Undecodable,
    }
}

fn index_complete_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> bool {
    matches!(INDEX_STATE.get(store, txn, &()), Ok(Some(INDEX_VERSION)))
}

/// Moves entity `id`'s index entry from its stored row to `replacement`
/// (the kind and body about to be stored), in the writing transaction;
/// `None` removes the row. Runs before the row itself is written or
/// removed, as the identity hint and named-entity indexes beside it do.
///
/// # Errors
///
/// The `entities` read's and the index write's own store errors.
pub(crate) fn reindex_companion_grant(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    replacement: Option<(u8, &[u8])>,
) -> Result<()> {
    let prior = EntityStoreRead::port_entity_raw_wiped(store, txn, id)?.map_or(
        IndexedRow::Outside,
        |raw| match EntityMetadataHeader::parse(&raw) {
            Some(header) => indexed_row(header.entity_type, &raw[ENTITY_METADATA_HEADER_LEN..]),
            None => IndexedRow::Outside,
        },
    );
    let next = replacement.map_or(IndexedRow::Outside, |(kind, body)| indexed_row(kind, body));
    if prior != next {
        match prior {
            IndexedRow::Companion { principal, person } => {
                GRANT_INDEX.delete(store, txn, &(principal, person, *id))?;
            }
            IndexedRow::Undecodable => {
                UNDECODABLE.delete(store, txn, id)?;
            }
            IndexedRow::Outside => {}
        }
    }
    match next {
        IndexedRow::Companion { principal, person } => {
            GRANT_INDEX.put(store, txn, &(principal, person, *id), &())?;
        }
        IndexedRow::Undecodable => {
            UNDECODABLE.put(store, txn, id, &())?;
        }
        IndexedRow::Outside => {}
    }
    Ok(())
}

impl Vault {
    /// Rebuilds the companion grant index from the ACCESS_GRANT rows when it
    /// is missing or stale, in one write transaction (a crash leaves nothing
    /// or everything). Runs at writable open and after a checkpoint restore
    /// (`force`); a complete index is left alone.
    ///
    /// # Errors
    ///
    /// At open (`force` false) none: a failed rebuild of this Derived index
    /// never refuses the open; the flag stays unset and the reads keep the
    /// walk. The restore rebuild (`force`) propagates its store errors like
    /// its sibling backfills.
    pub(crate) fn backfill_companion_grant_index(&self, force: bool) -> Result<()> {
        match self.rebuild_companion_grant_index(force) {
            Err(error) if !force => {
                tracing::warn!(
                    %error,
                    "companion grant index rebuild failed; companion grant reads keep the walk"
                );
                Ok(())
            }
            other => other,
        }
    }

    fn rebuild_companion_grant_index(&self, force: bool) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if !force && index_complete_in_txn(&self.store, &wtxn) {
            return Ok(());
        }
        let ids = EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            &wtxn,
            ENTITY_TYPE_ACCESS_GRANT,
            None,
        )?
        .collect::<Result<Vec<_>>>()?;
        let mut grants = Vec::new();
        let mut undecodable = Vec::new();
        for id in ids {
            let Some(row) = EntityStoreRead::port_entity_record(&self.store, &wtxn, &id)? else {
                continue;
            };
            match indexed_row(row.entity_type, &row.body) {
                IndexedRow::Companion { principal, person } => {
                    grants.push((principal, person, id));
                }
                IndexedRow::Undecodable => undecodable.push(id),
                IndexedRow::Outside => {}
            }
        }
        GRANT_INDEX.delete_from(&self.store, &mut wtxn, &[])?;
        UNDECODABLE.delete_from(&self.store, &mut wtxn, &[])?;
        for key in &grants {
            GRANT_INDEX.put(&self.store, &mut wtxn, key, &())?;
        }
        for id in &undecodable {
            UNDECODABLE.put(&self.store, &mut wtxn, id, &())?;
        }
        INDEX_STATE.put(&self.store, &mut wtxn, &(), &INDEX_VERSION)?;
        wtxn.commit()?;
        Ok(())
    }
}

/// The ACCESS_GRANT ids whose companion grant names `principal_ref` and
/// `person_ref`, in grant id order, when the index can answer for a walk
/// in `txn`. `None` means any doubt at all: the caller walks every
/// ACCESS_GRANT row.
fn indexed_companion_grant_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    principal_ref: &EntityId,
    person_ref: &EntityId,
) -> Option<Vec<EntityId>> {
    if !index_complete_in_txn(store, txn) {
        return None;
    }
    // The walks fail closed on an undecodable grant wherever it sits, so
    // while one is stored only a walk answers as they do.
    if UNDECODABLE
        .iter_from(store, txn, &[])
        .ok()?
        .next()
        .is_some()
    {
        return None;
    }
    let prefix = [
        principal_ref.as_bytes().as_slice(),
        person_ref.as_bytes().as_slice(),
    ]
    .concat();
    let keys = GRANT_INDEX.scan_keys(store, txn, &prefix).ok()?;
    let mut ids = Vec::with_capacity(keys.len());
    for (principal, person, id) in keys {
        if principal != *principal_ref || person != *person_ref {
            return None;
        }
        // The walk reads the ACCESS_GRANT type index: a hit it does not
        // hold is doubt, never an answer the walk would not give.
        if !EntityStoreRead::port_entity_type_indexed(store, txn, ENTITY_TYPE_ACCESS_GRANT, &id)
            .ok()?
        {
            return None;
        }
        ids.push(id);
    }
    Some(ids)
}

/// The ACCESS_GRANT ids a companion grant read for `principal_ref` and
/// `person_ref` visits in `txn`: the index's hits when it can answer, else
/// every ACCESS_GRANT id in the type index. Either way in grant id order,
/// so a read that takes the first grant that admits it takes the same one.
///
/// # Errors
///
/// The type index walk's own store error.
pub(crate) fn companion_grant_candidates_in_txn<'txn>(
    store: &Store,
    txn: &'txn heed::RoTxn<'_>,
    principal_ref: &EntityId,
    person_ref: &EntityId,
) -> Result<PortRows<'txn, EntityId>> {
    match indexed_companion_grant_ids_in_txn(store, txn, principal_ref, person_ref) {
        Some(ids) => Ok(Box::new(ids.into_iter().map(Ok))),
        None => store.port_entity_ids_by_type(txn, ENTITY_TYPE_ACCESS_GRANT, None),
    }
}

/// The door `scan_check::table_tests` and
/// `tests/companion_grant_index.rs` both use.
#[cfg(any(test, oneiron_test_support))]
impl Vault {
    /// Drops the index, its undecodable rows and its completeness flag, as
    /// a vault older than the index holds them, so the reads walk until the
    /// next open rebuilds it.
    pub(crate) fn drop_companion_grant_index_for_test(&self) -> Result<()> {
        self.with_write_txn(|wtxn| {
            GRANT_INDEX.delete_from(&self.store, wtxn, &[])?;
            UNDECODABLE.delete_from(&self.store, wtxn, &[])?;
            INDEX_STATE.delete(&self.store, wtxn, &())?;
            Ok(())
        })
    }
}

/// Doors for `tests/companion_grant_index.rs`.
#[cfg(oneiron_test_support)]
impl Vault {
    /// Whether the index is complete.
    pub(crate) fn companion_grant_index_complete_for_test(&self) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(index_complete_in_txn(&self.store, &rtxn))
    }

    /// Every `(principal, PERSON, grant)` row the index holds.
    pub(crate) fn companion_grant_index_rows_for_test(
        &self,
    ) -> Result<Vec<(EntityId, EntityId, EntityId)>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(GRANT_INDEX
            .scan(&self.store, &rtxn)?
            .into_iter()
            .map(|(key, ())| key)
            .collect())
    }

    /// The grant ids the index names for `principal_ref` and `person_ref`:
    /// `None` when the reads would walk instead.
    pub(crate) fn indexed_companion_grant_ids_for_test(
        &self,
        principal_ref: &EntityId,
        person_ref: &EntityId,
    ) -> Result<Option<Vec<EntityId>>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(indexed_companion_grant_ids_in_txn(
            &self.store,
            &rtxn,
            principal_ref,
            person_ref,
        ))
    }

    /// Stores `body` as the ACCESS_GRANT row `id` past the write door's
    /// validation, through the body stage's index writer and the staging
    /// ports, as a grant an earlier decoder wrote would sit: the reads then
    /// walk, and fail closed on it.
    pub(crate) fn put_undecodable_access_grant_for_test(
        &self,
        id: &EntityId,
        body: &[u8],
    ) -> Result<()> {
        let occurred = crate::temporal::TimeRange { start: 1, end: 1 };
        let row = crate::ports::EntityRecord {
            entity_type: ENTITY_TYPE_ACCESS_GRANT,
            occurred,
            learned_at: 1,
            row_version: 1,
            body: body.to_vec(),
        };
        self.with_write_txn(|wtxn| {
            reindex_companion_grant(
                &self.store,
                wtxn,
                id,
                Some((ENTITY_TYPE_ACCESS_GRANT, body)),
            )?;
            crate::ports::EntityStoreStaging::port_stage_entity_row(
                &self.store,
                wtxn,
                id,
                &row.encode(),
            )?;
            crate::batch::stage_entity_index_rows(
                &self.store,
                wtxn,
                id,
                ENTITY_TYPE_ACCESS_GRANT,
                occurred,
                1,
            )
        })
    }
}
