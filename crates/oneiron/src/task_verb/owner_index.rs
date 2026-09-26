//! Shared derived tasks-by-owner index for inbox and saved plan queries.
//! The replicated authority facts remain truth. Every read rechecks their
//! live ScopedTo witness, so a deleted edge or fork cannot grant ownership.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::side_table::{self, SideKey, SideTable};
use crate::store::Store;
use crate::task_authority::{TaskAuthorityFactKind, decode_task_authority_fact_body};
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

/// Owner's tasks forward index: `(owner, task, fact id) -> ()`.
const FORWARD: SideTable<(EntityId, EntityId, EntityId), (), side_table::Raw> =
    SideTable::new(&side_table::TASK_BY_OWNER_FORWARD);
/// Owner-authority fact to forward-index key: `fact id -> the forward row's
/// full stored key bytes`, so a fact's retraction can delete its forward row
/// without recomputing it from a stale body.
const REVERSE: SideTable<EntityId, Vec<u8>, side_table::Raw> =
    SideTable::new(&side_table::TASK_OWNER_FACT_REVERSE);
const BACKFILLED: SideTable<(), [u8; 1], side_table::Raw> =
    SideTable::new(&side_table::TASK_BY_OWNER_BACKFILLED);

pub(crate) fn index_owner_fact(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: Option<&[u8]>,
) -> Result<()> {
    if let Some(old) = REVERSE.get(store, txn, id)? {
        let suffix = old
            .get(FORWARD.decl().prefix.len()..)
            .ok_or(Error::CorruptedIndex("tasks by owner reverse index"))?;
        let forward_key = <(EntityId, EntityId, EntityId)>::decode_key(suffix)
            .ok_or(Error::CorruptedIndex("tasks by owner reverse index"))?;
        FORWARD.delete(store, txn, &forward_key)?;
        REVERSE.delete(store, txn, id)?;
    }
    let Some(body) = body else {
        return Ok(());
    };
    if crate::habit::task_role_from_body_bytes(body)? != crate::habit::TaskRole::AuthorityFact {
        return Ok(());
    }
    // AuthorityFact is a shared role byte: it also carries C02 ask group,
    // member and answer rows. Only the canonical authority-fact subkind feeds
    // the by-owner index; other subkinds are not authority facts.
    if !task_body_has_subkind(body, crate::task_authority::TASK_AUTHORITY_FACT_SUBKIND)? {
        return Ok(());
    }
    let fact = decode_task_authority_fact_body(body)?;
    if fact.kind == TaskAuthorityFactKind::Owner {
        let forward_key = (fact.actor_ref, fact.task_ref, *id);
        FORWARD.put(store, txn, &forward_key, &())?;
        REVERSE.put(store, txn, id, &FORWARD.key_bytes(&forward_key))?;
    }
    Ok(())
}

/// True when the body's `subkind` key equals `want`. Reads the exact key set
/// with the same strict map decode the role check uses; a missing or
/// duplicated subkind key is not a match, never an error.
fn task_body_has_subkind(body: &[u8], want: &str) -> Result<bool> {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        crate::error::Error::Record(crate::error::RecordError::InvalidTaskBody(
            "body is not valid MessagePack",
        ))
    })?;
    if !cursor.is_empty() {
        return Err(crate::error::Error::Record(
            crate::error::RecordError::InvalidTaskBody("trailing bytes after body map"),
        ));
    }
    let Some(entries) = value.as_map() else {
        return Err(crate::error::Error::Record(
            crate::error::RecordError::InvalidTaskBody("body must be a MessagePack map"),
        ));
    };
    let mut seen = None;
    for (key, val) in entries {
        if key.as_str() != Some("subkind") {
            continue;
        }
        if seen.is_some() {
            return Ok(false);
        }
        seen = Some(val);
    }
    Ok(seen.is_some_and(|val| val.as_str() == Some(want)))
}

impl Vault {
    /// One-time backfill for vaults with pre-index TASK authority facts.
    /// Normal writes, imports and replay maintain this at the storage door.
    pub fn backfill_tasks_by_owner(&self) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        if BACKFILLED.get(&self.store, &txn, &())?.is_some() {
            return Ok(());
        }
        drop(txn);
        self.with_write_txn(|txn| {
            if BACKFILLED.get(&self.store, txn, &())?.is_some() {
                return Ok(());
            }
            let rows = self
                .store
                .entities
                .iter(txn)?
                .filter_map(|entry| match entry {
                    Err(e) => Some(Err(e)),
                    Ok((id, raw)) if raw.first() == Some(&crate::registry::ENTITY_TYPE_TASK) => {
                        Some(Ok((id.to_vec(), raw.to_vec())))
                    }
                    _ => None,
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            for (id, raw) in rows {
                let id = EntityId::from_bytes(
                    id.as_slice()
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("task id"))?,
                )?;
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("task header"))?;
                index_owner_fact(
                    &self.store,
                    txn,
                    &id,
                    Some(&raw[ENTITY_METADATA_HEADER_LEN..]),
                )?;
            }
            BACKFILLED.put(&self.store, txn, &(), &[1])?;
            Ok(())
        })
    }

    /// Exact, sorted membership. An archive stays addressable but leaves the
    /// working-set query. `after` is an exclusive entity-id cursor.
    pub fn tasks_by_owner(
        &self,
        owner: EntityId,
        after: Option<EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>> {
        self.backfill_tasks_by_owner()?;
        let txn = self.store.env.read_txn()?;
        let mut tasks = BTreeSet::new();
        for entry in FORWARD.iter_from(&self.store, &txn, owner.as_bytes())? {
            let ((_, task, _), ()) = entry?;
            if after.is_some_and(|after| task <= after) || tasks.contains(&task) {
                continue;
            }
            if self.get_entity_type_in_txn(&txn, &task)? == Some(crate::registry::ENTITY_TYPE_TASK)
                && !crate::vault_cleanup::is_archived_in_txn(&self.store, &txn, &task)?
                && self
                    .task_authority_state_in(&txn, task)?
                    .is_some_and(|state| state.owner_ref == owner)
            {
                tasks.insert(task);
            }
            if tasks.len() >= limit {
                break;
            }
        }
        Ok(tasks.into_iter().take(limit).collect())
    }

    /// Per-entity reader of the same index for a saved-query evidence hash.
    pub fn indexed_task_owner(&self, task: EntityId) -> Result<Option<EntityId>> {
        self.backfill_tasks_by_owner()?;
        let txn = self.store.env.read_txn()?;
        if self.get_entity_type_in_txn(&txn, &task)? != Some(crate::registry::ENTITY_TYPE_TASK)
            || crate::vault_cleanup::is_archived_in_txn(&self.store, &txn, &task)?
        {
            return Ok(None);
        }
        let Some(state) = self.task_authority_state_in(&txn, task)? else {
            return Ok(None);
        };
        let mut prefix = state.owner_ref.as_bytes().to_vec();
        prefix.extend_from_slice(task.as_bytes());
        Ok(FORWARD
            .iter_from(&self.store, &txn, &prefix)?
            .next()
            .transpose()?
            .map(|_| state.owner_ref))
    }
}
