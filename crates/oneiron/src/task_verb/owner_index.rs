//! Shared derived tasks-by-owner index for inbox and saved plan queries.
//! The replicated authority facts remain truth. Every read rechecks their
//! live ScopedTo witness, so a deleted edge or fork cannot grant ownership.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::task_authority::{TaskAuthorityFactKind, decode_task_authority_fact_body};
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

const FORWARD: &[u8] = b"tasks.by_owner.v1/";
const REVERSE: &[u8] = b"tasks.owner_fact.v1/";
const BACKFILLED: &[u8] = b"tasks.by_owner.backfilled.v1";

pub(crate) fn index_owner_fact(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: Option<&[u8]>,
) -> Result<()> {
    let reverse = [REVERSE, id.as_bytes()].concat();
    if let Some(old) = store.vault_meta.get(txn, &reverse)?.map(|v| v.to_vec()) {
        store.vault_meta.delete(txn, &old)?;
        store.vault_meta.delete(txn, &reverse)?;
    }
    let Some(body) = body else {
        return Ok(());
    };
    if crate::habit::task_role_from_body_bytes(body)? != crate::habit::TaskRole::AuthorityFact {
        return Ok(());
    }
    let fact = decode_task_authority_fact_body(body)?;
    if fact.kind == TaskAuthorityFactKind::Owner {
        let key = [
            FORWARD,
            fact.actor_ref.as_bytes(),
            fact.task_ref.as_bytes(),
            id.as_bytes(),
        ]
        .concat();
        store.vault_meta.put(txn, &key, &[])?;
        store.vault_meta.put(txn, &reverse, &key)?;
    }
    Ok(())
}

impl Vault {
    /// One-time backfill for vaults with pre-index TASK authority facts.
    /// Normal writes, imports and replay maintain this at the storage door.
    pub fn backfill_tasks_by_owner(&self) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        if self.store.vault_meta.get(&txn, BACKFILLED)?.is_some() {
            return Ok(());
        }
        drop(txn);
        self.with_write_txn(|txn| {
            if self.store.vault_meta.get(txn, BACKFILLED)?.is_some() {
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
            self.store.vault_meta.put(txn, BACKFILLED, &[1])?;
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
        let prefix = [FORWARD, owner.as_bytes()].concat();
        let mut tasks = BTreeSet::new();
        for entry in self.store.vault_meta.prefix_iter(&txn, &prefix)? {
            let (key, _) = entry?;
            let id = key
                .get(prefix.len()..prefix.len() + 16)
                .ok_or(Error::CorruptedIndex("tasks by owner"))?;
            let task = EntityId::from_bytes(
                id.try_into()
                    .map_err(|_| Error::CorruptedIndex("tasks by owner"))?,
            )?;
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
        let prefix = [FORWARD, state.owner_ref.as_bytes(), task.as_bytes()].concat();
        Ok(self
            .store
            .vault_meta
            .prefix_iter(&txn, &prefix)?
            .next()
            .transpose()?
            .map(|_| state.owner_ref))
    }
}
