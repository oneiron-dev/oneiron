//! LMDB audit, dependency, content-addressed blob and queue adapters.
use super::*;
use crate::attempt_queue::*;
use crate::blob_artifact::{
    blob_artifact_asset_entity_id, blob_artifact_asset_ref_key, blob_artifact_asset_ref_prefix,
};
use crate::deletion::DeleteReason;
use crate::error::{Error, Result};
use crate::{EntityId, TimeRange, Vault};
use heed::{RoTxn, RwTxn};
impl DependencyIndex for Vault {
    fn port_dependency_put(
        &self,
        txn: &mut RwTxn<'_>,
        source: SourceSpan,
        dependent: &EntityId,
    ) -> Result<()> {
        record_dependency_in_txn(&self.store, txn, source, dependent)
    }
    fn port_dependency_list_by_source(
        &self,
        txn: &RoTxn<'_>,
        source: SourceSpan,
    ) -> Result<Vec<EntityId>> {
        super::integrity::list_by_source(&self.store, txn, source)
    }
}
const CHANGE: &[u8] = b"ports:change:v1:";
const BY_ENTITY: &[u8] = b"ports:change_entity:v1:";
const BY_ACTOR: &[u8] = b"ports:change_actor:v1:";
impl ChangeLogStore for Vault {
    fn port_changelog_append(&self, txn: &mut RwTxn<'_>, record: &ChangeLogRecord) -> Result<()> {
        let key = [CHANGE, &record.id].concat();
        let bytes = rmp_serde::to_vec_named(record)
            .map_err(|_| Error::InvariantViolation("changelog encode"))?;
        if let Some(prior) = self.store.vault_meta.get(txn, &key)? {
            if prior.as_ref() != bytes.as_slice() {
                return Err(Error::InvariantViolation("changelog rows are immutable"));
            }
            return Ok(());
        }
        self.store.vault_meta.put(txn, &key, &bytes)?;
        for (family, owner) in [
            (BY_ENTITY, record.entity),
            (BY_ACTOR, record.actor_principal),
        ] {
            let index = [
                family,
                owner.as_bytes(),
                &record.recorded_at.to_be_bytes(),
                &record.id,
            ]
            .concat();
            self.store.vault_meta.put(txn, &index, &record.id)?;
        }
        Ok(())
    }
    fn port_changelog_list_by_entity(
        &self,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        limit: usize,
    ) -> Result<Vec<ChangeLogRecord>> {
        list_changes(self, txn, BY_ENTITY, entity, limit)
    }
    fn port_changelog_list_by_actor(
        &self,
        txn: &RoTxn<'_>,
        actor: &EntityId,
        limit: usize,
    ) -> Result<Vec<ChangeLogRecord>> {
        list_changes(self, txn, BY_ACTOR, actor, limit)
    }
}
fn list_changes(
    vault: &Vault,
    txn: &RoTxn<'_>,
    family: &[u8],
    owner: &EntityId,
    limit: usize,
) -> Result<Vec<ChangeLogRecord>> {
    let prefix = [family, owner.as_bytes()].concat();
    let mut result = Vec::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(txn, &prefix)?
        .take(limit.min(100_000))
    {
        let (_, id) = row?;
        if id.len() != 16 {
            return Err(Error::CorruptedIndex("changelog index id"));
        }
        let key = [CHANGE, id.as_ref()].concat();
        let raw = vault
            .store
            .vault_meta
            .get(txn, &key)?
            .ok_or(Error::CorruptedIndex("changelog index"))?;
        result.push(
            rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex("changelog record"))?,
        );
    }
    Ok(result)
}
impl BlobStore for Vault {
    fn port_blob_put(
        &self,
        txn: &mut RwTxn<'_>,
        reference: &EntityId,
        bytes: &[u8],
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<[u8; 32]> {
        let hash = *blake3::hash(bytes).as_bytes();
        let id = blob_artifact_asset_entity_id(&hash)?;
        if id == *reference {
            return Err(Error::InvariantViolation("blob cannot reference itself"));
        }
        self.port_entity_put(
            txn,
            &id,
            &EntityRecord {
                entity_type: crate::registry::ENTITY_TYPE_ASSET,
                occurred,
                learned_at,
                body: bytes.to_vec(),
            },
        )?;
        self.store
            .vault_meta
            .put(txn, &blob_artifact_asset_ref_key(&hash, reference), &[])?;
        Ok(hash)
    }
    fn port_blob_get(&self, txn: &RoTxn<'_>, hash: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let id = blob_artifact_asset_entity_id(hash)?;
        let Some(row) = self.port_entity_get(txn, &id)? else {
            return Ok(None);
        };
        if row.entity_type != crate::registry::ENTITY_TYPE_ASSET
            || blake3::hash(&row.body).as_bytes() != hash
        {
            return Err(Error::CorruptedIndex("blob content hash"));
        }
        Ok(Some(row.body))
    }
    fn port_blob_delete(
        &self,
        txn: &mut RwTxn<'_>,
        reference: &EntityId,
        hash: &[u8; 32],
        reason: DeleteReason,
    ) -> Result<bool> {
        let prefix = blob_artifact_asset_ref_prefix(hash);
        let hard = matches!(
            reason,
            DeleteReason::UserHardDelete | DeleteReason::GdprDelete | DeleteReason::PolicyDelete
        );
        if hard {
            let keys = self
                .store
                .vault_meta
                .prefix_iter(txn, &prefix)?
                .map(|row| row.map(|(key, _)| key.to_vec()))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let mut references = Vec::new();
            for key in keys {
                if key.len() != prefix.len() + 16 {
                    return Err(Error::CorruptedIndex("blob reference key"));
                }
                references.push(EntityId::from_bytes(
                    key[prefix.len()..]
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("blob reference"))?,
                )?);
                self.store.vault_meta.delete(txn, &key)?;
            }
            for reference in references {
                self.port_entity_delete(txn, &reference)?;
            }
        } else {
            if !self
                .store
                .vault_meta
                .delete(txn, &blob_artifact_asset_ref_key(hash, reference))?
            {
                return Ok(false);
            }
            if self
                .store
                .vault_meta
                .prefix_iter(txn, &prefix)?
                .next()
                .transpose()?
                .is_some()
            {
                return Ok(false);
            }
        }
        self.port_entity_delete(txn, &blob_artifact_asset_entity_id(hash)?)
    }
}
impl JobQueue for Vault {
    fn port_job_enqueue(
        &self,
        txn: &mut RwTxn<'_>,
        input: EnqueueAttempt,
    ) -> Result<EnqueueOutcome> {
        AttemptQueue::new(self).port_job_enqueue(txn, input)
    }
    fn port_job_claim(
        &self,
        txn: &mut RwTxn<'_>,
        kind: Option<&str>,
        input: ClaimAttempt,
    ) -> Result<ClaimOutcome> {
        AttemptQueue::new(self).port_job_claim(txn, kind, input)
    }
    fn port_job_complete(
        &self,
        txn: &mut RwTxn<'_>,
        input: CompleteAttempt,
    ) -> Result<CompleteOutcome> {
        AttemptQueue::new(self).port_job_complete(txn, input)
    }
    fn port_job_fail(&self, txn: &mut RwTxn<'_>, input: FailAttempt) -> Result<FailOutcome> {
        AttemptQueue::new(self).port_job_fail(txn, input)
    }
}
