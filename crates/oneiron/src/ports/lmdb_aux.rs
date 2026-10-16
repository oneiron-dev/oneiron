//! LMDB audit, dependency, content-addressed blob and queue adapters.
use super::*;
use crate::attempt_queue::*;
use crate::blob_artifact::{
    blob_artifact_asset_entity_id, blob_artifact_asset_ref_key, blob_artifact_asset_ref_prefix,
};
use crate::deletion::DeleteReason;
use crate::error::{Error, Result};
use crate::side_table::{Named, SideTable};
use crate::{EntityId, TimeRange, Vault};
use heed::{RoTxn, RwTxn};
impl DependencyIndex for Vault {
    fn port_dependency_complete_regeneration(
        &self,
        txn: &mut RwTxn<'_>,
        dependent: &EntityId,
        regenerated_at: u64,
        sources: &[SourceSpan],
    ) -> Result<bool> {
        let cleared =
            super::regeneration::complete(&self.store, txn, dependent, regenerated_at, sources)?;
        // A stale mark ran the Dreamer's erase hook; the row it clears says
        // its words again, a publication of them.
        if cleared {
            crate::dreamer_wake::mark_on_publication_in_txn(&self.store, txn, dependent)?;
        }
        Ok(cleared)
    }

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
pub(crate) const CHANGE_LOG_KEY_PREFIX: &[u8] = b"ports:change:v1:";
const CHANGE: &[u8] = CHANGE_LOG_KEY_PREFIX;
const BY_ENTITY: &[u8] = b"ports:change_entity:v1:";
const BY_ACTOR: &[u8] = b"ports:change_actor:v1:";
impl ChangeLogStore for Vault {
    fn port_changelog_append(&self, txn: &mut RwTxn<'_>, record: &ChangeLogRecord) -> Result<()> {
        self.store.port_changelog_append(txn, record)
    }
    fn port_changelog_list_by_entity(
        &self,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        limit: usize,
    ) -> Result<Vec<ChangeLogRecord>> {
        self.store.port_changelog_list_by_entity(txn, entity, limit)
    }
    fn port_changelog_list_by_actor(
        &self,
        txn: &RoTxn<'_>,
        actor: &EntityId,
        limit: usize,
    ) -> Result<Vec<ChangeLogRecord>> {
        self.store.port_changelog_list_by_actor(txn, actor, limit)
    }
}
impl ChangeLogStore for crate::store::Store {
    fn port_changelog_append(&self, txn: &mut RwTxn<'_>, record: &ChangeLogRecord) -> Result<()> {
        recorded_at_in_txn(self, txn)?;
        let key = [CHANGE, &record.id].concat();
        let bytes = rmp_serde::to_vec_named(record)
            .map_err(|_| Error::InvariantViolation("changelog encode"))?;
        if let Some(prior) = self.vault_meta.get(txn, &key)? {
            if prior.as_ref() != bytes.as_slice() {
                return Err(Error::InvariantViolation("changelog rows are immutable"));
            }
            return Ok(());
        }
        self.vault_meta.put(txn, &key, &bytes)?;
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
            self.vault_meta.put(txn, &index, &record.id)?;
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
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    family: &[u8],
    owner: &EntityId,
    limit: usize,
) -> Result<Vec<ChangeLogRecord>> {
    let prefix = [family, owner.as_bytes()].concat();
    let mut result = Vec::new();
    for row in store
        .vault_meta
        .prefix_iter(txn, &prefix)?
        .take(limit.min(100_000))
    {
        let (_, id) = row?;
        if id.len() != 16 {
            return Err(Error::CorruptedIndex("changelog index id"));
        }
        let key = [CHANGE, id.as_ref()].concat();
        let raw = store
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
    fn port_job_enqueue_scoped(
        &self,
        txn: &mut RwTxn<'_>,
        input: EnqueueAttempt,
        scope: JobScope<'_>,
    ) -> Result<EnqueueOutcome> {
        AttemptQueue::new(self).port_job_enqueue_scoped(txn, input, scope)
    }
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
    fn port_job_claim_id(
        &self,
        txn: &mut RwTxn<'_>,
        id: crate::attempt_queue::AttemptId,
        input: ClaimAttempt,
    ) -> Result<ClaimOutcome> {
        AttemptQueue::new(self).port_job_claim_id(txn, id, input)
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
impl<T: crate::store::ManifestDbs> JobQueueRead for T {
    fn port_job_row(&self, txn: &RoTxn<'_>, id: &AttemptId) -> Result<Option<Vec<u8>>> {
        Ok(self
            .attempt_records()
            .get(txn, id.as_bytes())?
            .map(|raw| raw.to_vec()))
    }
    fn port_job_rows<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        after: Option<AttemptId>,
    ) -> Result<PortRows<'a, (AttemptId, Vec<u8>)>> {
        use std::ops::Bound;
        let after = after.map(|id| *id.as_bytes());
        let lower = after
            .as_ref()
            .map_or(Bound::Unbounded, |key| Bound::Excluded(key.as_slice()));
        let rows = self
            .attempt_records()
            .range(txn, &(lower, Bound::<&[u8]>::Unbounded))?;
        Ok(Box::new(rows.map(|row| {
            let (key, raw) = row?;
            Ok((AttemptId::from_bytes(&key)?, raw.to_vec()))
        })))
    }
}
impl JobQueueRead for Vault {
    fn port_job_row(&self, txn: &RoTxn<'_>, id: &AttemptId) -> Result<Option<Vec<u8>>> {
        self.store.port_job_row(txn, id)
    }
    fn port_job_rows<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        after: Option<AttemptId>,
    ) -> Result<PortRows<'a, (AttemptId, Vec<u8>)>> {
        self.store.port_job_rows(txn, after)
    }
}
const CHANGE_ROWS: SideTable<[u8; 16], ChangeLogRecord, Named> =
    SideTable::new(&crate::side_table::PORTS_CHANGE);
/// The change family's keys: its prefix, and the prefix with its final ':'
/// raised to ';', which bounds every id under it.
fn change_bounds() -> (&'static [u8], Vec<u8>) {
    let prefix = crate::side_table::PORTS_CHANGE.prefix;
    let mut end = prefix.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    (prefix, end)
}
/// One change row, failing with the side table's own key and codec errors.
fn change_row(key: &[u8], raw: &[u8]) -> Result<([u8; 16], ChangeLogRecord)> {
    let decl = &crate::side_table::PORTS_CHANGE;
    let bad_key = crate::error::SideTableRowProblem::KeyShape;
    let id = key
        .strip_prefix(decl.prefix)
        .and_then(|id| <[u8; 16]>::try_from(id).ok())
        .ok_or_else(|| decl.row_error(bad_key))?;
    Ok((id, CHANGE_ROWS.decode_value(raw)?))
}
impl<T: crate::store::ManifestDbs> ChangeLogStoreRead for T {
    fn port_changelog_after<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        after: Option<[u8; 16]>,
    ) -> Result<PortRows<'a, ([u8; 16], ChangeLogRecord)>> {
        use std::ops::Bound;
        let (prefix, end) = change_bounds();
        let start = match after {
            Some(id) => [prefix, &id].concat(),
            None => prefix.to_vec(),
        };
        let lower = if after.is_some() {
            Bound::Excluded(start.as_slice())
        } else {
            Bound::Included(start.as_slice())
        };
        let rows = self
            .vault_meta()
            .range(txn, &(lower, Bound::Excluded(end.as_slice())))?;
        Ok(Box::new(rows.map(|row| {
            let (key, raw) = row?;
            change_row(&key, &raw)
        })))
    }
    fn port_changelog_head(&self, txn: &RoTxn<'_>) -> Result<Option<([u8; 16], ChangeLogRecord)>> {
        use std::ops::Bound;
        let (prefix, end) = change_bounds();
        let range = (Bound::Included(prefix), Bound::Excluded(end.as_slice()));
        self.vault_meta()
            .rev_range(txn, &range)?
            .next()
            .map(|row| {
                let (key, raw) = row?;
                change_row(&key, &raw)
            })
            .transpose()
    }
}
impl ChangeLogStoreRead for Vault {
    fn port_changelog_after<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        after: Option<[u8; 16]>,
    ) -> Result<PortRows<'a, ([u8; 16], ChangeLogRecord)>> {
        self.store.port_changelog_after(txn, after)
    }
    fn port_changelog_head(&self, txn: &RoTxn<'_>) -> Result<Option<([u8; 16], ChangeLogRecord)>> {
        self.store.port_changelog_head(txn)
    }
}
impl Vault {
    /// The borrowed twin of `port_blob_get`: the same liveness checks
    /// (tombstone, stale index, stale body, entity type), but the bytes stay
    /// in the store's pages whenever the store lends them. The caller checks the content hash when it
    /// first reads them ([`crate::blob_artifact::BlobBytes::verified`]).
    pub(crate) fn lend_blob_in_txn<'t>(
        &self,
        txn: &'t RoTxn<'_>,
        hash: &[u8; 32],
    ) -> Result<Option<std::borrow::Cow<'t, [u8]>>> {
        use std::borrow::Cow;
        let id = blob_artifact_asset_entity_id(hash)?;
        let Some(raw) = self.store.entities.get(txn, id.as_bytes())? else {
            return Ok(None);
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_ASSET {
            return Err(Error::CorruptedIndex("blob content hash"));
        }
        if self.port_tombstone_is_deleted(txn, &id)?
            || super::integrity::stale_in_txn(&self.store, txn, &id)?
        {
            return Ok(None);
        }
        let body = match raw {
            Cow::Borrowed(raw) => Cow::Borrowed(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]),
            Cow::Owned(mut raw) => {
                raw.drain(..crate::batch::ENTITY_METADATA_HEADER_LEN);
                Cow::Owned(raw)
            }
        };
        if super::safe_read::body_is_stale(&body) {
            return Ok(None);
        }
        // A body migrated into an entity document resolves as
        // `port_entity_get` resolves it; only an unmigrated body is lent in place.
        #[cfg(feature = "sync")]
        if crate::entity_doc::has_record_head(&self.store, txn, &id)? {
            let resolved = crate::entity_doc::resolve_record_body(&self.store, txn, &id, &body)?;
            return Ok(Some(Cow::Owned(resolved)));
        }
        Ok(Some(body))
    }
}
