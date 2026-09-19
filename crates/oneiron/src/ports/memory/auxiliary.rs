//! In-memory secondary indexes, immutable audit rows, blobs and queue leases.
use super::*;
use crate::error::ArtifactError;
use crate::{DeleteReason, HydratedShortId};
impl RetrievalIndex for Memory {
    fn port_retrieval_phonetic_upsert(
        &self,
        txn: &mut MemoryWrite,
        id: &EntityId,
        codes: &[&str],
    ) -> Result<()> {
        for code in codes {
            txn.phonetic
                .entry((*code).to_owned())
                .or_default()
                .insert(*id);
        }
        Ok(())
    }

    fn port_retrieval_vector_get(&self, txn: &Snapshot, id: &EntityId) -> Result<Option<Vec<f32>>> {
        if txn.stale.contains(id) || txn.tombstones.contains_key(id) {
            return Ok(None);
        }
        Ok(txn.vectors.get(id).cloned())
    }

    fn port_retrieval_upsert(
        &self,
        txn: &mut MemoryWrite,
        id: &EntityId,
        vector: Option<&[f32]>,
        text: Option<&[(&str, &str)]>,
    ) -> Result<()> {
        if let Some(vector) = vector {
            if let Some(error) = Error::invalid_vector_component(vector) {
                return Err(error);
            }
            txn.vectors.insert(*id, vector.to_vec());
        }
        if let Some(fields) = text {
            txn.texts.insert(
                *id,
                fields
                    .iter()
                    .map(|(_, text)| *text)
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        Ok(())
    }
    fn port_retrieval_mark_stale(&self, txn: &mut MemoryWrite, id: &EntityId) -> Result<()> {
        let revision = txn.entities.get(id).map_or(0, |row| row.learned_at);
        txn.stale_revision.insert(*id, revision);
        txn.stale.insert(*id);
        txn.vectors.remove(id);
        txn.texts.remove(id);
        Ok(())
    }
    fn port_retrieval_vector_search(
        &self,
        txn: &Snapshot,
        query: &[f32],
        limit: usize,
    ) -> Result<Vec<ScoredEntity>> {
        let mut rows = Vec::new();
        for (id, vector) in &txn.vectors {
            if txn.stale.contains(id) || txn.tombstones.contains_key(id) {
                continue;
            }
            if query.len() != vector.len() {
                return Err(Error::DimensionMismatch {
                    expected: vector.len(),
                    got: query.len(),
                });
            }
            let dot: f32 = query.iter().zip(vector).map(|(a, b)| a * b).sum();
            let norm = (query.iter().map(|v| v * v).sum::<f32>()
                * vector.iter().map(|v| v * v).sum::<f32>())
            .sqrt();
            rows.push(ScoredEntity {
                id: *id,
                score: if norm > 0.0 { dot / norm } else { 0.0 },
            });
        }
        rows.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.id.cmp(&b.id)));
        rows.truncate(limit);
        Ok(rows)
    }
    fn port_retrieval_text_search(
        &self,
        txn: &Snapshot,
        query: &str,
        limit: usize,
    ) -> Result<Vec<ScoredEntity>> {
        Ok(txn
            .texts
            .iter()
            .filter(|(id, text)| {
                !txn.stale.contains(id)
                    && !txn.tombstones.contains_key(id)
                    && text.to_lowercase().contains(&query.to_lowercase())
            })
            .take(limit)
            .map(|(id, _)| ScoredEntity {
                id: *id,
                score: 1.0,
            })
            .collect())
    }
}
impl ShortIdStore for Memory {
    fn port_short_id_get_or_create(&self, txn: &mut MemoryWrite, id: &EntityId) -> Result<String> {
        let row = txn.entities.get(id).ok_or(Error::EntityNotFound)?;
        let kind = row.entity_type;
        let hash = (xxhash_rust::xxh32::xxh32(&row.body, 0) % 256) as u8;
        let name = if let Some((name, _)) = txn.shorts.get(id) {
            name.clone()
        } else {
            let prefix = crate::registry::short_id_prefix(kind)?;
            let counter = txn.counters.entry(kind).or_default();
            *counter = counter
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("short id counter"))?;
            format!("{prefix}{counter}")
        };
        txn.shorts.insert(*id, (name.clone(), hash));
        Ok(name)
    }
    fn port_short_id_resolve(
        &self,
        txn: &Snapshot,
        short_id: &str,
        content_hash: u8,
    ) -> Result<Option<HydratedShortId>> {
        let Some((id, _)) = txn
            .shorts
            .iter()
            .find(|(_, (name, hash))| name == short_id && *hash == content_hash)
        else {
            return Ok(None);
        };
        let row = txn
            .entities
            .get(id)
            .ok_or(Error::CorruptedIndex("short id entity"))?;
        Ok(Some(HydratedShortId {
            id: *id,
            entity_type: row.entity_type,
            learned_at: row.learned_at,
            deletion: None,
            body: super::super::safe_read_text(self, txn, id)?,
        }))
    }
}
impl TombstoneStore for Memory {
    fn port_tombstone_create(
        &self,
        txn: &mut MemoryWrite,
        id: &EntityId,
        value: TombstoneValueV2,
    ) -> Result<()> {
        txn.tombstones.insert(*id, value);
        let dependents: BTreeSet<_> = txn
            .dependencies
            .iter()
            .filter(|(source, _)| source.document == *id)
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect();
        for dependent in dependents {
            self.port_retrieval_mark_stale(txn, &dependent)?;
            self.port_job_enqueue(
                txn,
                EnqueueAttempt {
                    kind: "derived.regenerate".into(),
                    payload: [id.as_bytes().as_slice(), dependent.as_bytes()].concat(),
                    dedupe_key: Some(format!("{}:{}", id.to_hex(), dependent.to_hex())),
                    run_id: None,
                    now: 0,
                },
            )?;
        }
        self.port_retrieval_mark_stale(txn, id)
    }
    fn port_tombstone_is_deleted(&self, txn: &Snapshot, id: &EntityId) -> Result<bool> {
        Ok(txn.tombstones.contains_key(id))
    }
    fn port_tombstone_clean_expired(
        &self,
        _txn: &mut MemoryWrite,
        _now: u64,
        _limit: usize,
    ) -> Result<u64> {
        Ok(0)
    }
}
impl DependencyIndex for Memory {
    fn port_dependency_complete_regeneration(
        &self,
        txn: &mut MemoryWrite,
        dependent: &EntityId,
        regenerated_at: u64,
        sources: &[SourceSpan],
    ) -> Result<bool> {
        if sources.len() > 100_000 {
            return Err(Error::IndexOverflow("regeneration sources"));
        }
        let Some(stale_revision) = txn.stale_revision.get(dependent) else {
            return Ok(false);
        };
        if regenerated_at <= *stale_revision || txn.tombstones.contains_key(dependent) {
            return Ok(false);
        }
        let Some(row) = txn.entities.get(dependent) else {
            return Ok(false);
        };
        if row.learned_at != regenerated_at || super::super::safe_read::body_is_stale(&row.body) {
            return Ok(false);
        }
        for source in sources {
            if source.document == *dependent {
                return Err(Error::InvariantViolation("self dependency"));
            }
            if txn.stale.contains(&source.document) || txn.tombstones.contains_key(&source.document)
            {
                return Ok(false);
            }
            let Some(row) = txn.entities.get(&source.document) else {
                return Ok(false);
            };
            if row.learned_at != source.frontier
                || super::super::safe_read::body_is_stale(&row.body)
            {
                return Ok(false);
            }
        }
        for ids in txn.dependencies.values_mut() {
            ids.remove(dependent);
        }
        for source in sources {
            self.port_dependency_put(txn, *source, dependent)?;
        }
        txn.stale.remove(dependent);
        txn.stale_revision.remove(dependent);
        Ok(true)
    }

    fn port_dependency_put(
        &self,
        txn: &mut MemoryWrite,
        source: SourceSpan,
        dependent: &EntityId,
    ) -> Result<()> {
        if source.document == *dependent {
            return Err(Error::InvariantViolation("self dependency"));
        }
        if txn.tombstones.contains_key(&source.document) || txn.stale.contains(&source.document) {
            return Err(Error::EntityNotFound);
        }
        txn.dependencies
            .entry(source)
            .or_default()
            .insert(*dependent);
        Ok(())
    }
    fn port_dependency_list_by_source(
        &self,
        txn: &Snapshot,
        source: SourceSpan,
    ) -> Result<Vec<EntityId>> {
        Ok(txn
            .dependencies
            .get(&source)
            .map_or_else(Vec::new, |ids| ids.iter().copied().collect()))
    }
}
impl ChangeLogStore for Memory {
    fn port_changelog_append(&self, txn: &mut MemoryWrite, record: &ChangeLogRecord) -> Result<()> {
        if let Some(old) = txn.changes.get(&record.id)
            && old != record
        {
            return Err(Error::InvariantViolation("changelog rows are immutable"));
        }
        txn.changes.insert(record.id, record.clone());
        Ok(())
    }
    fn port_changelog_list_by_entity(
        &self,
        txn: &Snapshot,
        entity: &EntityId,
        limit: usize,
    ) -> Result<Vec<ChangeLogRecord>> {
        Ok(memory_changes(txn, |r| r.entity == *entity, limit))
    }
    fn port_changelog_list_by_actor(
        &self,
        txn: &Snapshot,
        actor: &EntityId,
        limit: usize,
    ) -> Result<Vec<ChangeLogRecord>> {
        Ok(memory_changes(txn, |r| r.actor_principal == *actor, limit))
    }
}
fn memory_changes(
    txn: &Snapshot,
    predicate: impl Fn(&ChangeLogRecord) -> bool,
    limit: usize,
) -> Vec<ChangeLogRecord> {
    let mut rows = txn
        .changes
        .values()
        .filter(|r| predicate(r))
        .cloned()
        .collect::<Vec<_>>();
    rows.sort_by_key(|r| (r.recorded_at, r.id));
    rows.truncate(limit.min(100_000));
    rows
}
impl BlobStore for Memory {
    fn port_blob_put(
        &self,
        txn: &mut MemoryWrite,
        reference: &EntityId,
        bytes: &[u8],
        _occurred: TimeRange,
        _learned_at: u64,
    ) -> Result<[u8; 32]> {
        let hash = *blake3::hash(bytes).as_bytes();
        let entry = txn
            .blobs
            .entry(hash)
            .or_insert_with(|| (bytes.to_vec(), BTreeSet::new()));
        entry.1.insert(*reference);
        Ok(hash)
    }
    fn port_blob_get(&self, txn: &Snapshot, hash: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(txn.blobs.get(hash).map(|(bytes, _)| bytes.clone()))
    }
    fn port_blob_delete(
        &self,
        txn: &mut MemoryWrite,
        reference: &EntityId,
        hash: &[u8; 32],
        reason: DeleteReason,
    ) -> Result<bool> {
        let hard = matches!(
            reason,
            DeleteReason::UserHardDelete | DeleteReason::GdprDelete | DeleteReason::PolicyDelete
        );
        let Some((_, refs)) = txn.blobs.get_mut(hash) else {
            return Ok(false);
        };
        if hard {
            let refs = refs.clone();
            txn.blobs.remove(hash);
            for id in refs {
                self.port_entity_delete(txn, &id)?;
            }
            return Ok(true);
        }
        if !refs.remove(reference) {
            return Ok(false);
        }
        if refs.is_empty() {
            txn.blobs.remove(hash);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
impl JobQueue for Memory {
    fn port_job_enqueue(
        &self,
        txn: &mut MemoryWrite,
        input: EnqueueAttempt,
    ) -> Result<EnqueueOutcome> {
        self.port_job_enqueue_scoped(txn, input, JobScope::default())
    }
    fn port_job_enqueue_scoped(
        &self,
        txn: &mut MemoryWrite,
        input: EnqueueAttempt,
        scope: JobScope<'_>,
    ) -> Result<EnqueueOutcome> {
        if input.kind.is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "attempt kind must not be empty",
            )));
        }
        if let Some(dedupe) = input.dedupe_key.as_ref()
            && let Some(existing) = txn.jobs.values().find(|r| {
                r.kind == input.kind
                    && r.dedupe_key.as_ref() == Some(dedupe)
                    && r.dedupe_actor_ref.as_deref() == scope.dedupe_actor_ref
                    && matches!(r.state, AttemptState::Queued | AttemptState::Leased)
            })
        {
            return Ok(EnqueueOutcome::Existing(existing.clone()));
        }
        let now = self.clock.now_recorded_at();
        let record = AttemptRecord {
            id: AttemptId::from_bytes(&self.clock.ulid()?)?,
            kind: input.kind,
            payload: input.payload,
            state: AttemptState::Queued,
            lease_owner: None,
            attempt_count: 0,
            claimed_at: None,
            scheduled_at: None,
            retry_of: None,
            backoff_until: None,
            last_error: None,
            task_ref: scope.task_ref,
            run_id: input.run_id,
            dedupe_actor_ref: input
                .dedupe_key
                .as_ref()
                .and(scope.dedupe_actor_ref)
                .map(str::to_owned),
            dedupe_key: input.dedupe_key,
            created_at: now,
            updated_at: now,
            events: Vec::new(),
            manifest: Vec::new(),
            cancel_state: Default::default(),
            result_ref: None,
        };
        txn.jobs.insert(*record.id.as_bytes(), record.clone());
        Ok(EnqueueOutcome::Enqueued(record))
    }
    fn port_job_claim(
        &self,
        txn: &mut MemoryWrite,
        kind: Option<&str>,
        input: ClaimAttempt,
    ) -> Result<ClaimOutcome> {
        if input.lease_owner.is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "lease owner must not be empty",
            )));
        }
        let now = self.clock.now_recorded_at();
        let cutoff = input.now.min(now);
        let candidate = txn
            .jobs
            .iter()
            .filter(|(_, r)| {
                kind.is_none_or(|kind| r.kind == kind)
                    && matches!(r.state, AttemptState::Queued | AttemptState::Scheduled)
                    && r.scheduled_at.or(r.backoff_until).unwrap_or(0) <= cutoff
            })
            .min_by_key(|(id, r)| (r.scheduled_at.or(r.backoff_until).unwrap_or(0), **id))
            .map(|(id, _)| *id);
        let Some(id) = candidate else {
            return Ok(ClaimOutcome::Empty);
        };
        let record = txn.jobs.get_mut(&id).ok_or(Error::EntityNotFound)?;
        record.state = AttemptState::Leased;
        record.scheduled_at = None;
        record.backoff_until = None;
        record.lease_owner = Some(input.lease_owner);
        record.attempt_count = record
            .attempt_count
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("attempt count"))?;
        record.claimed_at = Some(now);
        record.updated_at = now;
        Ok(ClaimOutcome::Claimed(record.clone()))
    }
    fn port_job_complete(
        &self,
        txn: &mut MemoryWrite,
        input: CompleteAttempt,
    ) -> Result<CompleteOutcome> {
        let record = txn
            .jobs
            .get_mut(input.id.as_bytes())
            .ok_or_else(|| transition("complete", "missing"))?;
        if record.state == AttemptState::Completed {
            return Ok(CompleteOutcome::AlreadyCompleted(record.clone()));
        }
        check_lease(record, &input.lease_owner, input.attempt_count, "complete")?;
        record.state = AttemptState::Completed;
        record.lease_owner = None;
        record.updated_at = self.clock.now_recorded_at();
        record.last_error = None;
        record.backoff_until = None;
        Ok(CompleteOutcome::Completed(record.clone()))
    }
    fn port_job_fail(&self, txn: &mut MemoryWrite, input: FailAttempt) -> Result<FailOutcome> {
        let record = txn
            .jobs
            .get_mut(input.id.as_bytes())
            .ok_or_else(|| transition("fail", "missing"))?;
        if record.state == AttemptState::Failed {
            return Ok(FailOutcome::AlreadyFailed(record.clone()));
        }
        check_lease(record, &input.lease_owner, input.attempt_count, "fail")?;
        if input.reason.is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                "failure reason must not be empty",
            )));
        }
        record.state = AttemptState::Failed;
        record.lease_owner = None;
        record.updated_at = self.clock.now_recorded_at();
        record.last_error = Some(input.reason);
        record.backoff_until = None;
        Ok(FailOutcome::Failed(record.clone()))
    }
}
fn transition(action: &'static str, state: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAttemptQueueTransition { action, state })
}
fn check_lease(
    record: &AttemptRecord,
    owner: &str,
    count: u32,
    action: &'static str,
) -> Result<()> {
    if record.state != AttemptState::Leased {
        return Err(transition(action, record.state.as_str()));
    }
    if record.lease_owner.as_deref() != Some(owner) || record.attempt_count != count {
        return Err(transition(action, "lease_mismatch"));
    }
    Ok(())
}
