//! Point/list/dedupe reads plus retry-chain and dreamer-root walks.

use std::collections::HashSet;

use crate::attempt_queue::encoding::{
    DedupeIndexKeys, decode_record, legacy_dedupe_index_key, ready_at, ready_key,
    validate_dedupe_record,
};
use crate::attempt_queue::types::{AttemptId, AttemptRecord, attempt_record_order};
use crate::attempt_queue::validate::validate_optional_run_id;
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerAttemptPayload, decode_dreamer_attempt_payload,
};
use crate::error::{Error, Result};
use crate::store::Store;

use super::AttemptQueue;
use super::ERR_DEDUPE_ACTOR_MISMATCH;
use crate::error::ArtifactError;
const DREAMER_RUN_ROOT_CLIMB_LIMIT: usize = 64;
/// Point reads one [`AttemptQueue::retry_chain_depth`] walk may spend. A
/// lineage this long is already past every backoff ceiling that reads it, so
/// the depth saturates here instead of letting a walk grow with the row set.
pub(in crate::attempt_queue) const RETRY_CHAIN_DEPTH_LIMIT: u32 = 1_024;
/// A `retry_of` link naming a row this queue does not hold.
pub(in crate::attempt_queue) const ERR_RETRY_CHAIN_MISSING_ROW: &str =
    "retry chain names a missing attempt";
/// A `retry_of` link returning to a row already on the walk.
pub(in crate::attempt_queue) const ERR_RETRY_CHAIN_CYCLE: &str = "retry chain cycles";
/// A `retry_of` link naming an existing row that is not a try of this attempt.
pub(in crate::attempt_queue) const ERR_RETRY_CHAIN_MISMATCH: &str =
    "retry chain links unrelated attempts";
impl AttemptQueue<'_> {
    /// Reads an attempt by id.
    pub fn get(&self, id: AttemptId) -> Result<Option<AttemptRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.attempt_records.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        decode_record(&raw, id).map(Some)
    }

    /// Counts the retries that precede `id` by walking its `retry_of` lineage.
    ///
    /// A first try is depth 0 and every `retry_of` hop adds one. [`Self::retry`]
    /// mints a NEW row whose `attempt_count` restarts at zero, so the lineage
    /// is the only honest logical retry counter: a caller spacing retries must
    /// read the depth here rather than infer one from a per-row lease counter.
    ///
    /// Missing rows, cycles, and content-inconsistent hops encountered during
    /// the bounded walk fail CLOSED with [`ArtifactError::InvalidAttemptQueueRecord`](crate::error::ArtifactError::InvalidAttemptQueueRecord),
    /// never a silently short depth that would collapse a long backoff onto
    /// its first rung. Every visited hop compares six fields: `kind`, `payload`,
    /// `task_ref`, `run_id`, `dedupe_key`, and `dedupe_actor_ref`. This checks
    /// content consistency, not general chain uniqueness: unrelated rows with
    /// identical values for all six fields are indistinguishable. To distinguish
    /// independent roots, they must differ on at least one of these fields.
    /// The durable connector satisfies this prerequisite with a unique
    /// `task_ref` per independent root.
    ///
    /// The walk reads the initial row plus at most `RETRY_CHAIN_DEPTH_LIMIT`
    /// (1,024) parent rows. Hop depth saturates at 1,024, so a legitimately vast
    /// lineage is bounded work rather than an error. All rows read one snapshot,
    /// so a concurrent retry cannot make the walk observe half of two different
    /// chains.
    pub fn retry_chain_depth(&self, id: AttemptId) -> Result<u32> {
        let rtxn = self.store.env.read_txn()?;
        let mut visited = HashSet::from([id]);
        let mut child = self.retry_chain_record_in_txn(&rtxn, id)?;
        let mut depth = 0_u32;
        while let Some(parent_id) = child.retry_of {
            // A revisit is a CYCLE before it is anything else: a row already on
            // the walk trivially matches itself on identity, so the field
            // compare below could never be the one to stop an endless loop.
            if !visited.insert(parent_id) {
                return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                    ERR_RETRY_CHAIN_CYCLE,
                )));
            }
            let parent = self.retry_chain_record_in_txn(&rtxn, parent_id)?;
            if !retries_the_same_attempt(&child, &parent) {
                return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                    ERR_RETRY_CHAIN_MISMATCH,
                )));
            }
            depth = depth.saturating_add(1);
            if depth >= RETRY_CHAIN_DEPTH_LIMIT {
                return Ok(RETRY_CHAIN_DEPTH_LIMIT);
            }
            child = parent;
        }
        Ok(depth)
    }

    /// One row of the lineage walk: it must exist, or the chain is broken.
    ///
    /// Yields the whole decoded record, not just its link, so the hop that
    /// follows can check parent-child identity within the same one read and
    /// one decode this walk already spends per visited row.
    fn retry_chain_record_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: AttemptId,
    ) -> Result<AttemptRecord> {
        let Some(raw) = self.store.attempt_records.get(rtxn, id.as_bytes())? else {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_RETRY_CHAIN_MISSING_ROW,
            )));
        };
        decode_record(&raw, id)
    }

    /// Reads an attempt by id inside a caller-owned write transaction.
    pub(crate) fn get_in_write_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        id: AttemptId,
    ) -> Result<Option<AttemptRecord>> {
        let Some(raw) = self.store.attempt_records.get(wtxn, id.as_bytes())? else {
            return Ok(None);
        };
        decode_record(&raw, id).map(Some)
    }

    /// Reads every row realizing one TASK inside a caller-owned write
    /// transaction, in deterministic creation order.
    ///
    /// Membership is re-DERIVED, never re-read by id: [`Self::retry`] mints a
    /// NEW row under the same `task_ref` and finalizes its source, so a caller
    /// holding a pre-transaction id snapshot cannot reach the successor by
    /// re-reading the ids it already knows.
    pub(crate) fn list_task_in_write_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        task_ref: &str,
    ) -> Result<Vec<AttemptRecord>> {
        let mut records = Vec::new();
        for row in self.store.attempt_records.iter(wtxn)? {
            let (key, raw_record) = row?;
            let id = AttemptId::from_bytes(&key)?;
            let record = decode_record(&raw_record, id)?;
            if record.task_ref.as_deref() == Some(task_ref) {
                records.push(record);
            }
        }
        records.sort_by(attempt_record_order);
        Ok(records)
    }

    /// Reads all persisted attempt rows in deterministic creation order.
    pub fn list(&self) -> Result<Vec<AttemptRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let mut records = Vec::new();
        for row in self.store.attempt_records.iter(&rtxn)? {
            let (key, raw_record) = row?;
            let id = AttemptId::from_bytes(&key)?;
            records.push(decode_record(&raw_record, id)?);
        }
        records.sort_by(attempt_record_order);
        Ok(records)
    }

    /// Reads persisted attempt rows for one run id in deterministic creation order.
    pub fn list_run(&self, run_id: &str) -> Result<Vec<AttemptRecord>> {
        validate_optional_run_id(Some(run_id))?;
        let rtxn = self.store.env.read_txn()?;
        let mut records = Vec::new();
        for id_bytes in self.store.attempt_ids_for_run_in_txn(&rtxn, run_id)? {
            let id = AttemptId::from_bytes(&id_bytes)?;
            let Some(raw_record) = self.store.attempt_records.get(&rtxn, id.as_bytes())? else {
                return Err(Error::CorruptedIndex("attempt run index"));
            };
            let record = decode_record(&raw_record, id)?;
            if record.run_id.as_deref() != Some(run_id) {
                return Err(Error::CorruptedIndex("attempt run index"));
            }
            records.push(record);
        }
        records.sort_by(attempt_record_order);
        Ok(records)
    }

    pub(crate) fn dreamer_run_root_id(&self, run_id: &str) -> Result<Option<AttemptId>> {
        validate_optional_run_id(Some(run_id))?;
        let rtxn = self.store.env.read_txn()?;
        dreamer_run_root_id_in_txn(self.store, &rtxn, run_id)
    }

    pub(super) fn read_existing_dedupe_in_read_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        index_key: &[u8],
        kind: &str,
        expected_dedupe_actor_ref: Option<&str>,
        dedupe_key: &str,
    ) -> Result<Option<AttemptRecord>> {
        let Some(existing_id) = self.store.attempt_dedupe.get(txn, index_key)? else {
            return Ok(None);
        };
        let id = AttemptId::from_bytes(&existing_id)?;
        let Some(raw) = self.store.attempt_records.get(txn, id.as_bytes())? else {
            return Ok(None);
        };
        let record = decode_record(&raw, id)?;
        validate_dedupe_record(&record, kind, dedupe_key)?;
        if record.dedupe_actor_ref.as_deref() != expected_dedupe_actor_ref {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_DEDUPE_ACTOR_MISMATCH,
            )));
        }
        if !record.state.is_pending() {
            return Ok(None);
        }
        Ok(Some(record))
    }

    /// Resolves a live dedupe hit in family order, checking the actor axis
    /// per path.
    ///
    /// An ACTOR-SCOPED request reads its own v2 entry, then the actorless v1
    /// entry, then the pre-v1 raw key. A pending legacy row has no trustworthy
    /// actor axis, so it stays the conservative winner until its chain
    /// terminalizes — returned as a hit without rewriting the row, promoting
    /// either index, or running the actorless self-heal.
    ///
    /// An ACTORLESS request keeps exactly today's behavior: the v1 entry, then
    /// the pre-v1 raw key with its landed raw→v1 self-heal. It never
    /// manufactures an actor scope.
    pub(super) fn read_existing_dedupe_in_write_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        keys: &DedupeIndexKeys,
        kind: &str,
        dedupe_actor_ref: Option<&str>,
        dedupe_key: &str,
    ) -> Result<Option<AttemptRecord>> {
        if let Some(record) = self.read_existing_dedupe_entry_in_write_txn(
            txn,
            &keys.primary[..],
            kind,
            dedupe_actor_ref,
            dedupe_key,
        )? {
            return Ok(Some(record));
        }

        let legacy_key = legacy_dedupe_index_key(kind, dedupe_key);
        match keys.fallback_v1 {
            // Actor-scoped: both legacy families are READ-ONLY here. A pending
            // actorless row keeps the key until its chain terminalizes, and
            // nothing about it is rewritten or promoted on the way out.
            Some(fallback_v1) => {
                if let Some(record) = self.read_existing_dedupe_entry_in_write_txn(
                    txn,
                    &fallback_v1[..],
                    kind,
                    None,
                    dedupe_key,
                )? {
                    return Ok(Some(record));
                }
                self.read_existing_dedupe_entry_in_write_txn(
                    txn,
                    &legacy_key,
                    kind,
                    None,
                    dedupe_key,
                )
            }
            // Actorless: today's pre-v1 raw fallback, including its landed
            // raw -> v1 index self-heal.
            None => {
                let Some(record) = self.read_existing_dedupe_entry_in_write_txn(
                    txn,
                    &legacy_key,
                    kind,
                    None,
                    dedupe_key,
                )?
                else {
                    return Ok(None);
                };
                self.store
                    .attempt_dedupe
                    .put(txn, &keys.primary[..], record.id.as_bytes())?;
                self.store.attempt_dedupe.delete(txn, &legacy_key)?;
                Ok(Some(record))
            }
        }
    }

    /// Reads one index entry, reaping it when it is verifiably stale.
    ///
    /// Reaping and terminal cleanup are distinct: this path deletes the entry
    /// it just examined and found dead, whichever family it belongs to, while
    /// cleanup derives keys only from a record's own persisted scope. A kind,
    /// key, or actor mismatch is corruption, never a miss.
    fn read_existing_dedupe_entry_in_write_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        index_key: &[u8],
        kind: &str,
        expected_dedupe_actor_ref: Option<&str>,
        dedupe_key: &str,
    ) -> Result<Option<AttemptRecord>> {
        let Some(existing_id) = self.store.attempt_dedupe.get(txn, index_key)? else {
            return Ok(None);
        };
        let id = AttemptId::from_bytes(&existing_id)?;
        let Some(raw) = self.store.attempt_records.get(txn, id.as_bytes())? else {
            self.store.attempt_dedupe.delete(txn, index_key)?;
            return Ok(None);
        };
        let record = decode_record(&raw, id)?;
        validate_dedupe_record(&record, kind, dedupe_key)?;
        if record.dedupe_actor_ref.as_deref() != expected_dedupe_actor_ref {
            return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
                ERR_DEDUPE_ACTOR_MISMATCH,
            )));
        }
        if !record.state.is_pending() {
            self.store.attempt_dedupe.delete(txn, index_key)?;
            return Ok(None);
        }
        Ok(Some(record))
    }

    /// Retires the index entries a settled row OWNS.
    ///
    /// Ownership follows the row's persisted scope: an actor-scoped row owns
    /// exactly its own v2 entry, because the v1 and pre-v1 raw entries may
    /// still belong to another actor's live legacy chain. An actorless row owns
    /// both of those, exactly as before.
    pub(in crate::attempt_queue) fn delete_dedupe_entry_for_record(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
    ) -> Result<()> {
        if let Some(dedupe_key) = record.dedupe_key.as_deref() {
            let keys =
                DedupeIndexKeys::new(&record.kind, record.dedupe_actor_ref.as_deref(), dedupe_key);
            self.store.attempt_dedupe.delete(txn, &keys.primary[..])?;
            if record.dedupe_actor_ref.is_none() {
                let legacy_key = legacy_dedupe_index_key(&record.kind, dedupe_key);
                self.store.attempt_dedupe.delete(txn, &legacy_key)?;
            }
        }
        Ok(())
    }

    pub(super) fn delete_dedupe_entries_for_ids(
        &self,
        txn: &mut heed::RwTxn<'_>,
        ids: &HashSet<AttemptId>,
    ) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut keys = Vec::new();
        for row in self.store.attempt_dedupe.iter(txn)? {
            let (key, value) = row?;
            let id = AttemptId::from_bytes(&value)?;
            if ids.contains(&id) {
                keys.push(key.to_vec());
            }
        }
        for key in keys {
            self.store.attempt_dedupe.delete(txn, &key)?;
        }
        Ok(())
    }

    pub(in crate::attempt_queue) fn delete_ready_entry_for_record(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
    ) -> Result<()> {
        self.store
            .attempt_ready
            .delete(txn, &ready_key(ready_at(record), record.id))?;
        Ok(())
    }
}
/// Whether a `retry_of` link joins two tries of the SAME attempt.
///
/// Both writers of that link — [`AttemptQueue::retry`] and the landing
/// successor in [`super::cancel`] — copy exactly these six fields verbatim
/// from the source row to the row that supersedes it, so a hop differing on
/// any of them is corruption by construction rather than a lineage. Nothing
/// else in the row is comparable: state, lease, counters, timestamps and the
/// event/manifest/cancel logs are all EXPECTED to diverge between a finalized
/// source and its fresh successor, which is why the link cannot be checked by
/// record equality.
fn retries_the_same_attempt(child: &AttemptRecord, parent: &AttemptRecord) -> bool {
    child.kind == parent.kind
        && child.payload == parent.payload
        && child.task_ref == parent.task_ref
        && child.run_id == parent.run_id
        && child.dedupe_key == parent.dedupe_key
        && child.dedupe_actor_ref == parent.dedupe_actor_ref
}
/// Resolves the OF-193 Dreamer root for one stamped run id using the durable
/// run index.  A branch-only run climbs parent links with the same bounded,
/// fail-safe behavior used by the inbox projection.
pub(crate) fn dreamer_run_root_id_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    run_id: &str,
) -> Result<Option<AttemptId>> {
    let mut records = Vec::new();
    // The sidecar is ordered by attempt id; preserve the prior `list_run`
    // behavior by selecting a root/branch in deterministic creation order.
    let mut first_branch: Option<(AttemptId, DreamerAttemptPayload)> = None;
    for id_bytes in store.attempt_ids_for_run_in_txn(txn, run_id)? {
        let id = AttemptId::from_bytes(&id_bytes)?;
        let Some(raw) = store.attempt_records.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex("attempt run index"));
        };
        let record = decode_record(&raw, id)?;
        if record.run_id.as_deref() != Some(run_id) {
            return Err(Error::CorruptedIndex("attempt run index"));
        }
        records.push(record);
    }
    records.sort_by(attempt_record_order);
    for record in records {
        if record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
            continue;
        }
        let Ok(payload) = decode_dreamer_attempt_payload(&record.payload) else {
            continue;
        };
        if payload.parent_attempt.is_none() {
            return Ok(Some(record.id));
        }
        if first_branch.is_none() {
            first_branch = Some((record.id, payload));
        }
    }

    let Some((mut attempt_id, mut payload)) = first_branch else {
        return Ok(None);
    };
    let mut visited = HashSet::from([attempt_id]);
    while let Some(parent_id) = payload.parent_attempt {
        if visited.len() >= DREAMER_RUN_ROOT_CLIMB_LIMIT || !visited.insert(parent_id) {
            break;
        }
        let Some(raw) = store.attempt_records.get(txn, parent_id.as_bytes())? else {
            break;
        };
        let parent = decode_record(&raw, parent_id)?;
        if parent.kind != DREAMER_RUNNER_ATTEMPT_KIND {
            break;
        }
        let Ok(parent_payload) = decode_dreamer_attempt_payload(&parent.payload) else {
            break;
        };
        attempt_id = parent_id;
        payload = parent_payload;
    }
    Ok(Some(attempt_id))
}
