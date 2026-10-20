//! The one storage write every enqueue door ends in: a fresh row, its
//! readiness, run and dedupe entries, in the caller's transaction.

use crate::attempt_queue::cancel::AttemptCancelState;
use crate::attempt_queue::encoding::{DedupeIndexKeys, ready_at, ready_key};
use crate::attempt_queue::types::{
    AttemptId, AttemptRecord, AttemptState, EnqueueAttempt, EnqueueOutcome,
};
use crate::attempt_queue::validate::{
    validate_kind, validate_optional_dedupe, validate_optional_dedupe_actor_ref,
    validate_optional_run_id,
};
use crate::error::Result;

use super::AttemptQueue;

impl AttemptQueue<'_> {
    pub(super) fn enqueue_storage_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: EnqueueAttempt,
        task_ref: Option<String>,
        dedupe_actor_ref: Option<&str>,
        id: Option<AttemptId>,
    ) -> Result<EnqueueOutcome> {
        validate_kind(&input.kind)?;
        validate_optional_dedupe(input.dedupe_key.as_deref())?;
        validate_optional_dedupe_actor_ref(dedupe_actor_ref)?;
        validate_optional_run_id(input.run_id.as_deref())?;

        // Key-gated persistence: with no key there is no index entry to scope,
        // so a scope offered anyway is normalized away rather than written into
        // a row that decode would then refuse.
        let persisted_actor_ref = input
            .dedupe_key
            .as_ref()
            .and_then(|_| dedupe_actor_ref.map(str::to_owned));
        let scoped_actor_ref = persisted_actor_ref.as_deref();
        let dedupe_keys = input
            .dedupe_key
            .as_deref()
            .map(|dedupe_key| DedupeIndexKeys::new(&input.kind, scoped_actor_ref, dedupe_key));
        if let (Some(dedupe_key), Some(keys)) = (input.dedupe_key.as_deref(), dedupe_keys.as_ref())
            && let Some(record) = self.read_existing_dedupe_in_write_txn(
                wtxn,
                keys,
                &input.kind,
                scoped_actor_ref,
                dedupe_key,
            )?
        {
            return Ok(EnqueueOutcome::Existing(record));
        }

        let id = match id {
            Some(id) => id,
            None => AttemptId::from_bytes(&self.store.clock.ulid()?)?,
        };
        crate::attempt_queue::check_owner_retained_range(&input.kind, &id)?;
        let mut record = AttemptRecord {
            id,
            kind: input.kind,
            payload: input.payload,
            state: AttemptState::Queued,
            lease_owner: None,
            attempt_count: 0,
            claimed_at: None,
            scheduled_at: None,
            retry_of: None,
            folded_retries: 0,
            backoff_until: None,
            last_error: None,
            task_ref,
            run_id: input.run_id,
            dedupe_key: input.dedupe_key,
            dedupe_actor_ref: persisted_actor_ref,
            created_at: input.now,
            updated_at: input.now,
            events: Vec::new(),
            manifest: Vec::new(),
            executor_model: None,
            executor_seat: None,
            executor_role: None,
            cancel_state: AttemptCancelState::default(),
            signals: Vec::new(),
            asks: Vec::new(),
            placement: None,
            result_ref: None,
            history: Vec::new(),
        };

        if self
            .store
            .attempt_records
            .get(wtxn, record.id.as_bytes())?
            .is_some()
        {
            return Err(crate::Error::InvariantViolation("attempt id collision"));
        }
        let encoded = self.encode_in_txn(wtxn, &mut record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        self.store.put_attempt_run_index_in_txn(
            wtxn,
            record.run_id.as_deref(),
            record.id.as_bytes(),
        )?;
        let ready_key = ready_key(ready_at(&record), record.id);
        self.store
            .attempt_ready
            .put(wtxn, &ready_key, record.id.as_bytes())?;
        // A new row writes its OWN family only. An actor-scoped row never
        // manufactures a v1 entry, which would re-create the actor-blind
        // collision this key family exists to end.
        if let Some(keys) = dedupe_keys.as_ref() {
            self.store
                .attempt_dedupe
                .put(wtxn, &keys.primary[..], record.id.as_bytes())?;
        }

        Ok(EnqueueOutcome::Enqueued(record))
    }
}
