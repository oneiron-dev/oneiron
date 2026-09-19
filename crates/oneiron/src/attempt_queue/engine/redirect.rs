//! Atomic operator placement changes with lease fencing and cycle refusal.

use std::collections::HashSet;

use super::AttemptQueue;
use crate::attempt_queue::encoding::{decode_record, encode_record, ready_at, ready_key};
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::validate::{
    append_attempt_event, validate_intervention_actor, validate_lease_owner,
    validate_optional_intervention_note,
};
use crate::attempt_queue::{
    AttemptInterventionEffect, AttemptInterventionKind, AttemptPlacement, AttemptState,
    InterveneAttempt, InterveneOutcome,
};
use crate::error::{Error, Result};

impl AttemptQueue<'_> {
    /// Redirects live work. A worker move revokes the old lease and queues the
    /// same try for the named worker; its next claim advances the lease fence.
    /// Parent-only moves preserve the current lease and its expiry clock.
    /// Repeating the same placement is a no-op, including its operator event.
    pub fn redirect(
        &self,
        input: InterveneAttempt,
        placement: AttemptPlacement,
    ) -> Result<InterveneOutcome> {
        if input.kind != AttemptInterventionKind::Redirect {
            return Err(invalid_transition("redirect", "wrong intervention kind"));
        }
        validate_intervention_actor(&input.actor)?;
        validate_optional_intervention_note(input.note.as_deref())?;
        if let Some(worker) = &placement.worker {
            validate_lease_owner(worker)?;
        }
        let mut txn = self.store.env.write_txn()?;
        let raw = self
            .store
            .attempt_records
            .get(&txn, input.id.as_bytes())?
            .ok_or_else(|| invalid_transition("redirect", "missing"))?;
        let mut record = decode_record(&raw, input.id)?;
        if !matches!(
            record.state,
            AttemptState::Queued | AttemptState::Scheduled | AttemptState::Leased
        ) {
            return Err(invalid_transition("redirect", record.state.as_str()));
        }
        if record.placement.as_ref() == Some(&placement) {
            return Ok(InterveneOutcome {
                effect: AttemptInterventionEffect::AlreadyRedirected,
                record,
            });
        }
        // Traverse effective parents under this same writer transaction. This
        // rejects self/cyclic and cross-run placement without a check/use race.
        let mut seen = HashSet::from([record.id]);
        let mut parent = placement.parent;
        while let Some(id) = parent {
            if !seen.insert(id) {
                return Err(invalid_transition("redirect", "parent cycle"));
            }
            let raw = self
                .store
                .attempt_records
                .get(&txn, id.as_bytes())?
                .ok_or_else(|| invalid_transition("redirect", "missing parent"))?;
            let ancestor = decode_record(&raw, id)?;
            if record.run_id.is_none() || ancestor.run_id != record.run_id {
                return Err(invalid_transition("redirect", "different run"));
            }
            parent = crate::run_tree::effective_parent(&ancestor);
        }
        let worker_moved = placement.worker.as_deref()
            != record
                .placement
                .as_ref()
                .and_then(|old| old.worker.as_deref());
        if worker_moved && record.state == AttemptState::Leased {
            record.state = AttemptState::Queued;
            record.lease_owner = None;
            record.scheduled_at = None;
            record.backoff_until = None;
            record.updated_at = input.now;
            // Fence the former worker immediately, even if a new worker uses
            // the same owner string before claiming.
            record.attempt_count = record
                .attempt_count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("redirect lease generation"))?;
            let key = ready_key(ready_at(&record), record.id);
            self.store
                .attempt_ready
                .put(&mut txn, &key, record.id.as_bytes())?;
        }
        record.placement = Some(placement);
        append_attempt_event(&mut record, input.kind, input.actor, input.note, input.now)?;
        self.store
            .attempt_records
            .put(&mut txn, record.id.as_bytes(), &encode_record(&record)?)?;
        txn.commit()?;
        self.store.notify_attempt_observers();
        Ok(InterveneOutcome {
            effect: AttemptInterventionEffect::Redirected,
            record,
        })
    }
}
