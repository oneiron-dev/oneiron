//! Lease-fenced verb-hook pauses: a workflow's, whose transcript its
//! checkpoint writer retains in the same transaction as this pause, and a
//! turn action's, whose resume point names its wait (FIX 1765).

use super::encoding::decode_record;
use super::telemetry::invalid_transition;
use super::types::{AttemptId, AttemptInterventionKind, AttemptPause, AttemptRecord, AttemptState};
use super::validate::{
    append_attempt_event, validate_lease_owner, validate_resume_point, validate_transition_lease,
};
use super::{ATTEMPT_RUNTIME_ACTOR, AttemptQueue, AttemptResumePoint, InterveneAttempt};
use crate::Result;

pub(crate) struct HoldAttemptForHook {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub invocation: [u8; 16],
    pub resume_point: AttemptResumePoint,
    pub now: u64,
}

impl AttemptRecord {
    /// A later person's pause takes over the hold and reads false here,
    /// even when the workflow's transcript still names this invocation.
    pub(crate) fn hook_wait_for(&self, invocation: [u8; 16]) -> bool {
        self.state == AttemptState::Paused
            && self.active_pause == Some(AttemptPause::Hook { invocation })
    }
}

impl AttemptQueue<'_> {
    /// The caller retains the transcript in this same writer. No budget
    /// hold, owner notice, retry, cancellation or completion is produced.
    pub(crate) fn hold_for_hook_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: HoldAttemptForHook,
    ) -> Result<AttemptRecord> {
        validate_lease_owner(&input.lease_owner)?;
        validate_resume_point(&input.resume_point)?;
        let Some(raw) = self.store.attempt_records.get(txn, input.id.as_bytes())? else {
            return Err(invalid_transition("hook_hold", "missing"));
        };
        let mut record = decode_record(&raw, input.id)?;
        if record.hook_wait_for(input.invocation) && record.attempt_count == input.attempt_count {
            return Ok(record);
        }
        if record.state != AttemptState::Leased {
            return Err(invalid_transition("hook_hold", record.state.as_str()));
        }
        validate_transition_lease(
            &record,
            &input.lease_owner,
            input.attempt_count,
            "hook_hold",
        )?;
        self.delete_ready_entry_for_record(txn, &record)?;
        record.cancel_state.landing = None;
        record.cancel_state.pressure.pending = 0;
        record.cancel_state.resume_point = Some(input.resume_point);
        append_attempt_event(
            &mut record,
            AttemptInterventionKind::Pause,
            ATTEMPT_RUNTIME_ACTOR.to_owned(),
            Some("waits on its verb hook".to_owned()),
            input.now,
        )?;
        record.state = AttemptState::Paused;
        record.active_pause = Some(AttemptPause::Hook {
            invocation: input.invocation,
        });
        record.lease_owner = None;
        record.updated_at = input.now;
        let encoded = self.encode_in_txn(txn, &mut record)?;
        self.store
            .attempt_records
            .put(txn, record.id.as_bytes(), &encoded)?;
        Ok(record)
    }

    /// Resume only this invocation's own pause at its recorded generation.
    /// The ordinary intervention restores the original readiness instant.
    /// A later person's pause, cancellation or different lease is untouched.
    pub(crate) fn resume_hook_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        invocation: [u8; 16],
        attempt_count: u32,
        now: u64,
    ) -> Result<bool> {
        let Some(raw) = self.store.attempt_records.get(txn, id.as_bytes())? else {
            return Ok(false);
        };
        let record = decode_record(&raw, id)?;
        if !record.hook_wait_for(invocation) || record.attempt_count != attempt_count {
            return Ok(false);
        }
        self.intervene_in_txn(
            txn,
            InterveneAttempt {
                id,
                kind: AttemptInterventionKind::Resume,
                actor: ATTEMPT_RUNTIME_ACTOR.to_owned(),
                note: Some("its verb hook answered".to_owned()),
                now,
            },
        )?;
        Ok(true)
    }
}
