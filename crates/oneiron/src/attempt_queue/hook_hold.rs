//! Lease-fenced verb-hook pauses: a workflow's, whose transcript its
//! checkpoint writer retains in the same transaction as this pause, and a
//! turn action's, whose resume point names its wait (FIX 1765).

use super::encoding::decode_record;
use super::lifecycle::{EngineHold, HoldWrite};
use super::types::{AttemptId, AttemptInterventionKind, AttemptPause, AttemptRecord, AttemptState};
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
        self.hold_in_txn(
            txn,
            HoldWrite {
                id: input.id,
                lease_owner: input.lease_owner,
                attempt_count: input.attempt_count,
                resume_point: input.resume_point,
                hold: EngineHold::Hook {
                    invocation: input.invocation,
                    attempt_count: input.attempt_count,
                },
                actor: ATTEMPT_RUNTIME_ACTOR,
                note: "waits on its verb hook".to_owned(),
                now: input.now,
            },
        )
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
        self.release_hold_in_txn(
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
