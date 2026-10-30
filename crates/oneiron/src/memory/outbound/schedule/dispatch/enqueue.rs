//! A held schedule's durable enqueue: its attempt, its connector TASK, an invite's sequence.

use super::*;

impl Memory<'_> {
    /// Inside the schedule's write: the ready attempt and, when it is new, the
    /// connector TASK that will replay it and an invite's SEQUENCE bump.
    pub(super) fn enqueue_scheduled_send_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        send: &ScheduledSend<'_>,
        payload: Vec<u8>,
        dedupe_actor_ref: &str,
    ) -> MemoryResult<EnqueueOutcome> {
        let outcome = crate::ports::JobQueue::port_job_enqueue_scoped(
            self.vault,
            wtxn,
            EnqueueAttempt {
                kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
                payload,
                dedupe_key: send.draft.idempotency_key.clone(),
                run_id: send.draft.job_ref.clone(),
                now: send.now,
            },
            crate::ports::JobScope {
                task_ref: Some(send.task_ref.to_hex()),
                dedupe_actor_ref: Some(dedupe_actor_ref),
            },
        )?;
        if matches!(&outcome, EnqueueOutcome::Enqueued(_)) {
            put_connector_send_task_in_txn(
                self.vault,
                wtxn,
                send.task_ref,
                send.intent,
                self.actor,
                self.actor_class,
                send.originating_session_ref,
                send.schedule_context,
                send.continuation,
                send.calendar_invite,
                send.counterparty_ref,
                send.now,
            )?;
            // The SEQUENCE bump joins the SAME transaction as the ready
            // attempt and the connector TASK that will replay it. No
            // bumped sequence can survive without its frozen intent,
            // because both commit here or neither does.
            if let Some(payload) = send.calendar_invite {
                let admission = crate::calendar::invite::admit_calendar_invite_in_txn(
                    self.vault, wtxn, self.actor, payload, send.now,
                )
                .map_err(facade_error_from_calendar)?;
                admission
                    .commit_in_txn(self.vault, wtxn, send.now)
                    .map_err(facade_error_from_calendar)?;
            }
        }
        Ok(outcome)
    }
}
