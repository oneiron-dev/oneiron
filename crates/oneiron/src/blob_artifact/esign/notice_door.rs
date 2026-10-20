//! `vault.esign.notices.dispatch` (FIX 5239): a signing document's staged
//! transition notices (pending, completed, rejection, expiry) cross the email
//! send gate as the principal their trail recorded, the first sender.
//!
//! The bound caller is the only authority: its actor and class come from
//! the credential, and it sends only the notices recorded for that actor. No
//! owner sends an agent's notice and no `on_behalf_of` widens the caller.
//! Each claimed notice goes through OF-327 as a gated email send
//! ([`crate::Vault::dispatch_esign_notice`]): a gated send needs its press or
//! a live Grant, and only an allowed one queues `esign.delivery` for the
//! outbox.
//!
//! With no caller, the housekeeping notice worker runs this same path as the
//! notices' recorded principal, while its recorded send act and its standing
//! hold (FIX 6219, `notice_unattended`).
use super::EsignNotice;
use super::notice_dispatch::{
    ScopedNotice, claim_notice_in_txn, notice_lease_prefix, principal_notices,
    recover_notice_in_txn,
};
use super::notice_scope::NoticeScope;
use crate::EntityId;
use crate::attempt_queue::{AttemptQueue, AttemptRecord};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
};
use serde::{Deserialize, Serialize};

/// The signing document whose staged notices the caller sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignNoticesDispatchRequest {
    /// The artifact the signing overlay lives on.
    pub document_ref: String,
}

/// What the send gate made of each staged notice recorded for the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EsignNoticesDispatchView {
    pub document_ref: String,
    /// The caller's claims on this document that an earlier call left
    /// leased, returned to the queue before this call claimed.
    pub recovered: usize,
    /// One row per unsettled notice of the document recorded for the
    /// caller, in queue order. Notices recorded for anyone else are not
    /// this caller's to send and are not listed.
    pub notices: Vec<EsignNoticeOutcome>,
}

/// One staged notice and what became of it in this call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EsignNoticeOutcome {
    /// The notice's queue row.
    pub attempt_ref: String,
    pub recipient: String,
    /// `pending`, `completed`, `rejection` or `expiry`.
    pub transition: String,
    /// The pipeline outcome (`delivered_to_channel` once the delivery is
    /// queued, `held`, `suppressed`, `let_go`, `failed`), or the door's own:
    /// `not_due` for a notice waiting out its retry, `in_flight` for one
    /// another call holds, `error` for a dispatch that did not run to its
    /// outcome. A held or failed send is tried again later, an `error`'s
    /// notice by the next call.
    pub outcome: String,
    /// The gate's outcome (`allow`, `pending`, `deny`) when the gate ran.
    pub gate_outcome: Option<String>,
    /// The persisted gate decision, readable with `vault.receipts.get`.
    pub gate_decision_ref: Option<String>,
    pub gate_reason_codes: Vec<String>,
    /// The error's code and message, for an `error` outcome.
    pub error_code: Option<String>,
    pub error: Option<String>,
}

impl EsignNoticeOutcome {
    fn door(attempt_ref: String, notice: &EsignNotice, outcome: &str) -> Self {
        Self {
            attempt_ref,
            recipient: notice.recipient.clone(),
            transition: notice.transition.clone(),
            outcome: outcome.to_owned(),
            gate_outcome: None,
            gate_decision_ref: None,
            gate_reason_codes: Vec::new(),
            error_code: None,
            error: None,
        }
    }
}

impl Memory<'_> {
    /// `vault.esign.notices.dispatch`: sends `document_ref`'s due staged
    /// notices recorded for the bound caller, each through the email send
    /// gate as that caller. The row's refs admission reads `document_ref`
    /// under the caller's scope first; each claim runs under the caller's
    /// verified actor and content-write admission, before its lease.
    /// # Errors
    /// A `document_ref` that is no id or names no signing document, a caller
    /// whose binding no longer holds or who may not write here, or a queue
    /// refusal. A gate that holds or denies a notice, or a dispatch that
    /// fails, is that notice's outcome, not an error.
    pub fn esign_notices_dispatch(
        &self,
        input: &EsignNoticesDispatchRequest,
    ) -> MemoryResult<EsignNoticesDispatchView> {
        let document = EntityId::from_hex(&input.document_ref)
            .map_err(|_| MemoryError::bad_request("document_ref is not an artifact id"))?;
        let vault = self.vault();
        let (actor, class) = (self.actor(), self.actor_class());
        crate::memory::verify_actor_binding(vault, actor, class)?;
        let scope = self.notice_scope()?;
        self.dispatch_notices_in(document, &scope)
    }

    /// The door's sending of `document`'s due staged notices recorded for
    /// this handle's actor, each judged in `scope`: the caller's own, or the
    /// notice worker's binding (FIX 6219).
    pub(super) fn dispatch_notices_in(
        &self,
        document: EntityId,
        scope: &NoticeScope<'_>,
    ) -> MemoryResult<EsignNoticesDispatchView> {
        let (vault, actor) = (self.vault(), self.actor());
        {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            scope.admit_in(&txn, document)?;
            super::ledger::read_in(vault, &txn, document)?;
        }
        let rows = principal_notices(vault, document, actor)?;
        let mut recovered = 0;
        for row in rows.iter().filter(|row| row.state.is_running()) {
            if scope.write(self, document, |txn| {
                Ok(recover_notice_in_txn(vault, txn, row.id, document, actor)?)
            })? {
                recovered += 1;
            }
        }
        let lease_owner = format!(
            "{}{}",
            notice_lease_prefix(actor),
            vault.new_entity_id()?.to_hex()
        );
        let mut notices = Vec::with_capacity(rows.len());
        for row in &rows {
            let attempt_ref = crate::entity_id::bytes_to_hex_lower(row.id.as_bytes());
            let claimed = scope.write(self, document, |txn| {
                Ok(claim_notice_in_txn(
                    vault,
                    txn,
                    row.id,
                    document,
                    actor,
                    &lease_owner,
                )?)
            })?;
            let outcome = match claimed {
                ScopedNotice::Claimed(attempt, notice) => self.dispatch_claimed_notice(
                    scope,
                    document,
                    attempt_ref,
                    &attempt,
                    &notice,
                    &lease_owner,
                ),
                ScopedNotice::NotDue(notice) => {
                    EsignNoticeOutcome::door(attempt_ref, &notice, "not_due")
                }
                ScopedNotice::InFlight(notice) => {
                    EsignNoticeOutcome::door(attempt_ref, &notice, "in_flight")
                }
                ScopedNotice::Gone => continue,
            };
            notices.push(outcome);
        }
        Ok(EsignNoticesDispatchView {
            document_ref: document.to_hex(),
            recovered,
            notices,
        })
    }

    /// One claimed notice through the email send gate as the bound caller.
    /// A dispatch that errs returns its lease to the queue as the same try,
    /// so the next call sends it as a new try; OF-327 replays a send that
    /// already crossed.
    fn dispatch_claimed_notice(
        &self,
        scope: &NoticeScope<'_>,
        document: EntityId,
        attempt_ref: String,
        attempt: &AttemptRecord,
        notice: &EsignNotice,
        lease_owner: &str,
    ) -> EsignNoticeOutcome {
        let vault = self.vault();
        let dispatched = notice_request(attempt, notice, self.actor(), self.actor_class())
            .and_then(|request| {
                scope
                    .dispatch(vault, document, attempt, request)
                    .map_err(crate::memory::facade_error_from_outbound_dispatch)
            });
        match dispatched {
            Ok(result) => EsignNoticeOutcome {
                outcome: result.outcome.as_str().to_owned(),
                gate_outcome: Some(result.gate_outcome),
                gate_decision_ref: result.gate_decision_id,
                gate_reason_codes: result.gate_reason_codes,
                ..EsignNoticeOutcome::door(attempt_ref, notice, "")
            },
            Err(error) => {
                if let Err(release) = scope.write(self, document, |txn| {
                    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
                    Ok(AttemptQueue::new(vault).release_lease_in_txn(
                        txn,
                        attempt.id,
                        lease_owner,
                        now,
                    )?)
                }) {
                    tracing::warn!(
                        code = %release.code,
                        "an e-sign notice lease stays leased until its claim runs out"
                    );
                }
                EsignNoticeOutcome {
                    error_code: Some(error.code),
                    error: Some(error.message),
                    ..EsignNoticeOutcome::door(attempt_ref, notice, "error")
                }
            }
        }
    }
}

/// The OF-327 email send for one claimed notice: the stored recipient
/// address as target, the stored triggering event as a record transition,
/// the stored principal as actor, which the caller is. The receipt id and
/// time are the try's own, so they hold on a replay of the try.
fn notice_request(
    attempt: &AttemptRecord,
    notice: &EsignNotice,
    actor: EntityId,
    class: crate::edge::EdgeActorClass,
) -> MemoryResult<OutboundDispatchRequest> {
    let (Some(principal), Some(event_ref)) = (&notice.principal, &notice.event_ref) else {
        return Err(MemoryError::bad_request("the notice records no origin"));
    };
    let try_ref = format!(
        "esign-notice:{}:{}",
        crate::entity_id::bytes_to_hex_lower(attempt.id.as_bytes()),
        attempt.attempt_count
    );
    Ok(OutboundDispatchRequest::new(
        format!("receipt:{try_ref}"),
        try_ref,
        OutboundIntent::from_trigger(
            OutboundIntentDraft::new(principal.clone(), "send", "email", notice.email.clone()),
            OutboundIntentTrigger::record_transition(event_ref.clone()),
        ),
        OutboundDispatchActor {
            actor_class: class.gate_actor_class().to_owned(),
            actor_ref: Some(principal.clone()),
            actor_entity_ref: Some(actor),
        },
        OutboundDispatchGate::allow_when_policy_grants(),
        attempt.updated_at,
        OutboundDeliveryWindowDecision::DeliverNow,
    ))
}
