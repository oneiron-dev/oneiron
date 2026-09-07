//! Outbound schedule/dispatch and the calendar read/search/freebusy/invite
//! surface. Split from the flat `facade.rs`; surface re-exported by [`super`].

use super::support::*;
use super::*;

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::attempt_queue::{AttemptId, AttemptQueue, EnqueueAttempt, EnqueueOutcome};
use crate::calendar::{
    CalendarEventView, CalendarRangeDto, CalendarReadRequest, CalendarSearchRequest, CalendarSel,
};
use crate::delivery_window::{DeliveryWindowApnsInterruptionLevel, DeliveryWindowResolvedLevel};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchError,
    OutboundDispatchGate, OutboundDispatchOutcome, OutboundDispatchRequest,
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent,
    OutboundIntentDraft, OutboundIntentTrigger, connector_send_attempt_payload,
    outbound_verb_contract, put_connector_send_task_in_txn,
};
use crate::receipt::delivered_send_receipt_for_task;
use crate::temporal::TimeRange;

/// Attempt-queue kind for bridge-scheduled outbound intents. Pending schedules
/// use the queue's kind-scoped dedupe index; delivered sends use the additive
/// durable client-idempotency index.
pub const BRIDGE_OUTBOUND_ATTEMPT_KIND: &str = "bridge.outbound.schedule";

/// Bound on the `retry_of` climb behind an `already_scheduled` receipt, the
/// same 64 steps the run-root climb uses.
///
/// The walk is infallible by construction — the dedupe hit itself is the floor
/// — so this cap only decides how far back a receipt may recover an origin, and
/// guarantees a fabricated chain can never make a replay hang.
const RETRY_LINEAGE_WALK_LIMIT: usize = 64;

/// One outbound schedule request (BRIDGE-03; rides OF-327 — the bridge
/// never implements delivery).
/// Host-supplied clock authority frozen on a connector TASK. No counterparty timezone is read.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OutboundScheduleContext {
    pub utc_offset_minutes: Option<i16>,
    pub iana_timezone: Option<String>,
    pub human_explicit_instant: bool,
    pub apns_interruption_level: Option<DeliveryWindowApnsInterruptionLevel>,
    /// Host-resolved level for a compatibility verb whose manifest name alone
    /// cannot decide ambient vs interrupt (a `telegram|line|imessage` `send`).
    /// The engine never guesses this from the verb string.
    pub resolved_level: Option<DeliveryWindowResolvedLevel>,
}

impl OutboundScheduleContext {
    fn validate(&self) -> MemoryResult<()> {
        if self.iana_timezone.is_some() && self.utc_offset_minutes.is_none() {
            return Err(MemoryError::bad_request_with(
                "iana_timezone requires utc_offset_minutes",
                &["Supply the current civil UTC offset."],
            ));
        }
        if self
            .utc_offset_minutes
            .is_some_and(|offset| !(-840..=840).contains(&offset))
        {
            return Err(MemoryError::bad_request_with(
                "utc_offset_minutes must be in -840..=840",
                &["Supply a current civil UTC offset."],
            ));
        }
        if self.iana_timezone.as_deref().is_some_and(|label| {
            label.trim().is_empty() || label.chars().any(char::is_control) || label.len() > 255
        }) {
            return Err(MemoryError::bad_request_with(
                "iana_timezone must be non-blank and contain no controls",
                &["Supply a valid IANA label as provenance."],
            ));
        }
        // A send cannot be both an APNs push and a resolved plain chat.
        if self.apns_interruption_level.is_some()
            && self
                .resolved_level
                .is_some_and(DeliveryWindowResolvedLevel::is_plain_chat)
        {
            return Err(MemoryError::bad_request_with(
                "an APNs push cannot resolve to plain chat",
                &["Drop the APNs level, or resolve the send as push."],
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundDraftInput {
    /// Verb (e.g. `send`).
    pub verb: String,
    /// Channel (e.g. `email`).
    pub channel: String,
    /// Delivery target (address/handle).
    pub target: String,
    /// Principal the send acts for, if delegated.
    pub on_behalf_of: Option<String>,
    /// Reference to the content entity to send.
    pub content_ref: Option<String>,
    /// Facade-enforced idempotency key: a second schedule with the same
    /// key coalesces instead of double-enqueueing.
    pub idempotency_key: Option<String>,
    /// Advisory dedupe key carried onto the receipt.
    pub dedupe_key: Option<String>,
    /// Trigger source: `commitment_timer_wake` | `gap_queue` |
    /// `agent_immediate`.
    pub trigger: String,
    /// What fired the trigger (commitment/session/queue ref).
    pub trigger_ref: String,
    /// Owning attempt/brief ref, if any.
    pub job_ref: Option<String>,
    /// Unix seconds; `None` ⇒ now.
    pub occurred_at: Option<u64>,
}

/// Receipt for one scheduled outbound intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundIntentReceipt {
    /// Stable intent ref (`intent:<attempt-hex>`).
    pub intent_ref: String,
    /// Dispatch outcome (`held` expected on this schedule-only surface;
    /// `suppressed` on gate denial; `already_scheduled` for a pending schedule
    /// dedupe; `already_sent` for a durable delivered-send dedupe).
    pub outcome: String,
    /// Gate outcome (`allow`/`pending`/`deny`). On dedupe this re-surfaces
    /// the first schedule's outcome (absent only if its binding is missing).
    pub gate_outcome: Option<String>,
    /// Persisted gate decision ref (`gate:<hex>`), queryable via
    /// [`Memory::receipts`]. On dedupe this re-surfaces the first
    /// schedule's decision (absent only if its binding is missing).
    pub gate_decision_ref: Option<String>,
    /// Gate reason codes.
    pub gate_reason_codes: Vec<String>,
    /// True when the idempotency key coalesced onto an existing schedule.
    pub deduped: bool,
}

/// Connector key the calendar invite surface schedules against. CAL-04
/// (ONE-1786) landed the `calendar` connector manifest, so
/// `outbound_verb_contract` now resolves this pair.
pub const CALENDAR_INVITE_OUTBOUND_CHANNEL: &str = "calendar";

/// Outbound verb the calendar invite surface schedules.
///
/// This string is the seam with CAL-04 (ONE-1786), which registered
/// `calendar.invite` in `COMMON_OUTBOUND_VERB_KINDS` and branches on it at the
/// dispatch chokepoint. A shorter local spelling would leave that branch dead
/// on arrival — the invite would schedule as a generic draft and never reach
/// the iMIP payload codec — so the value is pinned to CAL-04's, not to this
/// module's vocabulary, and
/// `calendar::invite::tests::verb_and_channel_match_the_cal_09_surface_constants`
/// keeps the two spellings from drifting apart.
pub const CALENDAR_INVITE_OUTBOUND_VERB: &str = "calendar.invite";

/// iMIP method the invite surface accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CalendarInviteSurfaceMethod {
    /// `METHOD:REQUEST` — create or update an invitation.
    Request,
    /// `METHOD:CANCEL` — withdraw an invitation.
    Cancel,
}

impl CalendarInviteSurfaceMethod {
    /// Wire token (`REQUEST` / `CANCEL`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "REQUEST",
            Self::Cancel => "CANCEL",
        }
    }

    /// Parses the wire token. The set is closed: an unrecognized iMIP method is
    /// a typed rejection at the boundary, never a defaulted `REQUEST`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "REQUEST" => Some(Self::Request),
            "CANCEL" => Some(Self::Cancel),
            _ => None,
        }
    }
}

/// C7's exact five-field invite payload.
///
/// Closed on purpose: an [`OutboundDraftInput`] here would let a caller choose
/// its own channel, verb, and trigger, which is precisely the bypass the
/// invite-through-the-gate rule exists to prevent.
///
/// This type *is* the payload CAL-04 (ONE-1786) exact-decodes — five typed
/// fields, uppercase iMIP method, closed to unknown keys. It stays typed all
/// the way to [`Self::outbound_draft`]; nothing here re-parses a key back into
/// a method, uid, or sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarInviteSurfaceInput {
    /// iMIP method.
    pub method: CalendarInviteSurfaceMethod,
    /// EVENT UID the invite addresses.
    pub uid: String,
    /// iTIP SEQUENCE of this revision.
    pub sequence: u32,
    /// Blob ref of the rendered ICS payload.
    pub ics_blob_ref: String,
    /// Delivery target.
    pub recipient: String,
}

impl CalendarInviteSurfaceInput {
    /// Deterministic idempotency key: a retry of the same revision to the same
    /// recipient coalesces instead of scheduling a second invite.
    #[must_use]
    pub fn idempotency_key(&self) -> String {
        format!(
            "calendar.invite:{}:{}:{}:{}",
            self.method.as_str(),
            self.uid,
            self.sequence,
            self.recipient
        )
    }

    /// Trigger ref carried onto the intent.
    #[must_use]
    pub fn trigger_ref(&self) -> String {
        format!("calendar.invite:{}:{}", self.uid, self.sequence)
    }

    /// The generic outbound draft this invite schedules.
    ///
    /// One named site for the whole invite→draft encoding, so the seam CAL-04
    /// (ONE-1786) picks up is testable before its half exists. What is pinned
    /// here: the verb is CAL-04's `calendar.invite`, the channel is the
    /// `calendar` connector, and `recipient`/`ics_blob_ref` ride the typed
    /// `target`/`content_ref` fields.
    ///
    /// KNOWN HOLE, CLOSED BY CAL-04 (ONE-1786): `method`, `uid`, and
    /// `sequence` had no typed home on [`OutboundDraftInput`] or
    /// `OutboundIntentDraft` on the CAL-09 baseline, so they reached the
    /// chokepoint only inside the derived idempotency/trigger strings. CAL-04
    /// added the typed channel it owns —
    /// [`crate::calendar::CalendarInvitePayload`], carried beside the draft
    /// through [`Self::frozen_payload`] below — so nothing here re-parses a key
    /// back into a method, uid, or sequence and the public surface above is
    /// unchanged.
    #[must_use]
    pub fn outbound_draft(&self) -> OutboundDraftInput {
        OutboundDraftInput {
            verb: CALENDAR_INVITE_OUTBOUND_VERB.to_owned(),
            channel: CALENDAR_INVITE_OUTBOUND_CHANNEL.to_owned(),
            target: self.recipient.clone(),
            on_behalf_of: None,
            content_ref: Some(self.ics_blob_ref.clone()),
            idempotency_key: Some(self.idempotency_key()),
            dedupe_key: None,
            // This surface carries no session, so it uses the queue trigger
            // class rather than fabricating an originating-session ref.
            trigger: "gap_queue".to_owned(),
            trigger_ref: self.trigger_ref(),
            job_ref: None,
            occurred_at: None,
        }
    }

    /// The exact five-field body CAL-04 freezes beside the draft.
    ///
    /// The one fill site for the typed payload channel: the surface's own five
    /// typed fields become the invite layer's five typed fields, in order, with
    /// no string round-trip. Crate-private on purpose — the public invite
    /// surface is [`Self`] and nothing else, so no caller can hand the
    /// chokepoint a payload that disagrees with the draft it schedules.
    pub(crate) fn frozen_payload(&self) -> crate::calendar::CalendarInvitePayload {
        crate::calendar::CalendarInvitePayload {
            method: match self.method {
                CalendarInviteSurfaceMethod::Request => {
                    crate::calendar::CalendarInviteMethod::Request
                }
                CalendarInviteSurfaceMethod::Cancel => {
                    crate::calendar::CalendarInviteMethod::Cancel
                }
            },
            uid: self.uid.clone(),
            sequence: self.sequence,
            ics_blob_ref: self.ics_blob_ref.clone(),
            recipient: self.recipient.clone(),
        }
    }

    fn validate(&self) -> MemoryResult<()> {
        for (field, value) in [
            ("uid", self.uid.as_str()),
            ("ics_blob_ref", self.ics_blob_ref.as_str()),
            ("recipient", self.recipient.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(MemoryError::bad_request_with(
                    format!("calendar invite {field} must not be blank"),
                    &["Supply method, uid, sequence, ics_blob_ref, and recipient."],
                ));
            }
        }
        Ok(())
    }
}

/// One source-redacted busy interval, half-open `[start_utc, end_utc)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarFreebusyIntervalDto {
    /// Inclusive half-open start, Unix seconds.
    pub start_utc: u64,
    /// Exclusive half-open end, Unix seconds.
    pub end_utc: u64,
}

/// External freebusy projection: occupancy only.
pub type CalendarFreebusyDto = Vec<CalendarFreebusyIntervalDto>;

/// Rejects an inverted calendar window at the surface boundary.
fn validate_calendar_range(range: Option<CalendarRangeDto>) -> MemoryResult<()> {
    match range {
        Some(range) if !range.is_ordered() => Err(MemoryError::bad_request_with(
            "calendar range start must not exceed end",
            &["Pass an inclusive range with start <= end."],
        )),
        _ => Ok(()),
    }
}

/// Internal side-index record: the gate surface a scheduled outbound attempt's
/// first dispatch produced, persisted by attempt id so an idempotent replay
/// (`EnqueueOutcome::Existing`) can re-surface the original decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OutboundGateBinding {
    gate_outcome: String,
    #[serde(default)]
    gate_decision_ref: Option<String>,
    #[serde(default)]
    gate_reason_codes: Vec<String>,
}

impl Memory<'_> {
    /// Schedules one connector-send TASK through the OF-327 chokepoint. The
    /// bridge never delivers: it gate-checks under a `Hold` window first, then
    /// durably co-commits the shared TASK and ready execution attempt. Thus no
    /// connector worker can claim the send before schedule admission finishes,
    /// while the gate decision remains a queryable governance receipt.
    pub fn schedule_outbound(
        &self,
        draft: &OutboundDraftInput,
    ) -> MemoryResult<OutboundIntentReceipt> {
        self.schedule_outbound_with_context(draft, &OutboundScheduleContext::default())
    }

    pub fn schedule_outbound_with_context(
        &self,
        draft: &OutboundDraftInput,
        schedule_context: &OutboundScheduleContext,
    ) -> MemoryResult<OutboundIntentReceipt> {
        self.schedule_outbound_inner(draft, schedule_context, None)
    }

    /// The single scheduling implementation.
    ///
    /// `calendar_invite` is CAL-04's typed payload channel: the invite surface
    /// is the only producer, and it is not reachable from the public draft type
    /// — which is exactly what keeps a hand-rolled `OutboundDraftInput` from
    /// scheduling an invite. Such a draft still resolves the registered
    /// capability, but it carries no five-field body, so the chokepoint's verb
    /// wall refuses it at the last durable boundary.
    fn schedule_outbound_inner(
        &self,
        draft: &OutboundDraftInput,
        schedule_context: &OutboundScheduleContext,
        calendar_invite: Option<&crate::calendar::CalendarInvitePayload>,
    ) -> MemoryResult<OutboundIntentReceipt> {
        schedule_context.validate()?;
        if schedule_context.apns_interruption_level.is_some()
            && !(draft.channel == "apns" && draft.verb == "push")
        {
            return Err(MemoryError::bad_request_with(
                "APNs interruption level requires an APNs push",
                &["Do not attach APNs levels to chat, email, voice, or ring sends."],
            ));
        }
        let trigger = match draft.trigger.as_str() {
            "commitment" | "commitment_timer_wake" => {
                OutboundIntentTrigger::commitment_timer_wake(draft.trigger_ref.clone())
            }
            "gap_queue" => OutboundIntentTrigger::gap_queue(draft.trigger_ref.clone()),
            "agent_immediate" => OutboundIntentTrigger::agent_immediate(draft.trigger_ref.clone()),
            other => {
                return Err(MemoryError::bad_request_with(
                    format!("unknown outbound trigger {other:?}"),
                    &["Use one of: commitment_timer_wake, gap_queue, agent_immediate."],
                ));
            }
        };
        let trigger = match &draft.job_ref {
            Some(job_ref) => trigger.job_ref(job_ref.clone()),
            None => trigger,
        };
        let originating_session_ref =
            (draft.trigger == "agent_immediate").then(|| draft.trigger_ref.clone());
        let now = draft.occurred_at.unwrap_or_else(crate::unix_seconds_now);

        // A completed attempt no longer owns the generic queue dedupe row.
        // Consult the additive delivered-only index before any new gate or
        // enqueue work so a client retry cannot charge or send twice.
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        if let Some(idempotency_key) = draft.idempotency_key.as_deref()
            && let Some(task_ref) = self
                .vault
                .store
                .get_delivered_send_task_by_idempotency(&self.actor, idempotency_key)?
        {
            let receipt =
                delivered_send_receipt_for_task(self.vault, task_ref)?.ok_or_else(|| {
                    MemoryError::from(Error::CorruptedIndex("send idempotency index"))
                })?;
            let actor_ref = self.actor.to_hex();
            if receipt.actor.as_deref() != Some(actor_ref.as_str())
                || receipt.fields.get("idempotency_key").map(String::as_str)
                    != Some(idempotency_key)
            {
                return Err(MemoryError::from(Error::CorruptedIndex(
                    "send idempotency index",
                )));
            }
            return Ok(OutboundIntentReceipt {
                intent_ref: receipt
                    .fields
                    .get("intent_ref")
                    .cloned()
                    .unwrap_or_else(|| format!("intent:task:{}", task_ref.to_hex())),
                outcome: "already_sent".to_owned(),
                gate_outcome: receipt.fields.get("gate_outcome").cloned(),
                gate_decision_ref: receipt.fields.get("gate_decision_ref").cloned(),
                gate_reason_codes: receipt
                    .fields
                    .get("gate_reason_codes")
                    .map(|codes| {
                        codes
                            .split(',')
                            .filter(|code| !code.is_empty())
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                deduped: true,
            });
        }

        // Pre-validate the channel/verb capability before either the gate or
        // durable enqueue, preserving a clean retry for malformed requests.
        outbound_verb_contract(&draft.channel, &draft.verb).map_err(|capability| {
            MemoryError::bad_request_with(
                format!("unsupported outbound capability: {capability}"),
                &["Use a registered channel/verb pair from the connector manifest."],
            )
        })?;

        let mut intent_draft = OutboundIntentDraft::new(
            self.actor.to_hex(),
            draft.verb.clone(),
            draft.channel.clone(),
            draft.target.clone(),
        );
        if let Some(on_behalf_of) = &draft.on_behalf_of {
            intent_draft = intent_draft.on_behalf_of(on_behalf_of.clone());
        }
        if let Some(content_ref) = &draft.content_ref {
            intent_draft = intent_draft.content_ref(content_ref.clone());
        }
        if let Some(idempotency_key) = &draft.idempotency_key {
            intent_draft = intent_draft.idempotency_key(idempotency_key.clone());
        }
        if let Some(dedupe_key) = &draft.dedupe_key {
            intent_draft = intent_draft.dedupe_key(dedupe_key.clone());
        }
        let intent = OutboundIntent::from_trigger(intent_draft, trigger);

        let queue = AttemptQueue::new(self.vault);
        let task_ref = EntityId::now();
        let payload = connector_send_attempt_payload(task_ref)?;
        // The queue's live-schedule dedupe is scoped by the BOUND EFFECT ACTOR
        // — never `on_behalf_of`, the target, the trigger, the TASK, or any
        // client-controlled content — matching the actor-scoped contract the
        // delivered-send index already keeps. Computed once so the abort-only
        // preflight and the durable enqueue below cannot disagree by a byte.
        let dedupe_actor_ref = self.actor.to_hex();

        // Abort-only enqueue preflight validates queue inputs and recovers an
        // existing live schedule without appending a second Gate decision. A
        // missing key writes only inside this uncommitted transaction and is
        // therefore neither durable nor claimable.
        let mut preflight_txn = self.vault.store.env.write_txn().map_err(Error::from)?;
        verify_actor_binding_in_txn(self.vault, &preflight_txn, self.actor, self.actor_class)?;
        let preflight = queue.enqueue_with_task_ref_and_dedupe_actor_in_txn(
            &mut preflight_txn,
            EnqueueAttempt {
                kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
                payload: payload.clone(),
                dedupe_key: draft.idempotency_key.clone(),
                run_id: draft.job_ref.clone(),
                now,
            },
            None,
            Some(dedupe_actor_ref.as_str()),
        )?;
        drop(preflight_txn);
        if let EnqueueOutcome::Existing(attempt) = preflight {
            return Ok(self.already_scheduled_outbound_receipt(attempt.id));
        }

        // CAL-04 (ONE-1786) chokepoint admission, in its fixed order: exact
        // decode (the typed payload is already decoded above), emit/state
        // validation against the live outbound passport, vault-only hygiene
        // hydration, hygiene evaluation. It runs AFTER the dedupe returns
        // above — a coalesced re-schedule must not re-check or re-bump anything
        // — and BEFORE the gate, so a refused invite consumes no gate decision,
        // no budget, and no queue row. The passport head it produces is applied
        // inside the durable transaction below.
        let invite_admission = match calendar_invite {
            Some(payload) => Some(
                crate::calendar::admit_calendar_invite(self.vault, self.actor, payload, now)
                    .map_err(facade_error_from_calendar)?,
            ),
            None => None,
        };

        let gate_intent_ref = format!("intent:task:{}", task_ref.to_hex());
        let actor = OutboundDispatchActor {
            actor_class: self.actor_class.gate_actor_class().to_owned(),
            actor_ref: Some(self.actor.to_hex()),
            actor_entity_ref: Some(self.actor),
        };
        let mut request = OutboundDispatchRequest::new(
            format!("outbound:{gate_intent_ref}"),
            gate_intent_ref.clone(),
            intent.clone(),
            actor,
            OutboundDispatchGate::allow_when_policy_grants(),
            now,
            OutboundDeliveryWindowDecision::Hold {
                reason: "bridge_scheduled".to_owned(),
                retry_at: None,
            },
        );
        if let Some(session_ref) = originating_session_ref.as_deref() {
            request = request.originating_session(session_ref);
        }
        if let Some(payload) = calendar_invite {
            request = request.calendar_invite(payload.clone());
        }
        let mut sink = ScheduleOnlySink;
        let result = self
            .vault
            .dispatch_outbound_intent_with_verified_actor(
                request,
                &mut sink,
                self.actor,
                self.actor_class,
            )
            .map_err(facade_error_from_outbound_dispatch)?;

        // A denied schedule is fully audited by its Gate decision but never
        // becomes executable. Under the schedule-only Hold window, Held is the
        // sole outcome admitted to the durable queue.
        if result.outcome != OutboundDispatchOutcome::Held {
            return Ok(OutboundIntentReceipt {
                intent_ref: gate_intent_ref,
                outcome: dispatch_outcome_str(&result.outcome).to_owned(),
                gate_outcome: Some(result.gate_outcome),
                gate_decision_ref: result.gate_decision_id,
                gate_reason_codes: result.gate_reason_codes,
                deduped: false,
            });
        }

        let outcome = self.with_verified_actor_write_txn(|wtxn| {
            let outcome = queue.enqueue_with_task_ref_and_dedupe_actor_in_txn(
                wtxn,
                EnqueueAttempt {
                    kind: BRIDGE_OUTBOUND_ATTEMPT_KIND.to_owned(),
                    payload,
                    dedupe_key: draft.idempotency_key.clone(),
                    run_id: draft.job_ref.clone(),
                    now,
                },
                Some(task_ref.to_hex()),
                Some(dedupe_actor_ref.as_str()),
            )?;
            if matches!(&outcome, EnqueueOutcome::Enqueued(_)) {
                put_connector_send_task_in_txn(
                    self.vault,
                    wtxn,
                    task_ref,
                    &intent,
                    self.actor,
                    self.actor_class,
                    originating_session_ref.as_deref(),
                    schedule_context,
                    calendar_invite,
                    now,
                )?;
                // The SEQUENCE bump joins the SAME transaction as the ready
                // attempt and the connector TASK that will replay it. No
                // bumped sequence can survive without its frozen intent,
                // because both commit here or neither does.
                if let Some(admission) = invite_admission.as_ref() {
                    admission
                        .commit_in_txn(self.vault, wtxn, now)
                        .map_err(facade_error_from_calendar)?;
                }
            }
            Ok(outcome)
        })?;
        let attempt = match outcome {
            EnqueueOutcome::Enqueued(attempt) => attempt,
            EnqueueOutcome::Existing(attempt) => {
                return Ok(self.already_scheduled_outbound_receipt(attempt.id));
            }
        };
        let intent_ref = outbound_intent_ref(attempt.id);
        // Persist the gate surface keyed by attempt id so an idempotent replay
        // recovers this decision (best-effort; a missing binding degrades a
        // replay to no gate fields, never a wrong decision) (#484b).
        self.persist_outbound_gate_binding(
            attempt.id,
            &result.gate_outcome,
            result.gate_decision_id.as_deref(),
            &result.gate_reason_codes,
        );
        Ok(OutboundIntentReceipt {
            intent_ref,
            outcome: dispatch_outcome_str(&result.outcome).to_owned(),
            gate_outcome: Some(result.gate_outcome),
            gate_decision_ref: result.gate_decision_id,
            gate_reason_codes: result.gate_reason_codes,
            deduped: false,
        })
    }

    fn already_scheduled_outbound_receipt(&self, attempt_id: AttemptId) -> OutboundIntentReceipt {
        // The live index owner may be a retry CHILD of the row that was
        // actually scheduled, and only the schedule-time row carries the intent
        // ref and Gate binding this receipt owes the caller. So resolve the
        // originating attempt first, then re-surface the ORIGINAL gate decision
        // it persisted. Ownership of the dedupe index never moves back.
        let origin_id = self.outbound_schedule_origin_id(attempt_id);
        let binding = self.outbound_gate_binding(origin_id);
        OutboundIntentReceipt {
            intent_ref: outbound_intent_ref(origin_id),
            outcome: "already_scheduled".to_owned(),
            gate_outcome: binding.as_ref().map(|binding| binding.gate_outcome.clone()),
            gate_decision_ref: binding
                .as_ref()
                .and_then(|binding| binding.gate_decision_ref.clone()),
            gate_reason_codes: binding
                .map(|binding| binding.gate_reason_codes)
                .unwrap_or_default(),
            deduped: true,
        }
    }

    /// Walks `retry_of` back from a dedupe hit to the attempt that was
    /// originally scheduled.
    ///
    /// Infallible and bounded by construction: the hit itself is the floor, a
    /// visited set refuses a cycle, and [`RETRY_LINEAGE_WALK_LIMIT`] caps the
    /// climb. A missing parent, a decode failure, or a parent that disagrees
    /// with its child on kind, dedupe key, TASK backlink, or dedupe actor scope
    /// stops the walk at the deepest ancestor already verified — a receipt
    /// never crosses from one schedule's lineage into another's.
    fn outbound_schedule_origin_id(&self, attempt_id: AttemptId) -> AttemptId {
        let queue = AttemptQueue::new(self.vault);
        let Ok(Some(hit)) = queue.get(attempt_id) else {
            return attempt_id;
        };
        let mut origin_id = attempt_id;
        let mut child = hit;
        let mut visited = HashSet::from([attempt_id]);
        while let Some(parent_id) = child.retry_of {
            if visited.len() >= RETRY_LINEAGE_WALK_LIMIT || !visited.insert(parent_id) {
                break;
            }
            let Ok(Some(parent)) = queue.get(parent_id) else {
                break;
            };
            if parent.kind != child.kind
                || parent.dedupe_key != child.dedupe_key
                || parent.task_ref != child.task_ref
                || parent.dedupe_actor_ref != child.dedupe_actor_ref
            {
                break;
            }
            origin_id = parent_id;
            child = parent;
        }
        origin_id
    }

    /// Persists the gate surface of a scheduled outbound attempt (best-effort).
    fn persist_outbound_gate_binding(
        &self,
        attempt_id: AttemptId,
        gate_outcome: &str,
        gate_decision_ref: Option<&str>,
        gate_reason_codes: &[String],
    ) {
        let binding = OutboundGateBinding {
            gate_outcome: gate_outcome.to_owned(),
            gate_decision_ref: gate_decision_ref.map(ToOwned::to_owned),
            gate_reason_codes: gate_reason_codes.to_vec(),
        };
        if let Ok(encoded) = serde_json::to_vec(&binding) {
            let _ = self
                .vault
                .store
                .put_outbound_gate_binding(attempt_id.as_bytes(), &encoded);
        }
    }

    /// Reads the persisted gate surface of a scheduled outbound attempt, if any.
    fn outbound_gate_binding(&self, attempt_id: AttemptId) -> Option<OutboundGateBinding> {
        self.vault
            .store
            .outbound_gate_binding(attempt_id.as_bytes())
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
    }

    // ── calendar (CAL-09) ───────────────────────────────────────────────

    /// The bound actor's scoped-read lane.
    ///
    /// Calendar bodies are imported foreign content, so this surface reads them
    /// through the policy scoped-read lane rather than raw vault reads: an
    /// actor's calendar view is always a subset of the internal projection.
    fn calendar_read_lane(&self) -> MemoryResult<crate::claim::ScopedRead<'_>> {
        let key = crate::claim::ScopedReadActorKey::with_actor_class(
            self.actor.to_hex(),
            self.actor_class.gate_actor_class(),
        )
        .ok_or_else(|| {
            MemoryError::bad_request("bound actor cannot be used as a scoped read key")
        })?;
        Ok(self.vault.scoped_read(key))
    }

    /// Reads one calendar EVENT under the caller's read scope.
    pub fn calendar_read(
        &self,
        req: &CalendarReadRequest,
    ) -> MemoryResult<Option<CalendarEventView>> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(crate::calendar::read_event_scoped(
            &self.calendar_read_lane()?,
            req,
        )?)
    }

    /// Searches calendar EVENTs under the caller's read scope.
    pub fn calendar_search(
        &self,
        req: &CalendarSearchRequest,
    ) -> MemoryResult<Vec<CalendarEventView>> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        validate_calendar_range(req.range)?;
        Ok(crate::calendar::search_events_scoped(
            &self.calendar_read_lane()?,
            req,
        )?)
    }

    /// Projects busy-only occupancy over `range`, source-redacted.
    ///
    /// The internal `BusyInterval` keeps a representative `source` EVENT for
    /// engine consumers; this external DTO drops it, so an SDK or MCP caller
    /// receives occupancy and nothing else — no name, description, attendee,
    /// meeting link, or entity ref.
    pub fn calendar_freebusy(
        &self,
        calendars: &[CalendarSel],
        range: TimeRange,
    ) -> MemoryResult<CalendarFreebusyDto> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        if range.start > range.end {
            return Err(MemoryError::bad_request_with(
                "calendar freebusy range start must not exceed end",
                &["Pass an inclusive range with start <= end."],
            ));
        }
        let union =
            crate::calendar::freebusy_scoped(&self.calendar_read_lane()?, calendars, range)?;
        Ok(union
            .into_iter()
            .map(|interval| CalendarFreebusyIntervalDto {
                start_utc: interval.start_utc,
                end_utc: interval.end_utc,
            })
            .collect())
    }

    /// Schedules one iMIP-shaped calendar invite through the ordinary outbound
    /// gate.
    ///
    /// The public input is C7's exact five-field payload, never an
    /// [`OutboundDraftInput`]: this surface owns the invite vocabulary and
    /// constructs the generic draft internally, so no caller can hand-roll a
    /// draft that bypasses the invite contract. Delivery is never performed
    /// here — the ordinary schedule path is the only route, and the invite's
    /// UID/SEQUENCE law plus its vault-only hygiene rows are checked at that
    /// chokepoint (CAL-04, ONE-1786) before the gate ever sees the send.
    ///
    /// Nothing about hygiene is an argument here: the five fields below are the
    /// whole public input, and every consent, binding, and sender-domain fact
    /// is read from the vault at the chokepoint. A caller cannot assert its way
    /// past a cold-invite refusal.
    pub fn calendar_invite(
        &self,
        input: &CalendarInviteSurfaceInput,
    ) -> MemoryResult<OutboundIntentReceipt> {
        input.validate()?;
        self.schedule_outbound_inner(
            &input.outbound_draft(),
            &OutboundScheduleContext::default(),
            Some(&input.frozen_payload()),
        )
    }
}

/// Maps a calendar-layer verdict onto the facade error vocabulary.
///
/// A refusal is a `bad_request`, not an internal fault: the engine declining to
/// send a cold invite, an off-domain invite, or a SEQUENCE that does not
/// advance is the correct outcome, and the caller needs to see which law
/// refused. Store failures stay internal.
pub(super) fn facade_error_from_calendar(err: crate::calendar::CalendarError) -> MemoryError {
    match err {
        crate::calendar::CalendarError::InviteRefused { ref reason } => {
            MemoryError::bad_request_with(
                format!("calendar invite refused: {reason}"),
                &[
                    "Invite only after a yes: a prior thread or a confirmed booking grant.",
                    "Send from the primary calendar domain, and advance SEQUENCE on the same UID.",
                ],
            )
        }
        crate::calendar::CalendarError::ImipEmit { ref reason } => MemoryError::bad_request_with(
            format!("iMIP emit failure: {reason}"),
            &["Render the invitation with an explicit METHOD, UID, and zone label."],
        ),
        other => MemoryError::new(
            MEMORY_CODE_INTERNAL,
            format!("calendar invite failed: {other}"),
            &["Retry after checking local storage health."],
        ),
    }
}

pub(super) fn facade_error_from_outbound_dispatch(err: OutboundDispatchError) -> MemoryError {
    match err {
        OutboundDispatchError::Engine(engine) => MemoryError::from(engine),
        OutboundDispatchError::Chokepoint(_) => MemoryError::new(
            MEMORY_CODE_INTERNAL,
            "outbound effect durability failed",
            &["Retry after checking local storage health."],
        ),
        OutboundDispatchError::InvalidBoundActor => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "the bound actor is no longer authorized for outbound dispatch",
            &["Refresh the actor binding and retry."],
        ),
        OutboundDispatchError::UnsupportedCapability(capability) => MemoryError::bad_request_with(
            format!("unsupported outbound capability: {capability}"),
            &["Use a registered channel/verb pair from the connector manifest."],
        ),
    }
}

/// Schedule-only execution sink: unreachable under the `Hold` window this
/// facade always dispatches with; fails closed if a future path ever
/// reaches it — the bridge carries no channel adapters (OF-327).
struct ScheduleOnlySink;

impl OutboundExecutionSink for ScheduleOnlySink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        OutboundExecutionOutcome::failed("bridge schedule-only surface has no channel adapter")
    }
}

fn outbound_intent_ref(attempt_id: AttemptId) -> String {
    format!("intent:{}", hex_string(attempt_id.as_bytes()))
}

pub(super) fn parse_job_ref(job_ref: &str) -> MemoryResult<AttemptId> {
    let reference = job_ref
        .trim()
        .strip_prefix("job:")
        .unwrap_or_else(|| job_ref.trim());
    if reference.len() != 32 || !reference.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(MemoryError::bad_request(format!(
            "attempt ref {job_ref:?} is not a 32-hex attempt id"
        )));
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&reference[index * 2..index * 2 + 2], 16)
            .map_err(|_| MemoryError::bad_request(format!("attempt ref {job_ref:?} is not hex")))?;
    }
    AttemptId::from_bytes(&bytes).map_err(|_| {
        MemoryError::bad_request(format!("attempt ref {job_ref:?} is not an attempt id"))
    })
}

const fn dispatch_outcome_str(outcome: &OutboundDispatchOutcome) -> &'static str {
    match outcome {
        OutboundDispatchOutcome::DeliveredToChannel => "delivered_to_channel",
        OutboundDispatchOutcome::Held => "held",
        OutboundDispatchOutcome::Degraded => "degraded",
        OutboundDispatchOutcome::Suppressed => "suppressed",
        OutboundDispatchOutcome::LetGo => "let_go",
        OutboundDispatchOutcome::Failed => "failed",
    }
}
