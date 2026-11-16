//! The host worker that drafts a meeting's follow-ups (CAL-08; Engine RULING
//! CAL-08-FOLLOWUP-APPROVAL = A, Sun 15 Nov 12:04): it claims each queued
//! `calendar.follow_up.draft` attempt, reads the transcript SESSION for the
//! model's destination, asks the model which follow-ups the owner promised,
//! and files the reply. Each follow-up lands as a draft in the owner's inbox
//! through the engine's door; nothing here sends.
//!
//! The engine owns the read, the reply contract and the filing
//! (`oneiron::calendar::follow_up`); this worker only places the model call
//! between them, as the commitment reminder's wording worker does.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::attempt_queue::{
    AcceptAttemptLanding, AttemptQueue, AttemptRecord, AttemptResumePoint, AttemptState,
    ClaimAttempt, ClaimOutcome, CompleteAttempt, FinishAttemptLanding, LandingTrigger,
    RetryAttempt,
};
use oneiron::calendar::follow_up::{
    MEETING_FOLLOW_UP_DRAFT_ATTEMPT_KIND, MeetingFollowUpDraftPayload, MeetingFollowUpRead,
    MeetingFollowUpRequest, MeetingFollowUpSource,
};
use oneiron::settings::{ReadDestination, ReleaseHold};
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, LlmMessage,
    LlmMessageRole, LlmRequest, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};
use tokio::sync::{broadcast, watch};

use super::{AiHandle, CHAT_ROLE};
use crate::config::models::{DreamerWording, ModelsConfig};
use crate::models::{SourceAdmission, SourceOffer};
use crate::server::blocking;

const LEASE_OWNER: &str = "oneiron-server-meeting-follow-up-drafting";
const PURPOSE: &str = "meeting_follow_up_drafting";

pub(super) fn spawn(vault: &Arc<Vault>, ai: &AiHandle, models: &ModelsConfig) {
    if ai.chat_seat().is_none() {
        return;
    }
    let vault = Arc::downgrade(vault);
    let ai = ai.clone();
    let wording = models.dreamer.wording.clone();
    let backoff = models.workflows.retry_backoff_secs;
    let mut stopped = ai.turns.stop_signal();
    tokio::spawn(async move {
        let Some(mut signals) = vault.upgrade().map(|v| AttemptQueue::new(&v).subscribe()) else {
            return;
        };
        loop {
            while !*stopped.borrow() {
                let Some(vault) = vault.upgrade() else { return };
                let Some(attempt) = claim(&vault) else { break };
                let result = draft(&vault, &ai, &wording, &attempt, stopped.clone()).await;
                blocking(|| settle(&vault, &attempt, result, backoff));
            }
            tokio::select! {
                biased;
                _ = stopped.wait_for(|stop| *stop) => return,
                signal = signals.recv() => {
                    if matches!(signal, Err(broadcast::error::RecvError::Closed)) { return }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(backoff)) => {}
            }
            while let Ok(()) | Err(broadcast::error::TryRecvError::Lagged(_)) = signals.try_recv() {
            }
        }
    });
}

fn claim(vault: &Vault) -> Option<AttemptRecord> {
    match blocking(|| {
        AttemptQueue::new(vault).claim_kind(
            MEETING_FOLLOW_UP_DRAFT_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: LEASE_OWNER.to_owned(),
                now: vault.now_recorded_at(),
            },
        )
    }) {
        Ok(ClaimOutcome::Claimed(attempt)) => Some(attempt),
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "meeting follow-up claim failed");
            None
        }
    }
}

fn owned(vault: &Vault, attempt: &AttemptRecord) -> oneiron::Result<Option<AttemptRecord>> {
    Ok(AttemptQueue::new(vault).get(attempt.id)?.filter(|row| {
        matches!(row.state, AttemptState::Leased | AttemptState::Landing)
            && row.lease_owner.as_deref() == Some(LEASE_OWNER)
            && row.attempt_count == attempt.attempt_count
            && row.kind == attempt.kind
            && row.payload == attempt.payload
            && row.cancel_state.cancellation.is_none()
    }))
}

fn active(vault: &Vault, attempt: &AttemptRecord) -> bool {
    blocking(|| owned(vault, attempt)).is_ok_and(|row| {
        row.is_some_and(|row| {
            row.state == AttemptState::Leased
                && row.cancel_state.landing.is_none()
                && row.cancel_state.pressure.pending == 0
        })
    })
}

fn run_id(attempt: &AttemptRecord) -> String {
    let id: String = attempt
        .id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("meeting-follow-up-drafting:{id}")
}

/// One try of `attempt`. `Ok` completes it: the reply was filed, or no try
/// can draft from it (the SESSION is gone or not a transcript, the read is
/// silent, or the payload or the model's reply is outside its contract).
/// `Err` names the stage that failed, and the attempt is tried again.
async fn draft(
    vault: &Vault,
    ai: &AiHandle,
    wording: &DreamerWording,
    attempt: &AttemptRecord,
    mut stopped: watch::Receiver<bool>,
) -> Result<(), &'static str> {
    if !active(vault, attempt) {
        return Err("follow_up_attempt_stopped");
    }
    let Ok(payload) = serde_json::from_slice::<MeetingFollowUpDraftPayload>(&attempt.payload)
    else {
        tracing::warn!(attempt = ?attempt.id, "a meeting follow-up payload does not decode");
        return Ok(());
    };
    // The widest destination first: a destination only narrows, so a
    // SESSION with nothing to draft here has nothing for any model. One
    // edge: a transcript past the size cap here completes too, though a
    // narrower destination lists fewer recipients and might fit under it.
    match blocking(|| vault.meeting_follow_up_source_for(&payload, &ReadDestination::on_device())) {
        Ok(MeetingFollowUpRead::Missing | MeetingFollowUpRead::Silent(_)) => return Ok(()),
        Ok(MeetingFollowUpRead::Held(_) | MeetingFollowUpRead::Ready(_)) => {}
        Err(_) => return Err("follow_up_source_read_failed"),
    }
    let seat = ai.chat_seat().ok_or("follow_up_model_not_configured")?;
    let purpose = CallPurpose::Other {
        name: PURPOSE.to_owned(),
    };
    let request = LlmRequest {
        model: seat.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(PURPOSE.to_owned())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: seat.locality,
            host_keyless: false,
            host_paid: false,
        },
        // The transcript enters only in the destination-admitted hook.
        messages: vec![message(
            LlmMessageRole::System,
            wording.meeting_follow_up_instruction().to_owned(),
        )],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    };
    let call = ai
        .admit_role(vault, CHAT_ROLE, request)
        .map_err(|_| "follow_up_role_refused")?;
    let id = run_id(attempt);
    let meter = blocking(|| {
        let actor = vault.dreamer_authority()?;
        vault.policy_budget_guard(
            id.clone(),
            ai.chat_settings().turn_budget_units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS,
            BudgetExhaustionPolicy::Suspend,
            actor,
        )
    })
    .map_err(|_| "follow_up_budget_unavailable")?;
    let run = ai.undeclared_run(id, meter);
    let sources = FollowUpSources {
        vault,
        attempt,
        payload: &payload,
        wording,
        stopped: stopped.clone(),
        sent: Mutex::new(None),
    };
    let mut signals = AttemptQueue::new(vault).subscribe();
    let generation = call
        .ladder
        .generate_admitted(&run, call.request, None, &sources);
    tokio::pin!(generation);
    let response = loop {
        tokio::select! {
            biased;
            _ = stopped.wait_for(|stop| *stop) => return Err("follow_up_host_stopped"),
            result = &mut generation => break result.map_err(|_| "follow_up_model_call_failed")?,
            signal = signals.recv() => {
                if matches!(signal, Err(broadcast::error::RecvError::Closed))
                    || !active(vault, attempt) { return Err("follow_up_attempt_stopped") }
            }
        }
    };
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let (destination, source) = sources
        .sent
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .ok_or("follow_up_source_not_sent")?;
    if sources.recheck(&destination).is_some() {
        return Err("follow_up_source_changed");
    }
    match blocking(|| {
        vault.file_meeting_follow_up_drafts_attempt(
            attempt.id,
            LEASE_OWNER,
            attempt.attempt_count,
            &source,
            &text,
        )
    }) {
        Ok(drafts) => {
            tracing::debug!(drafts = drafts.len(), "meeting follow-ups filed");
            Ok(())
        }
        // A reply outside the contract (or a queued row no try can read):
        // asking again spends the budget on the same refusal, so the attempt
        // completes with no draft.
        Err(oneiron::Error::InvalidClaimBody(reason)) => {
            tracing::warn!(reason, "a meeting follow-up reply was refused");
            Ok(())
        }
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "meeting follow-ups were not filed");
            Err("follow_up_filing_failed")
        }
    }
}

struct FollowUpSources<'a> {
    vault: &'a Vault,
    attempt: &'a AttemptRecord,
    payload: &'a MeetingFollowUpDraftPayload,
    wording: &'a DreamerWording,
    stopped: watch::Receiver<bool>,
    sent: Mutex<Option<(ReadDestination, MeetingFollowUpSource)>>,
}

impl FollowUpSources<'_> {
    fn admitted(
        &self,
        destination: &ReadDestination,
    ) -> Result<MeetingFollowUpSource, &'static str> {
        if *self.stopped.borrow() || !active(self.vault, self.attempt) {
            return Err(ReleaseHold::Placement.reason());
        }
        match blocking(|| {
            self.vault
                .meeting_follow_up_source_for(self.payload, destination)
        }) {
            Ok(MeetingFollowUpRead::Ready(source)) => Ok(source),
            Ok(MeetingFollowUpRead::Held(hold)) => Err(hold.reason()),
            // Nothing this destination may draft from: the rung is passed
            // over. When the SESSION has nothing left at all, the next try's
            // first read completes the attempt. When only this destination
            // lacks it (a recipient in a world it may not reach), the attempt
            // retries, as a world hold does, until a model that may see it
            // is configured.
            Ok(MeetingFollowUpRead::Missing | MeetingFollowUpRead::Silent(_)) => {
                Err(ReleaseHold::Placement.reason())
            }
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "meeting follow-up source admission failed");
                Err(ReleaseHold::Placement.reason())
            }
        }
    }
}

impl SourceAdmission for FollowUpSources<'_> {
    fn offer(&self, request: &LlmRequest, destination: &ReadDestination) -> SourceOffer {
        let source = match self.admitted(destination) {
            Ok(source) => source,
            Err(reason) => return SourceOffer::Held(reason),
        };
        let mut offered = request.clone();
        offered.messages = messages(&source.request, self.wording);
        *self.sent.lock().unwrap_or_else(PoisonError::into_inner) =
            Some((destination.clone(), source));
        SourceOffer::Send(offered)
    }

    fn recheck(&self, destination: &ReadDestination) -> Option<&'static str> {
        let sent = self
            .sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some((sent_destination, sent)) = sent.filter(|(sent, _)| sent == destination) else {
            return Some(ReleaseHold::Placement.reason());
        };
        let now = match self.admitted(&sent_destination) {
            Ok(now) => now,
            Err(reason) => return Some(reason),
        };
        (sent.session_ref != now.session_ref
            || sent.revision != now.revision
            || sent.request != now.request)
            .then(|| ReleaseHold::Placement.reason())
    }
}

fn message(role: LlmMessageRole, text: String) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text {
            text,
            signature: None,
        }],
    }
}

fn messages(request: &MeetingFollowUpRequest, wording: &DreamerWording) -> Vec<LlmMessage> {
    vec![
        message(
            LlmMessageRole::System,
            wording.meeting_follow_up_instruction().to_owned(),
        ),
        message(LlmMessageRole::User, request.transcript_message()),
    ]
}

fn settle(vault: &Vault, attempt: &AttemptRecord, result: Result<(), &'static str>, backoff: u64) {
    let settled = (|| -> oneiron::Result<()> {
        let Some(current) = owned(vault, attempt)? else {
            return Ok(());
        };
        let queue = AttemptQueue::new(vault);
        let now = vault.now_recorded_at();
        if current.state == AttemptState::Landing || current.cancel_state.pressure.pending > 0 {
            if current.state != AttemptState::Landing {
                queue.accept_landing(AcceptAttemptLanding {
                    id: attempt.id,
                    lease_owner: LEASE_OWNER.to_owned(),
                    attempt_count: attempt.attempt_count,
                    trigger: LandingTrigger::CancelRequest,
                    status: Some("meeting follow-up drafting stopped".to_owned()),
                    resume_point: Some(AttemptResumePoint {
                        marker: run_id(attempt),
                        artifact_ref: None,
                        recorded_at: now,
                    }),
                    request_sequence: None,
                    now,
                })?;
            }
            queue.finish_landing(FinishAttemptLanding {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                hand_off: false,
                scheduled_at: None,
                now,
            })?;
            return Ok(());
        }
        match result {
            Ok(()) => queue
                .complete(CompleteAttempt {
                    id: attempt.id,
                    lease_owner: LEASE_OWNER.to_owned(),
                    attempt_count: attempt.attempt_count,
                    now,
                })
                .map(drop),
            Err(reason) => queue
                .retry(RetryAttempt {
                    id: attempt.id,
                    lease_owner: LEASE_OWNER.to_owned(),
                    attempt_count: attempt.attempt_count,
                    backoff_until: now.saturating_add(backoff),
                    last_error: Some(reason.to_owned()),
                    now,
                })
                .map(drop),
        }
    })();
    if let Err(error) = settled {
        tracing::warn!(kind = ?error.kind(), attempt = ?attempt.id, "meeting follow-up drafting was not settled");
    }
}
