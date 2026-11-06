//! Native model wording for the durable commitment-reminder queue.
//! Fixed reminders never wait for this worker or for model wording.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::attempt_queue::{
    AcceptAttemptLanding, AttemptQueue, AttemptRecord, AttemptResumePoint, AttemptState,
    ClaimAttempt, ClaimOutcome, CompleteAttempt, FinishAttemptLanding, LandingTrigger,
    RetryAttempt,
};
use oneiron::code_run::model_call::{ModelCallDigests, model_call_digests};
use oneiron::commitment_wake::{
    COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND, CommitmentReminderWordingPayload,
    CommitmentReminderWordingRead, CommitmentReminderWordingRequest,
    CommitmentReminderWordingSource,
};
use oneiron::settings::{ReadDestination, ReleaseHold};
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, LlmMessage,
    LlmMessageRole, LlmRequest, ModelTierRef, ResponseFormat, TierPrecedence, Vault, WriteActor,
};
use tokio::sync::{broadcast, watch};

use super::{AiHandle, CHAT_ROLE};
use crate::config::models::{DreamerWording, ModelsConfig};
use crate::models::{SourceAdmission, SourceOffer};
use crate::server::blocking;

const LEASE_OWNER: &str = "oneiron-server-commitment-reminder-wording";
const PURPOSE: &str = "commitment_reminder_wording";

/// The new automatic wording execution, minted only by the native claim loop.
/// Its actor is this executor, not the historical commitment's caller.
struct WordingExecution<'a> {
    vault: &'a Vault,
    attempt: &'a AttemptRecord,
    actor: WriteActor,
    no_record_at_arrival: bool,
}

impl<'a> WordingExecution<'a> {
    fn from_claim(vault: &'a Vault, attempt: &'a AttemptRecord) -> Result<Self, &'static str> {
        let actor =
            blocking(|| vault.dreamer_authority()).map_err(|_| "wording_budget_unavailable")?;
        let no_record_at_arrival =
            blocking(|| vault.model_call_keeps_no_record_for(None, Some(actor.entity_ref())));
        Ok(Self {
            vault,
            attempt,
            actor,
            no_record_at_arrival,
        })
    }

    fn keeps_no_record(&self) -> bool {
        self.no_record_at_arrival
            || self
                .vault
                .model_call_keeps_no_record_for(None, Some(self.actor.entity_ref()))
    }
}

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
                let result = match WordingExecution::from_claim(&vault, &attempt) {
                    Ok(execution) => word(&execution, &ai, &wording, stopped.clone()).await,
                    Err(reason) => Err(reason),
                };
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
            COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: LEASE_OWNER.to_owned(),
                now: vault.now_recorded_at(),
            },
        )
    }) {
        Ok(ClaimOutcome::Claimed(attempt)) => Some(attempt),
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "reminder wording claim failed");
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
    format!("commitment-reminder-wording:{id}")
}

async fn word(
    execution: &WordingExecution<'_>,
    ai: &AiHandle,
    wording: &DreamerWording,
    mut stopped: watch::Receiver<bool>,
) -> Result<(), &'static str> {
    let vault = execution.vault;
    let attempt = execution.attempt;
    if !active(vault, attempt) {
        return Err("wording_attempt_stopped");
    }
    let payload: CommitmentReminderWordingPayload =
        serde_json::from_slice(&attempt.payload).map_err(|_| "wording_payload_invalid")?;
    let present = blocking(|| vault.commitment_reminder_wording_request(&payload))
        .map_err(|_| "wording_source_read_failed")?
        .is_some();
    if !present {
        return Ok(());
    }
    let persona = match payload.voice.persona_ref.as_deref() {
        None => None,
        Some(reference) => Some(
            wording
                .commitment_reminder_persona(reference)
                .ok_or("wording_persona_not_configured")?,
        ),
    };
    let seat = ai.chat_seat().ok_or("wording_model_not_configured")?;
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
        // Stored reminder data enters only in the destination-admitted hook.
        messages: vec![message(
            LlmMessageRole::System,
            wording.commitment_reminder_instruction().to_owned(),
        )],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    };
    let call = ai
        .admit_role(vault, CHAT_ROLE, request)
        .map_err(|_| "wording_role_refused")?;
    let id = run_id(attempt);
    let meter = blocking(|| {
        vault.policy_budget_guard(
            id.clone(),
            ai.chat_settings().turn_budget_units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS,
            BudgetExhaustionPolicy::Suspend,
            execution.actor,
        )
    })
    .map_err(|_| "wording_budget_unavailable")?;
    let run = ai.undeclared_run(id, meter);
    let sources = ReminderSources {
        vault,
        attempt,
        payload: &payload,
        wording,
        persona,
        stopped: stopped.clone(),
        sent: Mutex::new(None),
        captured_request: Mutex::new(None),
    };
    let mut signals = AttemptQueue::new(vault).subscribe();
    let generation = call
        .ladder
        .generate_admitted_recorded(&run, call.request, None, &sources);
    tokio::pin!(generation);
    let (response, binding) = loop {
        tokio::select! {
            biased;
            _ = stopped.wait_for(|stop| *stop) => return Err("wording_host_stopped"),
            result = &mut generation => break result.map_err(|_| "wording_model_call_failed")?,
            signal = signals.recv() => {
                if matches!(signal, Err(broadcast::error::RecvError::Closed))
                    || !active(vault, attempt) { return Err("wording_attempt_stopped") }
            }
        }
    };
    let captured_request = sources
        .captured_request
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some((digests, tools_present)) = captured_request
        && !blocking(|| execution.keeps_no_record())
    {
        blocking(|| {
            super::model_call_capture::record_generated_response(
                vault,
                None,
                digests,
                tools_present,
                &response,
                &binding,
                attempt,
                execution.actor,
                false,
            );
        });
    }
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
        .ok_or("wording_source_not_sent")?;
    if sources.recheck(&destination).is_some() {
        return Err("wording_source_changed");
    }
    blocking(|| {
        vault.file_commitment_reminder_wording_attempt(
            attempt.id,
            LEASE_OWNER,
            attempt.attempt_count,
            source.head,
            source.revision,
            &text,
            vault.now_recorded_at(),
        )
    })
    .map_err(|error| {
        tracing::warn!(kind = ?error.kind(), "reminder wording was not filed");
        "wording_filing_failed"
    })
}

struct ReminderSources<'a> {
    vault: &'a Vault,
    attempt: &'a AttemptRecord,
    payload: &'a CommitmentReminderWordingPayload,
    wording: &'a DreamerWording,
    persona: Option<&'a str>,
    stopped: watch::Receiver<bool>,
    sent: Mutex<Option<(ReadDestination, CommitmentReminderWordingSource)>>,
    captured_request: Mutex<Option<(ModelCallDigests, bool)>>,
}

impl ReminderSources<'_> {
    fn admitted(
        &self,
        destination: &ReadDestination,
    ) -> Result<CommitmentReminderWordingSource, &'static str> {
        if *self.stopped.borrow() || !active(self.vault, self.attempt) {
            return Err(ReleaseHold::Placement.reason());
        }
        match blocking(|| {
            self.vault
                .commitment_reminder_wording_source_for(self.payload, destination)
        }) {
            Ok(CommitmentReminderWordingRead::Ready(source)) => Ok(source),
            Ok(CommitmentReminderWordingRead::Held(hold)) => Err(hold.reason()),
            Ok(CommitmentReminderWordingRead::Missing) => Err(ReleaseHold::Placement.reason()),
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "reminder wording source admission failed");
                Err(ReleaseHold::Placement.reason())
            }
        }
    }
}

impl SourceAdmission for ReminderSources<'_> {
    fn capture_request(&self, request: &LlmRequest) {
        let captured = match model_call_digests(request) {
            Ok(digests) => Some((digests, !request.tools.is_empty())),
            Err(error) => {
                tracing::warn!(%error, "reminder wording model-call digests failed");
                None
            }
        };
        *self
            .captured_request
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = captured;
    }

    fn offer(&self, request: &LlmRequest, destination: &ReadDestination) -> SourceOffer {
        let source = match self.admitted(destination) {
            Ok(source) => source,
            Err(reason) => return SourceOffer::Held(reason),
        };
        let mut offered = request.clone();
        offered.messages = messages(&source.request, self.wording, self.persona);
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
        (sent.head != now.head || sent.revision != now.revision || sent.request != now.request)
            .then(|| ReleaseHold::Placement.reason())
    }
}

fn message(role: LlmMessageRole, text: String) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text { text, signature: None }],
    }
}

fn messages(
    request: &CommitmentReminderWordingRequest,
    wording: &DreamerWording,
    persona: Option<&str>,
) -> Vec<LlmMessage> {
    let data = serde_json::json!({
        "reader": request.reader.as_str(), "phase": request.phase.as_str(), "promise": request.promise,
        "due": request.due, "fixed_text": request.fixed_text, "persona": persona,
    })
    .to_string();
    vec![
        message(
            LlmMessageRole::System,
            wording.commitment_reminder_instruction().to_owned(),
        ),
        message(LlmMessageRole::User, data),
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
                    status: Some("reminder wording stopped".to_owned()),
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
        tracing::warn!(kind = ?error.kind(), attempt = ?attempt.id, "reminder wording was not settled");
    }
}
