//! System One reads sharing their ordinary and captured request boundaries.

use std::collections::BTreeMap;

use oneiron::code_run::model_call::NativeReadOutcome;
use oneiron::llm::decision::{
    AnswerContract, DecisionCallContext, DecisionReadOutcome, RemoteDecisionCapability, SeatRead,
};
use oneiron::llm::run_admission::RunAdmission;
use oneiron_llm_systemone::PreparedSystemOneRead;

use crate::decision_verdict::{ModelCallCaller, model_call_context};
use crate::models::native_call_capture::{NativeReadCapture, native_read_failure};

use super::{
    CallOutcome, DecisionAnswer, DecisionCall, DecisionPack, ProviderDecision, RemoteDecisionSeat,
    SeatPhase, SeatRequest, SystemOneRung,
};

impl SystemOneRung {
    pub(super) fn decide_pack_with_context(
        &self,
        pack: &DecisionPack<'_>,
        context: Option<&DecisionCallContext<'_>>,
    ) -> oneiron::Result<Vec<DecisionReadOutcome<ProviderDecision>>> {
        let mut decisions = Vec::new();
        let mut stopped = false;
        for call in (0..pack.questions.len()).filter_map(|index| pack.call(index)) {
            let outcome = if stopped {
                DecisionReadOutcome::NotStarted
            } else {
                self.decide_with_context(&call, context)?
            };
            stopped = matches!(
                &outcome,
                DecisionReadOutcome::NotStarted | DecisionReadOutcome::Stopped
            );
            decisions.push(outcome);
        }
        Ok(decisions)
    }

    pub(super) fn decide_with_context(
        &self,
        call: &DecisionCall<'_>,
        context: Option<&DecisionCallContext<'_>>,
    ) -> oneiron::Result<DecisionReadOutcome<ProviderDecision>> {
        let failed = |what: &str| oneiron::Error::InvalidConfig(format!("system one: {what}"));
        let abstain = ProviderDecision {
            answer: DecisionAnswer::Abstain,
            probability: None,
            paired: None,
            person: None,
            served: None,
        };
        let score_levels = call.score_levels().unwrap_or_default();
        if matches!(call.question.contract, AnswerContract::Score { .. }) && score_levels.is_empty()
        {
            return Ok(DecisionReadOutcome::Answered(abstain));
        }
        let request = SeatRequest {
            question: call.question.clone(),
            state: call.state.clone(),
            images: call.images.to_vec(),
            audio: call.audio.to_vec(),
            score_levels,
            posture: self.posture,
            remote_opt_in: self.remote_opt_in,
            phase: SeatPhase::Background,
        };
        // More levels than the seat reads passes it over (FIX 9909).
        if !RemoteDecisionCapability::default().takes(&request) {
            return Ok(DecisionReadOutcome::Answered(abstain));
        }
        request
            .validate_remote()
            .map_err(|_| failed("the posture or the request keeps this call local"))?;
        // A broker or key that is not there refuses the call before its
        // measurement starts.
        self.seat
            .preflight()
            .map_err(|_| failed("its credential broker or vault-secret key is not there"))?;
        if context.is_some_and(|context| !context.admit_generation()) {
            return Ok(DecisionReadOutcome::NotStarted);
        }
        // An extraction-admitted purpose with an explicit catalog binding
        // prepares the actual native request once and admits its
        // content-complete view before any paid step.
        let prepared = match (context, self.native_catalog.clone()) {
            (Some(context), Some(catalog))
                if *oneiron::inference_context::admitted_as(context.purpose)
                    == oneiron::llm::CallPurpose::Extraction =>
            {
                let prepared = self
                    .runtime
                    .block_on(self.seat.prepare_read(
                        request.clone(),
                        call.deadline.decision_time_left(),
                    ))
                    .map_err(|_| failed("the native request failed to build"))?;
                let admission =
                    extraction_admission_request(&prepared, context, &catalog)?;
                self.vault
                    .authorize_raw_inference(
                        admission,
                        &oneiron::llm::HostInferenceContext {
                            binding: oneiron::llm::HostInferenceBinding::Advertised {
                                model: catalog.clone(),
                                locality: oneiron::ModelLocality::ThirdParty,
                                keyless: false,
                            },
                            extraction_egress: context.extraction_egress,
                        },
                    )
                    .map_err(|_| failed("refused by native catalog admission"))?;
                Some(prepared)
            }
            _ => None,
        };
        // A call that carries its caller's run measures on it (FIX 10443).
        if let Some(run) = call.run {
            return self
                .decide_on_run(call, request, run, context.is_some(), prepared)
                .map(DecisionReadOutcome::Answered);
        }
        // Inside a verdict, use the caller's own line and room payer (FIX 1123,
        // FIX 3795); outside one, keep the rung's meter and the vault owner.
        let guard = crate::decision_verdict::rung_meter(&self.guard);
        let run = self
            .models
            .funded_run(
                self.connector.connector.clone(),
                guard.clone(),
                crate::decision_verdict::rung_payer(),
            )
            .sourced(Some(call.evidence.to_vec()));
        let permit = run
            .admit_paid(&self.connector, guard.reserve_units())
            .map_err(|_| failed("refused by the budget"))?;
        run.dispatch_paid(permit.lease(), &self.connector)
            .map_err(|_| failed("refused at dispatch"))?;
        // A measurement admitted after the work time is spent never starts.
        if call.deadline.decision_time_left().is_zero() {
            permit
                .settle(CallOutcome::Failed)
                .map_err(|_| failed("settlement refused"))?;
            return Err(failed("admitted after the work time"));
        }
        let asked = match prepared {
            Some(prepared) => self.runtime.block_on(async {
                let cancel = call.deadline.work_cancel();
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => Err(failed("the seat call was cancelled")),
                    read = prepared.ask_recorded(
                        permit.lease(),
                        call.deadline.decision_time_left(),
                        None,
                    ) => read.result.map_err(|error| failed(&format!("the seat failed: {error}"))),
                }
            }),
            None => self.runtime.block_on(async {
                let cancel = call.deadline.work_cancel();
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => Err(failed("the seat call was cancelled")),
                    result = self.seat.ask(
                        request,
                        permit.lease(),
                        call.deadline.decision_time_left(),
                    ) => result.map_err(|error| failed(&format!("the seat failed: {error}"))),
                }
            }),
        };
        let answer = match asked {
            Ok(answer) => {
                permit
                    .settle(CallOutcome::Answered(&answer.usage))
                    .map_err(|_| failed("settlement refused"))?;
                answer
            }
            Err(error) => {
                // The seat may still bill a failed or cancelled call.
                permit
                    .settle(CallOutcome::Failed)
                    .map_err(|_| failed("settlement refused"))?;
                return Err(error);
            }
        };
        let abstained = answer.answer == DecisionAnswer::Abstain;
        Ok(DecisionReadOutcome::Answered(ProviderDecision {
            answer: answer.answer,
            probability: (!abstained).then_some(answer.probability),
            paired: None,
            person: None,
            served: None,
        }))
    }

    /// [`DecisionProvider::decide`] for a call that carries its caller's run (FIX 10443):
    /// the measurement admits on that run as this rung's paid connector, sourced with
    /// the call's evidence, and settles there; the seat's own meter is untouched. The
    /// caller's run carries its own line, so no verdict meter wraps it.
    fn decide_on_run(
        &self,
        call: &DecisionCall<'_>,
        request: SeatRequest,
        run: &RunAdmission,
        capturing: bool,
        prepared: Option<PreparedSystemOneRead<'_>>,
    ) -> oneiron::Result<ProviderDecision> {
        let failed = |what: &str| oneiron::Error::InvalidConfig(format!("system one: {what}"));
        let run = run.sourced(Some(call.evidence.to_vec()));
        let run = if capturing {
            run.capturing_settlements()
        } else {
            run
        };
        let permit = run
            .admit_paid(&self.connector, run.declaration().budget().reserve_units)
            .map_err(|_| failed("refused by the budget"))?;
        run.dispatch_paid(permit.lease(), &self.connector)
            .map_err(|_| failed("refused at dispatch"))?;
        // A measurement admitted after the work time is spent never starts; the
        // dispatched permit's drop keeps its reservation as spend, as the own-meter
        // path's settlement does.
        if call.deadline.decision_time_left().is_zero() {
            return Err(failed("admitted after the work time"));
        }
        let caller = (!run.is_unrecorded()).then(model_call_context).flatten();
        let no_record_at_arrival = caller.as_ref().is_some_and(|caller| {
            self.vault
                .model_call_keeps_no_record_for(caller.session.as_deref(), Some(caller.principal))
        });
        let asked = match prepared {
            Some(prepared) => super::run_native_read(&run, || match run.send_guard() {
                Some(guard) => {
                    let release = || {
                        if guard() {
                            Ok(())
                        } else {
                            Err(oneiron::llm::FatalLlmError::Auth.into())
                        }
                    };
                    self.runtime.block_on(prepared.ask_recorded(
                        permit.lease(),
                        call.deadline.decision_time_left(),
                        Some(&release),
                    ))
                }
                None => self.runtime.block_on(prepared.ask_recorded(
                    permit.lease(),
                    call.deadline.decision_time_left(),
                    None,
                )),
            }),
            None => super::run_native_read(&run, || match run.send_guard() {
                Some(guard) => {
                    let release = || {
                        if guard() {
                            Ok(())
                        } else {
                            Err(oneiron::llm::FatalLlmError::Auth.into())
                        }
                    };
                    self.runtime.block_on(self.seat.ask_recorded_released(
                        request,
                        permit.lease(),
                        call.deadline.decision_time_left(),
                        &release,
                    ))
                }
                None => self.runtime.block_on(self.seat.ask_recorded(
                    request,
                    permit.lease(),
                    call.deadline.decision_time_left(),
                )),
            }),
        };
        // Observe only after the original settlement attempt. Its failure
        // still wins over the provider result exactly as before.
        let settled = match &asked.result {
            Ok(answer) => permit.settle(CallOutcome::Answered(&answer.usage)),
            // The seat may still bill a failed call.
            Err(_) => permit.settle(CallOutcome::Failed),
        };
        self.record_seat_read(&run, caller.as_ref(), no_record_at_arrival, &asked);
        settled.map_err(|_| failed("settlement refused"))?;
        let answer = match asked.result {
            Ok(answer) => answer,
            Err(error) => return Err(failed(&format!("the seat failed: {error}"))),
        };
        let abstained = answer.answer == DecisionAnswer::Abstain;
        Ok(ProviderDecision {
            answer: answer.answer,
            probability: (!abstained).then_some(answer.probability),
            paired: None,
            person: None,
            served: None,
        })
    }

    fn record_seat_read(
        &self,
        run: &RunAdmission,
        caller: Option<&ModelCallCaller>,
        no_record_at_arrival: bool,
        read: &SeatRead,
    ) {
        let Some(caller) = caller else {
            return;
        };
        let outcome = match &read.result {
            Ok(answer) => NativeReadOutcome::Completed {
                usage: answer.usage.clone(),
            },
            Err(error) => {
                let Some(failure) = native_read_failure(error) else {
                    tracing::warn!("native-seat evidence skipped: unmapped terminal failure");
                    return;
                };
                // Keep the class only, never the provider error's contents.
                NativeReadOutcome::Failed {
                    failure,
                    usage: None,
                }
            }
        };
        let Some(capture) = NativeReadCapture::from_seat(
            self.vault.as_ref(),
            read.request.clone(),
            caller.principal,
            caller.session.clone(),
            no_record_at_arrival,
        ) else {
            return;
        };
        let pin = self.seat.pin();
        capture.record(
            run,
            || run.next_model_call_index(),
            &pin.model,
            &pin.version,
            self.connector.locality,
            outcome,
        );
    }
}

/// The content-complete admission view of one exact prepared native request:
/// one text part carrying the whole prepared body as UTF-8, with the actual
/// endpoint, non-credential headers and wire model inside `provider_options`.
/// Internal admission only; the physical request remains the prepared bytes.
fn extraction_admission_request(
    prepared: &PreparedSystemOneRead<'_>,
    context: &DecisionCallContext<'_>,
    catalog: &oneiron::llm::ModelId,
) -> oneiron::Result<oneiron::LlmRequest> {
    let failed = |what: &str| oneiron::Error::InvalidConfig(format!("system one: {what}"));
    let sent = prepared.request();
    let text = std::str::from_utf8(&sent.body)
        .map_err(|_| failed("the prepared native body is not UTF-8"))?;
    let mut provider_options = BTreeMap::new();
    provider_options.insert(
        "system_one".to_owned(),
        serde_json::json!({
            "endpoint": sent.endpoint,
            "headers": sent.headers.iter().map(|(name, value)| serde_json::json!({"name": name, "value": value})).collect::<Vec<_>>(),
            "wire_model": sent.model,
        }),
    );
    Ok(oneiron::LlmRequest {
        model: catalog.clone(),
        envelope: oneiron::CallEnvelope {
            seat_effort: None,
            scope: context.scope.clone(),
            tier: oneiron::TierPrecedence::for_purpose(
                context.purpose,
                oneiron::ModelTierRef("system-one".to_owned()),
            ),
            purpose: context.purpose.clone(),
            class: oneiron::CallClass::BestEffort,
            response_format: oneiron::ResponseFormat::Text,
            locality: oneiron::ModelLocality::ThirdParty,
            host_keyless: false,
        },
        messages: vec![oneiron::LlmMessage {
            role: oneiron::LlmMessageRole::User,
            content: vec![oneiron::ContentPart::Text {
                text: text.to_owned(),
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options,
        host_segments: None,
    })
}
