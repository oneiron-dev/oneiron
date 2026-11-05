//! One Big read, shared by ordinary and captured calls.

use super::{Answerer, BigModel, PURPOSE, abstained, failed, typed};
use crate::models::CallDeadline;
use oneiron::llm::decision::{
    DecisionCall, DecisionCallContext, DecisionPack, ProviderDecision, ProviderPin,
};
use oneiron::{ContentPart, EntityId};

impl BigModel {
    pub(super) fn decide_pack_with_context(
        &self,
        pack: &DecisionPack<'_>,
        context: Option<&DecisionCallContext<'_>>,
    ) -> oneiron::Result<Vec<ProviderDecision>> {
        (0..pack.questions.len())
            .filter_map(|index| pack.call(index))
            .map(|call| self.decide_with_context(&call, context))
            .collect()
    }

    pub(super) fn decide_with_context(
        &self,
        call: &DecisionCall<'_>,
        context: Option<&DecisionCallContext<'_>>,
    ) -> oneiron::Result<ProviderDecision> {
        if call.question.contract.locates() {
            return Ok(abstained());
        }
        let route = self.resolve_decision_route()?;
        let joint = self.joint_read(call, &route);
        let request = self.request(
            call,
            &route,
            joint.as_ref(),
            context.map(|context| context.purpose),
        )?;
        // A route the vault narrowed past what this server serves, or one
        // with no offer the call may go to, ends the call here, before
        // anything leaves.
        let (ladder, request) = self.admit_decision_route_with_egress(
            request,
            context.and_then(|context| context.extraction_egress),
        )?;
        let left = call.deadline.decision_time_left();
        if left.is_zero() {
            return Err(failed("admitted after the work time"));
        }
        if let Some(context) = context {
            context.admit_generation()?;
        }
        // Inside a verdict, the caller's own line (FIX 1123), billing the
        // payer its run binds (FIX 3574).
        // Its input is the question over the state its producer built from
        // the access-checked evidence: those rows, complete (FIX 6935).
        // A call that carries its caller's run spends on it (FIX 10443).
        let run = match call.run {
            Some(run) => {
                let run = run.sourced(Some(call.evidence.to_vec()));
                if context.is_some() {
                    run.capturing_settlements()
                } else {
                    run
                }
            }
            None => self
                .models
                .funded_run(
                    format!("{PURPOSE}:{}", EntityId::now().to_hex()),
                    crate::decision_verdict::rung_meter(&self.meter),
                    crate::decision_verdict::rung_payer(),
                )
                .sourced(Some(call.evidence.to_vec())),
        };
        // FIX 12516/12742 capture: the capture caller bound on this thread,
        // when this decide runs inside a decision's capture scope. The bound
        // optional session is threaded through, `None` only at unbound
        // sources; the room is resolved by the existing session gate, never
        // invented.
        let caller = crate::decision_verdict::model_call_context();
        let no_record_at_arrival = caller.as_ref().is_some_and(|c| {
            self.vault
                .model_call_keeps_no_record_for(c.session.as_deref(), Some(c.principal))
        });
        // The admitted request, kept for the evidence row's digests when a
        // capture runs; the call below moves the original.
        let record_request = caller.is_some().then(|| request.clone());
        // The decision's clock bounds the whole call (FIX 7792): every send,
        // wait and fallback; past it the call ends incomplete, every rung it
        // admitted settled.
        let deadline = CallDeadline::caller_with_wait_cap(left, ladder.cooling_wait_budget(left));
        // A seat's answer names the rung model that served it; one model
        // alone answers or nothing does, so its pin names it already.
        let (response, served, binding) = self
            .runtime
            .block_on(async {
                match &self.answerer {
                    Answerer::Seat(_) => ladder
                        .generate_recorded_by(&run, request, None, &|| true, deadline)
                        .await
                        .map(|(response, binding)| {
                            (response, Some(binding.rung.model.clone()), binding)
                        }),
                    Answerer::Model(_) => ladder
                        .generate_exact_recorded_by(&run, request, None, &|| true, deadline)
                        .await
                        .map(|(response, binding)| (response, None, binding)),
                }
            })
            .map_err(|error| failed(format!("the seat failed: {error}")))?;
        // FIX 12516/12742: the completed call's evidence, before any parse —
        // even a typed abstain below records the provider terminal it read.
        // Outside a capture scope there is no caller and the capture is
        // skipped: never the payer, never a callerless row.
        if let Some(caller) = caller
            && let Some(record_request) = &record_request
        {
            let no_record = no_record_at_arrival
                || self.vault.model_call_keeps_no_record_for(
                    caller.session.as_deref(),
                    Some(caller.principal),
                );
            // Evidence-only: the live run above is untouched; this clone
            // shares its instance and revision so the row erases with it.
            let evidence_run = run.initiated_by(Some(caller.principal));
            crate::api::record_raw_response(
                &self.vault,
                &ladder,
                &evidence_run,
                record_request,
                &response,
                Some(&binding),
                no_record,
            );
        }
        if let Some(usage) = &self.trial_usage {
            usage
                .lock()
                .map_err(|_| failed("model trial usage lock"))?
                .push(response.usage.clone());
        }
        let served = served.map(|model| ProviderPin {
            rung: self.pin.rung,
            model: model.to_string(),
            version: self.pin.version.clone(),
        });
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        // A joint read's answer is its reply token's scores; a reply with none
        // is no reading (FIX 1557).
        if let Some(joint) = &joint {
            let decision = joint
                .decision(&call.question.contract, response.token_scores.as_ref())
                .unwrap_or_else(abstained);
            return Ok(ProviderDecision { served, ..decision });
        }
        let Some((answer, probability)) = self.reply.read(&text) else {
            return Ok(ProviderDecision {
                served,
                ..abstained()
            });
        };
        Ok(match typed(&call.question.contract, &answer) {
            Some(answer) => ProviderDecision {
                answer,
                probability: Some(probability),
                paired: None,
                person: None,
                served,
            },
            None => ProviderDecision {
                served,
                ..abstained()
            },
        })
    }
}
