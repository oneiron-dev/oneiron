//! Per-question routing after the first read, preserving the last eligible answer.

use super::capture::Capture;
use super::{
    AskTo, DecisionLadder, DecisionPack, HumanDecisionRequest, Read, Readings, Route, abstained,
    asks_person, millis, step_cause, validate_pin,
};
use crate::Result;
use crate::llm::decision::policy::Reversibility;
use crate::llm::decision::{
    DecisionAnswer, DecisionReceipt, DecisionRung, DecisionTime, HumanAskReason, Reasoning,
    ReceiptAsk, StopCause, TypedDecision,
};
use crate::llm::run_admission::RunAdmission;

impl DecisionLadder<'_> {
    /// One question's routing after the first read, `first` (none when the dial starts at
    /// the person).
    pub(super) fn route(
        &self,
        call: &Route<'_>,
        first: Option<Read>,
        mut readings: Readings,
        run: Option<&RunAdmission>,
        mut capture: Option<&mut Capture<'_, '_>>,
    ) -> Result<TypedDecision> {
        let Route {
            question,
            principal,
            evidence,
            images,
            audio,
            state,
            dial,
            row,
            person_row,
            person,
            policy,
            reversibility,
            deadline,
            labels,
        } = *call;
        let mut rung = dial.first;
        let mut prior = None;
        // The pin that served `prior`: a later cut rung's pin joins the receipt
        // (FIX 9907) but never speaks for an answer it did not give. Its cost goes with it.
        let mut prior_pin = None;
        let mut prior_cost = None;
        let mut answered = None;
        let mut in_band = false;
        let mut needs_person = false;
        let mut unavailable = false;
        let mut stop = StopCause::Done;
        let mut reasoning = Reasoning::NotNeeded;
        // Whether the first answer has been weighed for the one step up, and the cause of
        // the read in hand when it is that step.
        let mut weighed = false;
        let mut stepping = None;
        let mut next_read = first;
        // The think row routes only on a paired reading, so it applies only beside one.
        let think_row = policy.think_threshold().filter(|_| self.paired.is_some());
        while let Some(read) = next_read.take() {
            let unsupported_started = matches!(&read, Read::Cut(StopCause::CaptureUnsupported));
            let answer = match read {
                Read::NotStarted(StopCause::CaptureUnsupported)
                | Read::Cut(StopCause::CaptureUnsupported) => {
                    match self.next_available(rung, dial.ceiling, question, images, audio) {
                        Some(next)
                            if next != DecisionRung::Human && deadline.decision_may_start() =>
                        {
                            let questions = [question];
                            let pack = DecisionPack {
                                questions: &questions,
                                evidence,
                                images,
                                audio,
                                state,
                                deadline,
                                run,
                                labels,
                            };
                            next_read = Some(
                                self.read(
                                    next,
                                    &pack,
                                    person,
                                    std::slice::from_mut(&mut readings),
                                    capture.as_deref_mut(),
                                )?
                                .remove(0),
                            );
                            rung = next;
                            continue;
                        }
                        Some(next) if next != DecisionRung::Human => stop = StopCause::Deadline,
                        _ => stop = StopCause::CaptureUnsupported,
                    }
                    if let Some(cause) = stepping {
                        reasoning = if unsupported_started {
                            Reasoning::Cut(cause)
                        } else {
                            Reasoning::Skipped(cause)
                        };
                    }
                    break;
                }
                Read::Answer(answer) => answer,
                Read::NotStarted(cause) => {
                    stop = cause;
                    if let Some(cause) = stepping {
                        reasoning = Reasoning::Skipped(cause);
                    }
                    break;
                }
                Read::Cut(cause) => {
                    stop = cause;
                    if let Some(cause) = stepping {
                        reasoning = Reasoning::Cut(cause);
                    }
                    break;
                }
            };
            if let Some(cause) = stepping.take() {
                reasoning = Reasoning::Ran(cause);
            }
            answered = Some(rung);
            needs_person = asks_person(&answer, person_row);
            // A rung that abstains answered nothing, so the question goes on to the next
            // rung that can take it (ARCH-0076 #fit-ask: rules first, then the local head,
            // ending at the next authorised role). The first answer may step up once more.
            let passes = answer.answer == DecisionAnswer::Abstain;
            let cause = if passes || weighed {
                None
            } else {
                weighed = true;
                in_band = answer.probability.is_some_and(|p| row.band.contains(p));
                step_cause(&answer, in_band, row.mode, think_row)
            };
            prior = Some(answer);
            prior_pin = readings.pins.last().cloned();
            prior_cost = readings.cost;
            if needs_person {
                rung = DecisionRung::Human;
                break;
            }
            if (!passes && cause.is_none()) || rung >= dial.ceiling {
                break;
            }
            // A stronger rung, the person's included, starts only while work time is left.
            match self.next_available(rung, dial.ceiling, question, images, audio) {
                None => {
                    unavailable = true;
                    if let Some(cause) = cause {
                        reasoning = Reasoning::Skipped(cause);
                    }
                }
                Some(_) if !deadline.decision_may_start() => {
                    stop = StopCause::Deadline;
                    if let Some(cause) = cause {
                        reasoning = Reasoning::Skipped(cause);
                    }
                }
                Some(DecisionRung::Human) => rung = DecisionRung::Human,
                Some(next) => {
                    let questions = [question];
                    let pack = DecisionPack {
                        questions: &questions,
                        evidence,
                        images,
                        audio,
                        state,
                        deadline,
                        run,
                        labels,
                    };
                    next_read = Some(
                        self.read(
                            next,
                            &pack,
                            person,
                            std::slice::from_mut(&mut readings),
                            capture.as_deref_mut(),
                        )?
                        .remove(0),
                    );
                    rung = next;
                    stepping = cause;
                }
            }
        }
        // At a cut an irreversible step never takes an unfinished answer, and no step
        // takes an answer the call does not have, or one inside its band, enforced or
        // in shadow (packet rule 5: an in-band answer is not eligible).
        let cut_reason = match stop {
            StopCause::GenerationAllowance => HumanAskReason::GenerationAllowance,
            StopCause::CaptureUnsupported => HumanAskReason::CaptureUnsupported,
            _ => HumanAskReason::Deadline,
        };
        let abstains_at_cut = matches!(
            stop,
            StopCause::Deadline | StopCause::GenerationAllowance | StopCause::CaptureUnsupported
        ) && (prior
            .as_ref()
            .is_none_or(|prior| prior.answer == DecisionAnswer::Abstain)
            || reversibility == Reversibility::OutboundEffect
            || in_band);
        if abstains_at_cut && dial.ceiling == DecisionRung::Human {
            rung = DecisionRung::Human;
        }
        let mut human_ask = None;
        let mut asked = None;
        let outcome = if rung == DecisionRung::Human {
            validate_pin(&self.human_pin, DecisionRung::Human)?;
            let reason = if needs_person {
                HumanAskReason::NeedsPerson
            } else if abstains_at_cut {
                cut_reason
            } else if prior.is_some() {
                HumanAskReason::Uncertain
            } else {
                HumanAskReason::OwnerSelected
            };
            let to = self.ask_to.cloned().unwrap_or_else(AskTo::owner);
            // The ask carries the state the reads weighed (FIX 2424), and its receipt
            // names the role it went to (ARCH-0076, "Who answered").
            let seq = self.human.queue_with_state(
                HumanDecisionRequest {
                    question: question.clone(),
                    principal,
                    evidence: evidence.to_vec(),
                    reason,
                    // The prior is the last provider read's answer, from the pin that
                    // served it.
                    prior_provider: prior.as_ref().and(prior_pin.clone()),
                    prior,
                    queue_pin: self.human_pin.clone(),
                    to: to.clone(),
                    correlation: self.correlation,
                },
                state,
            )?;
            asked = Some(ReceiptAsk::queued(&to, seq));
            readings.pins.push(self.human_pin.clone());
            human_ask = Some(reason);
            abstained()
        } else if abstains_at_cut {
            human_ask = Some(cut_reason);
            abstained()
        } else if unavailable {
            // No rung up to the ceiling can take the step: a typed abstention.
            human_ask = Some(HumanAskReason::ProviderUnavailable);
            abstained()
        } else {
            prior.expect("a non-human rung has an answer")
        };
        // A rung that abstained answered nothing.
        let answered = answered.filter(|_| outcome.answer != DecisionAnswer::Abstain);
        let evidence_versions = images
            .iter()
            .map(|image| image.evidence.clone())
            .chain(audio.iter().map(|clip| clip.evidence.clone()))
            .collect();
        Ok(TypedDecision {
            answer: outcome.answer,
            probability: outcome.probability,
            evidence: evidence.to_vec(),
            in_band,
            human_ask,
            receipt: DecisionReceipt {
                question: question.id,
                question_version: question.version,
                principal,
                providers: readings.pins,
                band: row.band,
                band_version: row.version,
                evidence_versions,
                // The cost its answering provider knows, at the rung that answered.
                cost_per_thousand: prior_cost.filter(|_| answered.is_some()),
                paired: readings.paired,
                person: readings.person,
                time: Some(DecisionTime {
                    budget_ms: millis(deadline.budget()),
                    used_ms: millis(deadline.used()),
                    stop,
                    answered,
                    reasoning,
                }),
                images: readings.images,
                think_row: think_row.map(|row| row.version),
                person_row: person_row.map(|row| row.version),
                rule: readings
                    .rule
                    .filter(|_| answered == Some(DecisionRung::Rule)),
                asked,
                state_cut: None,
            },
        })
    }
}
