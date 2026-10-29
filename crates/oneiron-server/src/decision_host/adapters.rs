//! Decision host adapters: the engine traits its rungs and notes implement.
//! Entry: HouseGate.
//! Definitions: types stay in the parent; this module owns the listed impls.

use oneiron::llm::decision::{AnswerContract, HostRuleRef, RemoteDecisionCapability};
use oneiron::llm::routing::DescriptionNotes;
use oneiron::skill_hub::claim_replay_filled_state;

use super::{
    Arc, AutoCheckCandidate, AutoCheckNotes, BudgetLease, CallOutcome, DecisionAnswer,
    DecisionCall, DecisionPack, DecisionProvider, DecisionReadGate, GatedRead, HOUSE_READ_RUN,
    HouseGate, HouseRead, LadderNotes, ModelId, ProviderCapability, ProviderDecision, ProviderPin,
    ReasoningEffort, RemoteDecisionSeat, RetrievalDeadline, SeatCandidate, SeatNotes, SeatPhase,
    SeatRequest, SeatTask, SystemOneRung, Vault,
};

impl DecisionReadGate for HouseGate {
    fn read(
        &self,
        deadline: &RetrievalDeadline,
        read: &mut dyn FnMut(&BudgetLease) -> GatedRead,
    ) -> oneiron::Result<GatedRead> {
        let refused = |what: &str| oneiron::Error::InvalidConfig(format!("decision read: {what}"));
        // The host's own work: its turn comes while no caller waits for one,
        // and the wait ends with the caller's work time (FIX 9526). A turn
        // that never came admits nothing and pays nothing.
        let Ok(_turn) = self
            .admission
            .turns
            .admit_background_blocking_for(deadline.decision_time_left())
        else {
            return Ok(GatedRead::NotStarted);
        };
        // Inside a verdict, the caller's own line (FIX 1123), billing the
        // payer its run binds (FIX 3574).
        let meter = crate::decision_verdict::rung_meter(&self.meter);
        let run = crate::models::funded_run(
            HOUSE_READ_RUN,
            meter.clone(),
            Some(Arc::clone(&self.admission.host)),
            Arc::clone(&self.admission.receipts),
            crate::decision_verdict::rung_payer(),
        );
        let permit = run
            .admit_paid(&self.connector, meter.reserve_units())
            .map_err(|_| refused("refused by the budget"))?;
        run.dispatch_paid(permit.lease(), &self.connector)
            .map_err(|_| refused("refused at dispatch"))?;
        let gated = read(permit.lease());
        let unread = oneiron::llm::LlmUsage::zero();
        // A read that went out and failed keeps its reservation as spend.
        let outcome = match &gated {
            GatedRead::NotStarted => CallOutcome::Answered(&unread),
            GatedRead::Read(Ok(answer)) => CallOutcome::Answered(&answer.usage),
            GatedRead::Read(Err(_)) => CallOutcome::Failed,
        };
        if let Err(denied) = permit.settle(outcome) {
            tracing::error!(%denied, "a house decision read's settlement was refused");
        }
        Ok(gated)
    }
}

impl DecisionProvider for HouseRead {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    fn capability(&self) -> ProviderCapability {
        self.provider()
            .map_or_else(|_| ProviderCapability::default(), |read| read.capability())
    }

    fn leaves_host(&self) -> bool {
        self.leaves
    }

    /// The reader's price as its host knows it (FIX 11305): none for the
    /// house model this server serves, whose provider names no price.
    fn cost_per_thousand(&self) -> Option<f64> {
        self.reader.cost_per_thousand()
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        self.provider()?.decide(call)
    }

    fn decide_pack(&self, pack: &DecisionPack<'_>) -> oneiron::Result<Vec<ProviderDecision>> {
        self.provider()?.decide_pack(pack)
    }
}

impl DecisionProvider for SystemOneRung {
    fn pin(&self) -> ProviderPin {
        self.seat.pin()
    }

    /// A score goes to the seat with the caller's levels (FIX 3269); a score
    /// with none abstains, so the call steps up.
    fn capability(&self) -> ProviderCapability {
        ProviderCapability::default()
    }

    /// The seat sends a call's images as named wire assets, when the posture
    /// lets a call leave the host at all.
    fn reads_images(&self) -> bool {
        oneiron::llm::decision::unit_text_may_leave_host(self.posture, self.remote_opt_in)
    }

    fn image_edge(&self) -> Option<u32> {
        self.seat.image_edge()
    }

    /// The seat is remote: every call leaves the host.
    fn leaves_host(&self) -> bool {
        true
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        let failed = |what: &str| oneiron::Error::InvalidConfig(format!("system one: {what}"));
        let abstain = ProviderDecision {
            answer: DecisionAnswer::Abstain,
            probability: None,
            paired: None,
            person: None,
            served: None,
        };
        let score_levels = call.score_levels().unwrap_or_default();
        if matches!(call.question.contract, AnswerContract::Score { .. })
            && score_levels.is_empty()
        {
            return Ok(abstain);
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
            return Ok(abstain);
        }
        request
            .validate_remote()
            .map_err(|_| failed("the posture or the request keeps this call local"))?;
        // A broker or key that is not there refuses the call before its
        // measurement starts.
        self.seat
            .preflight()
            .map_err(|_| failed("its credential broker or vault-secret key is not there"))?;
        // Inside a verdict, the caller's own line (FIX 1123).
        let guard = crate::decision_verdict::rung_meter(&self.guard);
        let lease = guard
            .admit()
            .map_err(|_| failed("refused by the budget"))?
            .lease;
        // A measurement admitted after the work time is spent never starts.
        if call.deadline.decision_time_left().is_zero() {
            guard
                .settle_reserved(&lease)
                .map_err(|_| failed("settlement refused"))?;
            return Err(failed("admitted after the work time"));
        }
        let asked = self.runtime.block_on(self.seat.ask(
            request,
            &lease,
            call.deadline.decision_time_left(),
        ));
        let answer = match asked {
            Ok(answer) => {
                guard
                    .settle_per_call(&lease, &answer.usage)
                    .map_err(|_| failed("settlement refused"))?;
                answer
            }
            Err(error) => {
                // The seat may still bill a failed call.
                guard
                    .settle_reserved(&lease)
                    .map_err(|_| failed("settlement refused"))?;
                return Err(failed(&format!("the seat failed: {error}")));
            }
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
}

/// A model rung of a claim refinement's held-out replay that reads the
/// label bodies the replay's state left to evidence ids (FIX 1327). Each
/// call goes to `inner` with those bodies added, read by id from `vault`,
/// while the state still fits the ladder's bound; every other answer is
/// `inner`'s own.
pub(super) struct ClaimBodyRead<'a> {
    pub(super) inner: &'a dyn DecisionProvider,
    pub(super) vault: &'a Vault,
}

impl DecisionProvider for ClaimBodyRead<'_> {
    fn pin(&self) -> ProviderPin {
        self.inner.pin()
    }

    fn capability(&self) -> ProviderCapability {
        self.inner.capability()
    }

    fn reads_images(&self) -> bool {
        self.inner.reads_images()
    }

    fn image_edge(&self) -> Option<u32> {
        self.inner.image_edge()
    }

    fn reads_audio(&self) -> bool {
        self.inner.reads_audio()
    }

    fn leaves_host(&self) -> bool {
        self.inner.leaves_host()
    }

    fn cost_per_thousand(&self) -> Option<f64> {
        self.inner.cost_per_thousand()
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        match claim_replay_filled_state(self.vault, call.evidence, call.state)? {
            Some(state) => self.inner.decide(&DecisionCall {
                state: &state,
                ..*call
            }),
            None => self.inner.decide(call),
        }
    }

    fn decide_pack(&self, pack: &DecisionPack<'_>) -> oneiron::Result<Vec<ProviderDecision>> {
        match claim_replay_filled_state(self.vault, pack.evidence, pack.state)? {
            Some(state) => self.inner.decide_pack(&DecisionPack {
                state: &state,
                ..*pack
            }),
            None => self.inner.decide_pack(pack),
        }
    }

    fn rule_row(
        &self,
        call: &DecisionCall<'_>,
        decision: &ProviderDecision,
    ) -> Option<HostRuleRef> {
        self.inner.rule_row(call, decision)
    }
}

impl AutoCheckNotes for LadderNotes {
    fn hold_reasons(
        &self,
        candidate: &AutoCheckCandidate<'_>,
        _due: std::time::Instant,
    ) -> oneiron::Result<Vec<String>> {
        Ok(vec![format!(
            "the host's decision ladder held this {} write from a {} source",
            candidate.predicate,
            candidate.source.as_str()
        )])
    }
}

impl SeatNotes for LadderNotes {
    fn why(
        &self,
        task: &SeatTask,
        candidates: &[SeatCandidate],
        model: &ModelId,
        effort: ReasoningEffort,
        _deadline: &RetrievalDeadline,
    ) -> oneiron::Result<String> {
        let effort = effort_label(effort);
        let described = candidates
            .iter()
            .find(|candidate| candidate.model == *model)
            .and_then(|candidate| candidate.description.first())
            .map(|line| format!(" ({})", line.text))
            .unwrap_or_default();
        Ok(format!(
            "The host's decision ladder picked {model}{described} at {effort} effort for the {} profile, from {} eligible models.",
            task.facet,
            candidates.len()
        ))
    }
}

/// A routed seat's reason (FIX 11307), written from the route itself: the model, its effort,
/// its fitness and the description line it was graded on. No model is asked.
impl DescriptionNotes for LadderNotes {
    fn reason(
        &self,
        _task: &str,
        model: &ModelId,
        description: &str,
        effort: ReasoningEffort,
        fitness: f64,
    ) -> oneiron::Result<String> {
        Ok(format!(
            "The host's description route picked {model} at {} effort, fitness {fitness:.2}, on its line: {description}",
            effort_label(effort)
        ))
    }
}

/// The notes a routed task seat's receipt keeps (FIX 11307).
pub(crate) fn description_notes() -> &'static dyn DescriptionNotes {
    &LadderNotes
}

/// An effort's wire label, as a receipt names it.
fn effort_label(effort: ReasoningEffort) -> String {
    match serde_json::to_value(effort) {
        Ok(serde_json::Value::String(label)) => label,
        _ => format!("{effort:?}"),
    }
}
