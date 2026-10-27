//! Decision host adapters: the engine traits its rungs and notes implement.
//! Entry: HouseGate.
//! Definitions: types stay in the parent; this module owns the listed impls.

use super::{
    Arc, AutoCheckCandidate, AutoCheckNotes, BudgetLease, CallOutcome, DecisionAnswer,
    DecisionCall, DecisionPack, DecisionProvider, DecisionReadGate, GatedRead, HOUSE_READ_RUN,
    HostingPrivacyPosture, HouseGate, HouseRead, LadderNotes, ModelId, ProviderCapability,
    ProviderDecision, ProviderPin, ReasoningEffort, RemoteDecisionSeat, RetrievalDeadline,
    SeatCandidate, SeatNotes, SeatPhase, SeatRequest, SeatTask, SystemOneRung,
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

    fn capability(&self) -> ProviderCapability {
        ProviderCapability {
            score: false,
            ..ProviderCapability::default()
        }
    }

    /// The seat sends a call's images as named wire assets, when the posture
    /// lets a call leave the host at all.
    fn reads_images(&self) -> bool {
        (self.posture == HostingPrivacyPosture::Hosted || self.remote_opt_in)
            && self.posture != HostingPrivacyPosture::Relay
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
        let request = SeatRequest {
            question: call.question.clone(),
            state: call.state.clone(),
            images: call.images.to_vec(),
            audio: call.audio.to_vec(),
            score_levels: Vec::new(),
            posture: self.posture,
            remote_opt_in: self.remote_opt_in,
            phase: SeatPhase::Background,
        };
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

impl AutoCheckNotes for LadderNotes {
    fn hold_reasons(&self, candidate: &AutoCheckCandidate<'_>) -> oneiron::Result<Vec<String>> {
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
        let effort = match serde_json::to_value(effort) {
            Ok(serde_json::Value::String(label)) => label,
            _ => format!("{effort:?}"),
        };
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
