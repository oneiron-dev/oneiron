//! Decision host adapters: the engine traits its rungs and notes implement.
//! Entry: HouseGate.
//! Definitions: types stay in the parent; this module owns the listed impls.

use oneiron::llm::LabelReadGenerationReader;
use oneiron::llm::decision::{
    CapturedDecision, CapturedDecisionPack, DecisionCallContext, DecisionGenerationAdmission,
    DecisionReadOutcome, DecisionReadProvider, HostRuleRef,
};
use oneiron::llm::routing::DescriptionNotes;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::skill_hub::claim_replay_filled_state;

use super::native_capture::{HouseReadObserver, HouseReadRun};

use super::{
    Arc, AutoCheckCandidate, AutoCheckNotes, BudgetLease, CallOutcome, DecisionAnswer,
    DecisionCall, DecisionPack, DecisionProvider, DecisionReadGate, GatedRead, HOUSE_READ_RUN,
    HouseGate, HouseRead, LadderNotes, ModelId, ProviderCapability, ProviderDecision, ProviderPin,
    ReasoningEffort, RetrievalDeadline, SeatCandidate, SeatNotes, SeatTask, SystemOneRung, Vault,
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
            GatedRead::StoppedPaidPrefix { usage } => CallOutcome::Answered(usage),
            GatedRead::Read(Ok(answer))
            | GatedRead::ReadOnRun {
                read: Ok(answer), ..
            } => CallOutcome::Answered(&answer.usage),
            GatedRead::Read(Err(_)) | GatedRead::ReadOnRun { read: Err(_), .. } => {
                CallOutcome::Failed
            }
        };
        if let Err(denied) = permit.settle(outcome) {
            tracing::error!(%denied, "a house decision read's settlement was refused");
        }
        Ok(match gated {
            GatedRead::NotStarted => GatedRead::NotStarted,
            GatedRead::StoppedPaidPrefix { usage } => GatedRead::StoppedPaidPrefix { usage },
            GatedRead::Read(read) | GatedRead::ReadOnRun { read, .. } => {
                GatedRead::ReadOnRun { read, run }
            }
        })
    }
}

/// One house read admitted on the call the rung answers carries (FIX 10443): the same
/// turn, admission, dispatch and settlement as [`HouseGate`], but the permit comes from
/// the caller's run, already sourced with the call's evidence, instead of a run of the
/// gate's own. The caller's run carries its own line, so no verdict meter wraps it.
struct RunHouseGate<'a> {
    gate: &'a HouseGate,
    run: RunAdmission,
}

impl DecisionReadGate for RunHouseGate<'_> {
    fn send_guard(&self) -> Option<&(dyn Fn() -> bool + Sync)> {
        self.run.send_guard().map(|guard| guard as _)
    }

    fn read(
        &self,
        deadline: &RetrievalDeadline,
        read: &mut dyn FnMut(&BudgetLease) -> GatedRead,
    ) -> oneiron::Result<GatedRead> {
        super::run_native_read(&self.run, || {
            let refused =
                |what: &str| oneiron::Error::InvalidConfig(format!("decision read: {what}"));
            // The host's own work: its turn comes while no caller waits for one,
            // and the wait ends with the caller's work time (FIX 9526). A turn
            // that never came admits nothing and pays nothing.
            let Ok(_turn) = self
                .gate
                .admission
                .turns
                .admit_background_blocking_for(deadline.decision_time_left())
            else {
                return Ok(GatedRead::NotStarted);
            };
            let permit = self
                .run
                .admit_paid(
                    &self.gate.connector,
                    self.run.declaration().budget().reserve_units,
                )
                .map_err(|_| refused("refused by the budget"))?;
            self.run
                .dispatch_paid(permit.lease(), &self.gate.connector)
                .map_err(|_| refused("refused at dispatch"))?;
            let gated = read(permit.lease());
            let unread = oneiron::llm::LlmUsage::zero();
            // A read that went out and failed keeps its reservation as spend.
            let outcome = match &gated {
                GatedRead::NotStarted => CallOutcome::Answered(&unread),
                GatedRead::StoppedPaidPrefix { usage } => CallOutcome::Answered(usage),
                GatedRead::Read(Ok(answer))
                | GatedRead::ReadOnRun {
                    read: Ok(answer), ..
                } => CallOutcome::Answered(&answer.usage),
                GatedRead::Read(Err(_)) | GatedRead::ReadOnRun { read: Err(_), .. } => {
                    CallOutcome::Failed
                }
            };
            if let Err(denied) = permit.settle(outcome) {
                if !self.run.is_unrecorded() {
                    tracing::error!(%denied, "a house decision read's settlement was refused");
                }
            }
            Ok(gated)
        })
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

    fn decide_captured(
        &self,
        call: &DecisionCall<'_>,
        context: &DecisionCallContext<'_>,
    ) -> Option<CapturedDecision> {
        let generation = match context.generation {
            Some(admission) => Some((self.reader.generation_reader()?, admission)),
            None => None,
        };
        // A configured native reader prepares nonlocal extraction before funding.
        if *oneiron::inference_context::admitted_as(context.purpose)
            == oneiron::llm::CallPurpose::Extraction
            && self.gate.connector.locality != oneiron::ModelLocality::OnDevice
            && self.native.is_none()
        {
            return None;
        }
        let (result, receipts) = oneiron::llm::run_admission::capture_settlements_shared(|| {
            self.decide_captured_request(call, generation, context)
        });
        Some(CapturedDecision { result, receipts })
    }

    fn decide_pack_captured(
        &self,
        pack: &DecisionPack<'_>,
        context: &DecisionCallContext<'_>,
    ) -> Option<CapturedDecisionPack> {
        let generation = match context.generation {
            Some(admission) => Some((self.reader.generation_reader()?, admission)),
            None => None,
        };
        // A configured native reader prepares nonlocal extraction before funding.
        if *oneiron::inference_context::admitted_as(context.purpose)
            == oneiron::llm::CallPurpose::Extraction
            && self.gate.connector.locality != oneiron::ModelLocality::OnDevice
            && self.native.is_none()
        {
            return None;
        }
        let (result, receipts) = oneiron::llm::run_admission::capture_settlements_shared(|| {
            self.decide_pack_captured_request(pack, generation, context)
        });
        Some(CapturedDecisionPack { result, receipts })
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        // A call that carries its caller's run reads on it (FIX 10443).
        if let Some(run) = call.run {
            let gate = RunHouseGate {
                gate: &self.gate,
                run: run.sourced(Some(call.evidence.to_vec())),
            };
            let observer = HouseReadObserver::new(self, HouseReadRun::Caller(&gate.run));
            return DecisionReadProvider::new(
                self.pin.clone(),
                self.reader.as_ref(),
                &gate,
                &self.paired,
                self.person.as_ref(),
            )?
            .observed_by(&observer)
            .decide(call);
        }
        let observer = HouseReadObserver::new(self, HouseReadRun::HouseGate);
        self.provider()?.observed_by(&observer).decide(call)
    }

    fn decide_pack(&self, pack: &DecisionPack<'_>) -> oneiron::Result<Vec<ProviderDecision>> {
        // A pack that carries its caller's run reads on it (FIX 10443).
        if let Some(run) = pack.run {
            let gate = RunHouseGate {
                gate: &self.gate,
                run: run.sourced(Some(pack.evidence.to_vec())),
            };
            let observer = HouseReadObserver::new(self, HouseReadRun::Caller(&gate.run));
            return DecisionReadProvider::new(
                self.pin.clone(),
                self.reader.as_ref(),
                &gate,
                &self.paired,
                self.person.as_ref(),
            )?
            .observed_by(&observer)
            .decide_pack(pack);
        }
        let observer = HouseReadObserver::new(self, HouseReadRun::HouseGate);
        self.provider()?.observed_by(&observer).decide_pack(pack)
    }
}

struct HouseExtractionPreparer<'house, 'context> {
    house: &'house HouseRead,
    reader: &'house Arc<crate::models::DecisionReader>,
    context: &'house DecisionCallContext<'context>,
}

impl oneiron::llm::decision::DecisionReadPreparer for HouseExtractionPreparer<'_, '_> {
    fn prepare<'request>(
        &self,
        request: &oneiron::llm::LabelReadRequest<'request>,
    ) -> oneiron::Result<Box<dyn oneiron::llm::decision::PreparedDecisionRead + 'request>> {
        self.reader.prepare_extraction(
            request,
            &self.house.vault,
            self.context,
            self.house.gate.connector.locality,
        )
    }
}

impl HouseRead {
    fn decide_captured_request(
        &self,
        call: &DecisionCall<'_>,
        generation: Option<(
            &dyn LabelReadGenerationReader,
            &dyn DecisionGenerationAdmission,
        )>,
        context: &DecisionCallContext<'_>,
    ) -> oneiron::Result<DecisionReadOutcome<ProviderDecision>> {
        let mut answers = self.decide_pack_captured_request(
            &DecisionPack {
                questions: &[call.question],
                evidence: call.evidence,
                images: call.images,
                audio: call.audio,
                state: call.state,
                deadline: call.deadline,
                run: call.run,
                labels: call.labels,
            },
            generation,
            context,
        )?;
        answers
            .pop()
            .ok_or_else(|| oneiron::Error::InvalidConfig("malformed decision read".into()))
    }

    fn decide_pack_captured_request(
        &self,
        pack: &DecisionPack<'_>,
        generation: Option<(
            &dyn LabelReadGenerationReader,
            &dyn DecisionGenerationAdmission,
        )>,
        context: &DecisionCallContext<'_>,
    ) -> oneiron::Result<Vec<DecisionReadOutcome<ProviderDecision>>> {
        let preparer = self
            .native
            .as_ref()
            .filter(|_| {
                *oneiron::inference_context::admitted_as(context.purpose)
                    == oneiron::llm::CallPurpose::Extraction
                    && self.gate.connector.locality != oneiron::ModelLocality::OnDevice
            })
            .map(|reader| HouseExtractionPreparer {
                house: self,
                reader,
                context,
            });
        let read = |provider: DecisionReadProvider<'_>| {
            let provider = match &preparer {
                Some(preparer) => provider.prepared_by(preparer),
                None => provider,
            };
            match generation {
                Some((native, admission)) => {
                    provider.decide_pack_with_generation(pack, native, admission)
                }
                None => provider.decide_pack(pack).map(|answers| {
                    answers
                        .into_iter()
                        .map(DecisionReadOutcome::Answered)
                        .collect()
                }),
            }
        };
        if let Some(run) = pack.run {
            let gate = RunHouseGate {
                gate: &self.gate,
                run: run
                    .sourced(Some(pack.evidence.to_vec()))
                    .capturing_settlements(),
            };
            let observer = HouseReadObserver::new(self, HouseReadRun::Caller(&gate.run));
            return read(
                DecisionReadProvider::new(
                    self.pin.clone(),
                    self.reader.as_ref(),
                    &gate,
                    &self.paired,
                    self.person.as_ref(),
                )?
                .observed_by(&observer),
            );
        }
        let observer = HouseReadObserver::new(self, HouseReadRun::HouseGate);
        read(self.provider()?.observed_by(&observer))
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
        self.decide_with_context(call, None)
            .map(|outcome| match outcome {
                DecisionReadOutcome::Answered(answer) => answer,
                DecisionReadOutcome::NotStarted | DecisionReadOutcome::Stopped => {
                    unreachable!("an ordinary decision has no generation gate")
                }
            })
    }

    fn decide_captured(
        &self,
        call: &DecisionCall<'_>,
        context: &DecisionCallContext<'_>,
    ) -> Option<CapturedDecision> {
        // Extraction needs an explicit catalog binding; without one it stays
        // unsupported before capture.
        if *oneiron::inference_context::admitted_as(context.purpose)
            == oneiron::llm::CallPurpose::Extraction
            && self.native_catalog.is_none()
        {
            return None;
        }
        let (result, receipts) = oneiron::llm::run_admission::capture_settlements_shared(|| {
            self.decide_with_context(call, Some(context))
        });
        Some(CapturedDecision { result, receipts })
    }

    fn decide_pack_captured(
        &self,
        pack: &DecisionPack<'_>,
        context: &DecisionCallContext<'_>,
    ) -> Option<CapturedDecisionPack> {
        // Extraction needs an explicit catalog binding; without one it stays
        // unsupported before capture.
        if *oneiron::inference_context::admitted_as(context.purpose)
            == oneiron::llm::CallPurpose::Extraction
            && self.native_catalog.is_none()
        {
            return None;
        }
        let (result, receipts) = oneiron::llm::run_admission::capture_settlements_shared(|| {
            self.decide_pack_with_context(pack, Some(context))
        });
        Some(CapturedDecisionPack { result, receipts })
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
