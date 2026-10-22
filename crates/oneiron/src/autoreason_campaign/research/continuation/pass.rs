//! One research continuation pass over its persisted tasks.
//! Entry method: `Pass::advance`.
//! The `Pass` type and continuation records remain defined in `super`.

use super::*;

impl Pass<'_> {
    fn root(&self) -> AttemptId {
        self.binding.root
    }

    fn load(&self, work: ResearchWork) -> Result<Option<ResearchContinuation>> {
        let txn = self.vault.store.env.read_txn()?;
        CONTINUATION.get(
            &self.vault.store,
            &txn,
            &(*self.root().as_bytes(), work.key()),
        )
    }

    /// Up to [`MAX_STEPS_PER_PASS`] steps, each persisted on its own.
    pub(super) fn advance(&self, work: ResearchWork) -> Result<()> {
        for _ in 0..MAX_STEPS_PER_PASS {
            let Some(row) = self.load(work)? else {
                return Ok(());
            };
            if !row.state.live() {
                return Ok(());
            }
            match self.step(&row) {
                Ok(Flow::Next) => {}
                Ok(Flow::Stop) => return Ok(()),
                Err(Error::InvalidConfig(reason)) => return self.fail(&row, reason),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Store `next` over `row` in one write, unless another pass moved the
    /// row since it was read.
    fn save(&self, row: &ResearchContinuation, mut next: ResearchContinuation) -> Result<()> {
        next.updated_at = self.now;
        let key = (*row.root.as_bytes(), row.work.key());
        self.vault.with_write_txn_grouped(|txn| {
            if CONTINUATION.get(&self.vault.store, txn, &key)?.as_ref() != Some(row) {
                return Err(Error::ConcurrentWrite(
                    "another pass advanced this research continuation",
                ));
            }
            CONTINUATION.put(&self.vault.store, txn, &key, &next)
        })
    }

    /// End a continuation on a refusal. A reservation nothing was dispatched
    /// on is refunded; a dispatched run's stays as the run left it.
    fn fail(&self, row: &ResearchContinuation, reason: String) -> Result<()> {
        let mut next = row.clone();
        if let Some(running) = &row.running
            && running.run.is_none()
        {
            match self.refund(running.reservation) {
                Ok(()) | Err(Error::InvalidConfig(_)) => {}
                Err(error) => return Err(error),
            }
            next.running = None;
        }
        next.state = failed(reason);
        self.save(row, next)
    }

    fn step(&self, row: &ResearchContinuation) -> Result<Flow> {
        if let Some(running) = &row.running {
            return match running.run {
                None => self.dispatch(row, running),
                Some(run) => self.observe(row, running, run),
            };
        }
        let mut next = row.clone();
        // A budget hold retries its task now.
        next.state = ResearchContinuationState::Open;
        if next.pending.is_empty() {
            next.state = ResearchContinuationState::Done {
                note: "every task ran".to_owned(),
            };
            self.save(row, next)?;
            return Ok(Flow::Stop);
        }
        let task = next.pending.remove(0);
        let execution = self.execution;
        let (purpose, units, attempt) = match task {
            ResearchTask::Basis { candidate } => return self.basis(row, next, candidate),
            ResearchTask::Measure { node, split } => {
                let purpose = match split {
                    ResearchSplit::Search => RsiSpendPurpose::Judge,
                    ResearchSplit::HeldOut => RsiSpendPurpose::HeldOut,
                };
                (purpose, execution.measure_units, node)
            }
            ResearchTask::Experiment { parent, .. } => (
                RsiSpendPurpose::Experiment,
                execution.experiment_units,
                parent,
            ),
            ResearchTask::Confirm { candidate } => {
                (RsiSpendPurpose::HeldOut, execution.confirm_units, candidate)
            }
        };
        match reserve_research_work(
            self.vault,
            self.root(),
            purpose,
            units,
            Some(attempt),
            self.now,
        ) {
            Ok(reservation) => {
                next.running = Some(ResearchRunning {
                    task,
                    reservation,
                    run: None,
                    release: None,
                });
                self.save(row, next)?;
                Ok(Flow::Next)
            }
            // No room: the task waits at the front, as a round pauses.
            Err(error) if is_budget_refusal(&error) => {
                next.pending.insert(0, task);
                next.state = ResearchContinuationState::Held {
                    reason: BUDGET_HELD.to_owned(),
                };
                self.save(row, next)?;
                Ok(Flow::Stop)
            }
            Err(error) => Err(error),
        }
    }

    /// The held-out basis needs no run. Only a Promote goes on, and only to
    /// a confirmation seat with a referee.
    fn basis(
        &self,
        row: &ResearchContinuation,
        mut next: ResearchContinuation,
        candidate: AttemptId,
    ) -> Result<Flow> {
        let basis = match self.basis_of(candidate)? {
            Some(basis) => basis,
            None => promotion_basis(self.vault, self.root(), candidate, None, self.now)?,
        };
        let confirms = self.binding.confirmation.is_some() && self.execution.referee.is_some();
        next.state = match basis.call {
            HeldOutCall::Promote if confirms => {
                next.pending.insert(0, ResearchTask::Confirm { candidate });
                ResearchContinuationState::Open
            }
            HeldOutCall::Promote => ResearchContinuationState::Held {
                reason: NO_SEAT.to_owned(),
            },
            HeldOutCall::Reject => ResearchContinuationState::Done {
                note: "the held-out basis rejected the candidate".to_owned(),
            },
            HeldOutCall::EscalateTradeoff => ResearchContinuationState::Held {
                reason: TRADEOFF.to_owned(),
            },
        };
        self.save(row, next)?;
        Ok(Flow::Next)
    }

    /// Dispatch the task in flight. After a crash the same dedupe key brings
    /// back the run already made. A refused dispatch refunds and fails.
    fn dispatch(&self, row: &ResearchContinuation, running: &ResearchRunning) -> Result<Flow> {
        let root = self.root();
        let (agent, parent, briefing) = match running.task {
            ResearchTask::Experiment { parent, kind } => (
                self.execution.experimenter,
                parent,
                self.experimenter_briefing(parent, kind)?,
            ),
            ResearchTask::Measure { node, split } => (
                self.execution.scorer,
                root,
                self.scorer_briefing(node, split)?,
            ),
            ResearchTask::Confirm { candidate } => {
                let Some(release) = &running.release else {
                    return self.release(row, running, candidate);
                };
                let referee = self
                    .execution
                    .referee
                    .ok_or(invalid("the campaign names no referee"))?;
                (referee, root, self.referee_briefing(candidate, release)?)
            }
            ResearchTask::Basis { .. } => {
                return Err(invalid("a held-out basis dispatches no run"));
            }
        };
        let outcome = AgentDispatcher::new(self.vault).dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: Some(parent),
                dedupe_key: Some(format!(
                    "research:{}:{}:{}",
                    hex(&root),
                    row.work.key(),
                    row.runs.len()
                )),
                run_id: Some(self.binding.run_id.clone()),
                now: self.now,
            },
            AgentSpawnContext::default()
                .with_context_spec(ContextSpec::excluded().with_briefing(briefing)),
        );
        let reason = match outcome {
            Ok(
                AgentDispatchOutcome::Dispatched(status) | AgentDispatchOutcome::Existing(status),
            ) => {
                let mut next = row.clone();
                if let Some(running) = &mut next.running {
                    running.run = Some(status.attempt.id);
                }
                next.runs.push(status.attempt.id);
                self.save(row, next)?;
                return Ok(Flow::Next);
            }
            Ok(_) => "the dispatcher parked the run rather than start it".to_owned(),
            Err(error @ (Error::InvalidConfig(_) | Error::Artifact(_) | Error::Gate(_))) => {
                error.to_string()
            }
            Err(error) => return Err(error),
        };
        self.refund(running.reservation)?;
        let mut next = row.clone();
        next.running = None;
        next.state = failed(reason);
        self.save(row, next)?;
        Ok(Flow::Stop)
    }

    /// Spend the candidate's sealed confirmation and keep its release on the
    /// task. A shot already spent, here or before a crash, is never spent
    /// again: the campaign holds.
    fn release(
        &self,
        row: &ResearchContinuation,
        running: &ResearchRunning,
        candidate: AttemptId,
    ) -> Result<Flow> {
        let mut next = row.clone();
        if !self.shot_spent(candidate)? {
            match reserve_confirmation(self.vault, self.root(), candidate, self.now) {
                Ok(release) => {
                    if let Some(running) = &mut next.running {
                        running.release = Some(release);
                    }
                    self.save(row, next)?;
                    return Ok(Flow::Next);
                }
                Err(Error::InvalidConfig(reason)) => {
                    // Refused before the shot was consumed: nothing was spent.
                    if !self.shot_spent(candidate)? {
                        self.refund(running.reservation)?;
                        next.running = None;
                        next.state = failed(reason);
                        self.save(row, next)?;
                        return Ok(Flow::Stop);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        self.refund(running.reservation)?;
        next.running = None;
        next.state = ResearchContinuationState::Held {
            reason: SHOT_SPENT.to_owned(),
        };
        self.save(row, next)?;
        Ok(Flow::Stop)
    }

    /// Read a dispatched run: wait while it goes; once it ends, record its
    /// answer, settle what it spent, and move on.
    fn observe(
        &self,
        row: &ResearchContinuation,
        running: &ResearchRunning,
        run: AttemptId,
    ) -> Result<Flow> {
        let record = AttemptQueue::new(self.vault).get(run)?;
        if record
            .as_ref()
            .is_some_and(|record| !record.state.is_terminal())
        {
            return Ok(Flow::Stop);
        }
        let answer = match &record {
            Some(record) if matches!(record.state, AttemptState::Completed) => {
                run_answer_text(self.vault, record)?
            }
            _ => None,
        };
        let text = answer.as_deref();
        let mut next = row.clone();
        next.running = None;
        match running.task {
            ResearchTask::Experiment { parent, kind } => {
                self.experimented(&mut next, parent, kind, run, text)?;
            }
            ResearchTask::Measure { node, split } => {
                self.measured(&mut next, node, split, run, text)?;
            }
            ResearchTask::Confirm { candidate } => self.confirmed(&mut next, candidate, text)?,
            ResearchTask::Basis { .. } => {
                return Err(invalid("a held-out basis dispatches no run"));
            }
        }
        self.settle(running.reservation, run)?;
        self.save(row, next)?;
        Ok(Flow::Next)
    }

    /// A written candidate becomes the child node, then is measured on the
    /// search split. No candidate, no node: a child without a pin is none.
    fn experimented(
        &self,
        next: &mut ResearchContinuation,
        parent: AttemptId,
        kind: ForkKind,
        run: AttemptId,
        text: Option<&str>,
    ) -> Result<()> {
        let candidate = match text.and_then(answer_object::<ExperimentAnswer>) {
            Some(ExperimentAnswer::Candidate(candidate)) => candidate,
            Some(ExperimentAnswer::Failed { failed: why }) => {
                next.state = failed(format!("the experimenter gave up: {why}"));
                return Ok(());
            }
            None => {
                next.state = failed("the experimenter's run ended without an answer");
                return Ok(());
            }
        };
        if matches!(self.binding.target, ResearchTarget::Skill { .. })
            && proposal_of(&candidate).is_none()
        {
            next.state =
                failed("a skill experiment names its staged proposal as skill_proposal:<32 hex>");
            return Ok(());
        }
        if self.node(run)?.is_none() {
            let fork = ForkInput {
                parent,
                child: run,
                kind,
                candidate,
            };
            if refused(record_fork(self.vault, self.root(), fork, self.now), next)?.is_none() {
                return Ok(());
            }
        }
        next.pending.insert(
            0,
            ResearchTask::Measure {
                node: run,
                split: ResearchSplit::Search,
            },
        );
        Ok(())
    }

    fn measured(
        &self,
        next: &mut ResearchContinuation,
        node: AttemptId,
        split: ResearchSplit,
        run: AttemptId,
        text: Option<&str>,
    ) -> Result<()> {
        let Some(answer) = text.and_then(answer_object::<ScoreAnswer>) else {
            next.state = failed("the scorer's run ended without an answer");
            return Ok(());
        };
        match (answer, split) {
            (ScoreAnswer::Scores(scores), ResearchSplit::Search) => {
                self.searched(next, node, run, scores)
            }
            (ScoreAnswer::Scores(scores), ResearchSplit::HeldOut) => {
                let mut receipt_refs = scores.receipt_refs;
                receipt_refs.push(hex(&run));
                if self.node(node)?.is_none_or(|row| row.held_out.is_none()) {
                    let measurement =
                        self.measurement(&self.binding.config.splits.held_out, scores.scores);
                    refused(
                        record_held_out_measurement(
                            self.vault,
                            self.root(),
                            node,
                            measurement,
                            receipt_refs,
                            self.now,
                        ),
                        next,
                    )?;
                }
                Ok(())
            }
            (ScoreAnswer::Invalid { invalid: why, .. }, ResearchSplit::HeldOut) => {
                next.state = failed(format!("held-out scoring refused the candidate: {why}"));
                Ok(())
            }
            (
                ScoreAnswer::Invalid {
                    invalid: why,
                    mut evidence_refs,
                },
                ResearchSplit::Search,
            ) => {
                if node == self.root() {
                    next.state = failed(format!("the incumbent root measured invalid: {why}"));
                    return Ok(());
                }
                evidence_refs.push(hex(&run));
                if self.node(node)?.is_none_or(|row| row.invalid.is_none())
                    && refused(
                        record_invalid_experiment(
                            self.vault,
                            self.root(),
                            node,
                            &why,
                            evidence_refs,
                            self.now,
                        ),
                        next,
                    )?
                    .is_none()
                {
                    return Ok(());
                }
                if next.debug_spawned {
                    next.state = ResearchContinuationState::Done {
                        note: "the debug child measured invalid too".to_owned(),
                    };
                } else {
                    next.pending.insert(
                        0,
                        ResearchTask::Experiment {
                            parent: node,
                            kind: ForkKind::Debug,
                        },
                    );
                    next.debug_spawned = true;
                }
                Ok(())
            }
        }
    }

    /// Record search evidence. A child that beats the incumbent's search
    /// reward goes on to held-out evidence for both, then the basis.
    fn searched(
        &self,
        next: &mut ResearchContinuation,
        node: AttemptId,
        run: AttemptId,
        scores: Scores,
    ) -> Result<()> {
        let root = self.root();
        let (Some(confirmed_hits), Some(attribution), Some(hop_cost)) =
            (scores.confirmed_hits, scores.attribution, scores.hop_cost)
        else {
            next.state =
                failed("the scorer's search answer names no hits, attribution or hop cost");
            return Ok(());
        };
        let mut receipt_refs = scores.receipt_refs;
        receipt_refs.push(hex(&run));
        if self.node(node)?.is_none_or(|row| row.search.is_none()) {
            let mut evidence = SearchEvidence {
                measurement: self.measurement(&self.binding.config.splits.search, scores.scores),
                confirmed_hits,
                attribution,
                hop_cost,
                expected_gain: 0.0,
                estimator_version: ENGINE_ESTIMATOR_VERSION.to_owned(),
                knob_reliability: None,
                receipt_refs,
            };
            evidence.expected_gain = expected_gain_for(self.vault, self.binding, node, &evidence)?;
            if refused(
                record_search_measurement(self.vault, root, node, evidence),
                next,
            )?
            .is_none()
            {
                return Ok(());
            }
        }
        if node == root {
            return Ok(());
        }
        let nodes = self.nodes()?;
        let incumbent = research_incumbent(self.vault, root)?;
        let reward = |attempt: AttemptId| {
            nodes
                .get(attempt.as_bytes())
                .and_then(|row| row.search.as_ref())
                .map(SearchEvidence::reward)
        };
        let beats = reward(node)
            .zip(reward(incumbent))
            .is_some_and(|(candidate, held)| candidate > held);
        if incumbent == node || !beats {
            return Ok(());
        }
        let mut follow = Vec::new();
        if nodes
            .get(incumbent.as_bytes())
            .is_some_and(|row| row.held_out.is_none())
        {
            follow.push(ResearchTask::Measure {
                node: incumbent,
                split: ResearchSplit::HeldOut,
            });
        }
        follow.push(ResearchTask::Measure {
            node,
            split: ResearchSplit::HeldOut,
        });
        follow.push(ResearchTask::Basis { candidate: node });
        follow.append(&mut next.pending);
        next.pending = follow;
        Ok(())
    }

    /// Settle the candidate on the referee's sealed answer. One that does
    /// not come back, or does not parse, holds: the shot is spent.
    fn confirmed(
        &self,
        next: &mut ResearchContinuation,
        candidate: AttemptId,
        text: Option<&str>,
    ) -> Result<()> {
        let answer = text.and_then(answer_object::<RefereeAnswer>);
        let sealed = answer.as_ref().and_then(|answer| {
            SealedRefereeMeasurement::from_referee_scores(
                answer.candidate,
                answer.incumbent,
                &answer.referee_pin,
            )
            .ok()
        });
        let (Some(answer), Some(sealed)) = (answer, sealed) else {
            next.state = ResearchContinuationState::Held {
                reason: SHOT_SPENT.to_owned(),
            };
            return Ok(());
        };
        let basis = self.basis_of(candidate)?;
        if let Some(receipt) = basis.as_ref().and_then(|basis| basis.promotion.as_ref()) {
            next.state = settled(receipt.disposition);
            return Ok(());
        }
        let skill_proposal = match self.binding.target {
            ResearchTarget::Skill { .. } => basis
                .as_ref()
                .and_then(|basis| proposal_of(&basis.candidate_pin)),
            ResearchTarget::Config { .. } => None,
        };
        let outcome = ConfirmationOutcome {
            sealed,
            sufficiency: answer.sufficiency,
            skill_proposal,
        };
        if let Some(receipt) = refused(
            promote_measured(self.vault, self.root(), candidate, outcome, self.now),
            next,
        )? {
            next.state = settled(receipt.disposition);
        }
        Ok(())
    }

    fn node(&self, attempt: AttemptId) -> Result<Option<ExperimentNode>> {
        let txn = self.vault.store.env.read_txn()?;
        NODE.get(
            &self.vault.store,
            &txn,
            &(*self.root().as_bytes(), *attempt.as_bytes()),
        )
    }

    fn nodes(&self) -> Result<BTreeMap<[u8; 16], ExperimentNode>> {
        let txn = self.vault.store.env.read_txn()?;
        nodes_in_txn(self.vault, &txn, self.root())
    }

    fn basis_of(&self, candidate: AttemptId) -> Result<Option<PromotionBasis>> {
        Ok(research_promotions(self.vault, self.root())?
            .into_iter()
            .find(|basis| basis.candidate == candidate))
    }

    fn shot_spent(&self, candidate: AttemptId) -> Result<bool> {
        Ok(self
            .basis_of(candidate)?
            .is_some_and(|basis| basis.confirmation.is_some()))
    }

    fn measurement(
        &self,
        split: &CampaignDatasetRef,
        scores: BTreeMap<String, f64>,
    ) -> Measurement {
        let metric_set = &self.binding.config.metric_set;
        Measurement {
            dataset: split.clone(),
            metric_set_id: metric_set.set_id.clone(),
            metric_set_revision: metric_set.revision.clone(),
            scores,
        }
    }

    fn reservation(&self, id: EntityId) -> Result<Option<ResearchReservation>> {
        Ok(research_reservations(self.vault, self.root())?
            .into_iter()
            .find(|row| row.id == id))
    }

    /// Settle a finished run's reservation with what it spent, once.
    fn settle(&self, id: EntityId, run: AttemptId) -> Result<()> {
        if let Some(row) = self.reservation(id)?
            && row.settlement.is_none()
        {
            let actual = run_spend_units(self.vault, run, row.units)?;
            settle_research_work(self.vault, self.root(), id, actual)?;
        }
        Ok(())
    }

    /// Refund a reservation nothing was dispatched on, once.
    fn refund(&self, id: EntityId) -> Result<()> {
        if self
            .reservation(id)?
            .is_some_and(|row| row.settlement.is_none())
        {
            refund_research_work(self.vault, self.root(), id)?;
        }
        Ok(())
    }

    fn experimenter_briefing(&self, parent: AttemptId, kind: ForkKind) -> Result<String> {
        let node = self
            .node(parent)?
            .ok_or(invalid("the experiment's parent is not a campaign node"))?;
        let kind = match kind {
            ForkKind::Variation => "variation",
            ForkKind::Debug => "debug",
        };
        Ok(json!({
            "campaign": hex(&self.root()),
            "target": self.binding.target,
            "kind": kind,
            "parent": {
                "attempt": hex(&parent),
                "candidate": node.candidate,
                "search": node.search,
                "invalid": node.invalid,
            },
            "metric_set": self.binding.config.metric_set,
            "answer": EXPERIMENT_ANSWER,
        })
        .to_string())
    }

    fn scorer_briefing(&self, node: AttemptId, split: ResearchSplit) -> Result<String> {
        let row = self
            .node(node)?
            .ok_or(invalid("the measured node is not a campaign node"))?;
        let splits = &self.binding.config.splits;
        let split = match split {
            ResearchSplit::Search => &splits.search,
            ResearchSplit::HeldOut => &splits.held_out,
        };
        Ok(json!({
            "campaign": hex(&self.root()),
            "target": self.binding.target,
            "candidate": row.candidate,
            "split": split,
            "metric_set": self.binding.config.metric_set,
            "answer": SCORE_ANSWER,
        })
        .to_string())
    }

    fn referee_briefing(&self, candidate: AttemptId, release: &EvalRelease) -> Result<String> {
        let basis = self
            .basis_of(candidate)?
            .ok_or(invalid("the candidate has no held-out basis"))?;
        let cases = serde_json::to_value(&release.cases)
            .map_err(|_| invalid("the sealed cases cannot be briefed"))?;
        Ok(json!({
            "campaign": hex(&self.root()),
            "target": self.binding.target,
            "candidate": basis.candidate_pin,
            "incumbent": basis.incumbent_pin,
            "cases": cases,
            "metric_set": self.binding.config.metric_set,
            "answer": REFEREE_ANSWER,
        })
        .to_string())
    }
}
