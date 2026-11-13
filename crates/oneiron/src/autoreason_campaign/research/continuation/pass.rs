//! One research continuation pass over its persisted tasks.
//! Entry method: `Pass::advance`.
//! The `Pass` type and continuation records remain defined in `super`.
//!
//! Each step commits its accounting (reserve, serve, settle, refund) in the
//! same write as the row it moves to, and that write first checks that no
//! other pass moved the row since it was read. A pass that lost the row
//! changes nothing, and a crash leaves a step whole or undone. A dispatch
//! and the record doors an ended run's answer goes to write on their own,
//! each once: a dispatch by its dedupe key, a record by its node.

use super::*;

/// A refused refund or settlement leaves the reservation as it stands; any
/// other error stops the pass.
fn past_refusal(result: Result<()>) -> Result<()> {
    match result {
        Ok(()) | Err(Error::InvalidConfig(_)) => Ok(()),
        Err(error) => Err(error),
    }
}

/// No room on `line`: `task` waits at the front, as a round pauses, with
/// nothing reserved and nothing dispatched.
fn hold_front(next: &mut ResearchContinuation, task: ResearchTask, line: ResearchReservationLine) {
    next.pending.insert(0, task);
    next.state = ResearchContinuationState::Held {
        reason: BUDGET_HELD.to_owned(),
    };
    next.held_line = Some(line);
}

fn shot_spent_hold() -> ResearchContinuationState {
    ResearchContinuationState::Held {
        reason: SHOT_SPENT.to_owned(),
    }
}

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

    /// Store `next` over `row` with this step's accounting, in one write.
    /// The write first checks that no other pass moved the row since it was
    /// read, then runs `account` on `next`, then stores it; a pass that lost
    /// the row, or an `account` that fails, writes nothing.
    fn commit<T>(
        &self,
        row: &ResearchContinuation,
        mut next: ResearchContinuation,
        account: impl FnOnce(&mut heed::RwTxn<'_>, &mut ResearchContinuation) -> Result<T>,
    ) -> Result<T> {
        let key = (*row.root.as_bytes(), row.work.key());
        self.vault.with_write_txn_grouped(|txn| {
            if CONTINUATION.get(&self.vault.store, txn, &key)?.as_ref() != Some(row) {
                return Err(Error::ConcurrentWrite(
                    "another pass advanced this research continuation",
                ));
            }
            let value = account(txn, &mut next)?;
            next.updated_at = self.now;
            CONTINUATION.put(&self.vault.store, txn, &key, &next)?;
            Ok(value)
        })
    }

    /// Store `next` over `row` in one write, unless another pass moved the
    /// row since it was read.
    fn save(&self, row: &ResearchContinuation, next: ResearchContinuation) -> Result<()> {
        self.commit(row, next, |_, _| Ok(()))
    }

    /// End a continuation on a refusal. What a task nothing was dispatched on
    /// holds open is refunded in the same write; a dispatched run's
    /// reservation stays as the run left it, and a served confirmation's
    /// exposure stays spent.
    fn fail(&self, row: &ResearchContinuation, reason: String) -> Result<()> {
        let mut next = row.clone();
        let unrun = row.running.as_ref().filter(|running| running.run.is_none());
        if unrun.is_some() {
            next.running = None;
        }
        next.state = failed(reason);
        self.commit(row, next, |txn, _| {
            if let Some(running) = unrun {
                past_refusal(self.refund_in_txn(txn, running.reservation))?;
                if let Some(exposure) = running.exposure {
                    past_refusal(self.refund_in_txn(txn, exposure))?;
                }
            }
            Ok(())
        })
    }

    /// One step of `row`, as this pass read it.
    pub(super) fn step(&self, row: &ResearchContinuation) -> Result<Flow> {
        if let Some(running) = &row.running {
            return match running.run {
                None => self.dispatch(row, running),
                Some(run) => self.observe(row, running, run),
            };
        }
        let mut next = row.clone();
        // A budget hold retries its task now.
        next.state = ResearchContinuationState::Open;
        next.held_line = None;
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
        let work = ResearchReservationLine::Work { purpose };
        let exploration = ResearchReservationLine::Exploration;
        // The signing keys a token reservation may need load before the write.
        let work_signing = reservation_signing(self.vault, self.binding, work);
        let exploration_signing = reservation_signing(self.vault, self.binding, exploration);
        // The reservations and the running row are one write: a pass that
        // lost the row reserves nothing, and a crash leaves no reservation
        // without its row (FIX 14686 needs no compensation).
        self.commit(row, next, |txn, next| {
            // Serving the sealed cohort spends exposure on its own line,
            // reserved before the token work and before the shot.
            let exposure = match task {
                ResearchTask::Confirm { candidate } => {
                    let ask = ReservationAsk {
                        line: exploration,
                        units: SERVING_EXPOSURE,
                        attempt: Some(candidate),
                        at: self.now,
                    };
                    match reserve_in_txn(self.vault, txn, self.binding, ask, exploration_signing)? {
                        Reserved::Id(exposure) => Some(exposure),
                        Reserved::Refused(_) => {
                            hold_front(next, task, exploration);
                            return Ok(Flow::Stop);
                        }
                    }
                }
                _ => None,
            };
            let ask = ReservationAsk {
                line: work,
                units,
                attempt: Some(attempt),
                at: self.now,
            };
            let reservation =
                match reserve_in_txn(self.vault, txn, self.binding, ask, work_signing)? {
                    Reserved::Id(reservation) => reservation,
                    Reserved::Refused(_) => {
                        if let Some(exposure) = exposure {
                            finish_in_txn(self.vault, txn, self.root(), exposure, Finish::Refund)?;
                        }
                        hold_front(next, task, work);
                        return Ok(Flow::Stop);
                    }
                };
            next.running = Some(ResearchRunning {
                task,
                reservation,
                exposure,
                run: None,
                release: None,
            });
            Ok(Flow::Next)
        })
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
                // The serving settled its exposure in the write that served.
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
        let reservation = self
            .reservation(running.reservation)?
            .ok_or(invalid("the running research task has no reservation"))?;
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
                .with_token_ceiling(reservation.units)
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
        let mut next = row.clone();
        next.running = None;
        next.state = failed(reason);
        self.commit(row, next, |txn, _| self.refund_running_in_txn(txn, running))?;
        Ok(Flow::Stop)
    }

    /// Spend the candidate's sealed confirmation, serve its cohort and keep
    /// the release on the task, in one write with the serving's exposure
    /// settled. A shot already spent (by the workflow's own door) is never
    /// spent again: the campaign holds. A cohort that will not serve after
    /// the shot leaves the shot spent, as `reserve_confirmation` does.
    fn release(
        &self,
        row: &ResearchContinuation,
        running: &ResearchRunning,
        candidate: AttemptId,
    ) -> Result<Flow> {
        let root = self.root();
        let seat = self.binding.confirmation.as_ref().map(|seat| seat.cohort);
        self.commit(row, row.clone(), |txn, next| {
            if basis_in_txn(self.vault, txn, root, candidate)?
                .is_some_and(|basis| basis.confirmation.is_some())
            {
                return self.end_unserved(txn, next, running, shot_spent_hold());
            }
            let shot = seat
                .ok_or(invalid("this campaign names no sealed confirmation cohort"))
                .and_then(|cohort| {
                    spend_confirmation_shot_in_txn(
                        self.vault, txn, root, candidate, cohort, self.now,
                    )
                    .map(|_| cohort)
                });
            let cohort = match shot {
                Ok(cohort) => cohort,
                // Refused before the shot was consumed: nothing was spent.
                Err(Error::InvalidConfig(reason)) => {
                    return self.end_unserved(txn, next, running, failed(reason));
                }
                Err(error) => return Err(error),
            };
            match serve_confirmation_in_txn(self.vault, txn, root, candidate, cohort, self.now) {
                Ok(release) => {
                    if let Some(exposure) = running.exposure {
                        finish_in_txn(
                            self.vault,
                            txn,
                            root,
                            exposure,
                            Finish::Settle(SERVING_EXPOSURE),
                        )?;
                    }
                    if let Some(running) = &mut next.running {
                        running.release = Some(release);
                    }
                    Ok(Flow::Next)
                }
                Err(Error::InvalidConfig(_)) => {
                    self.end_unserved(txn, next, running, shot_spent_hold())
                }
                Err(error) => Err(error),
            }
        })
    }

    /// End a confirmation whose cohort was not served, in `txn`: refund what
    /// it holds open, clear it, and leave `state`.
    fn end_unserved(
        &self,
        txn: &mut heed::RwTxn<'_>,
        next: &mut ResearchContinuation,
        running: &ResearchRunning,
        state: ResearchContinuationState,
    ) -> Result<Flow> {
        self.refund_running_in_txn(txn, running)?;
        next.running = None;
        next.state = state;
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
        let actual = run_spend_units(self.vault, run)?;
        self.commit(row, next, |txn, _| {
            self.settle_in_txn(txn, running.reservation, actual)
        })?;
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

    /// Whether reservation `id` is still open in `txn`.
    fn open_in_txn(&self, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<bool> {
        Ok(reservation_in_txn(self.vault, txn, self.root(), id)?
            .is_some_and(|row| row.settlement.is_none()))
    }

    /// Settle a finished run's reservation in `txn` with what it spent
    /// (`None`: no token meter, so it stays committed), once.
    fn settle_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        actual: Option<u64>,
    ) -> Result<()> {
        if self.open_in_txn(txn, id)? {
            let how = actual.map_or(Finish::Unknown, Finish::Settle);
            finish_in_txn(self.vault, txn, self.root(), id, how)?;
        }
        Ok(())
    }

    /// Refund a reservation nothing was spent on, in `txn`, once.
    fn refund_in_txn(&self, txn: &mut heed::RwTxn<'_>, id: EntityId) -> Result<()> {
        if self.open_in_txn(txn, id)? {
            finish_in_txn(self.vault, txn, self.root(), id, Finish::Refund)?;
        }
        Ok(())
    }

    /// Refund what a task that dispatched nothing holds open, in `txn`: its
    /// token work, and a confirmation's exposure while it is open (the
    /// serving settles it in the write that serves).
    fn refund_running_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        running: &ResearchRunning,
    ) -> Result<()> {
        self.refund_in_txn(txn, running.reservation)?;
        if let Some(exposure) = running.exposure {
            self.refund_in_txn(txn, exposure)?;
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
