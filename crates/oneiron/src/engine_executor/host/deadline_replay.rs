//! The calls a resumed pending step already made (FIX 7703): answered from
//! their rows, in the order its program makes them, before any call runs
//! live, and the resume preflight the walk keeps over them (L8-23): each call
//! the program makes while recorded calls remain is replay free, changed or
//! past the walk's end, and a tail holding an effect step turns the replay dry.
//! Entry: `RecordingJsHost::answer_from_pending_prefix`.
//! `RecordingJsHost` state is defined by `engine_executor::host`.

use std::collections::VecDeque;

use super::super::resume_divergence::ResumeDivergenceChoice;
use super::resume_preflight::{
    ChangedStep, ResumePreflightReport, ResumeVerdict, UnreachedStep, call_verb, effect_step,
    request_digest,
};
use super::*;

mod recorded_answers;

/// One recorded program call popped from a pending step's rows: its row and the rows a
/// callable it called made (L8-23).
type PoppedProgramCall = (CodeRunBridgeCall, Vec<CodeRunBridgeCall>);

/// What a resumed step's guest reads once its replay holds: the call ran
/// nowhere, and the step commits nothing.
const PENDING_STEP_HELD: &str = "pending_step_held";

/// What a resumed step's guest reads once its walk turned dry (L8-23): the call ran nowhere,
/// and the entry holds with the walk's report. A result call there answers it too: a dry walk
/// stores and reads nothing live.
pub(super) const RESUME_PREFLIGHT_HELD: &str = "resume_preflight_held";

/// What a resumed step's guest reads for a changed effect step the owner left (L8-23): the call
/// ran nowhere, the recorded row stands, and the step goes on without it.
const EFFECT_CHANGED_LEFT: &str = "effect_changed_left";

const HOOK_VIEW: &str = "a recorded call's guest read a verb hook's view, which no row keeps";
const ROWS_MISSING: &str = "a recorded call's row is not where its pending step lists it";
const WITHHELD: &str = "the bound door no longer releases a recorded call's answer to its caller";

/// The calls one pending step's program already made (FIX 7703), each row
/// as the record kept it, answered in the order the program makes them, and
/// the preflight report the walk keeps over them (L8-23).
pub(in crate::engine_executor) struct DeadlineReplay {
    /// The step's rows not answered yet, in bridge order: each recorded
    /// program call's own row, then the rows a callable it called made.
    rows: VecDeque<CodeRunBridgeCall>,
    /// The bridge positions of the program's recorded calls not answered
    /// yet, in order.
    guest_calls: VecDeque<u64>,
    /// Why the replay holds, once a call did not line up.
    held: Option<&'static str>,
    /// The run whose step resumed, for the report.
    run_id: EntityId,
    /// The resumed step's seq, for the report.
    step_seq: u64,
    /// The pending step's bridge frontier, for the report.
    frontier: u64,
    /// Seqs that met their rows, in order.
    replay_free: Vec<u64>,
    /// Changed calls, in order.
    changed: Vec<ChangedStep>,
    /// Unreached recorded calls, in order.
    unreached: Vec<UnreachedStep>,
    /// The guest boundary changed since the step parked.
    boundary_changed: bool,
    /// The program prepares to other JavaScript than the parked one ran as.
    preparation_changed: bool,
    /// Whether the walk turned dry: an effect step changed or went unreached,
    /// so nothing runs live for the rest of the pass.
    dry: bool,
    /// Whether the walk ended on a tail holding an effect step: the positions past it no longer
    /// compare, so every later call holds and the tail stays unreached (L8-23).
    walk_ended: bool,
    /// The owner's answer to the ask this pass resumes under, when the run's row still waits on
    /// this step: the answered report and the choice, applied entry by entry (L8-23).
    answer: Option<(ResumePreflightReport, ResumeDivergenceChoice)>,
    /// Seqs whose recorded rows this pass dropped to run live under a refire answer, rows and
    /// nested rows alike: their kept outputs go before the commit or park appends the new ones
    /// (L8-23).
    refired: Vec<u64>,
    /// Whether the owner left the drifted tail: this call and every later call of the pass answer
    /// `effect_changed_left`, and the kept tail joins the step's rows at the commit (L8-23).
    left: bool,
}

/// What one call of the resumed program meets in the walk (L8-23).
enum PreflightTake {
    /// Answered from its rows: replay free, or dry from its recorded outcome.
    Row(Box<RecordedCall>),
    /// Runs live: a pure change, a refired change, or past dropped rows.
    Live,
    /// A changed effect step the owner left: its recorded rows stand, and the guest reads the
    /// typed `effect_changed_left` failure.
    Left(Box<RecordedCall>),
    /// A call past a left tail: no row, no seq, the typed `effect_changed_left` failure.
    LeftTail,
    /// The guest-visible typed failure: an integrity hold, or the dry hold.
    Held(PreflightHeld),
}

/// Why the walk refuses one call (L8-23).
enum PreflightHeld {
    /// An integrity fault, answered as `pending_step_held`.
    Integrity(&'static str),
    /// The dry tail, answered as `resume_preflight_held`.
    Preflight,
}

/// One recorded program call a resumed step meets again: its own row, the
/// rows a callable it called made, and the row's stored outcome.
struct RecordedCall {
    row: CodeRunBridgeCall,
    nested: Vec<CodeRunBridgeCall>,
    outcome: SelfDispatchOutcome,
}

impl RecordedCall {
    /// The rows the run was served producing this call's answer (DEC-0005):
    /// its own row's and those of the rows a callable it called made. A
    /// callable's answer also adds the rows the run's callables answered
    /// from (`callable`, joined as `RecordingJsHost::result_rows` joins
    /// them). Each outcome's own source witnesses join them too (FIX 7703
    /// review fix): the verb rows do not list them. `None` when one of them
    /// kept no set, or a made row's outcome does not decode.
    fn served_rows(
        &self,
        (skills, read): &(Vec<EntityId>, Option<Vec<EntityId>>),
    ) -> Option<Vec<EntityId>> {
        let own = agent_verb_rows_of(std::slice::from_ref(&self.row))?;
        let made = agent_verb_rows_of(&self.nested)?;
        let mut witnessed = outcome_sources(&self.outcome);
        for made in &self.nested {
            witnessed.extend(outcome_sources(&made.recorded_outcome().ok()?));
        }
        let served = [own.as_slice(), made.as_slice(), witnessed.as_slice()].concat();
        if !matches!(self.row.effect, SelfEffect::SkillsCall) {
            return Some(served);
        }
        let read = read.as_deref()?;
        Some([served.as_slice(), read, skills.as_slice()].concat())
    }
}

/// The records a recorded outcome names as its sources (FIX 7703 review
/// fix): the records a fold answer's words were written from, and each
/// memory search hit. A cached answer reaches the resumed guest only when
/// the bound door still releases these records to its caller.
fn outcome_sources(outcome: &SelfDispatchOutcome) -> Vec<EntityId> {
    match outcome {
        SelfDispatchOutcome::Fold(answer) => answer.word_sources(),
        SelfDispatchOutcome::MemorySearch(search) => {
            search.results.iter().map(|hit| hit.id).collect()
        }
        _ => Vec::new(),
    }
}

/// Whether the record still holds outputs of the recorded row at `seq` (L8-23): a bridge result
/// the park kept, which a later live call at the same seq would shadow with its own (this
/// step's, or the next step's once a dropped tail frees the seq).
fn output_owned(results: &[CodeRunRawOutput], seq: u64) -> bool {
    let path = bridge_result_output_path(seq);
    results.iter().any(|output| output.path == path)
}

/// Whether a recorded program call left behind counts as an effect step (L8-23): it, or a row a
/// callable it called made, is not a read, or still owns a kept output.
fn tail_call_holds_effect(
    row: &CodeRunBridgeCall,
    nested: &[CodeRunBridgeCall],
    results: &[CodeRunRawOutput],
) -> bool {
    std::iter::once(row).chain(nested).any(|made| {
        effect_step(made.effect, made.recorded_verb()) || output_owned(results, made.seq)
    })
}

/// Whether a call of `effect` runs a callable skill's body through the host (L8-23): only a
/// callable's calls take bridge positions past their caller, so only its effect makes nested rows.
/// The match is exhaustive with no wildcard arm, so a new variant forces a choice.
fn runs_callable(effect: SelfEffect) -> bool {
    match effect {
        SelfEffect::SkillsCall => true,
        SelfEffect::AgentsSpawn
        | SelfEffect::TasksAsk
        | SelfEffect::TasksWait
        | SelfEffect::TasksRefuse
        | SelfEffect::ConsultResult
        | SelfEffect::MemorySearch
        | SelfEffect::MemoryWriteFixture
        | SelfEffect::MemoryPutClaim
        | SelfEffect::MemorySupersedeClaim
        | SelfEffect::MemoryPutEdge
        | SelfEffect::Ask
        | SelfEffect::DestructiveFixture
        | SelfEffect::OutboundFixture
        | SelfEffect::TaskDelegate
        | SelfEffect::Context
        | SelfEffect::Speak
        | SelfEffect::Think
        | SelfEffect::Express
        | SelfEffect::ReportBlocked
        | SelfEffect::AgentsPut
        | SelfEffect::InferenceDefaultsRead
        | SelfEffect::InferenceDefaultsReplace
        | SelfEffect::WakePolicyWrite
        | SelfEffect::AgentVerb
        | SelfEffect::ConnectorAnswer
        | SelfEffect::WorldPrivacySet
        | SelfEffect::Fold
        | SelfEffect::ReaderSpawn
        | SelfEffect::ReaderReport
        | SelfEffect::TasksWaitSet
        | SelfEffect::Summarize
        | SelfEffect::Leader
        | SelfEffect::LeaderSplit
        | SelfEffect::Team
        | SelfEffect::WorkflowDispatch
        | SelfEffect::RepoSnapshotsGet
        | SelfEffect::RepoSnapshotsRead
        | SelfEffect::RepoSymbolsDefinitions
        | SelfEffect::RepoSymbolsNeighbors
        | SelfEffect::RepoViewsGet
        | SelfEffect::RepoViewsRead
        | SelfEffect::RepoMergeQueueObserve
        | SelfEffect::RepoSnapshotsIngest
        | SelfEffect::RepoWorkOpen
        | SelfEffect::RepoSymbolsDeclare
        | SelfEffect::RepoSymbolsRenew
        | SelfEffect::RepoSymbolsRelease
        | SelfEffect::RepoProposalSubmit
        | SelfEffect::RepoProposalResolve
        | SelfEffect::RepoMergeQueueEnqueue
        | SelfEffect::RepoCheckoutBind
        | SelfEffect::RepoExport
        | SelfEffect::RepoSymbolsObserve => false,
    }
}

impl DeadlineReplay {
    /// The replay of `rows`, a pending step's rows from its first bridge
    /// position to its frontier, whose program called `guest_calls`.
    pub(in crate::engine_executor) fn new(
        rows: Vec<CodeRunBridgeCall>,
        guest_calls: Vec<u64>,
        run_id: EntityId,
        step_seq: u64,
        frontier: u64,
    ) -> Self {
        Self {
            rows: rows.into(),
            guest_calls: guest_calls.into(),
            held: None,
            run_id,
            step_seq,
            frontier,
            replay_free: Vec::new(),
            changed: Vec::new(),
            unreached: Vec::new(),
            boundary_changed: false,
            preparation_changed: false,
            dry: false,
            walk_ended: false,
            answer: None,
            refired: Vec::new(),
            left: false,
        }
    }

    /// The replay under the owner's answer to this step's ask (L8-23): the answered report and the
    /// choice, applied entry by entry at the moment the walk would turn dry.
    pub(in crate::engine_executor) fn with_answer(
        mut self,
        report: ResumePreflightReport,
        choice: ResumeDivergenceChoice,
    ) -> Self {
        self.answer = Some((report, choice));
        self
    }

    /// The walk's boundary and preparation flags, decided before the pass runs (L8-23).
    pub(in crate::engine_executor) fn set_preflight_flags(
        &mut self,
        boundary_changed: bool,
        preparation_changed: bool,
    ) {
        self.boundary_changed = boundary_changed;
        self.preparation_changed = preparation_changed;
    }

    /// What the call at bridge position `at` meets in the walk (L8-23): its recorded rows
    /// when it lines up, a live run when it is a pure change past dropped rows, or the
    /// guest-visible typed failure. An integrity fault holds the replay as it always has; a
    /// tail holding an effect step turns it dry instead.
    fn take(&mut self, at: u64, call: &SelfCall, results: &[CodeRunRawOutput]) -> PreflightTake {
        if let Some(held) = self.held {
            return PreflightTake::Held(PreflightHeld::Integrity(held));
        }
        if self.left {
            return PreflightTake::LeftTail;
        }
        // A held call takes no position, so a later call could line up with the kept tail again
        // and read as replay free (L8-23).
        if self.walk_ended {
            return PreflightTake::Held(PreflightHeld::Preflight);
        }
        match (
            self.guest_calls.front().copied(),
            self.rows.front().map(|row| row.seq),
        ) {
            (None, None) => {
                if self.dry {
                    PreflightTake::Held(PreflightHeld::Preflight)
                } else {
                    PreflightTake::Held(PreflightHeld::Integrity(self.hold(ROWS_MISSING)))
                }
            }
            (Some(guest), Some(seq)) if seq == guest && guest == at => {
                self.take_aligned(at, call, results)
            }
            (Some(guest), Some(seq)) if seq == guest => self.end_walk(results),
            _ => PreflightTake::Held(PreflightHeld::Integrity(self.hold(ROWS_MISSING))),
        }
    }

    /// The front recorded call at this position (L8-23): replay free when it meets its row, a
    /// changed call when only its request differs, or the walk's end when its effect differs.
    fn take_aligned(
        &mut self,
        at: u64,
        call: &SelfCall,
        results: &[CodeRunRawOutput],
    ) -> PreflightTake {
        let Some(row) = self.rows.front() else {
            return PreflightTake::Held(PreflightHeld::Integrity(self.hold(ROWS_MISSING)));
        };
        if row.hook_view_served {
            return PreflightTake::Held(PreflightHeld::Integrity(self.hold(HOOK_VIEW)));
        }
        let same_effect = row.effect == call.effect();
        let replayed = row.strict_replay_answer(at, call.clone());
        match replayed {
            Ok(outcome) => {
                let Some((row, nested)) = self.pop_front_call() else {
                    return PreflightTake::Held(PreflightHeld::Integrity(self.hold(ROWS_MISSING)));
                };
                self.replay_free.push(at);
                PreflightTake::Row(Box::new(RecordedCall {
                    row,
                    nested,
                    outcome,
                }))
            }
            Err(_) if same_effect => self.take_changed(at, call, results),
            Err(_) => self.end_walk(results),
        }
    }

    /// Same position, same effect, another request (L8-23): a pure change drops its row and runs
    /// live at the same seq; an effect change answers from the recorded outcome and the replay
    /// turns dry. Past a dry tail every change answers from its recorded outcome. Under the
    /// owner's answer, an approved changed effect step re-fires live once or answers left.
    fn take_changed(
        &mut self,
        at: u64,
        call: &SelfCall,
        results: &[CodeRunRawOutput],
    ) -> PreflightTake {
        let Some(row) = self.rows.front() else {
            return PreflightTake::Held(PreflightHeld::Integrity(self.hold(ROWS_MISSING)));
        };
        let recorded_is_effect = effect_step(row.effect, row.recorded_verb());
        let recorded_digest = request_digest(&row.request);
        // The value the strict match compared; empty when the call does not encode.
        let reentered_digest = row
            .replay_request_value(call.clone())
            .map_or_else(|_| String::new(), |value| request_digest(&value));
        let outcome = row.recorded_outcome().ok();
        let reentered_is_effect = effect_step(call.effect(), call_verb(call));
        let nested_len = self.front_nested_len();
        let owns_output = output_owned(results, at);
        let entry_is_effect =
            recorded_is_effect || reentered_is_effect || nested_len > 0 || owns_output;
        if !entry_is_effect && !self.dry {
            if self.pop_front_call().is_none() {
                return PreflightTake::Held(PreflightHeld::Integrity(self.hold(ROWS_MISSING)));
            }
            self.changed.push(ChangedStep {
                seq: at,
                effect: call.effect(),
                recorded_request_digest: recorded_digest,
                reentered_request_digest: reentered_digest,
                effect_step: false,
            });
            return PreflightTake::Live;
        }
        if entry_is_effect && !self.dry {
            let approved = self.answer.as_ref().and_then(|(report, choice)| {
                report
                    .changed
                    .iter()
                    .any(|step| {
                        step.effect_step
                            && step.seq == at
                            && step.effect == call.effect()
                            && step.recorded_request_digest == recorded_digest
                            && step.reentered_request_digest == reentered_digest
                    })
                    .then_some(*choice)
            });
            if let Some(choice) = approved {
                match choice {
                    ResumeDivergenceChoice::Refire
                        if nested_len == 0 && !runs_callable(call.effect()) =>
                    {
                        let Some((row, _)) = self.pop_front_call() else {
                            return PreflightTake::Held(PreflightHeld::Integrity(
                                self.hold(ROWS_MISSING),
                            ));
                        };
                        self.changed.push(ChangedStep {
                            seq: at,
                            effect: row.effect,
                            recorded_request_digest: recorded_digest,
                            reentered_request_digest: reentered_digest,
                            effect_step: true,
                        });
                        self.refired.push(at);
                        return PreflightTake::Live;
                    }
                    ResumeDivergenceChoice::Leave => {
                        let Some((row, nested)) = self.pop_front_call() else {
                            return PreflightTake::Held(PreflightHeld::Integrity(
                                self.hold(ROWS_MISSING),
                            ));
                        };
                        let Ok(outcome) = row.recorded_outcome() else {
                            return PreflightTake::Held(PreflightHeld::Integrity(
                                self.hold(ROWS_MISSING),
                            ));
                        };
                        self.changed.push(ChangedStep {
                            seq: at,
                            effect: row.effect,
                            recorded_request_digest: recorded_digest,
                            reentered_request_digest: reentered_digest,
                            effect_step: entry_is_effect,
                        });
                        return PreflightTake::Left(Box::new(RecordedCall {
                            row,
                            nested,
                            outcome,
                        }));
                    }
                    ResumeDivergenceChoice::Refire => {}
                }
            }
        }
        let Some(outcome) = outcome else {
            return PreflightTake::Held(PreflightHeld::Integrity(self.hold(ROWS_MISSING)));
        };
        let Some((row, nested)) = self.pop_front_call() else {
            return PreflightTake::Held(PreflightHeld::Integrity(self.hold(ROWS_MISSING)));
        };
        self.dry = true;
        self.changed.push(ChangedStep {
            seq: at,
            effect: row.effect,
            recorded_request_digest: recorded_digest,
            reentered_request_digest: reentered_digest,
            effect_step: entry_is_effect,
        });
        PreflightTake::Row(Box::new(RecordedCall {
            row,
            nested,
            outcome,
        }))
    }

    /// The walk ends here (L8-23): every recorded program call left is unreached and classified.
    /// A tail holding an effect step turns the replay dry, and this call and every later one
    /// hold; a pure tail drops its rows and this call runs live. Under the owner's answer, an
    /// approved effect tail drops to re-fire or stays kept while the pass answers left.
    fn end_walk(&mut self, results: &[CodeRunRawOutput]) -> PreflightTake {
        if self.dry {
            self.walk_ended = true;
            return PreflightTake::Held(PreflightHeld::Preflight);
        }
        let mut tail: Vec<PoppedProgramCall> = Vec::new();
        while self.guest_calls.front().is_some() {
            let Some(popped) = self.pop_front_call() else {
                self.restore_tail(tail);
                return PreflightTake::Held(PreflightHeld::Integrity(self.hold(ROWS_MISSING)));
            };
            tail.push(popped);
        }
        let holds_effect = tail
            .iter()
            .any(|(row, nested)| tail_call_holds_effect(row, nested, results));
        if holds_effect {
            let approved = self.answer.as_ref().and_then(|(report, choice)| {
                tail.iter()
                    .all(|(row, nested)| {
                        !tail_call_holds_effect(row, nested, results)
                            || report.unreached.iter().any(|step| {
                                step.effect_step && step.seq == row.seq && step.effect == row.effect
                            })
                    })
                    .then_some(*choice)
            });
            if let Some(choice) = approved {
                match choice {
                    ResumeDivergenceChoice::Refire => {
                        for (row, nested) in &tail {
                            self.unreached.push(UnreachedStep {
                                seq: row.seq,
                                effect: row.effect,
                                effect_step: tail_call_holds_effect(row, nested, results),
                            });
                        }
                        for (row, nested) in tail {
                            self.refired.push(row.seq);
                            for made in nested {
                                self.refired.push(made.seq);
                            }
                        }
                        return PreflightTake::Live;
                    }
                    ResumeDivergenceChoice::Leave => {
                        self.restore_tail(tail);
                        self.left = true;
                        return PreflightTake::LeftTail;
                    }
                }
            }
            self.restore_tail(tail);
            self.dry = true;
            self.walk_ended = true;
            PreflightTake::Held(PreflightHeld::Preflight)
        } else {
            for (row, _) in &tail {
                self.unreached.push(UnreachedStep {
                    seq: row.seq,
                    effect: row.effect,
                    effect_step: false,
                });
            }
            PreflightTake::Live
        }
    }

    /// Puts a drained tail back where the walk left it, in order (L8-23).
    fn restore_tail(&mut self, tail: Vec<PoppedProgramCall>) {
        for (row, nested) in tail.into_iter().rev() {
            for made in nested.into_iter().rev() {
                self.rows.push_front(made);
            }
            let seq = row.seq;
            self.rows.push_front(row);
            self.guest_calls.push_front(seq);
        }
    }

    /// Pops the front recorded program call: its row and the rows a callable it called made
    /// (L8-23). `None` when the rows and the program calls disagree.
    fn pop_front_call(&mut self) -> Option<PoppedProgramCall> {
        let guest = self.guest_calls.front().copied()?;
        if self.rows.front()?.seq != guest {
            return None;
        }
        self.guest_calls.pop_front();
        let row = self.rows.pop_front()?;
        let next = self.guest_calls.front().copied();
        let mut nested = Vec::new();
        while self
            .rows
            .front()
            .is_some_and(|made| next.is_none_or(|next| made.seq < next))
        {
            nested.extend(self.rows.pop_front());
        }
        Some((row, nested))
    }

    /// How many rows the front recorded call's callables made (L8-23).
    fn front_nested_len(&self) -> usize {
        let next = self.guest_calls.iter().nth(1).copied();
        self.rows
            .iter()
            .skip(1)
            .take_while(|made| next.is_none_or(|next| made.seq < next))
            .count()
    }

    /// The pass ended with recorded calls unreached: each joins the report (L8-23). Whether any
    /// is an effect step, and the drained tail in order, for a park that keeps it. The rows stay
    /// drained; a pure tail's step commits without them, so its seqs go to the next step's calls,
    /// and a row that still owns a kept output counts as an effect step.
    fn finalize_tail(&mut self, results: &[CodeRunRawOutput]) -> (bool, Vec<PoppedProgramCall>) {
        let mut holds_effect = false;
        let mut tail = Vec::new();
        while self.guest_calls.front().is_some() {
            let Some((row, nested)) = self.pop_front_call() else {
                break;
            };
            let is_effect = tail_call_holds_effect(&row, &nested, results);
            holds_effect |= is_effect;
            self.unreached.push(UnreachedStep {
                seq: row.seq,
                effect: row.effect,
                effect_step: is_effect,
            });
            tail.push((row, nested));
        }
        (holds_effect, tail)
    }

    /// The walk's report as it stands (L8-23).
    fn report(&self) -> ResumePreflightReport {
        let changed_effects = self.changed.iter().filter(|step| step.effect_step).count();
        let unreached_effects = self
            .unreached
            .iter()
            .filter(|step| step.effect_step)
            .count();
        let effect_steps_would_refire =
            u64::try_from(changed_effects.saturating_add(unreached_effects)).unwrap_or(u64::MAX);
        ResumePreflightReport {
            run_id: self.run_id,
            step_seq: self.step_seq,
            frontier: self.frontier,
            replay_free: self.replay_free.clone(),
            changed: self.changed.clone(),
            unreached: self.unreached.clone(),
            boundary_changed: self.boundary_changed,
            preparation_changed: self.preparation_changed,
            effect_steps_would_refire,
            verdict: if effect_steps_would_refire == 0 {
                ResumeVerdict::Pure
            } else {
                ResumeVerdict::EffectTail
            },
        }
    }

    /// Whether the walk turned dry: nothing runs live for the rest of the pass (L8-23).
    fn dry(&self) -> bool {
        self.dry
    }

    fn hold(&mut self, why: &'static str) -> &'static str {
        self.held = Some(why);
        why
    }

    /// Whether the program has recorded calls it did not reach yet.
    fn unreached(&self) -> bool {
        !self.guest_calls.is_empty()
    }

    /// The rows and program calls the program did not reach, for a step
    /// that parks again before its frontier.
    fn into_unreached(self) -> (Vec<CodeRunBridgeCall>, Vec<u64>) {
        (self.rows.into(), self.guest_calls.into())
    }
}
