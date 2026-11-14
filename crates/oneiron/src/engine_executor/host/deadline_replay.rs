//! The calls a resumed pending step already made (FIX 7703): answered from
//! their rows, in the order its program makes them, before any call runs
//! live, and the resume preflight the walk keeps over them (L8-23): each call
//! the program makes while recorded calls remain is replay free, changed or
//! past the walk's end, and a tail holding an effect step turns the replay dry.
//! Entry: `RecordingJsHost::answer_from_pending_prefix`.
//! `RecordingJsHost` state is defined by `engine_executor::host`.

use std::borrow::Cow;
use std::collections::VecDeque;

use super::resume_preflight::{
    ChangedStep, ResumePreflightReport, ResumeVerdict, UnreachedStep, call_verb, effect_step,
    request_digest,
};
use super::*;

/// What a resumed step's guest reads once its replay holds: the call ran
/// nowhere, and the step commits nothing.
const PENDING_STEP_HELD: &str = "pending_step_held";

/// What a resumed step's guest reads once its walk turned dry (L8-23): the call ran nowhere,
/// and the entry holds with the walk's report.
const RESUME_PREFLIGHT_HELD: &str = "resume_preflight_held";

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
}

/// What one call of the resumed program meets in the walk (L8-23).
enum PreflightTake {
    /// Answered from its rows: replay free, or dry from its recorded outcome.
    Row(Box<RecordedCall>),
    /// Runs live: a pure change, or past dropped rows.
    Live,
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
        }
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
    /// turns dry. Past a dry tail every change answers from its recorded outcome.
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
    /// A tail holding an effect step turns the replay dry; a pure tail drops its rows and this
    /// call runs live.
    fn end_walk(&mut self, results: &[CodeRunRawOutput]) -> PreflightTake {
        if self.dry {
            return PreflightTake::Held(PreflightHeld::Preflight);
        }
        let mut tail: Vec<(CodeRunBridgeCall, Vec<CodeRunBridgeCall>)> = Vec::new();
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
            self.restore_tail(tail);
            self.dry = true;
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
    fn restore_tail(&mut self, tail: Vec<(CodeRunBridgeCall, Vec<CodeRunBridgeCall>)>) {
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
    fn pop_front_call(&mut self) -> Option<(CodeRunBridgeCall, Vec<CodeRunBridgeCall>)> {
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
    /// is an effect step. The rows stay drained; a pure tail's step commits without them, so its
    /// seqs go to the next step's calls, and a row that still owns a kept output counts as an
    /// effect step.
    fn finalize_tail(&mut self, results: &[CodeRunRawOutput]) -> bool {
        let mut holds_effect = false;
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
        }
        holds_effect
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

impl RecordingJsHost<'_, '_> {
    /// Lends a resumed pending step's recorded calls to this host (FIX
    /// 7703): its program's calls meet them first, in order.
    pub(in crate::engine_executor) fn with_deadline_replay(
        mut self,
        replay: Option<DeadlineReplay>,
    ) -> Self {
        self.deadline_replay = replay;
        self
    }

    /// Answers `call` from a resumed pending step's recorded rows while its
    /// program has recorded calls left (FIX 7703). Nothing is dispatched and
    /// no row is made: the rows join this step's calls as the record kept
    /// them, at their own positions, and the names their stored answers were
    /// bound to are bound again. A call that meets its row replays free; a pure
    /// change drops its row and runs live at the same seq (L8-23). An integrity
    /// fault holds the step as it always has; a tail holding an effect step turns
    /// the replay dry instead, and the entry holds with the walk's report. `None`
    /// once every recorded call is answered: the call runs live, at the step's
    /// frontier.
    ///
    /// A recorded answer reaches the guest only as the bound door rules
    /// now (FIX 7703). The door admits the read, as at a write's kept
    /// answer. The rows the answer was served from must not stay on this
    /// device for the door's caller. A refusal of either holds the step in
    /// the same way.
    pub(super) fn answer_from_pending_prefix(
        &mut self,
        call: &SelfCall,
    ) -> Option<SelfDispatchResponse> {
        if self
            .deadline_replay
            .as_ref()
            .is_some_and(|replay| replay.held.is_none() && !replay.dry() && !replay.unreached())
        {
            return None;
        }
        let at = self.next_seq;
        let taken = {
            let replay = self.deadline_replay.as_mut()?;
            let results = &self.results;
            replay.take(at, call, results)
        };
        let recorded = match taken {
            PreflightTake::Live => return None,
            PreflightTake::Row(recorded)
                if !self.gated_write.releases_recorded_answer(
                    recorded.served_rows(&self.callable_rows).as_deref(),
                ) =>
            {
                if let Some(replay) = self.deadline_replay.as_mut() {
                    replay.hold(WITHHELD);
                }
                return Some(self.held_pending_answer(call, PENDING_STEP_HELD));
            }
            PreflightTake::Row(recorded) => *recorded,
            PreflightTake::Held(PreflightHeld::Integrity(_)) => {
                return Some(self.held_pending_answer(call, PENDING_STEP_HELD));
            }
            PreflightTake::Held(PreflightHeld::Preflight) => {
                return Some(self.held_pending_answer(call, RESUME_PREFLIGHT_HELD));
            }
        };
        let RecordedCall {
            row,
            nested,
            outcome,
        } = recorded;
        let (seq, started_at_ms) = (row.seq, row.started_at_ms);
        let call = call.clone().with_bridge_stamp(seq, started_at_ms);
        // A callable's calls bound their stored answers before its own
        // answer was bound, as they ran.
        for made in &nested {
            if let Ok(made_outcome) = made.recorded_outcome() {
                self.rebind_recorded_card(made.seq, &made_outcome);
            }
        }
        self.rebind_recorded_card(seq, &outcome);
        if matches!(call, SelfCall::SkillsCall(_)) {
            let cause = crate::code_run::ReadWorldUnknown::CallableSkill;
            self.gated_write.read_worlds_unknown(self.run_id, cause);
        }
        if self.durable_wait.is_none()
            && let SelfDispatchOutcome::DurableWait(wait) = &outcome
        {
            self.durable_wait = Some(wait.clone());
        }
        if let SelfDispatchOutcome::TaskRefusal(refusal) = &outcome
            && refusal.declined()
        {
            self.declined = Some(refusal.task_ref);
        }
        self.guest_calls.push(seq);
        self.next_seq = seq.saturating_add(1).saturating_add(nested.len() as u64);
        self.bridge_calls.push(row);
        self.bridge_calls.extend(nested);
        // A granted `reveal.wait` reads its value again under its own lease,
        // for the guest's view only, as a pinned entry's replay does (FIX
        // 2360); its row keeps its value-free answer. A dry walk reads
        // nothing live, and its changed call never borrows the recorded
        // lease (L8-23).
        let view = if self.pending_replay_dry() {
            None
        } else {
            self.gated_write
                .replay_reveal_view(&call, &outcome)
                .ok()
                .flatten()
        };
        Some(self.respond(&call, Some(seq), outcome, view))
    }

    /// The guest-visible typed failure of a held replay: the call ran nowhere (L8-23).
    fn held_pending_answer(&mut self, call: &SelfCall, code: &str) -> SelfDispatchResponse {
        if self.hard_failure.is_none() {
            self.hard_failure = Some(Error::InvalidConfig(code.to_owned()));
        }
        let outcome = SelfDispatchOutcome::Failed(SelfFailedResult {
            effect: call.effect(),
            error: code.to_owned(),
            code: None,
            disk_floor: None,
        });
        // No row answers it: the replay context is incomplete.
        self.respond(call, None, outcome, None)
    }

    /// Binds again the stored answer a recorded row's outcome hands its
    /// guest by card, under the name the call that stored it bound (FIX
    /// 7703), so the resumed program's names stand as its first slice left
    /// them and its later calls meet their rows. Only a body the call stored
    /// for itself binds: a verb's, a skill's, a fold's or the leader's answer
    /// at the call's bridge result path, or a spilled typed reply, whose
    /// stored path a later store of the same bytes no longer reuses.
    fn rebind_recorded_card(&mut self, seq: u64, outcome: &SelfDispatchOutcome) {
        let card: Option<Cow<'_, serde_json::Value>> = match outcome {
            SelfDispatchOutcome::AgentVerb(answer) => Some(Cow::Borrowed(&answer.output)),
            SelfDispatchOutcome::SkillCall(result) => Some(Cow::Borrowed(&result.output)),
            SelfDispatchOutcome::StoredReply(reply) => Some(Cow::Borrowed(&reply.output)),
            SelfDispatchOutcome::Fold(answer) => {
                serde_json::from_str(&answer.json).ok().map(Cow::Owned)
            }
            SelfDispatchOutcome::Leader(json) => serde_json::from_str(json).ok().map(Cow::Owned),
            _ => None,
        };
        let Some(card) = card else {
            return;
        };
        let (Some(reference), Some(name)) = (
            card.get("ref").and_then(serde_json::Value::as_str),
            card.get("name").and_then(serde_json::Value::as_str),
        ) else {
            return;
        };
        if !reference.starts_with("occurrence:") {
            return;
        }
        let Some((output, _)) = self.resolve_result(&JsResultRef::Handle(reference.to_owned()))
        else {
            return;
        };
        let spilled = matches!(outcome, SelfDispatchOutcome::StoredReply(_));
        if !spilled && output.path != bridge_result_output_path(seq) {
            return;
        }
        if spilled && !self.replayed_stores.contains(&output.path) {
            self.replayed_stores.push(output.path.clone());
        }
        self.bind(name.to_owned(), output.handle, output.path);
    }

    /// Whether the step parks at its deadline (FIX 7703): its runtime
    /// stopped it there, and nothing else ended it (a hard failure, a gap,
    /// a wait or a declined TASK each end the step as they always have). A dry
    /// replay never parks: its divergence holds the entry (L8-23).
    pub(in crate::engine_executor) fn parks_at_deadline(&self) -> bool {
        self.step_deadline
            && self.hard_failure.is_none()
            && !self.left_a_gap
            && self.durable_wait.is_none()
            && self.declined.is_none()
            && self
                .deadline_replay
                .as_ref()
                .is_none_or(|replay| !replay.dry())
    }

    /// Why a resumed step's replay holds; `None` while it lines up, or for
    /// a step that is not a resumed one.
    pub(in crate::engine_executor) fn pending_replay_held(&self) -> Option<&'static str> {
        self.deadline_replay.as_ref().and_then(|replay| replay.held)
    }

    /// Whether a resumed step's program left recorded calls it never reached.
    pub(in crate::engine_executor) fn pending_replay_unreached(&self) -> bool {
        self.deadline_replay
            .as_ref()
            .is_some_and(DeadlineReplay::unreached)
    }

    /// Whether a resumed step's replay turned dry: an effect step changed or went unreached
    /// (L8-23).
    pub(in crate::engine_executor) fn pending_replay_dry(&self) -> bool {
        self.deadline_replay
            .as_ref()
            .is_some_and(DeadlineReplay::dry)
    }

    /// The walk's report as it stands; `None` for a step that resumed nothing (L8-23).
    pub(in crate::engine_executor) fn pending_preflight_report(
        &self,
    ) -> Option<ResumePreflightReport> {
        self.deadline_replay.as_ref().map(DeadlineReplay::report)
    }

    /// A dry replay's report, with every recorded call left listed unreached (L8-23); `None`
    /// unless the replay turned dry.
    pub(in crate::engine_executor) fn dry_preflight_report(
        &mut self,
    ) -> Option<ResumePreflightReport> {
        let results = &self.results;
        let replay = self.deadline_replay.as_mut()?;
        if !replay.dry() {
            return None;
        }
        replay.finalize_tail(results);
        Some(replay.report())
    }

    /// The report when the pass ended with recorded calls unreached (L8-23): each joins it, and
    /// `Some` only when one is an effect step. A pure tail's rows stay dropped for the commit.
    pub(in crate::engine_executor) fn effect_tail_preflight_report(
        &mut self,
    ) -> Option<ResumePreflightReport> {
        let results = &self.results;
        let replay = self.deadline_replay.as_mut()?;
        if replay.finalize_tail(results) {
            Some(replay.report())
        } else {
            None
        }
    }

    /// The step's calls for its park (FIX 7703): its rows, replayed and live,
    /// then the recorded ones its program did not reach yet, and its
    /// program's calls in the same order.
    pub(in crate::engine_executor) fn take_parked_calls(
        &mut self,
    ) -> (Vec<CodeRunBridgeCall>, Vec<u64>) {
        let mut rows = std::mem::take(&mut self.bridge_calls);
        let mut guest_calls = std::mem::take(&mut self.guest_calls);
        if let Some(replay) = self.deadline_replay.take() {
            let (unreached_rows, unreached_calls) = replay.into_unreached();
            rows.extend(unreached_rows);
            guest_calls.extend(unreached_calls);
        }
        (rows, guest_calls)
    }
}
