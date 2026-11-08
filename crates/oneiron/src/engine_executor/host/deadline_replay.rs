//! The calls a resumed pending step already made (FIX 7703): answered from
//! their rows, in the order its program makes them, before any call runs
//! live, and why the step holds once one does not line up.
//! Entry: `RecordingJsHost::answer_from_pending_prefix`.
//! `RecordingJsHost` state is defined by `engine_executor::host`.

use std::borrow::Cow;
use std::collections::VecDeque;

use super::*;

/// What a resumed step's guest reads once its replay holds: the call ran
/// nowhere, and the step commits nothing.
const PENDING_STEP_HELD: &str = "pending_step_held";

const DIVERGED: &str = "the resumed program made another call where its pending step recorded one";
const HOOK_VIEW: &str = "a recorded call's guest read a verb hook's view, which no row keeps";
const ROWS_MISSING: &str = "a recorded call's row is not where its pending step lists it";
const WITHHELD: &str = "the bound door no longer releases a recorded call's answer to its caller";

/// The calls one pending step's program already made (FIX 7703), each row
/// as the record kept it, answered in the order the program makes them.
pub(in crate::engine_executor) struct DeadlineReplay {
    /// The step's rows not answered yet, in bridge order: each recorded
    /// program call's own row, then the rows a callable it called made.
    rows: VecDeque<CodeRunBridgeCall>,
    /// The bridge positions of the program's recorded calls not answered
    /// yet, in order.
    guest_calls: VecDeque<u64>,
    /// Why the replay holds, once a call did not line up.
    held: Option<&'static str>,
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

impl DeadlineReplay {
    /// The replay of `rows`, a pending step's rows from its first bridge
    /// position to its frontier, whose program called `guest_calls`.
    pub(in crate::engine_executor) fn new(
        rows: Vec<CodeRunBridgeCall>,
        guest_calls: Vec<u64>,
    ) -> Self {
        Self {
            rows: rows.into(),
            guest_calls: guest_calls.into(),
            held: None,
        }
    }

    /// The recorded program call at bridge position `at` for `call`: its
    /// own row, the rows a callable it called made, and the row's stored
    /// outcome, matched as the replay cursor matches (position, effect and
    /// request; a spawn's miss is a mismatch, never a live call). A call
    /// that does not line up holds the replay: it and every call after it
    /// get the reason.
    fn take(
        &mut self,
        at: u64,
        call: &SelfCall,
    ) -> std::result::Result<RecordedCall, &'static str> {
        if let Some(held) = self.held {
            return Err(held);
        }
        let Some(row) = self
            .rows
            .front()
            .filter(|row| self.guest_calls.front() == Some(&at) && row.seq == at)
        else {
            return Err(self.hold(ROWS_MISSING));
        };
        if row.hook_view_served {
            return Err(self.hold(HOOK_VIEW));
        }
        let Ok(outcome) = row.strict_replay_answer(at, call.clone()) else {
            return Err(self.hold(DIVERGED));
        };
        self.guest_calls.pop_front();
        let row = self.rows.pop_front().ok_or(ROWS_MISSING)?;
        let next = self.guest_calls.front().copied();
        let mut nested = Vec::new();
        while self
            .rows
            .front()
            .is_some_and(|made| next.is_none_or(|next| made.seq < next))
        {
            nested.extend(self.rows.pop_front());
        }
        Ok(RecordedCall {
            row,
            nested,
            outcome,
        })
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
    /// bound to are bound again. A call that does not line up holds the
    /// step: it and every call after it are refused, nothing runs live, and
    /// the step commits nothing. `None` once every recorded call is
    /// answered: the call runs live, at the step's frontier.
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
        let replay = self.deadline_replay.as_mut()?;
        if replay.held.is_none() && !replay.unreached() {
            return None;
        }
        let taken = match replay.take(self.next_seq, call) {
            Ok(recorded)
                if !self.gated_write.releases_recorded_answer(
                    recorded.served_rows(&self.callable_rows).as_deref(),
                ) =>
            {
                Err(replay.hold(WITHHELD))
            }
            taken => taken,
        };
        let RecordedCall {
            row,
            nested,
            outcome,
        } = match taken {
            Ok(recorded) => recorded,
            Err(_) => {
                if self.hard_failure.is_none() {
                    self.hard_failure = Some(Error::InvalidConfig(PENDING_STEP_HELD.to_owned()));
                }
                let outcome = SelfDispatchOutcome::Failed(SelfFailedResult {
                    effect: call.effect(),
                    error: PENDING_STEP_HELD.to_owned(),
                    code: None,
                    disk_floor: None,
                });
                // No row answers it: the replay context is incomplete.
                return Some(self.respond(call, None, outcome, None));
            }
        };
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
        // 2360); its row keeps its value-free answer.
        let view = self
            .gated_write
            .replay_reveal_view(&call, &outcome)
            .ok()
            .flatten();
        Some(self.respond(&call, Some(seq), outcome, view))
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
    /// a wait or a declined TASK each end the step as they always have).
    pub(in crate::engine_executor) fn parks_at_deadline(&self) -> bool {
        self.step_deadline
            && self.hard_failure.is_none()
            && !self.left_a_gap
            && self.durable_wait.is_none()
            && self.declined.is_none()
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
