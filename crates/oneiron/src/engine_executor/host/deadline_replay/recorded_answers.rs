//! The host's side of a resumed pending step's replay (FIX 7703, L8-23): it lends the step's
//! recorded calls to the host, answers the program's calls from their rows, and hands the
//! walk's report and the rows it did not reach to the entry. The walk itself is
//! `DeadlineReplay` in the parent module.

use std::borrow::Cow;

use super::*;

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
    pub(in crate::engine_executor::host) fn answer_from_pending_prefix(
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
            PreflightTake::Left(recorded) => {
                return Some(self.left_changed_answer(call, *recorded));
            }
            PreflightTake::LeftTail => return Some(self.left_pending_answer(call)),
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

    /// A changed effect step the owner left (L8-23): its recorded row and nested rows join the
    /// step's rows at their own seqs, as the `Row` path does, and the guest reads the typed
    /// `effect_changed_left` failure without failing the step. The recorded answer reaches no
    /// one: no card binds again, no wait or declined TASK ends the step, and no response is kept
    /// at the row's seq, because the guest read another one there.
    fn left_changed_answer(
        &mut self,
        call: &SelfCall,
        recorded: RecordedCall,
    ) -> SelfDispatchResponse {
        let RecordedCall { row, nested, .. } = recorded;
        let seq = row.seq;
        if matches!(row.effect, SelfEffect::SkillsCall) {
            let cause = crate::code_run::ReadWorldUnknown::CallableSkill;
            self.gated_write.read_worlds_unknown(self.run_id, cause);
        }
        self.guest_calls.push(seq);
        self.next_seq = seq.saturating_add(1).saturating_add(nested.len() as u64);
        self.bridge_calls.push(row);
        self.bridge_calls.extend(nested);
        self.left_pending_answer(call)
    }

    /// A call past a left tail (L8-23): no row, no seq, the typed `effect_changed_left` failure,
    /// without failing the step.
    fn left_pending_answer(&mut self, call: &SelfCall) -> SelfDispatchResponse {
        let outcome = SelfDispatchOutcome::Failed(SelfFailedResult {
            effect: call.effect(),
            error: EFFECT_CHANGED_LEFT.to_owned(),
            code: None,
            disk_floor: None,
        });
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

    /// Whether a resumed step's walk still has recorded calls ahead (L8-23): a later call could
    /// still turn it dry.
    pub(in crate::engine_executor::host) fn pending_walk_open(&self) -> bool {
        self.deadline_replay.as_ref().is_some_and(|replay| {
            replay.held.is_none() && !replay.dry() && !replay.left && replay.unreached()
        })
    }

    /// Applies the owner's answer at the program's end when it left recorded calls unreached
    /// (L8-23): an approved refire drops the tail, an approved leave keeps it for the commit.
    pub(in crate::engine_executor) fn answer_unreached_tail(&mut self) {
        let results = &self.results;
        if let Some(replay) = self.deadline_replay.as_mut() {
            replay.end_walk_at_program_end(results);
        }
    }

    /// Ends an open walk at a body no recorded store holds (L8-23), as at a call past its rows:
    /// whether the pass holds after it.
    pub(in crate::engine_executor::host) fn end_walk_at_new_output(&mut self) -> bool {
        let results = &self.results;
        self.deadline_replay
            .as_mut()
            .is_some_and(|replay| replay.end_walk_at_new_output(results))
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
        let _ = replay.finalize_tail(results);
        Some(replay.report())
    }

    /// The report of a pass that cannot commit, for a park that keeps a refire (L8-23): the walk
    /// turned dry, or the program ended with an effect step unreached. The report lists every
    /// recorded call left unreached, and the drained tail is restored so the park keeps it.
    /// `None` when the pass can commit, with the walk left as it was.
    pub(in crate::engine_executor) fn preflight_report_for_park(
        &mut self,
    ) -> Option<ResumePreflightReport> {
        let results = &self.results;
        let replay = self.deadline_replay.as_mut()?;
        let listed = replay.unreached.len();
        let (holds_effect, tail) = replay.finalize_tail(results);
        let report = (replay.dry() || holds_effect).then(|| replay.report());
        replay.restore_tail(tail);
        if report.is_none() {
            replay.unreached.truncate(listed);
        }
        report
    }

    /// Whether the owner left the drifted tail: the pass answers left and commits its kept rows
    /// (L8-23).
    pub(in crate::engine_executor) fn pending_replay_left(&self) -> bool {
        self.deadline_replay
            .as_ref()
            .is_some_and(|replay| replay.left)
    }

    /// The kept tail of a left pass joins the step's rows (L8-23), each recorded call listed
    /// unreached in the walk's report: their seqs follow on, because no call after the left
    /// point took a seq.
    pub(in crate::engine_executor) fn commit_left_tail(&mut self) {
        let results = &self.results;
        let Some(replay) = self.deadline_replay.as_mut() else {
            return;
        };
        let (_, tail) = replay.finalize_tail(results);
        for (row, nested) in tail {
            self.guest_calls.push(row.seq);
            self.next_seq = row
                .seq
                .saturating_add(1)
                .saturating_add(nested.len() as u64);
            self.bridge_calls.push(row);
            self.bridge_calls.extend(nested);
        }
    }

    /// Seqs this pass dropped to run live under a refire answer (L8-23): their kept outputs go
    /// before the step's end appends the new ones.
    pub(in crate::engine_executor) fn refired_seqs(&self) -> &[u64] {
        match self.deadline_replay.as_ref() {
            Some(replay) => replay.refired.as_slice(),
            None => &[],
        }
    }

    /// The report when the pass ended with recorded calls unreached (L8-23): each joins it, and
    /// `Some` only when one is an effect step. A pure tail's rows stay dropped for the commit.
    pub(in crate::engine_executor) fn effect_tail_preflight_report(
        &mut self,
    ) -> Option<ResumePreflightReport> {
        let results = &self.results;
        let replay = self.deadline_replay.as_mut()?;
        let (holds_effect, _) = replay.finalize_tail(results);
        if holds_effect {
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
