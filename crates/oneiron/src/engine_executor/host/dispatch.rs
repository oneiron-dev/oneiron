//! Recording dispatch and callable-skill answers for one JS host.
//! Entry: `RecordingJsHost::dispatch_call`.
//! `RecordingJsHost` state is defined by `engine_executor::host`.

use super::*;
use crate::code_run::TextAnswerPost;
use crate::engine_executor::{AdmittedSkillAnswer, AdmittedSkillText};

/// What a pre-record spill stands for: the run's own result, or the view a
/// verb hook left the caller in its place.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Shown {
    /// The run's own result: a spilled body binds to the next auto name, as
    /// before, and its card carries that name.
    Result,
    /// A verb hook's view stands in the result's place: a spilled body is
    /// published at the call's record-only path and captured for the replay
    /// row, never bound to a name, and its card carries no `name`, so no read
    /// gives the real result back.
    View,
}

/// A callable skill's checked answer as the host read it: a value (the
/// answer itself, or the card of the body that holds it), or, for an answer
/// a live post chain judges that nests past [`WHOLE_ANSWER_MAX_DEPTH`], its
/// JSON text, which no value is built from (SKILL-ANSWER-DEEP-JSON-STACK-SAFE).
pub(super) enum ReadAnswer {
    Value(serde_json::Value),
    Text(Box<serde_json::value::RawValue>),
}

impl RecordingJsHost<'_, '_> {
    /// A verb's, a callable skill's, a fold's or the leader's answer too
    /// large for one reply, stored whole as a body of the run as it is
    /// encoded. The guest and the replay row get its handle
    /// (`result_handle_json`), never the answer; nothing is refused for size.
    /// Typed large replies and direct native team-start receipts spill
    /// pre-record below (FIX449), same card the guest's spill gets. With
    /// `Shown::View` every spill below stores record-only: published and
    /// captured for the replay row, never bound to a name.
    pub(super) fn store_large_answer(
        &mut self,
        seq: u64,
        mut outcome: SelfDispatchOutcome,
        shown: Shown,
    ) -> Result<SelfDispatchOutcome> {
        if let SelfDispatchOutcome::AgentVerb(answer) = &mut outcome
            && let Some(output) = answer.stored_output.take()
        {
            answer.output = self.import_write_answer(output, shown);
            return Ok(outcome);
        }
        // Typed replies use the guest's sweeping sink and full result card.
        if matches!(
            &outcome,
            SelfDispatchOutcome::InferenceDefaults(_)
                | SelfDispatchOutcome::TaskAskStatus(_)
                | SelfDispatchOutcome::TaskWaitSet(_)
                | SelfDispatchOutcome::Team(_)
        ) {
            return self.store_large_typed_reply(seq, outcome, shown);
        }
        let answer = match &mut outcome {
            SelfDispatchOutcome::AgentVerb(answer) => &mut answer.output,
            SelfDispatchOutcome::SkillCall(result) => &mut result.output,
            // Kept as its JSON text, framed under `output` as the others are
            // (FIX 1190): the row keeps the card's text in its place. A fold
            // answer's card keeps the folds whose words it copies, and its
            // body depends on their sources (FIX 18924).
            SelfDispatchOutcome::Fold(answer) => {
                if answer.json.len() <= RESULT_REPLY_INLINE_BYTES {
                    return Ok(outcome);
                }
                let sources = answer.word_sources();
                let card = self.store_sourced_answer(
                    seq,
                    &sources,
                    |sink| sink.write(answer.json.as_bytes()),
                    shown,
                )?;
                answer.json = card.to_string();
                return Ok(outcome);
            }
            SelfDispatchOutcome::Leader(json) => {
                if json.len() <= RESULT_REPLY_INLINE_BYTES {
                    return Ok(outcome);
                }
                let card =
                    self.store_sourced_answer(seq, &[], |sink| sink.write(json.as_bytes()), shown)?;
                *json = card.to_string();
                return Ok(outcome);
            }
            _ => return Ok(outcome),
        };
        let mut size = ByteCount::default();
        serde_json::to_writer(&mut size, &*answer).map_err(|error| {
            Error::InvalidConfig(format!("verb answer encoding failed: {error}"))
        })?;
        if size.0 <= RESULT_REPLY_INLINE_BYTES {
            return Ok(outcome);
        }
        *answer = self.store_sourced_answer(seq, &[], |sink| write_json(sink, &*answer), shown)?;
        Ok(outcome)
    }

    /// Retain a fresh decline's released reason without changing its outcome.
    fn capture_task_refusal_output(&mut self, seq: u64, outcome: &SelfDispatchOutcome) {
        let Some(bytes) = self.gated_write.take_task_refusal_output() else {
            return;
        };
        if !matches!(outcome, SelfDispatchOutcome::TaskRefusal(refusal)
            if refusal.declined() && !refusal.replay)
        {
            return;
        }
        let capture = || -> Result<Option<CodeRunRawOutput>> {
            let Some(storage) = self.storage else {
                return Ok(None);
            };
            let mut sink = storage.code_run_reply_spool()?;
            sink.write(&bytes)?;
            Ok(storage
                .publish_code_run_reply(
                    bridge_result_output_path(seq),
                    sink,
                    self.run_id,
                    &[],
                    None,
                )?
                .ok())
        };
        match capture() {
            Ok(Some(output)) => self.captured.push(output),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(run = %self.run_id.to_hex(), seq, error = %error,
                    "accepted task refusal output is unavailable");
            }
        }
    }

    /// Registers the write receipt's already-published body as this run's result.
    /// With `Shown::View` the body stays record-only: captured for the replay
    /// row, never bound to a name, and its card carries no `name`.
    fn import_write_answer(&mut self, output: CodeRunRawOutput, shown: Shown) -> serde_json::Value {
        let mut card = result_handle_json(self.run_id, &output);
        if shown == Shown::Result {
            let name = self.next_auto_name();
            self.bind(name.clone(), output.handle.clone(), output.path.clone());
            card["name"] = json!(name);
        }
        if !self
            .results
            .iter()
            .chain(&self.captured)
            .any(|held| held == &output)
        {
            self.captured.push(output);
        }
        card
    }

    /// A typed reply too large for one message (FIX449): the inference
    /// defaults, a settled ask, a world-privacy answer, a wait set, or a
    /// direct team's native receipt, spilled through the sweeping result sink
    /// and tainted card with facets, never `store_answer`. Under the inline
    /// size, or with no result store, the original outcome stays inline,
    /// unchanged. With `Shown::View` the spill is record-only: published at
    /// call `seq`'s record-only path and captured, never bound. A wait set's
    /// program feedback stays typed beside its card for its own release
    /// (FIX 10389/10390).
    fn store_large_typed_reply(
        &mut self,
        seq: u64,
        outcome: SelfDispatchOutcome,
        shown: Shown,
    ) -> Result<SelfDispatchOutcome> {
        use crate::code_run::{SelfStoredReply, SelfStoredReplyKind};
        use crate::task_verb::{TaskAskStatus, TaskAskWait};
        // No store: inline, as `fit_reply` sends it (a storageless large
        // inference replace must not become `Failed` or leave a gap).
        let Some(storage) = self.storage else {
            return Ok(outcome);
        };
        // The EXACT guest body `reply_body` would emit for the outcome, so a
        // pre-record spill happens exactly when the guest's spill would. JSON
        // only: the guest consumes JSON, and the `TaskAskWait` JSON is already
        // the durable form; no raw RMP is stored or rehydrated.
        let (kind, body) = match &outcome {
            SelfDispatchOutcome::InferenceDefaults(text) => (
                SelfStoredReplyKind::InferenceDefaults,
                json!({"json": text}),
            ),
            SelfDispatchOutcome::TaskAskStatus(TaskAskStatus::Settled(result)) => (
                SelfStoredReplyKind::TaskAskSettled,
                json!({"output": TaskAskWait::Ready(result.clone())}),
            ),
            SelfDispatchOutcome::TaskAskStatus(TaskAskStatus::WorldPrivacy(request)) => (
                SelfStoredReplyKind::TaskAskWorldPrivacy,
                json!({"output": TaskAskWait::WorldPrivacyReady(request.clone())}),
            ),
            // The feedback stays typed beside the card for its own release
            // (FIX 10389/10390): the stored body holds the findings alone.
            SelfDispatchOutcome::TaskWaitSet(result) => {
                if result.program_steps.is_empty() {
                    (SelfStoredReplyKind::TaskWaitSet, json!({"output": result}))
                } else {
                    let mut findings = result.clone();
                    findings.program_steps = Vec::new();
                    (
                        SelfStoredReplyKind::TaskWaitSetWithFeedback,
                        json!({"output": findings}),
                    )
                }
            }
            SelfDispatchOutcome::Team(result)
                if result.source_rows.is_some()
                    && matches!(
                        &result.answer,
                        crate::team::TeamRunAnswer::Started { .. }
                            | crate::team::TeamRunAnswer::ProposedWiden { .. }
                    ) =>
            {
                (
                    SelfStoredReplyKind::TeamStartReceipt,
                    json!({"output": result.answer}),
                )
            }
            _ => return Ok(outcome),
        };
        let mut size = ByteCount::default();
        serde_json::to_writer(&mut size, &body).map_err(|error| {
            Error::InvalidConfig(format!("verb answer encoding failed: {error}"))
        })?;
        if size.0 <= RESULT_REPLY_INLINE_BYTES {
            return Ok(outcome);
        }
        // SAME split as `fit_reply` (`wire.rs`): store `body["output"]` when
        // the body has one, else the whole body. `Ok(None)` keeps the original
        // inline; errors propagate, never swallowed.
        let stored = if body.get("output").is_some() {
            &body["output"]
        } else {
            &body
        };
        let card = if let SelfDispatchOutcome::Team(result) = &outcome {
            let mut sink = storage.code_run_output_sink()?;
            write_json(&mut sink, stored)?;
            if shown == Shown::View {
                // As `store_reply`: a stored body stands for the reply (FIX 3608).
                self.held_delivery.clear();
                let output = self.publish_stored_sourced(
                    storage,
                    sink,
                    &[],
                    result.source_rows.clone(),
                    Some(record_only_output_path(seq)),
                )?;
                Some(result_card(storage, self.run_id, &output, None)?)
            } else {
                Some(
                    self.bind_stored_sourced(storage, sink, None, &[], result.source_rows.clone())?
                        .1,
                )
            }
        } else if shown == Shown::View {
            // As `store_reply`: a stored body stands for the reply (FIX 3608).
            self.held_delivery.clear();
            let mut sink = storage.code_run_output_sink()?;
            write_json(&mut sink, stored)?;
            let rows = self.result_rows();
            let output = self.publish_stored_sourced(
                storage,
                sink,
                &[],
                rows,
                Some(record_only_output_path(seq)),
            )?;
            Some(result_card(storage, self.run_id, &output, None)?)
        } else {
            self.store_reply(stored)?
        };
        let program_steps = match &outcome {
            SelfDispatchOutcome::TaskWaitSet(result) => result.program_steps.clone(),
            _ => Vec::new(),
        };
        match card {
            Some(card) => Ok(SelfDispatchOutcome::StoredReply(SelfStoredReply {
                kind,
                output: card,
                program_steps,
            })),
            None => Ok(outcome),
        }
    }

    /// Stores what `write` puts in a sink as a body of the run, bound to the
    /// next auto name: the card the guest and the replay row get for it. The
    /// body is masked at write (FIX 5718 part 3): one holding a secret no
    /// handle can stand for is not stored, and the guest gets typed
    /// unavailable content in its place; the call it answers ran.
    pub(super) fn store_answer(
        &mut self,
        seq: u64,
        write: impl FnOnce(&mut BodySink) -> Result<()>,
    ) -> Result<serde_json::Value> {
        self.store_sourced_answer(seq, &[], write, Shown::Result)
    }

    /// [`Self::store_answer`] for an answer that copies the words of records
    /// `sources`: its body is published as a dependent of each of them, so
    /// a withdrawal of one reaches it (FIX 18924). With `Shown::View` the
    /// body stays record-only: published at call `seq`'s record-only path,
    /// which no read of the run's results resolves, and captured, never
    /// bound to a name; its card carries no `name`.
    fn store_sourced_answer(
        &mut self,
        seq: u64,
        sources: &[EntityId],
        write: impl FnOnce(&mut BodySink) -> Result<()>,
        shown: Shown,
    ) -> Result<serde_json::Value> {
        // The card stands for the answer: no skill body it holds reaches the
        // guest (FIX 3608).
        self.held_delivery.clear();
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        let mut sink = storage.code_run_reply_spool()?;
        write(&mut sink)?;
        let path = match shown {
            Shown::Result => bridge_result_output_path(seq),
            Shown::View => record_only_output_path(seq),
        };
        let output = match storage.publish_code_run_reply(path, sink, self.run_id, sources, None)? {
            Ok(output) => output,
            Err(unavailable) => {
                // The admitted caller reads what the row keeps: an answer
                // the wall withheld reaches it withheld too.
                if self.admitted_skill_seq == Some(seq) {
                    self.admitted_skill_answer = None;
                    self.admitted_skill_withheld = true;
                }
                return Ok(unavailable);
            }
        };
        let mut card = result_handle_json(self.run_id, &output);
        if shown == Shown::Result {
            let name = self.next_auto_name();
            self.bind(name.clone(), output.handle.clone(), output.path.clone());
            card["name"] = json!(name);
        }
        self.captured.push(output);
        Ok(card)
    }

    /// A callable skill's checked answer as the guest gets it: its JSON up
    /// to the inline reply size and nesting, else its card, the answer
    /// copied whole from the call's spool into a body of the run; only the
    /// stored-body copy here streams in frames without reading into one
    /// value. An answer nesting past [`WHOLE_ANSWER_MAX_DEPTH`] is stored
    /// that way at any size, so no value the host builds or drops follows
    /// its depth (SKILL-ANSWER-DEEP-JSON-STACK-SAFE); the guest reads its
    /// body as text. With `whole` (a verb-hook post chain is live for the
    /// call, its own or the admitted outer caller's) the answer is read
    /// into one value at any size, so that chain reads the body itself,
    /// never its card; `dispatch_call` then stores it for the record as it
    /// stores every large answer, a hook's view leaving it record-only
    /// ([`Shown::View`]). A whole answer nesting past that depth is read as
    /// its JSON text instead ([`ReadAnswer::Text`]), which that chain judges
    /// as text: the call's own here ([`Self::judge_text_answer`]), the
    /// admitted outer caller's once its entry returns it
    /// ([`Self::hold_admitted_text`]). Text a value could not hold but for
    /// its nesting is refused as non-JSON, as the value read refuses it
    /// ([`scalars_read_as_values`]).
    pub(super) fn skill_answer(
        &mut self,
        seq: u64,
        mut answer: crate::skill::CallableSkillAnswer,
        whole: bool,
    ) -> Result<ReadAnswer> {
        let non_json =
            || Error::InvalidConfig("callable skill returned non-JSON output".to_owned());
        if whole || answer.byte_len() <= RESULT_REPLY_INLINE_BYTES as u64 {
            let nests_past = answer_nests_past_whole_depth(&mut answer)?;
            if nests_past && whole {
                let mut text = String::new();
                std::io::Read::read_to_string(answer.reader()?, &mut text)
                    .map_err(|_| non_json())?;
                // The raw reader keeps its own frame stack and checks no
                // depth, so no recursion follows the answer's.
                let text =
                    serde_json::value::RawValue::from_string(text).map_err(|_| non_json())?;
                if !scalars_read_as_values(text.get()) {
                    return Err(non_json());
                }
                return Ok(ReadAnswer::Text(text));
            }
            if !nests_past {
                return serde_json::from_reader(std::io::BufReader::new(answer.reader()?))
                    .map(ReadAnswer::Value)
                    .map_err(|_| non_json());
            }
        }
        // The spool-to-body copy holds its bytes on the run's own share
        // (FIX 10674), as the answer check does; past the share the watch
        // has fired and the copy still goes out whole, as before. A host
        // lent none copies unheld, as before.
        let _copy_hold = self
            .result_share
            .zip(self.storage)
            .and_then(|(share, storage)| share.hold(answer.byte_len(), storage.limit_watch()));
        self.store_answer(seq, |sink| {
            let reader = answer.reader()?;
            let mut frame = vec![0; 64 * 1024];
            loop {
                let read = std::io::Read::read(reader, &mut frame)?;
                if read == 0 {
                    return Ok(());
                }
                sink.write(&frame[..read])?;
            }
        })
        .map(ReadAnswer::Value)
    }

    /// The call's own post chain over skill answer `text`, held as JSON text
    /// ([`ReadAnswer::Text`]), and the answer stored once it is done: the
    /// output its row keeps. A chain that left the view as it was leaves the
    /// guest the answer's body, bound to its name, as an answer no hook
    /// reads arrives. A Redact that hid anything, or a hook that stopped the
    /// call, leaves the body record-only ([`Shown::View`]) and serves what
    /// the chain left in its place ([`Self::text_view_reply`] for a Redact),
    /// as a value's view is served.
    fn judge_text_answer(
        &mut self,
        seq: u64,
        hooked: crate::code_run::HookedCall,
        text: &serde_json::value::RawValue,
    ) -> Result<serde_json::Value> {
        // The answer's bytes are held on the run's share before the chain
        // reads them, as the copy that stores them is (FIX 10674).
        let bytes = text.get().as_bytes();
        let _copy_hold = self
            .result_share
            .zip(self.storage)
            .and_then(|(share, storage)| share.hold(bytes.len() as u64, storage.limit_watch()));
        let post = self.gated_write.leave_verb_hooks_text(hooked, text)?;
        // The answer first, then the view in its place, as a value's
        // answer is stored before its view is served.
        let shown = match &post {
            TextAnswerPost::Unchanged => Shown::Result,
            TextAnswerPost::Narrowed(_) | TextAnswerPost::Stopped(_) => Shown::View,
        };
        let output = self.store_sourced_answer(seq, &[], |sink| sink.write(bytes), shown)?;
        let view = match post {
            TextAnswerPost::Unchanged => None,
            TextAnswerPost::Narrowed(view) => Some(self.text_view_reply(&view)?),
            TextAnswerPost::Stopped(view) => Some(view),
        };
        if let Some(view) = view {
            self.gated_write.serve_hook_view(view);
        }
        Ok(output)
    }

    /// Skill answer `text`, held as JSON text ([`ReadAnswer::Text`]), for
    /// the admitted outer caller's post chain, which judges it as text once
    /// the admitted entry returns it ([`AdmittedSkillAnswer::Text`]): the
    /// answer is stored record-only, as an answer held whole for that chain
    /// is (`dispatch_call`), and the output its row keeps is that body's
    /// card. An answer the row's store withheld holds nothing: the caller
    /// reads the row's withheld content, as for a value.
    fn hold_admitted_text(
        &mut self,
        seq: u64,
        text: Box<serde_json::value::RawValue>,
    ) -> Result<serde_json::Value> {
        let output = {
            let bytes = text.get().as_bytes();
            // Held on the run's share while the copy stores them (FIX 10674).
            let _copy_hold = self
                .result_share
                .zip(self.storage)
                .and_then(|(share, storage)| share.hold(bytes.len() as u64, storage.limit_watch()));
            self.store_sourced_answer(seq, &[], |sink| sink.write(bytes), Shown::View)?
        };
        if !self.admitted_skill_withheld {
            self.admitted_skill_answer = Some(AdmittedSkillAnswer::Text(AdmittedSkillText::new(
                self.run_id,
                text,
            )));
        }
        Ok(output)
    }

    /// The reply a Redact's view held as text gives the guest, as a value's
    /// view is served: read into a value when it nests no deeper than one
    /// may hold, else its `output` stored as a body of the run, bound to its
    /// name, and that body's card in its place. A view nesting that deep
    /// still holds the answer under `output`: a Redact only removes.
    fn text_view_reply(
        &mut self,
        view: &crate::runtime_hooks::verb::TextView,
    ) -> Result<serde_json::Value> {
        let unreadable = || Error::InvariantViolation("a redacted skill answer view does not read");
        if !text_nests_past_whole_depth(view.text()) {
            return serde_json::from_str(view.text()).map_err(|_| unreadable());
        }
        // One level: each member stays raw text, read with no depth.
        let mut members: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> =
            serde_json::from_str(view.text()).map_err(|_| unreadable())?;
        let output = members.remove("output").ok_or_else(unreadable)?;
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        // The card stands for the view: no skill body it holds reaches the
        // guest (FIX 3608), as `store_reply` keeps it.
        self.held_delivery.clear();
        let mut sink = storage.code_run_output_sink()?;
        sink.write(output.get().as_bytes())?;
        let card = self.bind_stored(storage, sink, None)?;
        Ok(json!({"output": card}))
    }

    /// `self.skills.call` (OF-353): an agent-callable skill run as a step of
    /// its own, on the sibling runtime the caller's step lent, under the
    /// running attempt's lease, with this host as its bridge. The skill's own
    /// calls are gated and recorded as the run's, at the positions after this
    /// one's. A skill that fails answers a typed failure the program reads;
    /// a halt or a declined TASK among its calls is this call's answer too.
    /// The skill runs under a child of `parent`, the caller's step token: a
    /// stop of the caller stops it, and its owner's suspension stops it alone
    /// (FIX 600). A cancelled skill answers `code_step_cancelled`, and the
    /// caller's step goes on. A callable's own call nests inside it: past
    /// the `[limits] callable_nest_depth` row it asks, and the call runs.
    /// Near the stack floor, a supported target lends the call another stack
    /// segment on this thread. Other targets retain the stack-floor refusal.
    /// A call that would start below the thread's stack floor answers
    /// `skills_call_stack_floor` instead. A call the step's own program made
    /// that answered is kept for the step's replay context (FIX 3608): what
    /// its load selected, its arguments and where its own calls end.
    pub(super) fn call_skill(
        &mut self,
        seq: u64,
        started_at_ms: u64,
        call: &SelfCall,
        skill: SelfSkillCall,
        runtime: &mut dyn JsCodeModeRuntime,
        parent: &StepCancellation,
    ) -> Result<(SelfDispatchOutcome, Option<SelfCall>)> {
        let answered = on_callable_stack(|| {
            self.call_skill_on_stack(seq, started_at_ms, call, skill, runtime, parent)
        })
        .unwrap_or_else(|| {
            Ok((
                SelfDispatchOutcome::Failed(SelfFailedResult {
                    effect: SelfEffect::SkillsCall,
                    error: "skills_call_stack_floor".to_owned(),
                    code: None,
                    disk_floor: None,
                }),
                None,
            ))
        });
        // However the call ended, before its caller goes on: a callable that
        // ran its body again must have met every call it settled before
        // (FIX 5878).
        if let Some(injection) = self.injection.as_mut() {
            injection.returned(seq);
        }
        answered
    }

    fn call_skill_on_stack(
        &mut self,
        seq: u64,
        started_at_ms: u64,
        call: &SelfCall,
        skill: SelfSkillCall,
        runtime: &mut dyn JsCodeModeRuntime,
        parent: &StepCancellation,
    ) -> Result<(SelfDispatchOutcome, Option<SelfCall>)> {
        let failed = |error: String| {
            (
                SelfDispatchOutcome::Failed(SelfFailedResult {
                    effect: SelfEffect::SkillsCall,
                    error,
                    code: None,
                    disk_floor: None,
                }),
                None,
            )
        };
        let site = ExecutorCallSite {
            run_id: self.run_id,
            seq,
            step_start: self.step_start,
            earlier: &self.bridge_calls,
            reply_publisher: None,
        };
        let lease = match self
            .gated_write
            .admit_skill_call_for_executor_run(site, call)?
        {
            Ok(lease) => lease,
            Err(refused) => return Ok((refused, None)),
        };
        // The call's verb hooks once it is admitted (ARCH-0080 §3): a rewrite
        // names the skill and the args it runs with.
        let (skill, mut hooked) = if self.admitted_skill_seq == Some(seq) {
            (skill, None)
        } else {
            match self.gated_write.enter_verb_hooks(
                SelfCall::SkillsCall(skill),
                Some(site),
                lease.read_as.clone(),
            )? {
                Ok((SelfCall::SkillsCall(skill), hooked)) => (skill, Some(hooked)),
                Ok(_) => {
                    return Err(Error::InvariantViolation(
                        "a skill call's hooks rewrote it into another call",
                    ));
                }
                Err(stopped) => return Ok((stopped, None)),
            }
        };
        // Whether a verb-hook post chain will read this call's answer: its
        // own, live once its pre chain found hooks on the call, or, for the
        // admitted outer call (`hooked` is `None` only there), the outer
        // caller's, live once its own pre chain found hooks on it. The
        // admitted entry carries that chain's state in
        // (`admitted_outer_hooks_live`); nothing here re-reads the current
        // bindings, so one toggled between the outer pre chain and this
        // dispatch cannot split them, and a binding that could not take
        // the outer caller leaves this call as it found it. While one may
        // run, the answer is read whole below, however large, so no chain
        // judges only a large answer's card and no name binds its real
        // body before that chain has seen it.
        let outer_hooks_live = hooked.is_none() && self.admitted_outer_hooks_live;
        let whole_for_hooks = outer_hooks_live
            || hooked
                .as_ref()
                .and_then(|held| held.0.as_ref())
                .is_some_and(|pre| !pre.passed_through());
        // A callable running its body again runs the call it ran before: a
        // hook that redirects it holds the entry, and the body's calls are
        // refused (FIX 5878).
        if hooked.as_ref().is_some_and(|hooked| hooked.1.is_some())
            && let Some(injection) = self.injection.as_mut()
        {
            injection.redirected(seq);
        }
        let Some(executor) = self.skill_executor.clone() else {
            return Ok(failed("skills_call_no_executor".to_owned()));
        };
        let (run_id, determinism) = (self.run_id, self.determinism);
        let from_program = self.callable_depth == 0;
        self.callable_depth += 1;
        lease.vault.measure_limit(
            crate::limit_ask::EngineLimit::CallableNestDepth,
            u64::from(self.callable_depth),
        );
        // The skill's stored body and its own calls reach the run (FIX 6130).
        let cause = crate::code_run::ReadWorldUnknown::CallableSkill;
        self.gated_write.read_worlds_unknown(run_id, cause);
        let (mut loaded, mut selected) = (Vec::new(), None);
        // The stores its own calls make, fresh or reusing a recorded one
        // (FIX 5878): a later entry that answers it whole replays none of
        // them.
        let stored_before = (self.captured.len(), self.replayed_stores.len());
        // The answer check holds its buffers on the run's own share (FIX
        // 10149); a host lent none checks unheld, as before.
        let memory = self.result_share.zip(self.storage).map(|(share, storage)| {
            crate::skill::AnswerMemory {
                share,
                watch: storage.limit_watch(),
            }
        });
        let ran = crate::skill::execute_callable_skill_cancellable(
            &lease.vault,
            &lease.leased,
            &skill.skill,
            &executor,
            &skill.args,
            runtime,
            &mut *self,
            run_id,
            seq,
            determinism,
            started_at_ms / 1000,
            parent,
            &mut loaded,
            &mut selected,
            memory,
        );
        self.callable_rows.0.extend(loaded);
        self.callable_depth -= 1;
        // A pinned entry's callable (FIX 5878): where its own calls end in
        // the entry's log, and how a later entry answers it. A body that
        // unwound on the entry's wait runs again; one that returned past that
        // wait (a caught wait's owner sits inside it), one the bridge halted
        // inside, or one whose own calls stored outputs, fresh or reusing a
        // recorded one, that a whole answer would leave unconsumed for a
        // later store of the same bytes, holds; any other answers whole.
        if let Some(injection) = self.injection.as_mut() {
            let kind = if self.hard_failure.is_some() || self.left_a_gap || self.declined.is_some()
            {
                ProgramResumeKind::HeldCallable
            } else if self.durable_wait.is_some() {
                if ran.is_ok() {
                    ProgramResumeKind::HeldCallable
                } else {
                    ProgramResumeKind::OpenCallable
                }
            } else if (self.captured.len(), self.replayed_stores.len()) != stored_before {
                ProgramResumeKind::HeldCallable
            } else {
                ProgramResumeKind::Settled
            };
            let log_end = injection.log_len();
            self.program_callables
                .push(ProgramCallableSpan { seq, log_end, kind });
        }
        // The callable's type feedback stays beside the run, however the
        // call ended (FIX 10389).
        self.keep_callable_check(seq, ran.is_ok());
        if self.hard_failure.is_some() || self.left_a_gap {
            return Ok(failed("host_bridge_halted".to_owned()));
        }
        if self.declined.is_some() {
            return Ok(failed("task_declined".to_owned()));
        }
        let rewritten = hooked.as_ref().and_then(|hooked| hooked.1.clone());
        let outcome = match ran {
            Ok(answer) => {
                let output = match self.skill_answer(seq, answer, whole_for_hooks)? {
                    ReadAnswer::Value(output) => output,
                    // An answer nesting past what a value may hold meets the
                    // live chain that reads it whole as text: the call's own
                    // judges it here, and the answer is stored once it is
                    // done; the admitted outer caller's takes it from the
                    // admitted entry (`hooked` is `None` only there).
                    ReadAnswer::Text(text) => match hooked.take() {
                        Some(own) => self.judge_text_answer(seq, own, &text)?,
                        None => {
                            return Err(Error::Refused(
                                "the skill answer nests too deep for the live post hook to judge"
                                    .to_owned(),
                            ));
                        }
                    },
                };
                SelfDispatchOutcome::SkillCall(SelfSkillCallResult {
                    skill: skill.skill,
                    output,
                })
            }
            // A cancelled skill is a failed call under its stable code, read
            // from the typed error the runtime raised, never from guest text.
            Err(Error::Code(CodeError::CodeStepCancelled)) => {
                failed(CodeError::CodeStepCancelled.to_string()).0
            }
            Err(
                error @ Error::Code(CodeError::SandboxProposalDiskFloor {
                    needed,
                    available,
                    reserve,
                }),
            ) => SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::SkillsCall,
                error: error.to_string(),
                code: Some(
                    oneiron_contracts::memory::MEMORY_CODE_SANDBOX_PROPOSAL_DISK_FLOOR.to_owned(),
                ),
                disk_floor: Some(crate::code_run::SelfSandboxProposalDiskFloor {
                    needed,
                    available,
                    reserve,
                }),
            }),
            Err(error) => failed(error.to_string()).0,
        };
        if from_program
            && matches!(outcome, SelfDispatchOutcome::SkillCall(_))
            && let Some(selected) = selected
        {
            let callable = crate::code_run::CapturedCallable {
                seq,
                nested_end: self.next_seq,
                skill: skill.skill,
                selected,
                args: skill.args,
            };
            self.context_capture.callables.push(callable);
        }
        // The admitted outer caller's post chain reads the whole answer
        // this host returns to it: hold it for that entry, while
        // `dispatch_call` records the outcome itself record-only below. An
        // answer held as text was held, or withheld, as it was stored.
        if outer_hooks_live
            && self.admitted_skill_answer.is_none()
            && !self.admitted_skill_withheld
            && let SelfDispatchOutcome::SkillCall(result) = &outcome
        {
            self.admitted_skill_answer = Some(AdmittedSkillAnswer::Value(result.output.clone()));
        }
        // The post chain reads the answer itself: while one is live a large
        // answer came back whole above, never by its card. No spill runs
        // before it here: `dispatch_call` stores the outcome for its row
        // once the chain has left its view, record-only when a view stands
        // in its place, as it does for every other call. An answer held as
        // text met its own chain above, which took `hooked`.
        match hooked {
            Some(hooked) => Ok((
                self.gated_write.leave_verb_hooks(hooked, outcome)?,
                rewritten,
            )),
            None => Ok((outcome, rewritten)),
        }
    }

    /// One `self.*` call over the bridge. `runtime` is the sibling a call
    /// that runs a step of its own runs it on, when the caller's runtime
    /// lent one ([`JsCodeModeHost::dispatch_self_nested`]), with the
    /// caller's step token that step's own descends from.
    pub(super) fn dispatch_call(
        &mut self,
        call: SelfCall,
        runtime: Option<(&mut dyn JsCodeModeRuntime, &StepCancellation)>,
    ) -> Result<SelfDispatchResponse> {
        // No skill body an earlier call's answer held reaches this call's
        // reply (FIX 3608).
        self.held_delivery.clear();
        // A resumed turn program's settled calls answer from the rows that
        // settled them, before a position is taken or anything dispatched
        // (DOOR-141 PR3b). Only a pinned entry binds an injection.
        // A value base custody holds took its handle in a settled row, and
        // meets it there (FIX REPLAY-COMPARE-KNOWN-MATCHER).
        let gated_write = self.gated_write;
        let base_known = || gated_write.base_known_values();
        if let Some(injection) = self.injection.as_mut() {
            match injection.answer(&call, &base_known) {
                InjectedAnswer::Live => {}
                InjectedAnswer::Settled { seq, outcome, view } => {
                    // The injected card replaces `store_reply`: consume its
                    // exact occurrence before another same-byte store replays.
                    if let SelfDispatchOutcome::StoredReply(reply) = &*outcome
                        && let Some(reference) = reply
                            .output
                            .get("ref")
                            .and_then(serde_json::Value::as_str)
                            .filter(|reference| reference.starts_with("occurrence:"))
                        && let Some((output, _)) =
                            self.resolve_result(&JsResultRef::Handle(reference.to_owned()))
                        && !self.replayed_stores.contains(&output.path)
                    {
                        self.replayed_stores.push(output.path);
                    }
                    // A granted `reveal.wait` reads its value again under its
                    // own lease, for the guest's view only; the row keeps its
                    // value-free answer (FIX 2360). A failed replay leaves
                    // the kept answer, as before.
                    let view = match view {
                        Some(view) => Some(view),
                        None => self
                            .gated_write
                            .replay_reveal_view(&call, &outcome)
                            .ok()
                            .flatten(),
                    };
                    // Its response is kept at the settled row's own position.
                    return Ok(self.respond(&call, Some(seq), *outcome, view));
                }
                InjectedAnswer::Hold => {
                    if self.hard_failure.is_none() {
                        self.hard_failure =
                            Some(Error::InvalidConfig(PROGRAM_RESUME_HELD.to_owned()));
                    }
                    let outcome = SelfDispatchOutcome::Failed(SelfFailedResult {
                        effect: call.effect(),
                        error: PROGRAM_RESUME_HELD.to_owned(),
                        code: None,
                        disk_floor: None,
                    });
                    // No row answers it: the replay context is incomplete.
                    return Ok(self.respond(&call, None, outcome, None));
                }
            }
        }
        // A resumed pending step's calls answer from the rows its program
        // already made, before a position is taken (FIX 7703).
        if let Some(answered) = self.answer_from_pending_prefix(&call) {
            return Ok(answered);
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        if self.callable_depth == 0 {
            self.guest_calls.push(seq);
        }
        // A pinned entry logs the call it issues here (FIX 5878).
        if let Some(injection) = self.injection.as_mut() {
            injection.issued(seq);
        }
        let started_at_ms = self.determinism.frozen_unix_ms.saturating_add(seq);
        // ONE-1686: the speech family's order and timestamp are the BRIDGE's,
        // stamped here — on the one ordering path every `self.*` call takes —
        // before the row is recorded or the effect dispatched. Guest code
        // cannot forge either, and the replay row, the dispatched call and the
        // emitted bubble all carry the same number.
        let call = call.with_bridge_stamp(seq, started_at_ms);
        // Past a wait or a halt the bridge answers without dispatching, but a
        // session-bound run is still answered as its participant stands: once
        // they left the room it hears `NotInRoom`, never the wait or the halt.
        if (self.durable_wait.is_some()
            || self.hard_failure.is_some()
            || self.left_a_gap
            || self.declined.is_some())
            && let Some(storage) = self.storage
            && let Err(err) = storage.answered(|| Ok(()))
        {
            self.left_a_gap = true;
            return Err(err);
        }
        if let Some(wait) = &self.durable_wait {
            let outcome = SelfDispatchOutcome::DurableWait(wait.clone());
            let mut row =
                CodeRunBridgeCall::record(seq, &call, &outcome, started_at_ms, started_at_ms)?;
            crate::code_run::barrier_spawn_call(&mut row)?;
            self.bridge_calls.push(row);
            return Ok(self.respond(&call, Some(seq), outcome, None));
        }
        if self.hard_failure.is_some() || self.left_a_gap || self.declined.is_some() {
            // Fail-closed after the first hard failure or unrecorded call:
            // no further gate dispatches; the guest sees a typed Failed
            // response (budget attached) and the replay row records exactly
            // that. A declined TASK is closed the same way, without failing
            // the step.
            let error =
                if self.declined.is_some() && self.hard_failure.is_none() && !self.left_a_gap {
                    "task_declined"
                } else {
                    "host_bridge_halted"
                };
            let outcome = SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect(),
                error: error.to_owned(),
                code: None,
                disk_floor: None,
            });
            let mut row =
                CodeRunBridgeCall::record(seq, &call, &outcome, started_at_ms, started_at_ms)?;
            crate::code_run::barrier_spawn_call(&mut row)?;
            self.bridge_calls.push(row);
            return Ok(self.respond(&call, Some(seq), outcome, None));
        }
        // OF-568: what this call reads, captured before it runs, for its
        // row's action digest. Only the vault's own storage is versioned: a
        // session overlay's reads, or a capture that failed, stay unknown.
        let inputs = match self.storage {
            Some(ExecutorStorage::Canonical(vault)) => {
                self_call_inputs(vault, &call).ok().flatten()
            }
            _ => None,
        };
        // ONE-1314: the current step's own history, observed at the last
        // moment before this call dispatches. The durable half was observed
        // when the step opened; together they are every bridge call this run
        // has made, so a write can never be sealed against a narrower history
        // than the one already recorded.
        self.gated_write.observe_bridge_history(&self.bridge_calls);
        // This call's row keeps its own position: a callable skill's calls
        // take the positions after it, and their rows land first.
        let place = self.bridge_calls.len();
        // The call, a callable skill's or a reader's included, holds the
        // attempt's tool witness open until it is answered (OF-568 L5).
        let _tool = self.gated_write.activity_tool();
        // The ordinary dispatcher cannot mutate this host's bindings. Its
        // result name is fixed now; the native descriptor is adopted only
        // after the dispatch and its inner receipt have succeeded.
        let reply_publisher = self.storage.map(|storage| {
            reply::CallReplyPublisher::new(
                storage,
                self.result_share,
                self.run_id,
                seq,
                self.next_auto_name(),
            )
        });
        let dispatched = match (&call, runtime) {
            (SelfCall::SkillsCall(skill), Some((runtime, parent))) => {
                let skill = skill.clone();
                self.call_skill(seq, started_at_ms, &call, skill, runtime, parent)
            }
            (SelfCall::ReaderSpawn(spawn), _) => {
                let spawn = (**spawn).clone();
                self.spawn_reader(seq, spawn)
            }
            (SelfCall::ReaderReport(report), _) => {
                let report = report.clone();
                self.report_finding(seq, report)
            }
            (SelfCall::Summarize(summary), _) => {
                let summary = (**summary).clone();
                self.summarize(seq, summary)
            }
            (SelfCall::SayResult(say), _) => {
                let say = say.clone();
                self.say_result(seq, say)
            }
            _ => {
                let site = ExecutorCallSite {
                    run_id: self.run_id,
                    seq,
                    step_start: self.step_start,
                    earlier: &self.bridge_calls,
                    reply_publisher: reply_publisher
                        .as_ref()
                        .map(|publisher| publisher as &dyn crate::code_run::ExecutorReplyPublisher),
                };
                self.gated_write
                    .dispatch_for_executor_run(site, call.clone())
            }
        };
        // A verb hook's view of this call's result, taken whatever came of
        // the call: the guest reads it, the row keeps the outcome and whether
        // a view was served (the view's own read rows stay unwitnessed).
        let view = self.gated_write.take_hook_view();
        if dispatched.is_ok()
            && let Some(reply) = reply_publisher
                .as_ref()
                .and_then(|publisher| publisher.take())
        {
            // The caller is shown the view; a bound name would read the real
            // result back.
            if view.is_none() {
                self.bind(
                    reply.name,
                    reply.output.handle.clone(),
                    reply.output.path.clone(),
                );
            }
            if !self
                .results
                .iter()
                .chain(&self.captured)
                .any(|held| held.path == reply.output.path)
            {
                self.captured.push(reply.output);
            }
        }
        // The skill bodies its producer witnessed, held while the guest's
        // reply may still carry them whole (FIX 3608).
        let given = dispatched.as_ref().ok().map(|(outcome, _)| outcome);
        self.hold_delivery(seq, view.is_some(), given);
        // The seats this call's spawn resolved, taken whatever came of it:
        // its row keeps them, a failure's included (FIX 9180).
        let seats = self.gated_write.take_spawn_seats();
        // The admitted skill call's whole answer is held for its outer
        // caller, whose post chain may still serve a view of it: its real
        // body records record-only here too, bound to no name, exactly as
        // when this call's own chain left a view. An answer held as text
        // was stored record-only already.
        let admitted_answer = matches!(&call, SelfCall::SkillsCall(_))
            && self.admitted_skill_seq == Some(seq)
            && self.admitted_skill_answer.is_some();
        let shown = if view.is_some() || admitted_answer {
            Shown::View
        } else {
            Shown::Result
        };
        let (outcome, rewritten) = match dispatched.and_then(|(outcome, rewritten)| {
            self.capture_task_refusal_output(seq, &outcome);
            self.store_large_answer(seq, outcome, shown)
                .map(|outcome| (outcome, rewritten))
        }) {
            Ok(answered) => answered,
            Err(err) => {
                self.held_delivery.clear();
                let Some(error_outcome) = dispatch_error_outcome(&call, &err) else {
                    // Infrastructure failure: no guest-visible response
                    // exists for this call at all.
                    self.left_a_gap = true;
                    return Err(err);
                };
                let row = CodeRunBridgeCall::record(
                    seq,
                    &call,
                    &error_outcome,
                    started_at_ms,
                    started_at_ms,
                )?
                .with_inputs(inputs.as_ref())
                .with_spawn_seats(seats);
                self.bridge_calls.insert(place, row);
                self.hard_failure = Some(err);
                return Ok(self.respond(&call, Some(seq), error_outcome, None));
            }
        };
        let finished_at_ms = started_at_ms;
        let mut row =
            CodeRunBridgeCall::record(seq, &call, &outcome, started_at_ms, finished_at_ms)?
                .with_inputs(inputs.as_ref())
                .with_spawn_seats(seats)
                .with_rewritten_request(rewritten.as_ref())?;
        row.hook_view_served = view.is_some() || admitted_answer;
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
        self.bridge_calls.insert(place, row);
        Ok(self.respond(&call, Some(seq), outcome, view))
    }
}

pub(super) fn dispatch_error_outcome(call: &SelfCall, err: &Error) -> Option<SelfDispatchOutcome> {
    match err {
        Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        }) => Some(SelfDispatchOutcome::Denied(SelfDeniedResult {
            hook_notice: None,
            effect: call.effect(),
            outcome: (*outcome).to_owned(),
            reason_codes: reason_codes
                .iter()
                .map(|reason| (*reason).to_owned())
                .collect(),
        })),
        // A door's outage or durable trap ends the native step even when
        // the guest catches its typed failure.
        Error::ProviderUnavailable { .. } | Error::DurableStepTrapped => {
            Some(SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect(),
                error: err.to_string(),
                code: None,
                disk_floor: None,
            }))
        }
        // A refusal names its bound: the guest reads what it can act on.
        Error::Refused(_) => Some(SelfDispatchOutcome::Failed(SelfFailedResult {
            effect: call.effect(),
            error: err.to_string(),
            code: None,
            disk_floor: None,
        })),
        _ if records_failed_effect(call.effect()) => {
            Some(SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: call.effect(),
                error: err.to_string(),
                code: None,
                disk_floor: None,
            }))
        }
        _ => None,
    }
}

/// Effects whose failure is REPLAY-VISIBLE rather than infrastructural.
///
/// These cross an audited durable boundary, so a refusal is part of the run's
/// history: the guest sees a typed `Failed` response, the row lands in the
/// replay log, and the fail-closed barrier refuses everything after it.
/// ONE-1686 adds the speech family — a refused bubble (a stale route after a
/// mid-run mode flip, a door rejection) is exactly that kind of failure.
pub(super) fn records_failed_effect(effect: SelfEffect) -> bool {
    matches!(
        effect,
        SelfEffect::MemoryPutClaim
            | SelfEffect::AgentsPut
            | SelfEffect::AgentsSpawn
            | SelfEffect::MemorySupersedeClaim
            | SelfEffect::MemoryPutEdge
            | SelfEffect::ReportBlocked
            | SelfEffect::InferenceDefaultsReplace
    ) || effect.is_speech()
}

/// The deepest answer `serde_json::from_reader` parses with its default
/// recursion limit: 128 levels of budget, one spent per `[` or `{`
/// (`serde_json` 1.0.151 `de.rs`, `remaining_depth: 128`, `check_recursion`
/// failing at zero), so 127 nests. The spool check accepts any depth
/// (`skill/call/json_tokens.rs` keeps its own stack); past this one the
/// whole-answer parse would fail a valid answer as non-JSON, and a value
/// built past it would be cloned, serialized and dropped by recursion
/// that follows its depth on the host's stack. So no value is built:
/// the answer is stored as a body (`RecordingJsHost::skill_answer`),
/// or, when a live post chain must judge it, held as its JSON text
/// (`RecordingJsHost::judge_text_answer`).
const WHOLE_ANSWER_MAX_DEPTH: u32 = 127;

/// Whether a spooled answer nests past [`WHOLE_ANSWER_MAX_DEPTH`]: the
/// whole-answer parse cannot read it, however valid its JSON. Reads the
/// spool from its first byte; each [`crate::skill::CallableSkillAnswer::reader`]
/// call rewinds it again.
fn answer_nests_past_whole_depth(answer: &mut crate::skill::CallableSkillAnswer) -> Result<bool> {
    let reader = answer.reader()?;
    let mut scan = NestingScan::default();
    let mut chunk = vec![0; 8 * 1024];
    loop {
        let read = std::io::Read::read(reader, &mut chunk)?;
        if read == 0 {
            return Ok(false);
        }
        if scan.passes_whole_depth(&chunk[..read]) {
            return Ok(true);
        }
    }
}

/// Whether JSON `text` nests past [`WHOLE_ANSWER_MAX_DEPTH`], so no value
/// may be read from it.
pub(in crate::engine_executor) fn text_nests_past_whole_depth(text: &str) -> bool {
    NestingScan::default().passes_whole_depth(text.as_bytes())
}

/// Whether each string and number JSON `text` holds reads as a value's
/// does. `text` is JSON already (a [`serde_json::value::RawValue`]), but
/// that reader takes a lone surrogate escape and a number past `f64`,
/// which a value refuses. Each scalar is read on its own, so no recursion
/// follows the nesting; a string with no escape reads as it is.
fn scalars_read_as_values(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'"' => {
                let mut end = at + 1;
                let mut escaped = false;
                loop {
                    match bytes.get(end) {
                        None => return false,
                        Some(b'\\') => {
                            escaped = true;
                            end += 2;
                        }
                        Some(b'"') => break,
                        Some(_) => end += 1,
                    }
                }
                if escaped && serde_json::from_str::<String>(&text[at..=end]).is_err() {
                    return false;
                }
                at = end + 1;
            }
            b'-' | b'0'..=b'9' => {
                let end = bytes[at..]
                    .iter()
                    .position(|byte| {
                        !matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                    })
                    .map_or(bytes.len(), |length| at + length);
                if serde_json::from_str::<serde_json::Number>(&text[at..end]).is_err() {
                    return false;
                }
                at = end;
            }
            _ => at += 1,
        }
    }
    true
}

/// JSON nesting counted byte by byte, outside strings: it keeps no stack,
/// so no depth limits it.
#[derive(Default)]
struct NestingScan {
    depth: u32,
    string: bool,
    escaped: bool,
}

impl NestingScan {
    /// Reads `bytes` on from where the scan stands: whether the nesting
    /// passes [`WHOLE_ANSWER_MAX_DEPTH`] within them.
    fn passes_whole_depth(&mut self, bytes: &[u8]) -> bool {
        for byte in bytes {
            if self.string {
                if self.escaped {
                    self.escaped = false;
                } else if *byte == b'\\' {
                    self.escaped = true;
                } else if *byte == b'"' {
                    self.string = false;
                }
                continue;
            }
            match *byte {
                b'"' => self.string = true,
                b'{' | b'[' => {
                    self.depth = self.depth.saturating_add(1);
                    if self.depth > WHOLE_ANSWER_MAX_DEPTH {
                        return true;
                    }
                }
                b'}' | b']' => self.depth = self.depth.saturating_sub(1),
                _ => {}
            }
        }
        false
    }
}
