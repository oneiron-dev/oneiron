//! Where one run's reads and writes land: the canonical vault or a bound off-record session.

use crate::claim::{ClaimReadStatus, ScopedReadActorKey};
use crate::memory::WitnessReceipt;
use crate::off_record::{ExecutorUtterance, OffRecordMode, OffRecordSession, SessionWriteRoute};
use crate::session_overlay::RouteTarget;
use crate::vault::VaultId;
use crate::{EntityId, ModelId, Result, ScoredEntity, Vault, WriteActor};

use super::super::codec::validate_raw_output;
use super::super::replay::{
    CodeRunRawOutput, CodeRunReplayGeneration, CodeRunReplayRecord, ResultOccurrence,
};
use super::super::support::invalid_code_run_replay;
use super::records::{
    MODEL_HEAL_COUNTS, RAW_OUTPUT_SECRETS, RAW_OUTPUT_TAINTS, RAW_OUTPUTS, REPLAY_RECORDS,
    finish_output, load_whole_body, next_additive_heal_count, read_body_row_range,
    replay_generation_matches,
};
use super::speech_identity::{
    canonical_witness_executor_turn, executor_speech_message_id_for_run, executor_speech_turn_id,
};
use crate::limit_ask::{EngineLimit, LimitWatch};
use crate::result_memory::ResultShare;
use crate::secret_rotation::ArtifactTaintState;
use crate::store::BodySink;

#[cfg(test)]
use super::records::CodeRunModelHealCount;
#[cfg(test)]
use crate::Error;

/// The session half of an executor binding (ONE-1729/P4b).
///
/// ONE-1728's typed session handle, the run's ONE [`SessionWriteRoute`], and
/// the session-owned conversation shell its turns ride — captured together at
/// RUN ENTRY and never re-minted (owner ruling R-20260807-02 rider 2). Route
/// and handle live in the same value because "one route per run" has to be a
/// type fact: a per-dispatch mint is not something this shape can express.
///
/// The handle is the run's own, bound to the participant the run acts as:
/// every transaction it reads or writes the stretch in checks they are still
/// in its room (Codex burn engine-prs-01), and every call the run makes is
/// [`answered`](Self::answered) as they stand once it is done.
pub(crate) struct SessionBinding<'a> {
    pub(crate) session: OffRecordSession<'a>,
    pub(crate) route: SessionWriteRoute,
    pub(crate) container: EntityId,
}

impl SessionBinding<'_> {
    /// One call of the bound run, checked against its participant before it
    /// runs and answered only after a second check, in a snapshot taken once
    /// it is done. A run removed from the room before or while the call ran
    /// gets `NotInRoom` in place of whatever the call met there: nothing that
    /// changed in the room, its saver or its rows since reaches it, even when
    /// the call read it with no check of its own (Astra and Sol on
    /// engine-prs-01). A write the call landed before the removal stays.
    pub(crate) fn answered<T>(&self, call: impl FnOnce() -> Result<T>) -> Result<T> {
        self.session.admit_participant()?;
        let answer = call();
        self.session.admit_participant()?;
        answer
    }

    /// Records one host-bound executor turn through the session witness entry.
    ///
    /// The deterministic TURN and MESSAGE ids are both derived from the run
    /// identity before this call. They travel through the distinct host-only
    /// path; the guest-facing `witness_executor_turn(Some(turn_ref))` refusal
    /// remains unchanged and unreachable from here.
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is a host-owned witness axis; the explicit turn and message ids are the idempotency contract"
    )]
    pub(crate) fn witness_executor_turn(
        &self,
        kind: ExecutorUtterance,
        text: &str,
        occurred_at: u64,
        order: u32,
        message_id: EntityId,
        turn_id: EntityId,
        actor: WriteActor,
    ) -> Result<WitnessReceipt> {
        if self.session.participant() != Some(actor.entity_ref()) {
            return Err(crate::Error::InvalidConfig(
                "executor storage/dispatcher binding mismatch".to_owned(),
            ));
        }
        self.answered(|| {
            self.session.witness_host_executor_turn(
                &self.container,
                kind,
                text,
                occurred_at,
                order,
                message_id,
                turn_id,
                &self.route,
                actor,
            )
        })
    }

    /// In-room retrieval through the run's captured route.
    ///
    /// Search registers a retrieval-run row, so it is an APPLY like any other
    /// and goes through the stored route rather than a fresh one: a room that
    /// flipped mid-run refuses the search instead of quietly landing base
    /// telemetry for a run whose replay record sits in an evaporating overlay.
    fn search_text(&self, query: &str, limit: usize) -> Result<Vec<ScoredEntity>> {
        self.answered(|| self.session.search_text_routed(&self.route, query, limit))
    }

    fn get_replay_record(&self, run_id: &EntityId) -> Result<Option<CodeRunReplayRecord>> {
        self.answered(|| self.session.side_table_get(&REPLAY_RECORDS, run_id))
    }

    /// Compare-and-set against the SAME composed view it will update, in the
    /// SAME transaction — the canonical sibling's atomicity, routed.
    ///
    /// A failed comparison writes neither overlay nor base; the routed
    /// compare-and-put refuses inside its transaction, so nothing commits.
    /// `expected` is the replay record's own generation protocol, a separate
    /// concern from the mode-flip route: the number says "no one else
    /// appended", the route says "the room is still the room you bound".
    #[cfg(test)]
    fn put_replay_record_if_generation(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
    ) -> Result<CodeRunReplayGeneration> {
        self.put_replay_record_if_generation_with_heal(record, expected, None)
    }

    /// Commits one replay append and its optional overlay/base heal tally as
    /// one routed transaction. The overlay stores a DELTA while base stores the
    /// canonical contribution, so later base commits remain visible in the
    /// session's additive total instead of being shadowed.
    fn put_replay_record_if_generation_with_heal(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        healed_model: Option<&ModelId>,
    ) -> Result<CodeRunReplayGeneration> {
        REPLAY_RECORDS.encode_value(record)?;
        let next_generation = record.generation()?;
        self.answered(|| match healed_model {
            Some(model) => self
                .session
                .side_table_compare_and_put_with_counter_routed(
                    &self.route,
                    &REPLAY_RECORDS,
                    &record.run_id,
                    record,
                    |current| replay_generation_matches(current, expected),
                    &MODEL_HEAL_COUNTS,
                    &model.as_str().to_owned(),
                    next_additive_heal_count,
                )
                .map(drop),
            None => self.session.side_table_compare_and_put_routed(
                &self.route,
                &REPLAY_RECORDS,
                &record.run_id,
                record,
                |current| replay_generation_matches(current, expected),
            ),
        })?;
        Ok(next_generation)
    }

    #[cfg(test)]
    fn model_heal_count(&self, model: &ModelId) -> Result<CodeRunModelHealCount> {
        let (base, overlay) = self.answered(|| {
            self.session
                .side_table_counter_components(&MODEL_HEAL_COUNTS, &model.as_str().to_owned())
        })?;
        let base = base.map_or(0, |count| count.0);
        let overlay = overlay.map_or(0, |count| count.0);
        let healed_turns = base
            .checked_add(overlay)
            .ok_or(Error::ArithmeticOverflow("code-run model heal count"))?;
        Ok(CodeRunModelHealCount {
            model_id: model.as_str().to_owned(),
            healed_turns,
        })
    }

    /// A writer for one result body: into the session's own body directory
    /// while the room is off record, the vault's `bodies/` once on record.
    /// Each value custody knows is replaced by its handle as it streams
    /// (OF-560 C), as on the canonical vault.
    fn output_sink(&self) -> Result<BodySink> {
        let known = self.answered(|| self.session.known_values())?;
        Ok(self.script_sink()?.sweeping(known))
    }

    /// [`Self::output_sink`] with no sweep, for a step's program, which a
    /// resumed step runs again as stored.
    fn script_sink(&self) -> Result<BodySink> {
        let dir = self.answered(|| self.session.body_dir(self.route.target()))?;
        Ok(BodySink::new(
            dir,
            self.session
                .limit_watch()
                .bound(EngineLimit::CodeResultInlineBytes),
        ))
    }

    fn publish_output(
        &self,
        path: String,
        sink: BodySink,
        complete: bool,
        owner: EntityId,
    ) -> Result<CodeRunRawOutput> {
        let finished = finish_output(path, sink, complete, self.session.limit_watch())?;
        self.mark_secret(&finished.output, owner, finished.secret)?;
        self.answered(|| {
            self.session.side_table_put_routed(
                &self.route,
                &RAW_OUTPUTS,
                &finished.output.handle,
                &finished.body,
            )
        })?;
        Ok(finished.output)
    }

    /// Marks the occurrence of a body the secret scan hit that run `owner`
    /// holds, on the session's route, before its row is written. An
    /// off-record room files no lift proposal: nothing of it reaches the
    /// base vault.
    fn mark_secret(
        &self,
        output: &CodeRunRawOutput,
        owner: EntityId,
        secret: Option<&'static str>,
    ) -> Result<()> {
        let Some(reason) = secret else {
            return Ok(());
        };
        let key = ResultOccurrence::of(Some(owner), output)?.mark_key(&output.handle);
        self.answered(|| {
            self.session.side_table_put_routed(
                &self.route,
                &RAW_OUTPUT_SECRETS,
                &key,
                &reason.to_owned(),
            )
        })
    }

    fn put_raw_output(&self, owner: EntityId, output: &CodeRunRawOutput, raw: &[u8]) -> Result<()> {
        let mut sink = self.output_sink()?;
        sink.write(raw)?;
        let finished = finish_output(output.path.clone(), sink, true, self.session.limit_watch())?;
        if finished.output != *output {
            return Err(invalid_code_run_replay(
                "raw output metadata does not match bytes",
            ));
        }
        self.mark_secret(output, owner, finished.secret)?;
        self.answered(|| {
            self.session.side_table_put_routed(
                &self.route,
                &RAW_OUTPUTS,
                &output.handle,
                &finished.body,
            )
        })
    }

    fn get_raw_output(&self, output: &CodeRunRawOutput) -> Result<Option<Vec<u8>>> {
        validate_raw_output(output)?;
        let _pin = self.session.pin_result_body(output.raw_blake3);
        let Some(body) =
            self.answered(|| self.session.side_table_get(&RAW_OUTPUTS, &output.handle))?
        else {
            return Ok(None);
        };
        load_whole_body(output, body, || self.session.body_dirs()).map(Some)
    }

    fn read_raw_output_range(
        &self,
        output: &CodeRunRawOutput,
        offset: u64,
        len: usize,
    ) -> Result<Option<Vec<u8>>> {
        validate_raw_output(output)?;
        let _pin = self.session.pin_result_body(output.raw_blake3);
        self.answered(|| {
            self.session
                .side_table_read_bytes(&RAW_OUTPUTS, &output.handle, |row| {
                    read_body_row_range(output, row, offset, len, || self.session.body_dirs())
                })
        })
    }

    /// [`Vault::inherit_code_run_result_marks`] on the room's route: the
    /// marks of every occurrence in `from` join those of `owner`'s
    /// occurrence of `output`.
    fn inherit_marks(
        &self,
        owner: EntityId,
        output: &CodeRunRawOutput,
        from: &[(EntityId, CodeRunRawOutput)],
    ) -> Result<()> {
        let get_marks = |owner: EntityId, output: &CodeRunRawOutput| {
            let key = ResultOccurrence::of(Some(owner), output)?.mark_key(&output.handle);
            let refs = self.answered(|| self.session.side_table_get(&RAW_OUTPUT_TAINTS, &key))?;
            let secret =
                self.answered(|| self.session.side_table_get(&RAW_OUTPUT_SECRETS, &key))?;
            Ok::<_, crate::Error>((key, refs.unwrap_or_default(), secret))
        };
        let (key, mut refs, mut secret) = get_marks(owner, output)?;
        let (own_refs, own_secret) = (refs.len(), secret.is_some());
        for (source, held) in from {
            let (_, more, marked) = get_marks(*source, held)?;
            for taint in more {
                if !refs.contains(&taint) {
                    refs.push(taint);
                }
            }
            secret = secret.or(marked);
        }
        if refs.len() > own_refs {
            self.answered(|| {
                self.session
                    .side_table_put_routed(&self.route, &RAW_OUTPUT_TAINTS, &key, &refs)
            })?;
        }
        if !own_secret && let Some(reason) = &secret {
            self.answered(|| {
                self.session
                    .side_table_put_routed(&self.route, &RAW_OUTPUT_SECRETS, &key, reason)
            })?;
        }
        Ok(())
    }

    /// The taint of the occurrence of a body that `owner` holds (the bytes'
    /// own, with none), from the room's sidecars: a secret-scan mark is live
    /// taint for good, and so is any taint ref, since a room keeps no view
    /// of custody rotation.
    fn result_taint(
        &self,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
    ) -> Result<(ArtifactTaintState, Option<String>)> {
        let key = ResultOccurrence::of(owner, output)?.mark_key(&output.handle);
        if let Some(reason) =
            self.answered(|| self.session.side_table_get(&RAW_OUTPUT_SECRETS, &key))?
        {
            return Ok((ArtifactTaintState::TaintedLive, Some(reason)));
        }
        let refs = self.answered(|| self.session.side_table_get(&RAW_OUTPUT_TAINTS, &key))?;
        Ok(match refs {
            Some(refs) if !refs.is_empty() => (ArtifactTaintState::TaintedLive, None),
            _ => (ArtifactTaintState::Clean, None),
        })
    }
}

/// Where one code run's storage lives: the canonical vault, or a live
/// off-record session.
///
/// EXHAUSTIVE by design, and deliberately narrow: neither arm hands out a
/// [`Store`](crate::store::Store) or a base [`Vault`]. The session arm
/// delegates every read and write to ONE-1728's session handle, whose own
/// accessors route by mode — overlay while `OffRecord`, ordinary base after
/// the room flips `OnRecord`. Adding a method here is adding a way for the
/// executor to reach storage, so the set below is closed: identity, policy,
/// search, and the four replay/raw-output accessors. The memory-write verbs
/// are NOT here; they route inside their own dispatch bodies.
pub(crate) enum ExecutorStorage<'a> {
    Canonical(&'a Vault),
    Session(SessionBinding<'a>),
}

impl<'a> ExecutorStorage<'a> {
    /// Binds a run acting as `participant` to a live session, capturing its
    /// route and shell ONCE. In a room `participant` must be on its roster.
    pub(crate) fn for_session(
        session: &OffRecordSession<'a>,
        participant: EntityId,
    ) -> Result<Self> {
        let session = session.for_participant(participant)?;
        // Answered as the participant stands once the route and shell are
        // read, as every later call of the run is.
        let captured = session
            .write_route()
            .and_then(|route| Ok((session.routed_conversation_shell(&route)?, route)));
        session.admit_participant()?;
        let (container, route) = captured?;
        Ok(Self::Session(SessionBinding {
            session,
            route,
            container,
        }))
    }

    /// One call of the run: a session-bound run's is
    /// [`SessionBinding::answered`], a canonical run's runs as it is.
    pub(crate) fn answered<T>(&self, call: impl FnOnce() -> Result<T>) -> Result<T> {
        match self {
            Self::Canonical(_) => call(),
            Self::Session(binding) => binding.answered(call),
        }
    }

    pub(crate) fn session_ref(&self) -> Option<&str> {
        match self {
            Self::Canonical(_) => None,
            Self::Session(binding) => Some(binding.session.session_ref()),
        }
    }

    /// The participant a session-bound run acts as; `None` for a canonical
    /// run.
    pub(crate) fn participant(&self) -> Option<EntityId> {
        match self {
            Self::Canonical(_) => None,
            Self::Session(binding) => binding.session.participant(),
        }
    }

    /// Privacy-route target captured at executor entry. Overlay and base are
    /// distinct replay bindings; the overlay's RAM-local mode generation is
    /// deliberately not durable identity and may reset after process restart.
    pub(crate) fn session_route_target(&self) -> Option<RouteTarget> {
        match self {
            Self::Canonical(_) => None,
            Self::Session(binding) => Some(binding.route.target()),
        }
    }

    /// Whether the off-record effect policy applies to THIS dispatch.
    ///
    /// Reads the room's LIVE mode, not the captured route: the policy is
    /// mode-scoped, so a room that has gone on record runs the ordinary verb
    /// path again. The captured route is what refuses the write afterwards if
    /// the flip happened mid-run.
    pub(in crate::code_run) fn off_record_policy_active(&self) -> Result<bool> {
        match self {
            Self::Canonical(_) => Ok(false),
            Self::Session(binding) => Ok(binding.session.mode()? != OffRecordMode::OnRecord),
        }
    }

    /// Identity of the owning vault. Nothing dereferenceable escapes; the
    /// executor compares it and never reads through it.
    pub(crate) fn vault_id(&self) -> VaultId {
        match self {
            Self::Canonical(vault) => vault.vault_id(),
            Self::Session(binding) => binding.session.vault_id(),
        }
    }

    pub(crate) fn search_text(&self, query: &str, limit: usize) -> Result<Vec<ScoredEntity>> {
        match self {
            Self::Canonical(vault) => vault.search_text(query, limit),
            Self::Session(binding) => binding.search_text(query, limit),
        }
    }

    /// [`Self::search_text`] on `reader`'s lane: the hits its grants admit,
    /// surfaceable claims only, as the memory surface's own BM25 channel
    /// serves them.
    pub(crate) fn search_text_as(
        &self,
        query: &str,
        limit: usize,
        reader: ScopedReadActorKey,
    ) -> Result<Vec<ScoredEntity>> {
        match self {
            Self::Canonical(vault) => Ok(vault
                .scoped_read(reader)
                .with_claim_status(ClaimReadStatus::Surfaceable)
                .filter_scored_entities(vault.search_text(query, limit)?)?
                .value),
            // A room's hits include overlay rows the vault's grants cannot
            // name, and no host narrows a room run's reads.
            Self::Session(_) => Err(crate::Error::InvalidConfig(
                "a narrowed search reads the canonical vault".into(),
            )),
        }
    }

    /// Emits ONE speech bubble through the run's bound storage (ONE-1686).
    ///
    /// Returning a [`WitnessReceipt`] rather than a flag is the contract: a
    /// speech effect either MATERIALIZES its MESSAGE or fails, and the receipt
    /// is the proof. There is no arm that reports "spoken" with no bubble
    /// behind it, and no arm that swallows an utterance silently — an earlier
    /// canonical shortcut did the second, which made `emitted: false` a
    /// truthful field on an untruthful contract.
    ///
    /// The SESSION arm goes through the same captured shell and route every
    /// other executor turn uses, so a mid-run mode flip refuses the bubble
    /// instead of splitting the room's speech across the flip.
    ///
    /// The CANONICAL arm goes through the same ONE-1728 facade witness door,
    /// into a conversation and turn DERIVED from the run ref plus the durable
    /// run id when one exists — one shell and one turn per run, created on first
    /// speech. It is not a second transcript surface: no schema, no message
    /// program, and no second write boundary is minted here, only the identity
    /// a canonical run needs so its bubbles have somewhere to be and stay
    /// reproducible across a resume.
    ///
    /// # Replay-owned identity (ONE-1929)
    ///
    /// The TURN and MESSAGE ids below are DERIVED, never minted per attempt,
    /// so this is also the door that makes speech replay-stable: both the
    /// explicit `self.speak`/`self.think`/`self.express` family and the
    /// checkpointed implicit fallback reach materialization through here, and
    /// a retry of a step whose replay append failed converges on the row it
    /// already wrote instead of speaking twice. A retry that would put
    /// DIFFERENT bytes at that identity is refused typed by the witness door
    /// rather than duplicated.
    #[expect(
        clippy::too_many_arguments,
        reason = "run ref/id, utterance envelope, order, and actor are distinct host-owned witness axes"
    )]
    pub(crate) fn witness_executor_utterance(
        &self,
        run_ref: &str,
        run_id: Option<EntityId>,
        kind: ExecutorUtterance,
        text: &str,
        occurred_at: u64,
        order: u32,
        actor: WriteActor,
    ) -> Result<WitnessReceipt> {
        // HOST-derived, on both arms: durable executors bind the replay run id
        // as well as the dispatcher ref, while standalone callers retain the
        // legacy ref-only family. A step re-run after a failed replay-record
        // persist therefore re-puts THIS run's row instead of adding a second
        // one or colliding with another durable run.
        let message_id = executor_speech_message_id_for_run(run_ref, run_id, order)?;
        let turn_id = executor_speech_turn_id(run_ref, run_id)?;
        match self {
            Self::Canonical(vault) => canonical_witness_executor_turn(
                vault,
                run_ref,
                run_id,
                kind,
                text,
                occurred_at,
                order,
                message_id,
                actor,
            ),
            Self::Session(binding) => binding.witness_executor_turn(
                kind,
                text,
                occurred_at,
                order,
                message_id,
                turn_id,
                actor,
            ),
        }
    }

    pub(crate) fn witness_blocked_report(
        &self,
        run_ref: &str,
        run_id: Option<EntityId>,
        call: &crate::code_run::blocked::SelfReportBlockedCall,
        actor: WriteActor,
    ) -> Result<EntityId> {
        let receipt = crate::code_run::blocked::BlockedReceipt::new(call.category, &call.detail)?;
        self.witness_executor_utterance(
            run_ref,
            run_id,
            ExecutorUtterance::ReportBlocked,
            &receipt.content()?,
            call.occurred_at,
            call.order,
            actor,
        )?;
        let id = executor_speech_message_id_for_run(run_ref, run_id, call.order)?;
        // OF-418: a report on the record reaches the Coach's Issues job.
        if let Self::Canonical(vault) = self {
            vault.file_blocked_report(id, actor.entity_ref(), run_id, call.occurred_at)?;
        }
        Ok(id)
    }

    pub(crate) fn get_code_run_replay_record(
        &self,
        run_id: &EntityId,
    ) -> Result<Option<CodeRunReplayRecord>> {
        match self {
            Self::Canonical(vault) => vault.get_code_run_replay_record(run_id),
            Self::Session(binding) => binding.get_replay_record(run_id),
        }
    }

    #[cfg(test)]
    pub(crate) fn put_code_run_replay_record_if_generation(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
    ) -> Result<CodeRunReplayGeneration> {
        match self {
            Self::Canonical(vault) => {
                vault.put_code_run_replay_record_if_generation(record, expected)
            }
            Self::Session(binding) => binding.put_replay_record_if_generation(record, expected),
        }
    }

    /// Atomically commits a replay append and the optional one-per-turn heal
    /// signal through the run's bound storage route.
    pub(crate) fn put_code_run_replay_record_if_generation_with_heal(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        healed_model: Option<&ModelId>,
    ) -> Result<CodeRunReplayGeneration> {
        match self {
            Self::Canonical(vault) => vault.put_code_run_replay_record_if_generation_with_heal(
                record,
                expected,
                healed_model,
            ),
            Self::Session(binding) => {
                binding.put_replay_record_if_generation_with_heal(record, expected, healed_model)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn code_run_model_heal_count(
        &self,
        model: &ModelId,
    ) -> Result<CodeRunModelHealCount> {
        match self {
            Self::Canonical(vault) => vault.code_run_model_heal_count(model),
            Self::Session(binding) => binding.model_heal_count(model),
        }
    }

    /// Stores a complete body as the occurrence run `owner` holds; no body
    /// descriptor is published.
    pub(crate) fn put_code_run_raw_output(
        &self,
        owner: EntityId,
        output: &CodeRunRawOutput,
        raw: &[u8],
    ) -> Result<()> {
        match self {
            Self::Canonical(vault) => vault.put_code_run_raw_output(Some(owner), output, raw),
            Self::Session(binding) => binding.put_raw_output(owner, output, raw),
        }
    }

    pub(crate) fn get_code_run_raw_output(
        &self,
        output: &CodeRunRawOutput,
    ) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Canonical(vault) => vault.get_code_run_raw_output(output),
            Self::Session(binding) => binding.get_raw_output(output),
        }
    }

    /// See [`Vault::read_code_run_raw_output_range`].
    pub(crate) fn read_code_run_raw_output_range(
        &self,
        output: &CodeRunRawOutput,
        offset: u64,
        len: usize,
    ) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Canonical(vault) => vault.read_code_run_raw_output_range(output, offset, len),
            Self::Session(binding) => binding.read_raw_output_range(output, offset, len),
        }
    }

    /// The taint of one result occurrence, from its sidecars and never its
    /// bytes: its read-time state, and the reason the secret scan marked it
    /// with, if it did. `owner` is the run that holds it (the host's run
    /// id); a context output, which no run holds, has none, and is read as
    /// its bytes are.
    pub(crate) fn code_run_result_taint(
        &self,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
    ) -> Result<(ArtifactTaintState, Option<String>)> {
        match self {
            Self::Canonical(vault) => Ok((
                vault.code_run_raw_output_taint_state(owner, output)?,
                vault.code_run_raw_output_secret(owner, output)?,
            )),
            Self::Session(binding) => binding.result_taint(owner, output),
        }
    }

    /// Marks run `owner`'s occurrence of `output` with the taint of every
    /// occurrence in `from`, on the run's route: a body made from a tainted
    /// one is tainted as long as it is.
    pub(crate) fn inherit_code_run_result_marks(
        &self,
        owner: EntityId,
        output: &CodeRunRawOutput,
        from: &[(EntityId, CodeRunRawOutput)],
    ) -> Result<()> {
        match self {
            Self::Canonical(vault) => vault.inherit_code_run_result_marks(owner, output, from),
            Self::Session(binding) => binding.inherit_marks(owner, output, from),
        }
    }

    /// The sparse line index of one of this run's file bodies (the newline
    /// count before each 64 KiB block), from the first body directory the
    /// run reads that holds one. `None` for an inline body, or for an index
    /// lost and not rebuilt.
    pub(crate) fn code_run_line_index(
        &self,
        output: &CodeRunRawOutput,
    ) -> Result<Option<Vec<u64>>> {
        let dirs = match self {
            Self::Canonical(vault) => vec![vault.store.body_dir()?],
            Self::Session(binding) => binding.answered(|| binding.session.body_dirs())?,
        };
        Ok(dirs
            .iter()
            .find_map(|dir| dir.read_line_index(&output.raw_blake3, output.raw_len)))
    }

    /// A writer for one result body, where this run's bodies go.
    pub(crate) fn code_run_output_sink(&self) -> Result<BodySink> {
        match self {
            Self::Canonical(vault) => vault.code_run_output_sink(),
            Self::Session(binding) => binding.output_sink(),
        }
    }

    /// [`Self::code_run_output_sink`] for a step's program, which a resumed
    /// step runs again as stored: never swept.
    pub(crate) fn code_run_script_sink(&self) -> Result<BodySink> {
        match self {
            Self::Canonical(vault) => vault.code_run_script_sink(),
            Self::Session(binding) => binding.script_sink(),
        }
    }

    /// Publishes the body `sink` wrote as run `owner`'s output at `path`. An
    /// off-record session's body is not registered: it lives in the
    /// session's spill directory and goes when the session closes.
    pub(crate) fn publish_code_run_output(
        &self,
        path: String,
        sink: BodySink,
        complete: bool,
        owner: EntityId,
    ) -> Result<CodeRunRawOutput> {
        match self {
            Self::Canonical(vault) => {
                vault.publish_code_run_output(path, sink, complete, Some(owner))
            }
            Self::Session(binding) => binding.publish_output(path, sink, complete, owner),
        }
    }

    /// The `[limits]` rows of the vault this run's storage is on.
    pub(crate) fn limit_watch(&self) -> &LimitWatch {
        match self {
            Self::Canonical(vault) => vault.limit_watch(),
            Self::Session(binding) => binding.session.limit_watch(),
        }
    }

    /// A share of the result-memory pool for this run.
    pub(crate) fn result_share(&self) -> ResultShare {
        match self {
            Self::Canonical(vault) => vault.result_share(),
            Self::Session(binding) => binding.session.result_share(),
        }
    }
}

/// A facet stamp puts its source in front of every reader narrowed to the
/// facet, so a door's credential places only a row its lane reads, in a facet
/// its Scope holds, judged in `txn`, the edge's own write transaction (Astra
/// on #1432). The target must be a stored FACET, or the type table refuses
/// the stamp later naming the target's type. Any other stamp is refused here
/// naming no endpoint type, so the refusal says nothing about a target the
/// lane may not read (Astra R9 F2, R11 F1). A custody source is no lane's to
/// read, and its read refusal names its type, so it is refused here as a
/// missing source is (Sol R13 F1).
pub(crate) fn require_facet_placement_in(
    vault: &Vault,
    reader: &ScopedReadActorKey,
    txn: &heed::RoTxn<'_>,
    src: EntityId,
    tgt: EntityId,
) -> Result<()> {
    let in_scope = reader
        .authority_scope()
        .is_none_or(|scope| scope.facets.contains(&crate::federation::ScopeId(tgt)));
    // An owner key's standing is rechecked in this snapshot, as every point
    // read rechecks it: a key kept past its owner's revocation places nothing.
    let lane = vault.scoped_read(reader.clone());
    if in_scope
        && crate::batch::stored_entity_type(&vault.store, txn, &tgt)?
            == Some(crate::registry::ENTITY_TYPE_FACET)
        && crate::batch::stored_entity_type(&vault.store, txn, &src)?
            != Some(crate::registry::ENTITY_TYPE_SECRET_CUSTODY)
        && lane.is_entity_readable_with_policy_in(txn, &lane.live_policy_manifest_in(txn)?, &src)?
    {
        return Ok(());
    }
    Err(unplaceable(src, tgt))
}

/// The refusal a facet stamp a door's credential may not place gets.
pub(crate) fn unplaceable(src: EntityId, tgt: EntityId) -> crate::Error {
    crate::Error::Registry(crate::error::RegistryError::InvalidFacetOfEdge {
        src,
        src_type: None,
        tgt,
        tgt_type: None,
    })
}
