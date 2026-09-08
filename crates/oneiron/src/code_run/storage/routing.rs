//! Where one run's reads and writes land: the canonical vault or a bound off-record session.

use crate::memory::WitnessReceipt;
use crate::off_record::{ExecutorUtterance, OffRecordMode, OffRecordSession, SessionWriteRoute};
use crate::session_overlay::RouteTarget;
use crate::store::Store;
use crate::{EntityId, ModelId, Result, ScoredEntity, Vault, WriteActor};

use super::super::codec::{
    decode_code_run_replay_record, encode_code_run_replay_record, validate_raw_output,
};
use super::super::replay::{CodeRunRawOutput, CodeRunReplayGeneration, CodeRunReplayRecord};
use super::super::support::invalid_code_run_replay;
use super::records::{
    code_run_model_heal_count_key, code_run_raw_output_key, code_run_replay_record_key,
    next_additive_heal_count, replay_generation_matches,
};
use super::speech_identity::{
    canonical_witness_executor_turn, executor_speech_message_id_for_run, executor_speech_turn_id,
};

#[cfg(test)]
use super::records::{CodeRunModelHealCount, decode_code_run_model_heal_count};
#[cfg(test)]
use crate::Error;

/// The session half of an executor binding (ONE-1729/P4b).
///
/// ONE-1728's typed session handle, the run's ONE [`SessionWriteRoute`], and
/// the session-owned conversation shell its turns ride — captured together at
/// RUN ENTRY and never re-minted (owner ruling R-20260807-02 rider 2). Route
/// and handle live in the same value because "one route per run" has to be a
/// type fact: a per-dispatch mint is not something this shape can express.
pub(crate) struct SessionBinding<'a> {
    pub(crate) session: &'a OffRecordSession<'a>,
    pub(crate) route: SessionWriteRoute,
    pub(crate) container: EntityId,
}

impl SessionBinding<'_> {
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
    }

    /// In-room retrieval through the run's captured route.
    ///
    /// Search registers a retrieval-run row, so it is an APPLY like any other
    /// and goes through the stored route rather than a fresh one: a room that
    /// flipped mid-run refuses the search instead of quietly landing base
    /// telemetry for a run whose replay record sits in an evaporating overlay.
    fn search_text(&self, query: &str, limit: usize) -> Result<Vec<ScoredEntity>> {
        self.session.search_text_routed(&self.route, query, limit)
    }

    fn get_replay_record(&self, run_id: &EntityId) -> Result<Option<CodeRunReplayRecord>> {
        self.session
            .vault_meta_get(&code_run_replay_record_key(run_id))?
            .map(|raw| decode_code_run_replay_record(&raw))
            .transpose()
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
        let encoded = encode_code_run_replay_record(record)?;
        let next_generation = record.generation()?;
        let replay_key = code_run_replay_record_key(&record.run_id);
        if let Some(model) = healed_model {
            let counter_key = code_run_model_heal_count_key(model);
            self.session
                .vault_meta_compare_and_put_with_counter_routed(
                    &self.route,
                    &replay_key,
                    &encoded,
                    |current| replay_generation_matches(current, expected),
                    &counter_key,
                    next_additive_heal_count,
                )?;
        } else {
            self.session.vault_meta_compare_and_put_routed(
                &self.route,
                &replay_key,
                &encoded,
                |current| replay_generation_matches(current, expected),
            )?;
        }
        Ok(next_generation)
    }

    #[cfg(test)]
    fn model_heal_count(&self, model: &ModelId) -> Result<CodeRunModelHealCount> {
        let key = code_run_model_heal_count_key(model);
        let (base, overlay) = self.session.vault_meta_counter_components(&key)?;
        let base = decode_code_run_model_heal_count(base.as_deref())?;
        let overlay = decode_code_run_model_heal_count(overlay.as_deref())?;
        let healed_turns = base
            .checked_add(overlay)
            .ok_or(Error::ArithmeticOverflow("code-run model heal count"))?;
        Ok(CodeRunModelHealCount {
            model_id: model.as_str().to_owned(),
            healed_turns,
        })
    }

    fn put_raw_output(&self, output: &CodeRunRawOutput, raw: &[u8]) -> Result<()> {
        if CodeRunRawOutput::from_bytes(output.path.clone(), raw)? != *output {
            return Err(invalid_code_run_replay(
                "raw output metadata does not match bytes",
            ));
        }
        self.session
            .vault_meta_put_routed(&self.route, &code_run_raw_output_key(output), raw)
    }

    fn get_raw_output(&self, output: &CodeRunRawOutput) -> Result<Option<Vec<u8>>> {
        validate_raw_output(output)?;
        let Some(raw) = self
            .session
            .vault_meta_get(&code_run_raw_output_key(output))?
        else {
            return Ok(None);
        };
        if CodeRunRawOutput::from_bytes(output.path.clone(), &raw)? != *output {
            return Err(invalid_code_run_replay(
                "stored raw output bytes drifted from metadata",
            ));
        }
        Ok(Some(raw))
    }
}

/// Where one code run's storage lives: the canonical vault, or a live
/// off-record session.
///
/// EXHAUSTIVE by design, and deliberately narrow: neither arm hands out a
/// [`Store`] or a base [`Vault`]. The session arm delegates every read and
/// write to ONE-1728's session handle, whose own accessors route by mode —
/// overlay while `OffRecord`, ordinary base after the room flips `OnRecord`.
/// Adding a method here is adding a way for the executor to reach storage, so
/// the set below is closed: identity, policy, search, and the four
/// replay/raw-output accessors. The memory-write verbs are NOT here; they
/// route inside their own dispatch bodies.
pub(crate) enum ExecutorStorage<'a> {
    Canonical(&'a Vault),
    Session(SessionBinding<'a>),
}

impl<'a> ExecutorStorage<'a> {
    /// Binds a run to a live session, capturing its route and shell ONCE.
    pub(crate) fn for_session(session: &'a OffRecordSession<'a>) -> Result<Self> {
        let route = session.write_route()?;
        let container = session.routed_conversation_shell(&route)?;
        Ok(Self::Session(SessionBinding {
            session,
            route,
            container,
        }))
    }

    pub(crate) fn session_ref(&self) -> Option<&str> {
        match self {
            Self::Canonical(_) => None,
            Self::Session(binding) => Some(binding.session.session_ref()),
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
    pub(crate) fn off_record_policy_active(&self) -> Result<bool> {
        match self {
            Self::Canonical(_) => Ok(false),
            Self::Session(binding) => Ok(binding.session.mode()? == OffRecordMode::OffRecord),
        }
    }

    /// Identity-only projection of the owning store. Nothing dereferenceable
    /// escapes; the executor compares it and never reads through it.
    pub(crate) fn store_identity(&self) -> *const Store {
        match self {
            Self::Canonical(vault) => std::ptr::from_ref(&vault.store),
            Self::Session(binding) => binding.session.store_identity(),
        }
    }

    pub(crate) fn search_text(&self, query: &str, limit: usize) -> Result<Vec<ScoredEntity>> {
        match self {
            Self::Canonical(vault) => vault.search_text(query, limit),
            Self::Session(binding) => binding.search_text(query, limit),
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

    pub(crate) fn put_code_run_raw_output(
        &self,
        output: &CodeRunRawOutput,
        raw: &[u8],
    ) -> Result<()> {
        match self {
            Self::Canonical(vault) => vault.put_code_run_raw_output(output, raw),
            Self::Session(binding) => binding.put_raw_output(output, raw),
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
}
