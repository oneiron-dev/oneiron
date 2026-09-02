use sha2::{Digest, Sha256};

use crate::memory::WitnessReceipt;
use crate::off_record::{ExecutorUtterance, OffRecordMode, OffRecordSession, SessionWriteRoute};
use crate::store::Store;
use crate::{EntityId, Error, Result, ScoredEntity, Vault, WriteActor};

use super::codec::{
    decode_code_run_replay_record, encode_code_run_replay_record, validate_raw_output,
};
use super::replay::{CodeRunRawOutput, CodeRunReplayGeneration, CodeRunReplayRecord};
use super::support::invalid_code_run_replay;

const CODE_RUN_REPLAY_RECORD_KEY_PREFIX: &[u8] = b"code_run:replay:v1:";
const CODE_RUN_RAW_OUTPUT_KEY_PREFIX: &[u8] = b"code_run:raw_output:v1:";

/// Domain tags for a canonical run's speech identities (ONE-1686).
///
/// Executor-owned transcript identity is DERIVED, never minted. A durable
/// executor passes both the host-bound run ref and `EngineExecutorConfig.run_id`,
/// so two replay records cannot share transcript rows merely because their
/// dispatchers reused a ref. The optional run id preserves the original
/// run-ref-only identity for standalone dispatcher and witness APIs that have no
/// durable executor config.
const EXECUTOR_SPEECH_CONVERSATION_DOMAIN: &[u8] = b"oneiron:executor-speech-conversation:v1";
const EXECUTOR_SPEECH_TURN_DOMAIN: &[u8] = b"oneiron:executor-speech-turn:v1";
const EXECUTOR_SPEECH_MESSAGE_DOMAIN: &[u8] = b"oneiron:executor-speech-message:v1";

/// Derives one deterministic entity id from a domain tag and length-prefixed
/// material, re-salting past a reserved sentinel rather than truncating into
/// one.
fn derived_executor_id(domain: &[u8], parts: &[&[u8]]) -> Result<EntityId> {
    for salt in 0..=u8::MAX {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update([salt]);
        for part in parts {
            let len = u64::try_from(part.len())
                .map_err(|_| Error::ArithmeticOverflow("executor speech id material"))?;
            hasher.update(len.to_le_bytes());
            hasher.update(part);
        }
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "executor speech id derivation failed",
    ))
}

/// The legacy standalone conversation identity. Runtime executor paths use
/// [`canonical_speech_conversation_id_for_run`] with their durable run id.
#[cfg(test)]
pub(crate) fn canonical_speech_conversation_id(run_ref: &str) -> Result<EntityId> {
    canonical_speech_conversation_id_for_run(run_ref, None)
}

/// The conversation a CANONICAL run's speech lands in: one shell per durable
/// run, create-or-get through the ordinary witness door.
pub(crate) fn canonical_speech_conversation_id_for_run(
    run_ref: &str,
    run_id: Option<EntityId>,
) -> Result<EntityId> {
    match run_id {
        Some(run_id) => derived_executor_id(
            EXECUTOR_SPEECH_CONVERSATION_DOMAIN,
            &[run_ref.as_bytes(), run_id.as_bytes()],
        ),
        None => derived_executor_id(EXECUTOR_SPEECH_CONVERSATION_DOMAIN, &[run_ref.as_bytes()]),
    }
}

/// The turn one run's speech appends to.
///
/// ONE turn per run, not one per utterance: a TURN is the maximal consecutive
/// run of ONE speaker, and every bubble a run emits is the same Companion. The
/// bubbles' own `order` values carry the interleaving.
fn executor_speech_turn_id(run_ref: &str, run_id: Option<EntityId>) -> Result<EntityId> {
    match run_id {
        Some(run_id) => derived_executor_id(
            EXECUTOR_SPEECH_TURN_DOMAIN,
            &[run_ref.as_bytes(), run_id.as_bytes()],
        ),
        None => derived_executor_id(EXECUTOR_SPEECH_TURN_DOMAIN, &[run_ref.as_bytes()]),
    }
}

/// The legacy standalone MESSAGE identity. Runtime executor paths also fold in
/// their durable run id through [`executor_speech_message_id_for_run`].
#[cfg(test)]
pub(crate) fn executor_speech_message_id(run_ref: &str, order: u32) -> Result<EntityId> {
    executor_speech_message_id_for_run(run_ref, None, order)
}

/// The MESSAGE id for one executor bubble: the run identity plus the bubble's
/// host-owned position.
///
/// `order` is the bridge ordering the host stamped (or, for the trailing
/// fallback, the run's next bridge position), so it is unique within the run
/// and reproducible from the persisted replay state. That is what makes a
/// re-emission a re-PUT of the same row rather than a second bubble.
fn executor_speech_message_id_for_run(
    run_ref: &str,
    run_id: Option<EntityId>,
    order: u32,
) -> Result<EntityId> {
    let order_bytes = order.to_le_bytes();
    match run_id {
        Some(run_id) => derived_executor_id(
            EXECUTOR_SPEECH_MESSAGE_DOMAIN,
            &[run_ref.as_bytes(), run_id.as_bytes(), &order_bytes],
        ),
        None => derived_executor_id(
            EXECUTOR_SPEECH_MESSAGE_DOMAIN,
            &[run_ref.as_bytes(), &order_bytes],
        ),
    }
}

impl Vault {
    /// Persists the replay record for `record.run_id`.
    pub fn put_code_run_replay_record(&self, record: &CodeRunReplayRecord) -> Result<()> {
        let encoded = encode_code_run_replay_record(record)?;
        let mut wtxn = self.store.env.write_txn()?;
        self.store.vault_meta.put(
            &mut wtxn,
            &code_run_replay_record_key(&record.run_id),
            &encoded,
        )?;
        Ok(wtxn.commit()?)
    }

    /// Persists the replay record only if the stored row still matches `expected`.
    pub fn put_code_run_replay_record_if_generation(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
    ) -> Result<CodeRunReplayGeneration> {
        let encoded = encode_code_run_replay_record(record)?;
        let next_generation = record.generation()?;
        let key = code_run_replay_record_key(&record.run_id);
        let mut wtxn = self.store.env.write_txn()?;
        let current = self
            .store
            .vault_meta
            .get(&wtxn, &key)?
            .map(|raw| decode_code_run_replay_record(&raw))
            .transpose()?;
        let current_generation = current
            .as_ref()
            .map(CodeRunReplayRecord::generation)
            .transpose()?;
        if current_generation != expected {
            return Err(Error::ConcurrentWrite(
                "code-run replay record changed; retry executor",
            ));
        }
        self.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
        wtxn.commit()?;
        Ok(next_generation)
    }

    /// Loads the replay record for `run_id`, if present.
    pub fn get_code_run_replay_record(
        &self,
        run_id: &EntityId,
    ) -> Result<Option<CodeRunReplayRecord>> {
        let rtxn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&rtxn, &code_run_replay_record_key(run_id))?
            .map(|raw| decode_code_run_replay_record(&raw))
            .transpose()
    }

    /// Stores raw output bytes under a deterministic content handle.
    pub fn put_code_run_raw_output(&self, output: &CodeRunRawOutput, raw: &[u8]) -> Result<()> {
        let expected = CodeRunRawOutput::from_bytes(output.path.clone(), raw)?;
        if expected != *output {
            return Err(invalid_code_run_replay(
                "raw output metadata does not match bytes",
            ));
        }

        let mut wtxn = self.store.env.write_txn()?;
        self.store
            .vault_meta
            .put(&mut wtxn, &code_run_raw_output_key(output), raw)?;
        Ok(wtxn.commit()?)
    }

    /// Loads raw output bytes for `output` and verifies they still match metadata.
    pub fn get_code_run_raw_output(&self, output: &CodeRunRawOutput) -> Result<Option<Vec<u8>>> {
        validate_raw_output(output)?;
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self
            .store
            .vault_meta
            .get(&rtxn, &code_run_raw_output_key(output))?
            .map(|value| value.to_vec())
        else {
            return Ok(None);
        };
        let expected = CodeRunRawOutput::from_bytes(output.path.clone(), &raw)?;
        if expected != *output {
            return Err(invalid_code_run_replay(
                "stored raw output bytes drifted from metadata",
            ));
        }
        Ok(Some(raw))
    }
}

fn code_run_replay_record_key(run_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CODE_RUN_REPLAY_RECORD_KEY_PREFIX.len() + 16);
    key.extend_from_slice(CODE_RUN_REPLAY_RECORD_KEY_PREFIX);
    key.extend_from_slice(run_id.as_bytes());
    key
}

fn code_run_raw_output_key(output: &CodeRunRawOutput) -> Vec<u8> {
    let mut key = Vec::with_capacity(CODE_RUN_RAW_OUTPUT_KEY_PREFIX.len() + output.handle.len());
    key.extend_from_slice(CODE_RUN_RAW_OUTPUT_KEY_PREFIX);
    key.extend_from_slice(output.handle.as_bytes());
    key
}

/// The session half of an executor binding (ONE-1729/P4b).
///
/// ONE-1728's typed session handle, the run's ONE [`SessionWriteRoute`], and
/// the session-owned conversation shell its turns ride — captured together at
/// RUN ENTRY and never re-minted (owner ruling R-20260807-02 rider 2). Route
/// and handle live in the same value because "one route per run" has to be a
/// type fact: a per-dispatch mint is not something this shape can express.
pub(crate) struct SessionBinding<'a> {
    pub(super) session: &'a OffRecordSession<'a>,
    pub(super) route: SessionWriteRoute,
    pub(super) container: EntityId,
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
    fn put_replay_record_if_generation(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
    ) -> Result<CodeRunReplayGeneration> {
        let encoded = encode_code_run_replay_record(record)?;
        let next_generation = record.generation()?;
        self.session.vault_meta_compare_and_put_routed(
            &self.route,
            &code_run_replay_record_key(&record.run_id),
            &encoded,
            |current| {
                let stored = current
                    .map(decode_code_run_replay_record)
                    .transpose()?
                    .as_ref()
                    .map(CodeRunReplayRecord::generation)
                    .transpose()?;
                if stored == expected {
                    return Ok(());
                }
                Err(Error::ConcurrentWrite(
                    "code-run replay record changed; retry executor",
                ))
            },
        )?;
        Ok(next_generation)
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

/// Records ONE canonical-run executor turn through ONE-1728's facade witness
/// door (ONE-1686).
///
/// A CALL SITE, not a transcript surface — the same standing the session arm
/// has. Conversation identity, container resolution, role tags, the approval
/// ceiling, the `AuthoredBy` edge and the BM25 posting are all the door's; what
/// this adds is the run-scoped shell and turn a canonical run has no session to
/// hand it, both derived from the durable run identity so they are the same on
/// every attempt but distinct from another run that reused the dispatcher ref.
///
/// `turn_ref` IS supplied here, unlike on the session arm. The typed refusal
/// there guards GUEST-named turns inside a room; this id is host-derived from
/// the run identity, and naming it is exactly what makes a retried step append
/// to the turn it already opened instead of opening another.
///
/// # Errors
///
/// Propagates the witness door's refusals, including the ONE-1686 approval
/// ceiling — preserved as the typed gate denial so the dispatcher records a
/// `Denied` bridge row rather than an opaque failure.
#[expect(
    clippy::too_many_arguments,
    reason = "every parameter is a distinct axis the witness envelope binds; folding them into a \
              struct would hide which ones the host owns"
)]
fn canonical_witness_executor_turn(
    vault: &Vault,
    run_ref: &str,
    run_id: Option<EntityId>,
    kind: ExecutorUtterance,
    text: &str,
    occurred_at: u64,
    order: u32,
    message_id: EntityId,
    actor: WriteActor,
) -> Result<WitnessReceipt> {
    let conversation_id = canonical_speech_conversation_id_for_run(run_ref, run_id)?;
    let turn_id = executor_speech_turn_id(run_ref, run_id)?;
    vault
        .memory(actor.entity_ref(), actor.actor_class())
        .witness(&crate::memory::WitnessTurn {
            conversation_ref: conversation_id.to_hex(),
            turn_ref: Some(turn_id.to_hex()),
            messages: vec![crate::memory::WitnessMessage {
                id: Some(message_id.to_hex()),
                author: crate::memory::WitnessAuthor::Companion,
                message_type: kind.as_message_type().to_owned(),
                content: text.to_owned(),
                metadata: None,
                is_visible: kind.is_visible(),
                order,
            }],
            occurred_at,
        })
        .map_err(|error| {
            error
                .gate_denial_error()
                .unwrap_or(Error::InvariantViolation(
                    "executor witness door rejected the canonical turn",
                ))
        })
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
