use crate::off_record::{OffRecordMode, OffRecordSession, SessionWriteRoute};
use crate::store::Store;
use crate::{EntityId, Error, Result, ScoredEntity, Vault, WriteActor};

use super::codec::{
    decode_code_run_replay_record, encode_code_run_replay_record, validate_raw_output,
};
use super::replay::{CodeRunRawOutput, CodeRunReplayGeneration, CodeRunReplayRecord};
use super::support::invalid_code_run_replay;

const CODE_RUN_REPLAY_RECORD_KEY_PREFIX: &[u8] = b"code_run:replay:v1:";
const CODE_RUN_RAW_OUTPUT_KEY_PREFIX: &[u8] = b"code_run:raw_output:v1:";

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
    /// Records one executor turn through the session-side witness entry.
    ///
    /// Supplies the run's captured shell and route so the executor never sees
    /// either, and passes `turn_ref: None` — the only value that entry
    /// accepts. Widening this to admit a caller-supplied turn ref would be a
    /// visible API change, which is the point of the typed refusal behind it.
    pub(crate) fn witness_executor_turn(
        &self,
        kind: crate::off_record::ExecutorUtterance,
        text: &str,
        occurred_at: u64,
        actor: WriteActor,
    ) -> Result<crate::memory::WitnessReceipt> {
        self.session.witness_executor_turn(
            &self.container,
            kind,
            text,
            occurred_at,
            None,
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
