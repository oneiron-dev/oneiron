//! The code-run vault_meta row families: replay records, raw output, taint refs and heal counts.

use crate::secret_lease::SecretTaintRef;
use crate::secret_rotation::{
    ArtifactTaintState, decode_taint_refs_row, encode_taint_refs_row, taint_state_for_refs_in_txn,
    validate_taint_refs,
};
use crate::session_overlay::RouteTarget;
use crate::{EntityId, Error, ModelId, Result, Vault};

use super::super::codec::{
    decode_code_run_replay_record, encode_code_run_replay_record, validate_raw_output,
};
use super::super::replay::{CodeRunRawOutput, CodeRunReplayGeneration, CodeRunReplayRecord};
use super::super::support::invalid_code_run_replay;

const CODE_RUN_REPLAY_RECORD_KEY_PREFIX: &[u8] = b"code_run:replay:v1:";

const CODE_RUN_RAW_OUTPUT_KEY_PREFIX: &[u8] = b"code_run:raw_output:v1:";

/// SECRET-04 (ONE-1922): the FORWARD taint sidecar of one raw-output row.
///
/// A sidecar rather than a wrapper because the raw-output row is bytes and
/// nothing else — `get_code_run_raw_output` re-hashes it against its
/// metadata, so a framing change there would break every stored output. The
/// sidecar is keyed by the SAME handle, written in the SAME transaction, and
/// absent for the overwhelmingly common untainted run.
const CODE_RUN_RAW_OUTPUT_TAINT_KEY_PREFIX: &[u8] = b"code_run:raw_output:taint:v1:";

/// Replay-adjacent, NODE-LOCAL per-model wire-heal tally (ONE-1929).
const CODE_RUN_MODEL_HEAL_COUNT_PREFIX: &[u8] = b"code_run:heal_count:v1:";

/// How many durable executor turns one model needed wire healing for.
///
/// A ROUTING SIGNAL, nothing more: the row lives in the same node-local
/// `vault_meta` store the replay record does, carries no entity, claim, edge,
/// or sync hook, and no residency decision reads it in this diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRunModelHealCount {
    pub model_id: String,
    pub healed_turns: u64,
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
        self.put_code_run_replay_record_if_generation_with_heal(record, expected, None)
    }

    /// The executor commit primitive: compare-and-put the replay append and,
    /// for a healed turn, increment its model tally in the SAME transaction.
    /// A tally decode/overflow/write failure therefore leaves the replay row
    /// unchanged, and a committed replay can never be followed by a false
    /// executor failure from a second telemetry transaction.
    pub(super) fn put_code_run_replay_record_if_generation_with_heal(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        healed_model: Option<&ModelId>,
    ) -> Result<CodeRunReplayGeneration> {
        let encoded = encode_code_run_replay_record(record)?;
        let next_generation = record.generation()?;
        let replay_key = code_run_replay_record_key(&record.run_id);
        let mut wtxn = self.store.env.write_txn()?;
        let current = self
            .store
            .vault_meta
            .get(&wtxn, &replay_key)?
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
        let next_heal_count = healed_model
            .map(|model| {
                let key = code_run_model_heal_count_key(model);
                let current = decode_code_run_model_heal_count(
                    self.store.vault_meta.get(&wtxn, &key)?.as_deref(),
                )?;
                let next = current
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow("code-run model heal count"))?;
                Ok::<_, Error>((key, next))
            })
            .transpose()?;
        self.store
            .vault_meta
            .put(&mut wtxn, &replay_key, &encoded)?;
        if let Some((key, count)) = next_heal_count {
            self.store
                .vault_meta
                .put(&mut wtxn, &key, &count.to_be_bytes()[..])?;
        }
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

    /// Stores raw output bytes ALONGSIDE the taint refs of the action that
    /// produced them (SECRET-04, ONE-1922).
    ///
    /// A SIBLING of [`Vault::put_code_run_raw_output`], not a replacement:
    /// the existing signature is untouched, so every live persist call site
    /// stays exactly as it was and no executor learns about secrets it does
    /// not consume. A build leg that DID consume one calls this instead and
    /// hands over the door receipt's taint token.
    ///
    /// One write transaction carries the sidecar and the raw-output row, so
    /// tainted exhaust can never survive a half-failed write wearing no
    /// mark. An empty ref list is exactly the untainted put (the sidecar is
    /// cleared, not written empty).
    ///
    /// Deliberately a VAULT door and not (yet) an `ExecutorStorage` arm: the
    /// durable executor has no secret awareness to route, so a passthrough
    /// added here would be an uncalled arm on the executor's closed storage
    /// set. The consumer that teaches a build leg to declare its taint adds
    /// the arm together with the call site that needs it.
    pub fn put_code_run_raw_output_tainted(
        &self,
        output: &CodeRunRawOutput,
        raw: &[u8],
        taint_refs: &[SecretTaintRef],
    ) -> Result<()> {
        let expected = CodeRunRawOutput::from_bytes(output.path.clone(), raw)?;
        if expected != *output {
            return Err(invalid_code_run_replay(
                "raw output metadata does not match bytes",
            ));
        }
        validate_taint_refs(taint_refs)?;

        let mut wtxn = self.store.env.write_txn()?;
        let taint_key = code_run_raw_output_taint_key(output);
        if taint_refs.is_empty() {
            self.store.vault_meta.delete(&mut wtxn, &taint_key)?;
        } else {
            self.store.vault_meta.put(
                &mut wtxn,
                &taint_key,
                &encode_taint_refs_row(taint_refs)?,
            )?;
        }
        self.store
            .vault_meta
            .put(&mut wtxn, &code_run_raw_output_key(output), raw)?;
        Ok(wtxn.commit()?)
    }

    /// The taint refs stored beside one raw output (empty when the sidecar
    /// row is absent — an untainted run).
    pub fn code_run_raw_output_taint_refs(
        &self,
        output: &CodeRunRawOutput,
    ) -> Result<Vec<SecretTaintRef>> {
        let rtxn = self.store.env.read_txn()?;
        match self
            .store
            .vault_meta
            .get(&rtxn, &code_run_raw_output_taint_key(output))?
        {
            Some(raw) => decode_taint_refs_row(&raw),
            None => Ok(Vec::new()),
        }
    }

    /// The READ-TIME taint state of one raw output (ARCH-0069 S7, amended).
    ///
    /// Derived on every call from the sidecar refs and the custody records'
    /// CURRENT generations: `Clean` when the sidecar is absent,
    /// `TaintedLive` while every named record still sits at the generation
    /// the output was produced under, `TaintedStale` the moment one rotates
    /// or is revoked. No row is rewritten at rotation time to make that
    /// true.
    pub fn code_run_raw_output_taint_state(
        &self,
        output: &CodeRunRawOutput,
    ) -> Result<ArtifactTaintState> {
        let rtxn = self.store.env.read_txn()?;
        let refs = match self
            .store
            .vault_meta
            .get(&rtxn, &code_run_raw_output_taint_key(output))?
        {
            Some(raw) => decode_taint_refs_row(&raw)?,
            None => Vec::new(),
        };
        taint_state_for_refs_in_txn(&self.store, &rtxn, &refs)
    }

    /// Test-only direct tally increment. Production executor commits use the
    /// replay-and-heal transaction above so telemetry cannot lag persistence.
    #[cfg(test)]
    pub(in crate::code_run) fn increment_code_run_model_heal_count(
        &self,
        model: &ModelId,
    ) -> Result<CodeRunModelHealCount> {
        let key = code_run_model_heal_count_key(model);
        let mut wtxn = self.store.env.write_txn()?;
        let current =
            decode_code_run_model_heal_count(self.store.vault_meta.get(&wtxn, &key)?.as_deref())?;
        let healed_turns = current
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("code-run model heal count"))?;
        self.store
            .vault_meta
            .put(&mut wtxn, &key, &healed_turns.to_be_bytes()[..])?;
        wtxn.commit()?;
        Ok(CodeRunModelHealCount {
            model_id: model.as_str().to_owned(),
            healed_turns,
        })
    }

    /// Reads the node-local healed-turn tally for `model` (0 when absent).
    ///
    /// Deliberately `pub`: the residency-routing consumer is later work, and
    /// an unread crate-internal accessor would trip the workspace dead-code
    /// lint under `-D warnings`.
    pub fn code_run_model_heal_count(&self, model: &ModelId) -> Result<CodeRunModelHealCount> {
        let rtxn = self.store.env.read_txn()?;
        let healed_turns = decode_code_run_model_heal_count(
            self.store
                .vault_meta
                .get(&rtxn, &code_run_model_heal_count_key(model))?
                .as_deref(),
        )?;
        Ok(CodeRunModelHealCount {
            model_id: model.as_str().to_owned(),
            healed_turns,
        })
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

pub(super) fn code_run_replay_record_key(run_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CODE_RUN_REPLAY_RECORD_KEY_PREFIX.len() + 16);
    key.extend_from_slice(CODE_RUN_REPLAY_RECORD_KEY_PREFIX);
    key.extend_from_slice(run_id.as_bytes());
    key
}

pub(super) fn code_run_raw_output_key(output: &CodeRunRawOutput) -> Vec<u8> {
    let mut key = Vec::with_capacity(CODE_RUN_RAW_OUTPUT_KEY_PREFIX.len() + output.handle.len());
    key.extend_from_slice(CODE_RUN_RAW_OUTPUT_KEY_PREFIX);
    key.extend_from_slice(output.handle.as_bytes());
    key
}

/// The taint sidecar key for one raw-output handle.
///
/// Note the prefixes do not nest ambiguously: `code_run:raw_output:v1:` and
/// `code_run:raw_output:taint:v1:` are disjoint because the handle follows a
/// terminating `:` in both, so a prefix scan of one never sees the other.
fn code_run_raw_output_taint_key(output: &CodeRunRawOutput) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(CODE_RUN_RAW_OUTPUT_TAINT_KEY_PREFIX.len() + output.handle.len());
    key.extend_from_slice(CODE_RUN_RAW_OUTPUT_TAINT_KEY_PREFIX);
    key.extend_from_slice(output.handle.as_bytes());
    key
}

/// The heal-tally key: the fixed prefix followed by the VALIDATED model id
/// bytes, so two model ids can never share a row.
pub(super) fn code_run_model_heal_count_key(model: &ModelId) -> Vec<u8> {
    let model = model.as_str().as_bytes();
    let mut key = Vec::with_capacity(CODE_RUN_MODEL_HEAL_COUNT_PREFIX.len() + model.len());
    key.extend_from_slice(CODE_RUN_MODEL_HEAL_COUNT_PREFIX);
    key.extend_from_slice(model);
    key
}

/// An absent row is zero; any other length is a corrupted LOCAL row, reported
/// through the existing typed error rather than a new class.
pub(super) fn decode_code_run_model_heal_count(raw: Option<&[u8]>) -> Result<u64> {
    let Some(raw) = raw else {
        return Ok(0);
    };
    let bytes: [u8; 8] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("code-run model heal count row"))?;
    Ok(u64::from_be_bytes(bytes))
}

pub(super) fn replay_generation_matches(
    current: Option<&[u8]>,
    expected: Option<CodeRunReplayGeneration>,
) -> Result<()> {
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
}

/// Advances the contribution owned by `target` and returns both its encoded
/// next value and the additive overlay + base total.
pub(super) fn next_additive_heal_count(
    base: Option<&[u8]>,
    overlay: Option<&[u8]>,
    target: RouteTarget,
) -> Result<(Vec<u8>, u64)> {
    let base = decode_code_run_model_heal_count(base)?;
    let overlay = decode_code_run_model_heal_count(overlay)?;
    let (base, overlay, next) = match target {
        RouteTarget::Base => {
            let next = base
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("code-run model heal count"))?;
            (next, overlay, next)
        }
        RouteTarget::Overlay => {
            let next = overlay
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("code-run model heal count"))?;
            (base, next, next)
        }
    };
    let total = base
        .checked_add(overlay)
        .ok_or(Error::ArithmeticOverflow("code-run model heal count"))?;
    Ok((next.to_be_bytes().to_vec(), total))
}
