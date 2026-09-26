//! The code-run vault_meta row families: replay records, raw output, taint refs and heal counts.

use crate::secret_lease::SecretTaintRef;
use crate::secret_rotation::{
    ArtifactTaintState, taint_state_for_refs_in_txn, validate_taint_refs,
};
use crate::session_overlay::RouteTarget;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::{EntityId, Error, ModelId, Result, Vault};

use super::super::codec::validate_raw_output;
use super::super::replay::{CodeRunRawOutput, CodeRunReplayGeneration, CodeRunReplayRecord};
use super::super::support::invalid_code_run_replay;

/// The replay record of one run, keyed by run id.
pub(super) const REPLAY_RECORDS: SideTable<EntityId, CodeRunReplayRecord, Raw> =
    SideTable::new(&side_table::CODE_RUN_REPLAY);

/// Raw output bytes, keyed by their deterministic content handle.
pub(super) const RAW_OUTPUTS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::CODE_RUN_RAW_OUTPUT);

/// SECRET-04 (ONE-1922): the FORWARD taint sidecar of one raw-output row.
///
/// A sidecar rather than a wrapper because the raw-output row is bytes and
/// nothing else — `get_code_run_raw_output` re-hashes it against its
/// metadata, so a framing change there would break every stored output. The
/// sidecar is keyed by the SAME handle, written in the SAME transaction, and
/// absent for the overwhelmingly common untainted run.
const RAW_OUTPUT_TAINTS: SideTable<String, Vec<SecretTaintRef>, Raw> =
    SideTable::new(&side_table::CODE_RUN_RAW_OUTPUT_TAINT);

/// Replay-adjacent, NODE-LOCAL per-model wire-heal tally (ONE-1929), keyed by
/// the VALIDATED model id, so two model ids can never share a row.
pub(super) const MODEL_HEAL_COUNTS: SideTable<String, HealCount, Raw> =
    SideTable::new(&side_table::CODE_RUN_HEAL_COUNT);

/// One model's heal tally: eight big-endian bytes. Any other length is a
/// corrupted LOCAL row, reported through the existing typed error rather than
/// a new class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HealCount(pub(super) u64);

impl RawValue for HealCount {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.to_be_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let bytes: [u8; 8] = bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex("code-run model heal count row"))?;
        Ok(Self(u64::from_be_bytes(bytes)))
    }
}

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
        let mut wtxn = self.store.env.write_txn()?;
        REPLAY_RECORDS.put(&self.store, &mut wtxn, &record.run_id, record)?;
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
        REPLAY_RECORDS.encode_value(record)?;
        let next_generation = record.generation()?;
        let mut wtxn = self.store.env.write_txn()?;
        let current = REPLAY_RECORDS.get(&self.store, &wtxn, &record.run_id)?;
        replay_generation_matches(current.as_ref(), expected)?;
        let next_heal_count = healed_model
            .map(|model| {
                let key = model.as_str().to_owned();
                let current = MODEL_HEAL_COUNTS
                    .get(&self.store, &wtxn, &key)?
                    .map_or(0, |count| count.0);
                let next = current
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow("code-run model heal count"))?;
                Ok::<_, Error>((key, next))
            })
            .transpose()?;
        REPLAY_RECORDS.put(&self.store, &mut wtxn, &record.run_id, record)?;
        if let Some((key, count)) = next_heal_count {
            MODEL_HEAL_COUNTS.put(&self.store, &mut wtxn, &key, &HealCount(count))?;
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
        REPLAY_RECORDS.get(&self.store, &rtxn, run_id)
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
        RAW_OUTPUTS.put(&self.store, &mut wtxn, &output.handle, &raw.to_vec())?;
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
        if taint_refs.is_empty() {
            RAW_OUTPUT_TAINTS.delete(&self.store, &mut wtxn, &output.handle)?;
        } else {
            RAW_OUTPUT_TAINTS.put(&self.store, &mut wtxn, &output.handle, &taint_refs.to_vec())?;
        }
        RAW_OUTPUTS.put(&self.store, &mut wtxn, &output.handle, &raw.to_vec())?;
        Ok(wtxn.commit()?)
    }

    /// The taint refs stored beside one raw output (empty when the sidecar
    /// row is absent — an untainted run).
    pub fn code_run_raw_output_taint_refs(
        &self,
        output: &CodeRunRawOutput,
    ) -> Result<Vec<SecretTaintRef>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(RAW_OUTPUT_TAINTS
            .get(&self.store, &rtxn, &output.handle)?
            .unwrap_or_default())
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
        let refs = RAW_OUTPUT_TAINTS
            .get(&self.store, &rtxn, &output.handle)?
            .unwrap_or_default();
        taint_state_for_refs_in_txn(&self.store, &rtxn, &refs)
    }

    /// Test-only direct tally increment. Production executor commits use the
    /// replay-and-heal transaction above so telemetry cannot lag persistence.
    #[cfg(test)]
    pub(in crate::code_run) fn increment_code_run_model_heal_count(
        &self,
        model: &ModelId,
    ) -> Result<CodeRunModelHealCount> {
        let key = model.as_str().to_owned();
        let mut wtxn = self.store.env.write_txn()?;
        let current = MODEL_HEAL_COUNTS
            .get(&self.store, &wtxn, &key)?
            .map_or(0, |count| count.0);
        let healed_turns = current
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("code-run model heal count"))?;
        MODEL_HEAL_COUNTS.put(&self.store, &mut wtxn, &key, &HealCount(healed_turns))?;
        wtxn.commit()?;
        Ok(CodeRunModelHealCount {
            model_id: key,
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
        let healed_turns = MODEL_HEAL_COUNTS
            .get(&self.store, &rtxn, &model.as_str().to_owned())?
            .map_or(0, |count| count.0);
        Ok(CodeRunModelHealCount {
            model_id: model.as_str().to_owned(),
            healed_turns,
        })
    }

    /// Loads raw output bytes for `output` and verifies they still match metadata.
    pub fn get_code_run_raw_output(&self, output: &CodeRunRawOutput) -> Result<Option<Vec<u8>>> {
        validate_raw_output(output)?;
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = RAW_OUTPUTS.get(&self.store, &rtxn, &output.handle)? else {
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

pub(super) fn replay_generation_matches(
    current: Option<&CodeRunReplayRecord>,
    expected: Option<CodeRunReplayGeneration>,
) -> Result<()> {
    let stored = current.map(CodeRunReplayRecord::generation).transpose()?;
    if stored == expected {
        return Ok(());
    }
    Err(Error::ConcurrentWrite(
        "code-run replay record changed; retry executor",
    ))
}

/// Advances the contribution owned by `target` and returns both its next
/// value and the additive overlay + base total.
pub(super) fn next_additive_heal_count(
    base: Option<HealCount>,
    overlay: Option<HealCount>,
    target: RouteTarget,
) -> Result<(HealCount, u64)> {
    let base = base.map_or(0, |count| count.0);
    let overlay = overlay.map_or(0, |count| count.0);
    let (base, overlay, next) = match target {
        RouteTarget::Discard => {
            return Err(Error::InvariantViolation(
                "anonymous routes cannot update heal tallies",
            ));
        }
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
    Ok((HealCount(next), total))
}
