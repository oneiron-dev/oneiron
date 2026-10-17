//! The code-run vault_meta row families: replay records, raw output, taint refs and heal counts.

use crate::limit_ask::{EngineLimit, LimitWatch};
use crate::secret_lease::SecretTaintRef;
use crate::secret_rotation::{
    ArtifactTaintState, taint_state_for_refs_in_txn, validate_taint_refs,
};
use crate::session_overlay::RouteTarget;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::{BodyDir, BodySink, SunkBody, read_body_range};
use crate::{EntityId, Error, ModelId, Result, Vault};

use super::super::codec::validate_raw_output;
use super::super::replay::{
    CodeRunRawOutput, CodeRunReplayGeneration, CodeRunReplayRecord, ResultOccurrence,
};
use super::super::support::invalid_code_run_replay;

/// The replay record of one run, keyed by run id.
pub(super) const REPLAY_RECORDS: SideTable<EntityId, CodeRunReplayRecord, Raw> =
    SideTable::new(&side_table::CODE_RUN_REPLAY);

/// One result body, keyed by its deterministic content handle: inline, or the
/// file beside `data.mdb` that holds it (OF-597).
pub(super) const RAW_OUTPUTS: SideTable<String, StoredBody, Raw> =
    SideTable::new(&side_table::CODE_RUN_RAW_OUTPUT);

const STORED_INLINE: u8 = 0;
const STORED_FILE: u8 = 1;

/// Where one body's bytes are: in its row, within `[limits]
/// code_result_inline_bytes`, or in the body file named by its digest, of
/// `len` bytes. The row is written only once the file is whole on disk, so a
/// row naming a file never names a partial one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoredBody {
    Inline(Vec<u8>),
    File { len: u64 },
}

impl RawValue for StoredBody {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(match self {
            Self::Inline(bytes) => {
                let mut raw = Vec::with_capacity(bytes.len() + 1);
                raw.push(STORED_INLINE);
                raw.extend_from_slice(bytes);
                raw
            }
            Self::File { len } => {
                let mut raw = vec![STORED_FILE];
                raw.extend_from_slice(&len.to_be_bytes());
                raw
            }
        })
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        match bytes.split_first() {
            Some((&STORED_INLINE, body)) => Ok(Self::Inline(body.to_vec())),
            Some((&STORED_FILE, len)) => Ok(Self::File {
                len: u64::from_be_bytes(
                    len.try_into()
                        .map_err(|_| Error::CorruptedIndex("code-run raw output row"))?,
                ),
            }),
            _ => Err(Error::CorruptedIndex("code-run raw output row").into()),
        }
    }
}

/// SECRET-04 (ONE-1922): the FORWARD taint sidecar of one result
/// occurrence (Docs Q08), keyed by [`ResultOccurrence::mark_key`]: the
/// occurrence under its body's handle. Written in the SAME transaction as
/// the body row, and absent for the overwhelmingly common untainted run.
/// Another occurrence of the same bytes neither reads nor clears it.
pub(super) const RAW_OUTPUT_TAINTS: SideTable<String, Vec<SecretTaintRef>, Raw> =
    SideTable::new(&side_table::CODE_RUN_RAW_OUTPUT_TAINT);

/// The secret scan's hit in one result occurrence's body, keyed as its
/// taint sidecar is and written before or with its row: a secret no custody
/// record holds, so no taint ref can name it. Absent for a body the scan
/// found nothing in.
pub(super) const RAW_OUTPUT_SECRETS: SideTable<String, String, Raw> =
    SideTable::new(&side_table::CODE_RUN_RAW_OUTPUT_SECRET);

/// A proposal to lift a secret the scan found in a run result into the
/// vault. It holds no part of the secret: the body's handle, the occurrence
/// the scan marked, the detector's reason and a suggested custody name
/// drawn from the handle alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRunSecretLiftProposal {
    pub handle: String,
    pub occurrence: ResultOccurrence,
    pub detector_reason: String,
    pub suggested_secret_name: String,
}

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
        REPLAY_RECORDS.put(self, &mut wtxn, &record.run_id, record)?;
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
        let record = record.over_held(current.as_ref());
        REPLAY_RECORDS.put(self, &mut wtxn, &record.run_id, &record)?;
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

    /// A writer for one result body, into this vault's `bodies/`.
    pub(crate) fn code_run_output_sink(&self) -> Result<BodySink> {
        Ok(BodySink::new(
            self.store.body_dir()?,
            self.limit_watch().bound(EngineLimit::CodeResultInlineBytes),
        ))
    }

    /// Publishes the body `sink` wrote as the output at `path`: a spilled
    /// body's file is whole on disk before the row naming it commits. With an
    /// `owner` (the run whose record names it), the same transaction
    /// registers the body as that owner's occurrence, so erasing the owner
    /// releases it.
    pub(crate) fn publish_code_run_output(
        &self,
        path: String,
        sink: BodySink,
        complete: bool,
        owner: Option<EntityId>,
    ) -> Result<CodeRunRawOutput> {
        let finished = finish_output(path, sink, complete, self.limit_watch())?;
        let mut wtxn = self.store.env.write_txn()?;
        self.put_code_run_output_in_txn(&mut wtxn, &finished, &finished.output, owner)?;
        wtxn.commit()?;
        Ok(finished.output)
    }

    /// Writes the row of the body `finished` holds, the secret mark of
    /// `owner`'s occurrence of it, and, with an `owner`, `occurrence` as that
    /// owner's: the manifest of the same bytes at the owner's path.
    pub(crate) fn put_code_run_output_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        finished: &FinishedOutput,
        occurrence: &CodeRunRawOutput,
        owner: Option<EntityId>,
    ) -> Result<()> {
        self.put_code_run_output_row_in_txn(
            wtxn,
            finished,
            occurrence,
            ResultOccurrence::of(owner, occurrence)?,
        )?;
        if let Some(owner) = owner {
            crate::provenance::body::publish_body_in_txn(
                &self.store,
                wtxn,
                &owned_body(owner, occurrence, &finished.body)?,
            )?;
        }
        Ok(())
    }

    /// Writes the row of the body `finished` holds and, when the secret scan
    /// hit it, the mark of `at`, the occurrence `output` is.
    fn put_code_run_output_row_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        finished: &FinishedOutput,
        output: &CodeRunRawOutput,
        at: ResultOccurrence,
    ) -> Result<()> {
        if output.handle != finished.output.handle {
            return Err(Error::InvariantViolation(
                "code-run output occurrence names other bytes",
            ));
        }
        RAW_OUTPUTS.put(&self.store, wtxn, &output.handle, &finished.body)?;
        if let Some(reason) = finished.secret {
            self.mark_code_run_output_secret_in_txn(wtxn, output, at, reason)?;
        }
        Ok(())
    }

    /// Writes `bytes` as a complete body at `path`: a file, past the inline
    /// bound, is whole on disk when this returns, and no row names it yet.
    pub(crate) fn stage_code_run_output(
        &self,
        path: String,
        bytes: &[u8],
    ) -> Result<FinishedOutput> {
        let mut sink = self.code_run_output_sink()?;
        sink.write(bytes)?;
        finish_output(path, sink, true, self.limit_watch())
    }

    /// Stores a complete body held whole under its content handle; `output`
    /// must be its manifest, and `owner` the run that holds it, if one does.
    pub fn put_code_run_raw_output(
        &self,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
        raw: &[u8],
    ) -> Result<()> {
        self.put_code_run_raw_output_tainted(owner, output, raw, &[])
    }

    /// Stores a complete body ALONGSIDE the taint refs of the action that
    /// produced them (SECRET-04, ONE-1922), on the occurrence `owner` holds
    /// (or the bytes' own, with none). No body descriptor is published.
    ///
    /// One write transaction carries the sidecar and the body row, so
    /// tainted exhaust can never survive a half-failed write wearing no
    /// mark. An empty ref list is exactly the untainted put (the sidecar is
    /// cleared, not written empty); it clears this occurrence's sidecar only,
    /// never another's of the same bytes.
    pub fn put_code_run_raw_output_tainted(
        &self,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
        raw: &[u8],
        taint_refs: &[SecretTaintRef],
    ) -> Result<()> {
        validate_taint_refs(taint_refs)?;
        let at = ResultOccurrence::of(owner, output)?;
        let mut sink = self.code_run_output_sink()?;
        sink.write(raw)?;
        let finished = finish_output(output.path.clone(), sink, true, self.limit_watch())?;
        if finished.output != *output {
            return Err(invalid_code_run_replay(
                "raw output metadata does not match bytes",
            ));
        }
        let key = at.mark_key(&output.handle);
        let mut wtxn = self.store.env.write_txn()?;
        if taint_refs.is_empty() {
            RAW_OUTPUT_TAINTS.delete(&self.store, &mut wtxn, &key)?;
        } else {
            RAW_OUTPUT_TAINTS.put(&self.store, &mut wtxn, &key, &taint_refs.to_vec())?;
        }
        self.put_code_run_output_row_in_txn(&mut wtxn, &finished, output, at)?;
        Ok(wtxn.commit()?)
    }

    /// The taint refs and secret-scan reason of the occurrence of `output`
    /// that `owner` holds. With no owner the read names the bytes alone,
    /// which hold no authority of their own, so it carries the marks of
    /// every occurrence of them.
    fn result_marks_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
    ) -> Result<(Vec<SecretTaintRef>, Option<String>)> {
        if owner.is_some() {
            let key = ResultOccurrence::of(owner, output)?.mark_key(&output.handle);
            return Ok((
                RAW_OUTPUT_TAINTS
                    .get(&self.store, rtxn, &key)?
                    .unwrap_or_default(),
                RAW_OUTPUT_SECRETS.get(&self.store, rtxn, &key)?,
            ));
        }
        let prefix = ResultOccurrence::marks_prefix(&output.handle);
        let refs = RAW_OUTPUT_TAINTS
            .scan_from(&self.store, rtxn, prefix.as_bytes())?
            .into_iter()
            .flat_map(|(_, refs)| refs)
            .collect();
        let secret = RAW_OUTPUT_SECRETS
            .scan_from(&self.store, rtxn, prefix.as_bytes())?
            .into_iter()
            .next()
            .map(|(_, reason)| reason);
        Ok((refs, secret))
    }

    /// The taint refs stored beside the occurrence of one raw output that
    /// `owner` holds (empty when the sidecar row is absent — an untainted
    /// run).
    pub fn code_run_raw_output_taint_refs(
        &self,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
    ) -> Result<Vec<SecretTaintRef>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(self.result_marks_in_txn(&rtxn, owner, output)?.0)
    }

    /// The READ-TIME taint state of one raw output (ARCH-0069 S7, amended).
    ///
    /// Derived on every call from the sidecar refs and the custody records'
    /// CURRENT generations: `Clean` when the sidecar is absent,
    /// `TaintedLive` while every named record still sits at the generation
    /// the output was produced under, `TaintedStale` the moment one rotates
    /// or is revoked. No row is rewritten at rotation time to make that
    /// true.
    ///
    /// A body the secret scan marked is `TaintedLive` for good: no custody
    /// record holds what it found, so nothing can rotate it away.
    ///
    /// The state is that of the occurrence `owner` holds (Docs Q08); with no
    /// owner, of every occurrence of the bytes.
    pub fn code_run_raw_output_taint_state(
        &self,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
    ) -> Result<ArtifactTaintState> {
        let rtxn = self.store.env.read_txn()?;
        let (refs, secret) = self.result_marks_in_txn(&rtxn, owner, output)?;
        if secret.is_some() {
            return Ok(ArtifactTaintState::TaintedLive);
        }
        taint_state_for_refs_in_txn(&self.store, &rtxn, &refs)
    }

    /// The reason the secret scan marked the occurrence of `output` that
    /// `owner` holds with, if it did.
    pub fn code_run_raw_output_secret(
        &self,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
    ) -> Result<Option<String>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(self.result_marks_in_txn(&rtxn, owner, output)?.1)
    }

    /// Every run's result manifests in the base vault, from its replay
    /// record: an off-record run's records live in its room, never here.
    pub(crate) fn code_run_result_manifests_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<Vec<(EntityId, Vec<CodeRunRawOutput>)>> {
        Ok(REPLAY_RECORDS
            .scan(&self.store, rtxn)?
            .into_iter()
            .map(|(run_id, record)| (run_id, record.outputs))
            .collect())
    }

    /// Why the occurrence of `output` that `owner` holds is withheld from a
    /// view leaving the vault: the secret scan marked it, or it carries
    /// taint refs, live or stale alike. Another occurrence of the same
    /// bytes neither withholds nor clears it.
    pub(crate) fn code_run_result_withheld_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
    ) -> Result<Option<&'static str>> {
        let (refs, secret) = self.result_marks_in_txn(rtxn, owner, output)?;
        if secret.is_some() {
            return Ok(Some("secret_scan"));
        }
        if !refs.is_empty() {
            return Ok(Some("tainted"));
        }
        Ok(None)
    }

    /// The whole body of `output` under `rtxn`, checked against its digest;
    /// `None` when no row holds it.
    pub(crate) fn code_run_result_body_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        output: &CodeRunRawOutput,
    ) -> Result<Option<Vec<u8>>> {
        RAW_OUTPUTS
            .get(&self.store, rtxn, &output.handle)?
            .map(|body| load_whole_body(output, body, || Ok(vec![self.store.body_dir()?])))
            .transpose()
    }

    /// The value-free proposals to lift what the secret scan found in run
    /// results into the vault (ARCH-0069 S5), one per marked occurrence, for
    /// the owner to take or dismiss. Each names the body by its handle and
    /// the occurrence the scan marked only.
    pub fn code_run_secret_lift_proposals(&self) -> Result<Vec<CodeRunSecretLiftProposal>> {
        let rtxn = self.store.env.read_txn()?;
        RAW_OUTPUT_SECRETS
            .scan(&self.store, &rtxn)?
            .into_iter()
            .map(|(key, detector_reason)| lift_proposal(&key, detector_reason))
            .collect()
    }

    /// Marks `at`, the occurrence `output` is, with the secret scan's
    /// `reason`, which files its lift proposal. The body stays whole: the
    /// mark redacts this occurrence's views and nulls it in an export.
    fn mark_code_run_output_secret_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        output: &CodeRunRawOutput,
        at: ResultOccurrence,
        reason: &str,
    ) -> Result<()> {
        RAW_OUTPUT_SECRETS.put(
            &self.store,
            wtxn,
            &at.mark_key(&output.handle),
            &reason.to_owned(),
        )
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

    /// Loads the whole body of `output`, checked against its digest. For
    /// small bodies and explicit whole reads; context reads take ranges.
    pub fn get_code_run_raw_output(&self, output: &CodeRunRawOutput) -> Result<Option<Vec<u8>>> {
        validate_raw_output(output)?;
        let _pin = self.pin_result_body(output.raw_blake3);
        let body = {
            let rtxn = self.store.env.read_txn()?;
            RAW_OUTPUTS.get(&self.store, &rtxn, &output.handle)?
        };
        body.map(|body| load_whole_body(output, body, || Ok(vec![self.store.body_dir()?])))
            .transpose()
    }

    /// The whole body a context reference names, by its digest and length,
    /// checked against both.
    pub(crate) fn get_raw_body(
        &self,
        source: crate::compaction::output::OutputRef,
    ) -> Result<Option<Vec<u8>>> {
        let output = CodeRunRawOutput::of_ref(source);
        let _pin = self.pin_result_body(source.hash);
        let body = {
            let rtxn = self.store.env.read_txn()?;
            RAW_OUTPUTS.get(&self.store, &rtxn, &output.handle)?
        };
        body.map(|body| load_whole_body(&output, body, || Ok(vec![self.store.body_dir()?])))
            .transpose()
    }

    /// `len` bytes of `output`'s body from `offset`, cut at its end: an
    /// inline body is read in place, a file by range. Nothing else of the
    /// body is read.
    pub(crate) fn read_code_run_raw_output_range(
        &self,
        output: &CodeRunRawOutput,
        offset: u64,
        len: usize,
    ) -> Result<Option<Vec<u8>>> {
        validate_raw_output(output)?;
        let _pin = self.pin_result_body(output.raw_blake3);
        let rtxn = self.store.env.read_txn()?;
        let Some(row) = RAW_OUTPUTS.get_borrowed(&self.store, &rtxn, &output.handle)? else {
            return Ok(None);
        };
        read_body_row_range(output, &row, offset, len, || {
            Ok(vec![self.store.body_dir()?])
        })
        .map(Some)
    }
}

/// A finished body: its manifest, its row and the secret scan's hit. A
/// spilled body's file is already whole on disk.
pub(crate) struct FinishedOutput {
    pub(crate) output: CodeRunRawOutput,
    pub(super) body: StoredBody,
    pub(super) secret: Option<&'static str>,
}

impl FinishedOutput {
    /// The manifest of these bytes at `path`, as one owner's occurrence.
    pub(crate) fn at(&self, path: String, complete: bool) -> Result<CodeRunRawOutput> {
        let output = CodeRunRawOutput {
            path,
            complete,
            ..self.output.clone()
        };
        validate_raw_output(&output)?;
        Ok(output)
    }
}

/// Finishes `sink` into the output's manifest, its row and the secret
/// scan's hit. A body that took the disk below `[limits]
/// code_result_disk_floor_bytes` asks that row's question; it is stored
/// whole all the same, as a body the scan marked is.
pub(super) fn finish_output(
    path: String,
    sink: BodySink,
    complete: bool,
    watch: &LimitWatch,
) -> Result<FinishedOutput> {
    let (facts, sunk) = sink.finish(crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS)?;
    let output = CodeRunRawOutput::from_facts(path, &facts, complete)?;
    let body = match sunk {
        SunkBody::Inline(bytes) => StoredBody::Inline(bytes),
        SunkBody::File { free_bytes } => {
            if let Some(free_bytes) = free_bytes {
                watch.floor(EngineLimit::CodeResultDiskFloorBytes, free_bytes);
            }
            StoredBody::File { len: facts.len }
        }
    };
    Ok(FinishedOutput {
        output,
        body,
        secret: facts.secret,
    })
}

/// The lift proposal of the secret mark at `key`.
fn lift_proposal(key: &str, detector_reason: String) -> Result<CodeRunSecretLiftProposal> {
    let (handle, occurrence) = ResultOccurrence::parse_mark_key(key)?;
    Ok(CodeRunSecretLiftProposal {
        suggested_secret_name: format!(
            "code_run.{}",
            handle
                .strip_prefix(super::super::support::CODE_RUN_OUTPUT_HANDLE_PREFIX)
                .unwrap_or(handle)
                .get(..16)
                .unwrap_or_default()
        ),
        handle: handle.to_owned(),
        occurrence,
        detector_reason,
    })
}

/// `output` as an occurrence `owner` holds: one per owner and path.
fn owned_body(
    owner: EntityId,
    output: &CodeRunRawOutput,
    body: &StoredBody,
) -> Result<crate::provenance::body::OwnedBody> {
    use crate::provenance::body::{BodyLocation, BodyRef, BodyState, OwnedBody};
    let body = BodyRef {
        blake3: output.raw_blake3,
        bytes: output.raw_len,
        location: match body {
            StoredBody::Inline(_) => BodyLocation::Inline,
            StoredBody::File { .. } => BodyLocation::File,
        },
    };
    Ok(OwnedBody {
        owner,
        occurrence: ResultOccurrence::of(Some(owner), output)?.id(),
        state: if output.complete {
            BodyState::Complete { body }
        } else {
            BodyState::Incomplete {
                retained: Some(body),
            }
        },
    })
}

/// The body file of `output` in the first of `dirs` that holds it.
fn open_body_file(output: &CodeRunRawOutput, dirs: Vec<BodyDir>) -> Result<std::fs::File> {
    for dir in dirs {
        if let Some(file) = dir.open_body(&output.raw_blake3, output.raw_len)? {
            return Ok(file);
        }
    }
    Err(Error::CorruptedIndex("code-run result body file missing"))
}

/// The whole body of `output`, from its row or its file, checked against
/// its digest.
pub(super) fn load_whole_body(
    output: &CodeRunRawOutput,
    body: StoredBody,
    dirs: impl FnOnce() -> Result<Vec<BodyDir>>,
) -> Result<Vec<u8>> {
    let bytes = match body {
        StoredBody::Inline(bytes) => bytes,
        StoredBody::File { len } => {
            if len != output.raw_len {
                return Err(drifted());
            }
            let len = usize::try_from(len)
                .map_err(|_| Error::ArithmeticOverflow("code-run result body length"))?;
            read_body_range(&open_body_file(output, dirs()?)?, 0, len)?
        }
    };
    if u64::try_from(bytes.len()).ok() != Some(output.raw_len)
        || *blake3::hash(&bytes).as_bytes() != output.raw_blake3
    {
        return Err(drifted());
    }
    Ok(bytes)
}

/// A range of the body whose stored row is `row`, cut at the body's end.
pub(super) fn read_body_row_range(
    output: &CodeRunRawOutput,
    row: &[u8],
    offset: u64,
    len: usize,
    dirs: impl FnOnce() -> Result<Vec<BodyDir>>,
) -> Result<Vec<u8>> {
    if offset > output.raw_len {
        return Err(Error::InvalidConfig(
            "result read starts past the body's end".into(),
        ));
    }
    let end = offset.saturating_add(len as u64).min(output.raw_len);
    let take = usize::try_from(end - offset)
        .map_err(|_| Error::ArithmeticOverflow("code-run result range"))?;
    match row.split_first() {
        Some((&STORED_INLINE, body)) => {
            if u64::try_from(body.len()).ok() != Some(output.raw_len) {
                return Err(drifted());
            }
            let start = usize::try_from(offset)
                .map_err(|_| Error::ArithmeticOverflow("code-run result range"))?;
            Ok(body[start..start + take].to_vec())
        }
        Some((&STORED_FILE, _)) => read_body_range(&open_body_file(output, dirs()?)?, offset, take),
        _ => Err(Error::CorruptedIndex("code-run raw output row")),
    }
}

/// The body file a raw `vault_meta` row names, as its digest and length:
/// `Some` only for a result body row stored as a file. A checkpoint reads
/// its rows raw, so this is how it finds the files beside them.
pub(crate) fn code_run_body_file_of_row(key: &[u8], value: &[u8]) -> Option<([u8; 32], u64)> {
    let handle = key.strip_prefix(RAW_OUTPUTS.decl().prefix)?;
    let hex =
        handle.strip_prefix(super::super::support::CODE_RUN_OUTPUT_HANDLE_PREFIX.as_bytes())?;
    let StoredBody::File { len } = StoredBody::from_raw(value).ok()? else {
        return None;
    };
    let mut digest = [0; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    (hex.len() == 64).then_some((digest, len))
}

fn drifted() -> Error {
    invalid_code_run_replay("stored raw output bytes drifted from metadata")
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
