//! The code-run vault_meta row families: replay records, raw output, taint refs and heal counts.

use std::borrow::Cow;

use crate::limit_ask::{EngineLimit, LimitWatch};
use crate::secret_lease::SecretTaintRef;
use crate::secret_rotation::{
    ArtifactTaintState, taint_state_for_refs_in_txn, validate_taint_refs,
};
use crate::session_overlay::RouteTarget;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::{
    BodyDir, BodyFile, BodyKeyRow, BodySink, StagedBodyKey, SunkBody, body_key_row_in_txn,
};
use crate::{EntityId, Error, ModelId, Result, Vault};

use super::super::codec::validate_raw_output;
use super::super::replay::{
    CodeRunRawOutput, CodeRunReplayGeneration, CodeRunReplayRecord, ResultOccurrence,
};
use super::super::support::invalid_code_run_replay;
use super::replay_bodies::RESPONSE_ERASED;
use super::response_erase::{fence_replay_in_txn, response_erased_in_txn};

mod admitted;
mod bodies;

pub(crate) use self::admitted::ReplyBody;
use self::bodies::owned_body;
pub(crate) use self::bodies::{
    FinishedOutput, StagedSinks, code_run_body_file_of_row, code_run_body_row_key,
    code_run_inline_body_of_row,
};
pub(super) use self::bodies::{
    body_drifted, finish_output, load_whole_body, open_body_file, read_body_row_range,
};

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
        let record = fence_replay_in_txn(self, &mut wtxn, Cow::Borrowed(record))?;
        REPLAY_RECORDS.put(self, &mut wtxn, &record.run_id, &record)?;
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
        self.put_code_run_replay_record_if_generation_with_heal_and(
            record,
            expected,
            healed_model,
            |_| Ok(()),
        )
    }

    /// [`Self::put_code_run_replay_record_if_generation_with_heal`], with
    /// `also`'s rows written in the same transaction after the record's: a
    /// turn program's verb write binds and settles its step here (DOOR-141).
    pub(crate) fn put_code_run_replay_record_if_generation_with_heal_and(
        &self,
        record: &CodeRunReplayRecord,
        expected: Option<CodeRunReplayGeneration>,
        healed_model: Option<&ModelId>,
        also: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
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
        // A record whose replies an erase took stays erased (FIX 5718).
        let record = fence_replay_in_txn(self, &mut wtxn, record)?;
        REPLAY_RECORDS.put(self, &mut wtxn, &record.run_id, &record)?;
        if let Some((key, count)) = next_heal_count {
            MODEL_HEAL_COUNTS.put(&self.store, &mut wtxn, &key, &HealCount(count))?;
        }
        also(&mut wtxn)?;
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

    /// [`Self::get_code_run_replay_record`] in the caller's snapshot.
    pub(crate) fn get_code_run_replay_record_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        run_id: &EntityId,
    ) -> Result<Option<CodeRunReplayRecord>> {
        REPLAY_RECORDS.get(&self.store, rtxn, run_id)
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
        if secret.is_some() || self.result_erased_in_txn(&rtxn, owner)? {
            return Ok(ArtifactTaintState::TaintedLive);
        }
        taint_state_for_refs_in_txn(&self.store, &rtxn, &refs)
    }

    /// The reason the secret scan marked the occurrence of `output` that
    /// `owner` holds with, if it did; `response_erased` once an erase of the
    /// run's actor took its replies (FIX 5718).
    pub fn code_run_raw_output_secret(
        &self,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
    ) -> Result<Option<String>> {
        let rtxn = self.store.env.read_txn()?;
        if self.result_erased_in_txn(&rtxn, owner)? {
            return Ok(Some(RESPONSE_ERASED.to_owned()));
        }
        Ok(self.result_marks_in_txn(&rtxn, owner, output)?.1)
    }

    /// Whether run `owner`'s results read as erased (FIX 5718): an erase of
    /// the run's actor took its replies, so every read of one is withheld
    /// as a marked body's is, naming `response_erased`, whoever else holds
    /// the same bytes. A result no run holds is read as its bytes are.
    fn result_erased_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        owner: Option<EntityId>,
    ) -> Result<bool> {
        match owner {
            Some(owner) => response_erased_in_txn(&self.store, rtxn, &owner),
            None => Ok(false),
        }
    }

    /// Marks the occurrence of `output` that `owner` holds with the taint of
    /// every occurrence in `from` (each by the run that holds it), in one
    /// transaction: their taint refs join its own, and the first secret mark
    /// among them stands as its own when it has none. A body made from a
    /// tainted one is tainted as long as it is.
    pub(crate) fn inherit_code_run_result_marks(
        &self,
        owner: EntityId,
        output: &CodeRunRawOutput,
        from: &[(EntityId, CodeRunRawOutput)],
    ) -> Result<()> {
        let key = ResultOccurrence::of(Some(owner), output)?.mark_key(&output.handle);
        let mut wtxn = self.store.env.write_txn()?;
        let mut refs = RAW_OUTPUT_TAINTS
            .get(&self.store, &wtxn, &key)?
            .unwrap_or_default();
        let mut secret = RAW_OUTPUT_SECRETS.get(&self.store, &wtxn, &key)?;
        let (own_refs, own_secret) = (refs.len(), secret.is_some());
        for (source, held) in from {
            let (more, marked) = self.result_marks_in_txn(&wtxn, Some(*source), held)?;
            for taint in more {
                if !refs.contains(&taint) {
                    refs.push(taint);
                }
            }
            secret = secret.or(marked);
        }
        if refs.len() > own_refs {
            validate_taint_refs(&refs)?;
            RAW_OUTPUT_TAINTS.put(&self.store, &mut wtxn, &key, &refs)?;
        }
        if !own_secret && let Some(reason) = &secret {
            RAW_OUTPUT_SECRETS.put(&self.store, &mut wtxn, &key, reason)?;
        }
        Ok(wtxn.commit()?)
    }

    /// MESSAGE `message`'s hold on the body `attachment` names, published in
    /// the caller's transaction (FIX 365): its own occurrence of the body,
    /// beside the producer's, carrying the producer's taint and secret marks
    /// and what reopens it once the producer's replay is gone. The MESSAGE
    /// keeps the body while it holds it; erasing the MESSAGE releases it.
    pub(crate) fn retain_message_result_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        message: EntityId,
        attachment: &crate::memory::MessageResultAttachment,
        served_rows: Option<Vec<EntityId>>,
    ) -> Result<()> {
        let output = attachment.output()?;
        let stored = RAW_OUTPUTS
            .get(&self.store, wtxn, &output.handle)?
            .ok_or(Error::CorruptedIndex("message result body"))?;
        let (refs, secret) =
            self.result_marks_in_txn(wtxn, Some(attachment.source.run_id), &output)?;
        let key = ResultOccurrence::of(Some(message), &output)?.mark_key(&output.handle);
        if !refs.is_empty() {
            RAW_OUTPUT_TAINTS.put(&self.store, wtxn, &key, &refs)?;
        }
        if let Some(reason) = &secret {
            RAW_OUTPUT_SECRETS.put(&self.store, wtxn, &key, reason)?;
        }
        let mut held = owned_body(message, &output, &stored)?;
        held.result = Some(crate::provenance::body::RetainedResultProvenance {
            run_id: attachment.source.run_id,
            occurrence: attachment.source.occurrence,
            path: attachment.source.path.clone(),
            served_rows,
        });
        crate::provenance::body::publish_body_in_txn(&self.store, wtxn, &held)
    }

    /// Run `child`'s hold on an output it inherits from `source`, the run it
    /// was forked from (FIX 3694), published in the caller's transaction: its
    /// own occurrence of the body at the same path, carrying the source
    /// occurrence's taint and secret marks, so a body withheld under the
    /// source stays withheld under the child. The child's replay row names
    /// the output, so the hold carries no retained-result provenance.
    pub(crate) fn retain_inherited_result_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        child: EntityId,
        source: EntityId,
        output: &CodeRunRawOutput,
    ) -> Result<()> {
        let stored = RAW_OUTPUTS
            .get(&self.store, wtxn, &output.handle)?
            .ok_or(Error::CorruptedIndex("inherited run result body"))?;
        let (refs, secret) = self.result_marks_in_txn(wtxn, Some(source), output)?;
        let key = ResultOccurrence::of(Some(child), output)?.mark_key(&output.handle);
        if !refs.is_empty() {
            RAW_OUTPUT_TAINTS.put(&self.store, wtxn, &key, &refs)?;
        }
        if let Some(reason) = &secret {
            RAW_OUTPUT_SECRETS.put(&self.store, wtxn, &key, reason)?;
        }
        crate::provenance::body::publish_body_in_txn(
            &self.store,
            wtxn,
            &owned_body(child, output, &stored)?,
        )
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
    /// view leaving the vault: an erase of the run's actor took it (FIX
    /// 5718), the secret scan marked it, or it carries taint refs, live or
    /// stale alike. Another occurrence of the same bytes neither withholds
    /// nor clears it.
    pub(crate) fn code_run_result_withheld_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
    ) -> Result<Option<&'static str>> {
        if self.result_erased_in_txn(rtxn, owner)? {
            return Ok(Some(RESPONSE_ERASED));
        }
        let (refs, secret) = self.result_marks_in_txn(rtxn, owner, output)?;
        if secret.is_some() {
            return Ok(Some("secret_scan"));
        }
        if !refs.is_empty() {
            return Ok(Some("tainted"));
        }
        Ok(None)
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
