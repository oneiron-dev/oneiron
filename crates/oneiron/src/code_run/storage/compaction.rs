//! Node-local executor coverage: typed run/step binding to a committed epoch SUMMARY.
//! Raw outputs cannot write or impersonate this disjoint vault-meta keyspace.

use crate::code_run::CodeRunReplayRecord;
use crate::compaction::EpochMint;
use crate::compaction::{CompactionRequest, EpochSummaryBody, decode_epoch_summary_body};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SUMMARY;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// One coverage row per (run id, minted SUMMARY id), in the fixed frame
/// [`encode`] spells.
const COVERAGE: SideTable<(EntityId, EntityId), CodeRunCompactionCoverage, Raw> =
    SideTable::new(&side_table::CODE_RUN_COMPACTION);
/// Version 2 adds the accepted body's digest; version 3 the calls its
/// sources were read from. No vault holds an older row.
const VERSION: u8 = 3;
const BODY_LEN: usize = 1 + 16 * 3 + 8 * 4 + 32;

/// A run-local span derived from the durable replay and the sealed compaction
/// request, not from model-supplied bytes or an assembled context-vector length.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExecutorOutputSpan {
    run_id: EntityId,
    session_ref: EntityId,
    first: u64,
    last: u64,
    calls: u64,
    #[cfg(test)]
    fail_after_write: bool,
}

impl ExecutorOutputSpan {
    pub(crate) fn from_replay(
        record: &CodeRunReplayRecord,
        request: &CompactionRequest,
    ) -> Result<Self> {
        let first = request.turn_start;
        let last = request
            .window
            .last()
            .ok_or(Error::InvariantViolation(
                "compaction window carries no messages",
            ))?
            .turn;
        let completed = u64::try_from(record.step_checkpoints.len())
            .map_err(|_| Error::ArithmeticOverflow("executor step count"))?;
        let calls = request.host_calls().ok_or(Error::InvariantViolation(
            "executor compaction request is cut from no host log",
        ))?;
        let made = u64::try_from(record.bridge_calls.len())
            .map_err(|_| Error::ArithmeticOverflow("executor call count"))?;
        if first > last
            || last >= completed
            || calls > made
            || request.window.first().is_none_or(|row| row.turn != first)
        {
            return Err(Error::InvalidConfig(
                "executor compaction span exceeds committed observations".into(),
            ));
        }
        Ok(Self {
            run_id: record.run_id,
            session_ref: request.session_ref,
            first,
            last,
            calls,
            #[cfg(test)]
            fail_after_write: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn wrong_range_for_test(mut self) -> Self {
        self.last = self.last.saturating_add(1);
        self
    }

    #[cfg(test)]
    pub(crate) fn fail_after_write_for_test(mut self) -> Self {
        self.fail_after_write = true;
        self
    }
}

/// Strictly decoded coverage. Only the SUMMARY mint transaction can construct
/// a persisted row; no public constructor or raw-output handle is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CodeRunCompactionCoverage {
    run_id: EntityId,
    session_ref: EntityId,
    summary_id: EntityId,
    epoch: u64,
    first: u64,
    last: u64,
    /// How many of the run's calls the summary's sources were read from: the
    /// ids those calls served are its sources, directly or through the epoch
    /// before it, so the next epoch lets this one stand for them.
    calls: u64,
    /// BLAKE3 of the SUMMARY body the gate accepted: a generic write that
    /// replaces it later never renders as the run's summary.
    digest: [u8; 32],
}

impl CodeRunCompactionCoverage {
    pub(crate) fn covers(&self, run_id: EntityId, step: u64) -> bool {
        self.run_id == run_id && (self.first..=self.last).contains(&step)
    }

    pub(crate) fn summary_id(&self) -> EntityId {
        self.summary_id
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
    pub(crate) fn first(&self) -> u64 {
        self.first
    }
    pub(crate) fn last(&self) -> u64 {
        self.last
    }
    pub(crate) fn calls(&self) -> u64 {
        self.calls
    }
}

impl RawValue for CodeRunCompactionCoverage {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode(self))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode(bytes)?)
    }
}

fn encode(row: &CodeRunCompactionCoverage) -> Vec<u8> {
    let mut raw = Vec::with_capacity(BODY_LEN);
    raw.push(VERSION);
    raw.extend_from_slice(row.run_id.as_bytes());
    raw.extend_from_slice(row.session_ref.as_bytes());
    raw.extend_from_slice(row.summary_id.as_bytes());
    raw.extend_from_slice(&row.epoch.to_be_bytes());
    raw.extend_from_slice(&row.first.to_be_bytes());
    raw.extend_from_slice(&row.last.to_be_bytes());
    raw.extend_from_slice(&row.calls.to_be_bytes());
    raw.extend_from_slice(&row.digest);
    raw
}

fn decode(raw: &[u8]) -> Result<CodeRunCompactionCoverage> {
    let corrupt = || Error::CorruptedIndex("code-run compaction coverage");
    if raw.len() != BODY_LEN || raw[0] != VERSION {
        return Err(corrupt());
    }
    let id = |start| {
        let bytes: [u8; 16] = raw[start..start + 16].try_into().map_err(|_| corrupt())?;
        EntityId::from_bytes(bytes).map_err(|_| corrupt())
    };
    let number = |start| {
        let bytes: [u8; 8] = raw[start..start + 8].try_into().map_err(|_| corrupt())?;
        Ok::<_, Error>(u64::from_be_bytes(bytes))
    };
    let row = CodeRunCompactionCoverage {
        run_id: id(1)?,
        session_ref: id(17)?,
        summary_id: id(33)?,
        epoch: number(49)?,
        first: number(57)?,
        last: number(65)?,
        calls: number(73)?,
        digest: raw[81..].try_into().map_err(|_| corrupt())?,
    };
    if row.epoch == 0 || row.first > row.last {
        return Err(corrupt());
    }
    Ok(row)
}

/// The bound SUMMARY's prose, or `None` once it is withdrawn: erased, stale
/// because a record it was written from was erased, or replaced by a write
/// the gate never judged. A withdrawn summary leaves its steps covered (as
/// references) and renders no words.
fn verify_summary(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &CodeRunCompactionCoverage,
) -> Result<Option<String>> {
    let corrupt = || Error::CorruptedIndex("code-run compaction summary binding");
    let Some(summary) = vault.store.port_entity_record(txn, &row.summary_id)? else {
        return Ok(None);
    };
    let state =
        crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, txn, &row.summary_id)?;
    if state.deleted || state.stale || summary.body.is_empty() {
        return Ok(None);
    }
    if *blake3::hash(&summary.body).as_bytes() != row.digest {
        return Ok(None);
    }
    if summary.entity_type != ENTITY_TYPE_SUMMARY {
        return Err(corrupt());
    }
    let body: EpochSummaryBody = decode_epoch_summary_body(&summary.body).map_err(|_| corrupt())?;
    if EntityId::from_hex(&body.session).map_err(|_| corrupt())? != row.session_ref
        || body.epoch != row.epoch
        || body.turn_start != row.first
        || body.turn_end != row.last
    {
        return Err(corrupt());
    }
    Ok(Some(body.text))
}

impl Vault {
    /// Called only by the epoch mint's transaction, after its actual SUMMARY
    /// row has been put. A post-write refusal rolls back both rows.
    pub(crate) fn put_code_run_compaction_coverage_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        span: &ExecutorOutputSpan,
        mint: &EpochMint,
    ) -> Result<()> {
        if span.session_ref != mint.session_ref()
            || span.first != mint.turn_start()
            || span.last != mint.turn_end()
        {
            return Err(Error::InvariantViolation(
                "executor coverage differs from minted summary",
            ));
        }
        let replay = super::records::REPLAY_RECORDS
            .get(&self.store, txn, &span.run_id)?
            .ok_or(Error::CorruptedIndex("missing executor replay record"))?;
        let completed = u64::try_from(replay.step_checkpoints.len())
            .map_err(|_| Error::ArithmeticOverflow("executor step count"))?;
        if replay.run_id != span.run_id || span.last >= completed {
            return Err(Error::InvariantViolation(
                "executor coverage exceeds durable replay",
            ));
        }
        let minted = self
            .store
            .port_entity_record(&*txn, &mint.summary_id())?
            .ok_or(Error::InvariantViolation(
                "executor coverage names no live summary",
            ))?;
        let row = CodeRunCompactionCoverage {
            run_id: span.run_id,
            session_ref: span.session_ref,
            summary_id: mint.summary_id(),
            epoch: mint.epoch(),
            first: span.first,
            last: span.last,
            calls: span.calls,
            digest: *blake3::hash(&minted.body).as_bytes(),
        };
        verify_summary(self, &*txn, &row)?.ok_or(Error::InvariantViolation(
            "executor coverage names no live summary",
        ))?;
        // The mint took its epoch and boundary from the run's rows; they
        // must still be the run's last ones in this transaction.
        let mut last = None;
        for item in COVERAGE.iter_from(&self.store, &*txn, span.run_id.as_bytes())? {
            let (_, prior) = item?;
            last = last.max(Some((prior.epoch, prior.last, prior.calls)));
        }
        let continues = match last {
            None => row.epoch == 1,
            Some((epoch, end, calls)) => {
                epoch.checked_add(1) == Some(row.epoch)
                    && end.checked_add(1) == Some(row.first)
                    && calls <= row.calls
            }
        };
        if !continues {
            return Err(Error::InvariantViolation(
                "executor coverage does not continue the run's last epoch",
            ));
        }
        let key = (row.run_id, row.summary_id);
        if COVERAGE.contains(&self.store, txn, &key)? {
            return Err(Error::InvariantViolation(
                "duplicate executor compaction coverage",
            ));
        }
        COVERAGE.put(&self.store, txn, &key, &row)?;
        #[cfg(test)]
        if span.fail_after_write {
            return Err(Error::InvariantViolation(
                "injected executor coverage write failure",
            ));
        }
        Ok(())
    }

    /// Read-time verification never trusts the coverage bytes alone: the
    /// keyed run/summary and the durable minted SUMMARY must all agree.
    pub(crate) fn code_run_compaction_coverage(
        &self,
        run_id: EntityId,
    ) -> Result<Vec<CodeRunCompactionCoverage>> {
        Ok(self
            .code_run_compaction_epochs(run_id)?
            .into_iter()
            .map(|(row, _)| row)
            .collect())
    }

    /// Every coverage row of `run_id` with its summary's prose, `None` when
    /// the summary is withdrawn.
    pub(crate) fn code_run_compaction_epochs(
        &self,
        run_id: EntityId,
    ) -> Result<Vec<(CodeRunCompactionCoverage, Option<String>)>> {
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for item in COVERAGE.iter_from(&self.store, &txn, run_id.as_bytes())? {
            let ((key_run, key_summary), row) = item?;
            if (key_run, key_summary) != (row.run_id, row.summary_id) || row.run_id != run_id {
                return Err(Error::CorruptedIndex("code-run compaction coverage key"));
            }
            let text = verify_summary(self, &txn, &row)?;
            rows.push((row, text));
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests;
