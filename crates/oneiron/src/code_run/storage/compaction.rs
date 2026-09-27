//! Node-local executor coverage: typed run/step binding to a committed epoch SUMMARY.
//! Raw outputs cannot write or impersonate this disjoint vault-meta keyspace.

use crate::code_run::{CodeRunReplayRecord, decode_code_run_replay_record};
use crate::compaction::EpochMint;
use crate::compaction::{CompactionRequest, EpochSummaryBody, decode_epoch_summary_body};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SUMMARY;
use crate::{EntityId, Error, Result, Vault};

const PREFIX: &[u8] = b"code_run:compaction:v1:";
const VERSION: u8 = 1;
const BODY_LEN: usize = 1 + 16 * 3 + 8 * 3;

/// A run-local span derived from the durable replay and the sealed compaction
/// request, not from model-supplied bytes or an assembled context-vector length.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExecutorOutputSpan {
    run_id: EntityId,
    session_ref: EntityId,
    first: u64,
    last: u64,
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
        if first > last
            || last >= completed
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
            #[cfg(test)]
            fail_after_write: false,
        })
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
}

impl CodeRunCompactionCoverage {
    pub(crate) fn covers(&self, run_id: EntityId, step: u64) -> bool {
        self.run_id == run_id && (self.first..=self.last).contains(&step)
    }

    #[cfg(test)]
    pub(crate) fn summary_id(&self) -> EntityId {
        self.summary_id
    }
    #[cfg(test)]
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
}

fn key(run_id: EntityId, summary_id: EntityId) -> Vec<u8> {
    [PREFIX, run_id.as_bytes(), summary_id.as_bytes()].concat()
}

fn prefix(run_id: EntityId) -> Vec<u8> {
    [PREFIX, run_id.as_bytes()].concat()
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
    };
    if row.epoch == 0 || row.first > row.last {
        return Err(corrupt());
    }
    Ok(row)
}

fn verify_summary(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &CodeRunCompactionCoverage,
) -> Result<()> {
    let corrupt = || Error::CorruptedIndex("code-run compaction summary binding");
    let summary = vault
        .store
        .port_entity_record(txn, &row.summary_id)?
        .ok_or_else(corrupt)?;
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
    Ok(())
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
        let replay_raw = self
            .store
            .vault_meta
            .get(
                txn,
                &super::records::code_run_replay_record_key(&span.run_id),
            )?
            .ok_or(Error::CorruptedIndex("missing executor replay record"))?;
        let replay = decode_code_run_replay_record(&replay_raw)?;
        let completed = u64::try_from(replay.step_checkpoints.len())
            .map_err(|_| Error::ArithmeticOverflow("executor step count"))?;
        if replay.run_id != span.run_id || span.last >= completed {
            return Err(Error::InvariantViolation(
                "executor coverage exceeds durable replay",
            ));
        }
        let row = CodeRunCompactionCoverage {
            run_id: span.run_id,
            session_ref: span.session_ref,
            summary_id: mint.summary_id(),
            epoch: mint.epoch(),
            first: span.first,
            last: span.last,
        };
        verify_summary(self, &*txn, &row)?;
        let key = key(row.run_id, row.summary_id);
        if self.store.vault_meta.get(txn, &key)?.is_some() {
            return Err(Error::InvariantViolation(
                "duplicate executor compaction coverage",
            ));
        }
        self.store.vault_meta.put(txn, &key, &encode(&row))?;
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
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for item in self.store.vault_meta.prefix_iter(&txn, &prefix(run_id))? {
            let (stored_key, raw) = item?;
            let row = decode(&raw)?;
            if stored_key != key(row.run_id, row.summary_id) || row.run_id != run_id {
                return Err(Error::CorruptedIndex("code-run compaction coverage key"));
            }
            verify_summary(self, &txn, &row)?;
            rows.push(row);
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests;
