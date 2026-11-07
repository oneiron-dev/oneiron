//! The code-run correction table (CODE-RUNTIME-02 slice 1: FIX 4411, 4412):
//! one row per model response the live REPL normalized, keyed by its run,
//! step and attempt, on the run's own route. A canonical run's rows are the
//! vault's. A session-bound run's rows land on the route it captured at
//! entry, as its replay row does: in its room's overlay while off record, in
//! base on record. None is copied to base, and none is read from base once
//! its stretch is gone.
//!
//! The writing transaction assigns the attempt: the step's next one after
//! the attempts its rows hold, so a rejected response and the re-entry that
//! asks again never share a key.
//!
//! A clean or normalized response's row commits with its step's checkpoint
//! and heal tally (`reader_folds`). A rejected response's row commits alone,
//! before the executor returns its error
//! ([`ExecutorStorage::put_rejected_code_run_correction`]).

use std::ops::Bound;

use super::super::correction::{
    CodeRunCorrection, CodeRunCorrectionCheckpoint, CodeRunCorrectionDraft,
};
use super::super::replay::CodeRunReplayRecord;
use super::routing::ExecutorStorage;
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::{EntityId, Error, Result, Vault};

/// One response's row. Key: (run, step, attempt).
type CorrectionKey = (EntityId, u64, u64);

const CORRECTIONS: SideTable<CorrectionKey, CodeRunCorrection, Named> =
    SideTable::new(&side_table::CODE_RUN_CORRECTION);

/// One page of a run's correction records, oldest first: every attempt of
/// each step the page holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodeRunCorrectionPage {
    pub(crate) records: Vec<CodeRunCorrection>,
    /// The last step of this page when a later step holds records: the
    /// `after_step` that reads the next page.
    pub(crate) next_after_step: Option<u64>,
}

/// Writes `draft` as its step's next attempt in `wtxn` on `dbs`, with the
/// checkpoint its step commits.
pub(super) fn put_correction_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    draft: &CodeRunCorrectionDraft<'_>,
    checkpoint: Option<CodeRunCorrectionCheckpoint>,
) -> Result<()> {
    let (run, step) = (draft.run_id(), draft.step());
    // The key bytes of (run, step): id16 + be64, as the key encodes them.
    let mut step_prefix = run.as_bytes().to_vec();
    step_prefix.extend_from_slice(&step.to_be_bytes());
    let attempt = match CORRECTIONS.scan_keys(dbs, &*wtxn, &step_prefix)?.last() {
        Some((_, _, last)) => last
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("code-run correction attempt"))?,
        None => 0,
    };
    let row = draft.record(attempt, checkpoint);
    CORRECTIONS.put(dbs, wtxn, &(run, step, attempt), &row)
}

/// The checkpoint `record` commits for `draft`'s step. A rejected response
/// commits no step.
pub(super) fn committed_checkpoint(
    record: &CodeRunReplayRecord,
    draft: &CodeRunCorrectionDraft<'_>,
) -> Result<CodeRunCorrectionCheckpoint> {
    if draft.is_rejected() {
        return Err(Error::InvariantViolation(
            "a rejected model response commits no step",
        ));
    }
    CodeRunCorrectionCheckpoint::committed(record, draft.step())
}

impl Vault {
    /// One page of `run`'s canonical correction records, oldest first: the
    /// records of up to `steps` steps after `after_step` (from step 0 when
    /// none), every attempt of each. A private session's rows are never
    /// read here.
    ///
    /// # Errors
    ///
    /// Storage errors, and a row that does not decode.
    pub(crate) fn code_run_corrections(
        &self,
        run: EntityId,
        after_step: Option<u64>,
        steps: u32,
    ) -> Result<CodeRunCorrectionPage> {
        let mut page = CodeRunCorrectionPage {
            records: Vec::new(),
            next_after_step: None,
        };
        let first = match after_step {
            None => 0,
            Some(step) => match step.checked_add(1) {
                Some(first) => first,
                None => return Ok(page),
            },
        };
        let rtxn = self.store.env.read_txn()?;
        let start = (run, first, 0);
        let end = (run, u64::MAX, u64::MAX);
        let rows = CORRECTIONS.iter_range(
            &self.store,
            &rtxn,
            Bound::Included(&start),
            Bound::Included(&end),
        )?;
        let mut held_steps = 0_u32;
        for row in rows {
            let ((_, step, _), record) = row?;
            let last_step = page.records.last().map(|last| last.step);
            if last_step != Some(step) {
                if held_steps == steps {
                    page.next_after_step = last_step;
                    break;
                }
                held_steps += 1;
            }
            page.records.push(record);
        }
        Ok(page)
    }
}

impl ExecutorStorage<'_> {
    /// Writes a rejected response's record on the run's route, in its own
    /// transaction (FIX 4412). No checkpoint, step count or heal tally
    /// moves.
    ///
    /// # Errors
    ///
    /// Storage errors, a stale route, a run no longer in its room, and a
    /// draft the normalization accepted, whose record commits with its step.
    pub(crate) fn put_rejected_code_run_correction(
        &self,
        draft: &CodeRunCorrectionDraft<'_>,
    ) -> Result<()> {
        if !draft.is_rejected() {
            return Err(Error::InvariantViolation(
                "an accepted model response records with its step's commit",
            ));
        }
        match self {
            Self::Canonical(vault) => {
                let mut wtxn = vault.store.env.write_txn()?;
                put_correction_in_txn(&vault.store, &mut wtxn, draft, None)?;
                Ok(wtxn.commit()?)
            }
            Self::Session(binding) => binding.answered(|| {
                binding
                    .session
                    .routed_side_txn(&binding.route, |wtxn, _, write| {
                        put_correction_in_txn(&write, wtxn, draft, None)
                    })
            }),
        }
    }
}
