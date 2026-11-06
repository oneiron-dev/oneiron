//! One code-run output body for a heal's recorded cause (FIX 7275): the
//! context-safe read of a raw output beside the executor's own doors.
//!
//! The caller holds the whole-set result-body pin and the gate-custody read
//! guard BEFORE the snapshot `rtxn` lives in opened, through the last body
//! and key use and file close: the pin keeps the collector off the bodies,
//! the guard keeps custody under the snapshot. The conditional file-plane pin
//! inside the lane's projected read does not stand for that explicit pin.
//! Every check below runs in that same snapshot; nothing here opens a newer
//! one, writes a mark, or widens an owner door.

use crate::claim::ScopedRead;
use crate::code_run::CodeRunRawOutput;
use crate::secret_rotation::taint_state_for_refs_in_txn;
use crate::{EntityId, Result, Vault};

impl Vault {
    /// The whole body of the canonical occurrence `requested` names in run
    /// `run`, as `lane` reads it in `rtxn` (FIX 7275): `Ok` with the bytes
    /// when every guard below passes, `Ok` with `None` when no row holds
    /// them, `Ok` with why not otherwise. Storage failures are the outer
    /// error; the inner `&'static str` is the body's own unavailability, in
    /// the heal's existing vocabulary.
    ///
    /// The canonical replay record is looked up in this snapshot, and
    /// `requested` must match one of its outputs exactly by path, handle,
    /// digest and length: the caller's manifest is never authority. That
    /// canonical output's complete source rows and the record's own served
    /// rows must both be recorded (`None` on either is `unprovable`, never
    /// an empty set), and `lane` must read every row of their union, in this
    /// snapshot, or the body is `withheld`. The lane's own admission already
    /// judges each row's device-local residence for where its rows go, so no
    /// second residence check is added here.
    ///
    /// An erase of the run's actor took the body first (`response_erased`);
    /// then the occurrence's secret mark or its live or stale taint withholds
    /// it as `source_withheld`, without naming the scan's reason. Only after
    /// membership, source, secret, taint and erase guards pass is the checked
    /// whole body read, in this same snapshot.
    pub(crate) fn code_run_context_body_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        lane: &ScopedRead<'_>,
        run: EntityId,
        requested: &CodeRunRawOutput,
    ) -> Result<std::result::Result<Option<Vec<u8>>, &'static str>> {
        let Some(record) = self.get_code_run_replay_record_in_txn(rtxn, &run)? else {
            return Ok(Err("missing"));
        };
        let Some(actual) = record.outputs.iter().find(|output| {
            output.path == requested.path
                && output.handle == requested.handle
                && output.raw_blake3 == requested.raw_blake3
                && output.raw_len == requested.raw_len
        }) else {
            return Ok(Err("missing"));
        };
        let Some(verb_rows) = record.agent_verb_rows() else {
            return Ok(Err("unprovable"));
        };
        let Some(input_rows) = &actual.input_rows else {
            return Ok(Err("unprovable"));
        };
        let mut sources = Vec::with_capacity(verb_rows.len() + input_rows.len());
        sources.extend(verb_rows);
        sources.extend(input_rows.iter().copied());
        if lane
            .entities_readable_in_txn(rtxn, &sources)?
            .contains(&false)
        {
            return Ok(Err("withheld"));
        }
        if self.result_erased_in_txn(rtxn, Some(run))? {
            return Ok(Err("response_erased"));
        }
        let (refs, secret) = self.result_marks_in_txn(rtxn, Some(run), actual)?;
        if secret.is_some() {
            return Ok(Err("source_withheld"));
        }
        if taint_state_for_refs_in_txn(&self.store, rtxn, &refs)?.is_tainted() {
            return Ok(Err("source_withheld"));
        }
        Ok(Ok(self.code_run_result_body_in_txn(rtxn, actual)?))
    }
}
