//! The batch door with mask on write (OF-560): the door's scan, a plan on a
//! copy of the batch's ops, the custody records it mints, and the minted
//! pass that writes each handle into the ops themselves.

use heed::RwTxn;

use super::super::{SecretScanMode, scan_batch_ops, secret_scan_mode_in_txn};
use super::known_note;
use super::text_log::TextLog;
use super::wipe::PlanOps;
use super::{MaskedFiles, Masker, marked_files, op_record, put_file_marks_in_txn, scan_screened};
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::secret_custody::{CustodyWrite, KeptValues, KnownValues};
use crate::store::Store;
use crate::write_envelope::ClaimCandidate;

/// The batch door with mask on write. `masks` is false for a replayed batch,
/// which keeps the plain door: a hit refuses it, save in a file marked
/// before. `at` stamps each custody record the batch mints. It also returns
/// each MACHINE claim candidate the minted pass rewrote with its pre-mask
/// body, in op order, so the candidate apply can renew its proof over what
/// is stored (FIX 11356); a replayed batch reports none.
#[expect(
    clippy::too_many_arguments,
    reason = "the batch's own apply parts, its origin and its time"
)]
pub(in crate::batch) fn mask_batch_ops(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut RwTxn<'_>,
    ops: &mut [BatchOp],
    text_index_trusted: bool,
    masks: bool,
    at: u64,
) -> Result<(MaskedFiles, Vec<(EntityId, ClaimCandidate)>)> {
    let refusal = match scan_batch_ops(store, &*wtxn, ops) {
        // A clean batch that is replayed, or that holds no put, claim or
        // text for a pass to read, places nothing whatever custody knows:
        // the index is not loaded (speed).
        Ok(()) if !masks || ops.iter().all(|op| op_record(op).is_none()) => {
            return Ok((MaskedFiles::default(), Vec::new()));
        }
        Ok(()) => None,
        Err(refusal) => Some(refusal),
    };
    // A value custody already holds keeps its own handle wherever it comes
    // back, shape or none (OF-560 C). A replayed batch reads only what it
    // wrote before.
    let known = if masks {
        KnownValues::shared_in_writer(store, wtxn)?
    } else {
        None
    };
    if refusal.is_none() && known.is_none() {
        return Ok((MaskedFiles::default(), Vec::new()));
    }
    // A value the owner ruled no secret in a record is no hit there.
    let kept = KeptValues::for_records_in_txn(store, &*wtxn, ops.iter().filter_map(op_record))?;
    if known.is_none() && !kept.is_empty() && scan_screened(store, wtxn, &kept, ops).is_ok() {
        return Ok((MaskedFiles::default(), Vec::new()));
    }
    // The owner's switch, read once: when it is off the plan places known
    // values only and mints nothing (FIX 8644).
    let known_only = secret_scan_mode_in_txn(store, &*wtxn)? == SecretScanMode::Off;
    // A clean scan read each body and text field the passes read by the
    // same text rules: no shape is sought in them again (speed).
    let shapes_read = refusal.is_none() && !known_only;
    // The plan's copy, and every value it finds, are wiped however the
    // plan ends (FIX 1101).
    let mut planned = PlanOps::of(ops);
    let mut plan = Masker {
        marked: marked_files(store, &*wtxn, ops)?,
        mints: masks,
        kept,
        known: known.clone(),
        known_only,
        shapes_read,
        text_log: TextLog::recording(),
        ..Masker::default()
    };
    plan.mask_ops(&mut planned)?;
    if plan.found.is_empty() && plan.file_ids.is_empty() && !plan.placed_known {
        return refusal.map_or_else(|| Ok((MaskedFiles::default(), Vec::new())), Err);
    }
    // A hit no span places is still in the copy, and refuses as before.
    scan_screened(store, wtxn, &plan.kept, &planned)?;
    drop(planned);
    let kept = std::mem::take(&mut plan.kept);
    let files = std::mem::take(&mut plan.files);
    let text_log = std::mem::take(&mut plan.text_log).replayed();
    let masked = MaskedFiles(std::mem::take(&mut plan.file_ids));
    if !masks {
        return Ok((masked, Vec::new()));
    }
    let write = CustodyWrite {
        store,
        config,
        analyzer,
        text_index_trusted,
    };
    let minted = plan.mint(&write, wtxn, at)?;
    // A known value in a file names that file in the found-key notice (FIX 2780).
    known_note::note_known_file_keys_in_txn(store, wtxn, &files, at)?;
    put_file_marks_in_txn(store, wtxn, files, &minted, at)?;
    // The minted pass places the same values the plan did (FIX 8644), in
    // the same texts: it takes their spans from the plan's log.
    let mut minted_pass = Masker {
        handles: minted.map(|(handle, _)| handle),
        minted: true,
        kept,
        known,
        known_only,
        shapes_read,
        text_log,
        ..Masker::default()
    };
    minted_pass.mask_ops(ops)?;
    let masked_claims = std::mem::take(&mut minted_pass.masked_claims);
    Ok((masked, masked_claims))
}
