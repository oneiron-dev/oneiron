//! A successor attempt's approved continuation of a failed run (FIX 3694,
//! OF-568): the run it forks from, the step it starts at, the owner's
//! approval and the exact prompt bytes approved, written once; and the one
//! transaction that seeds the child run's replay row from that fork, with
//! its read-world ledger from the source's (FIX 7085).

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use super::super::replay::{
    CodeRunRawOutput, CodeRunReplayGeneration, CodeRunReplayRecord, ResultOccurrence,
};
use super::read_worlds::seed_read_world_prefix_in_txn;
use super::records::{FinishedOutput, REPLAY_RECORDS, body_drifted, finish_output};
use super::response_erase::fence_replay_in_txn;
use super::response_owners::{inherit_response_owner_in_txn, stamp_response_owner_in_txn};
use crate::attempt_queue::AttemptId;
use crate::provenance::body::owned_body_in_txn;
use crate::side_table::{self, Named, SideTable};
use crate::store::{BodyMint, BodySink};
use crate::{EntityId, Error, Result, Vault};

/// Continuations. Key: id16(successor attempt).
const CONTINUATIONS: SideTable<EntityId, StoredRunContinuation, Named> =
    SideTable::new(&side_table::CODE_RUN_CONTINUATION);
/// Whether a masked copy of a `CODE_RUN_CONTINUATION` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn code_run_continuation_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<StoredRunContinuation, Named>(bytes)
}

/// One successor attempt's continuation, immutable once written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredRunContinuation {
    /// The Failed attempt the successor retries.
    pub(crate) predecessor: AttemptId,
    /// The predecessor's executor run, whose id is the predecessor's.
    pub(crate) source_run: EntityId,
    /// The step the child starts at: its prefix is the source's checkpoints
    /// `0..step`.
    pub(crate) step: u64,
    /// The owner's durable approval.
    pub(crate) approval: EntityId,
    /// The approved bytes, as the side-row wall stores them.
    pub(crate) prompt: String,
    /// BLAKE3 of `prompt`.
    pub(crate) prompt_digest: [u8; 32],
    /// BLAKE3 of the start body the child forks from.
    pub(crate) start_digest: [u8; 32],
    /// The lease generation of the capsule that holds that start.
    pub(crate) lease_generation: u32,
}

/// The continuation `successor` carries, read in the caller's transaction.
///
/// # Errors
///
/// Storage errors, and a row whose prompt is no longer its digest.
pub(crate) fn run_continuation_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    successor: EntityId,
) -> Result<Option<StoredRunContinuation>> {
    let Some(row) = CONTINUATIONS.get(&vault.store, rtxn, &successor)? else {
        return Ok(None);
    };
    if *blake3::hash(row.prompt.as_bytes()).as_bytes() != row.prompt_digest {
        return Err(Error::CorruptedIndex("code-run continuation prompt digest"));
    }
    Ok(Some(row))
}

/// Writes `row` as `successor`'s continuation unless it holds one already,
/// in the caller's transaction. `row` becomes what the side-row wall stores
/// (a secret the approved text holds becomes its handle), its prompt digest
/// taken over those bytes. Answers the row already held, which stays as it
/// is, or `None` once `row` is written.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_run_continuation_row_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    successor: EntityId,
    row: &mut StoredRunContinuation,
) -> Result<Option<StoredRunContinuation>> {
    CONTINUATIONS.admit(vault, wtxn, &successor, row)?;
    row.prompt_digest = *blake3::hash(row.prompt.as_bytes()).as_bytes();
    if let Some(held) = run_continuation_in_txn(vault, wtxn, successor)? {
        return Ok(Some(held));
    }
    CONTINUATIONS.put(vault, wtxn, &successor, row)?;
    Ok(None)
}

/// Seeds the child's row in the caller's writer, after its bodies were
/// published there. Ownership precedes the erase fence; no descriptor is
/// republished after the fence releases it. Before the row, the child's
/// read-world ledger is seeded from the source's proof of the calls before
/// `cut`, the proved cut's bridge position, and before every copied call
/// past it (FIX 7085). A child that copied fewer calls than `cut` begins a
/// ledger that misses them.
pub(crate) fn seed_continuation_run(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    child: &CodeRunReplayRecord,
    source: EntityId,
    cut: u64,
    actor: EntityId,
    inherited: &[CodeRunRawOutput],
) -> Result<CodeRunReplayGeneration> {
    if REPLAY_RECORDS.contains(&vault.store, txn, &child.run_id)? {
        return Err(Error::ConcurrentWrite("code-run continuation seed"));
    }
    stamp_response_owner_in_txn(vault, txn, child.run_id, child.run_id, actor)?;
    // An erased source stays erased; a kept source cannot replace the
    // actual proving capsule's actor with a different attribution.
    inherit_response_owner_in_txn(vault, txn, child.run_id, &source)?;
    for output in inherited {
        vault.retain_inherited_result_in_txn(txn, child.run_id, source, output)?;
    }
    // The copied row holds the proved prefix through `cut` and, when the cut
    // falls after a failed step, that step's recorded calls too: each copied
    // position is the source's own call, so its proof covers it (FIX 7085).
    let copied = child.bridge_calls.len() as u64;
    let copied_cut = (copied >= cut).then_some(copied);
    seed_read_world_prefix_in_txn(vault, txn, source, copied_cut, child.run_id)?;
    let generation = child.generation()?;
    let child = fence_replay_in_txn(vault, txn, Cow::Borrowed(child))?;
    REPLAY_RECORDS.put(vault, txn, &child.run_id, &child)?;
    Ok(generation)
}

/// Publishes already-admitted continuation values through the native body
/// store, preserving custody handles. The returned body keeps its file pin
/// until the caller commits; its instances were reserved before this writer.
pub(crate) fn publish_continuation_output_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    mint: &BodyMint,
    owner: EntityId,
    path: String,
    bytes: &[u8],
) -> Result<FinishedOutput> {
    let mut sink = BodySink::new(
        vault.store.body_dir()?,
        vault.code_result_inline_bytes(),
        Some(mint.clone()),
    );
    sink.write(bytes)?;
    let finished = finish_output(path, sink, true, vault.limit_watch(), |digest| {
        vault.pin_result_body(digest)
    })?;
    vault.put_code_run_output_in_txn(txn, &finished, &finished.output, Some(owner))?;
    Ok(finished)
}

/// Reads the child's own held seed occurrence, not shared bytes or a
/// config marker. Withholding, release and byte drift all remove its witness.
pub(crate) fn continuation_seed_body_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
    output: &CodeRunRawOutput,
) -> Result<Option<Vec<u8>>> {
    let _pin = vault.pin_result_body(output.raw_blake3);
    let occurrence = ResultOccurrence::of(Some(owner), output)?.id();
    let held = owned_body_in_txn(&vault.store, txn, &owner, &occurrence)?.is_some_and(|body| {
        body.state
            .held()
            .is_some_and(|held| held.blake3 == output.raw_blake3)
    });
    if !held
        || vault
            .code_run_result_withheld_in_txn(txn, Some(owner), output)?
            .is_some()
    {
        return Ok(None);
    }
    let bytes = match vault.code_run_result_body_in_txn(txn, output) {
        Err(error) if body_drifted(&error) => return Ok(None),
        bytes => bytes?,
    };
    Ok(bytes.filter(|bytes| *blake3::hash(bytes).as_bytes() == output.raw_blake3))
}
