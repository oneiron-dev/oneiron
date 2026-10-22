//! The step replay capsule and contribution fork rows (FIX 3028): each
//! capsule's metadata keyed by its attempt, lease generation and step, each
//! matched pair's fork receipts or the reason it is unavailable, and the
//! request, start and response bodies they name, owned by the original run.
//!
//! Each body is written as the side-row wall admits it, in the writer that
//! puts its capsule ([`admit`]), and an erase of the capsule's actor
//! releases them all ([`erase`]). A read checks, in its own snapshot, that
//! the capsule still holds its content and that the run still holds the
//! body's occurrence, whoever else keeps the same bytes (FIX 6144).

mod admit;
mod erase;
mod spawn_erase;

use serde::{Deserialize, Serialize};

use super::super::contribution::{
    ContributionForkReceipt, ContributionReplayUnavailable, ForkTreatment,
};
use super::super::replay::{CodeRunRawOutput, ResultOccurrence};
use super::super::replay_capsule::{
    CapsuleRequest, CapsuleRungBinding, ReplayRoutePin, StepReplayCapsule,
};
use super::records::body_drifted;
use crate::compaction::output::OutputRef;
use crate::provenance::body::owned_body_in_txn;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, LlmRequest, LlmResponse, Result, Vault};

pub(crate) use self::admit::{put_staged_capsule, store_fork_response};
pub(crate) use self::erase::erase_capsule_actor_in_txn;
pub(super) use self::erase::{actor_gone_in_txn, capsule_bodies_in_txn, names_no_actor};
pub(super) use self::spawn_erase::erase_spawn_prefixes_in_txn;

/// Capsules. Key: id16(attempt) + be64(lease generation) + be64(step).
const CAPSULES: SideTable<(EntityId, u64, u64), StepReplayCapsule, Named> =
    SideTable::new(&side_table::CODE_RUN_REPLAY_CAPSULE);

/// Fork rows. Key: hash32(attempt receipt, skill, axis) + the row's name.
const FORKS: SideTable<([u8; 32], String), ForkRow, Named> =
    SideTable::new(&side_table::CODE_RUN_CONTRIBUTION_FORK);

/// The row name of the reason a pair is unavailable.
const UNAVAILABLE_ROW: &str = "unavailable";

/// One row of a matched pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum ForkRow {
    Fork(ContributionForkReceipt),
    Unavailable(ContributionReplayUnavailable),
}

/// A matched pair's rows as they stand.
#[derive(Debug, Default)]
pub(crate) struct ForkRows {
    pub(crate) unavailable: Option<ContributionReplayUnavailable>,
    pub(crate) with_skill: Option<ContributionForkReceipt>,
    pub(crate) without_skill: Option<ContributionForkReceipt>,
}

fn fork_row_name(treatment: ForkTreatment) -> &'static str {
    match treatment {
        ForkTreatment::WithSkill => "with_skill",
        ForkTreatment::WithoutSkill => "without_skill",
    }
}

/// A capsule's key: its attempt, lease generation and step.
fn capsule_key(capsule: &StepReplayCapsule) -> (EntityId, u64, u64) {
    (
        capsule.attempt,
        u64::from(capsule.lease_generation),
        capsule.step,
    )
}

/// The capsule at `key` as `rtxn` sees it, while it holds its content.
fn kept_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    key: &(EntityId, u64, u64),
) -> Result<Option<StepReplayCapsule>> {
    Ok(CAPSULES
        .get(&vault.store, rtxn, key)?
        .filter(|capsule| capsule.content.actor().is_some()))
}

/// The whole body `body` names at `path`, as run `owner` holds it, read in
/// `rtxn`: `None` when the owner no longer holds that occurrence (an erase
/// released it, though another holder may keep the same bytes), when the
/// occurrence is under taint or the secret scan marked it, or when its bytes
/// are gone.
fn held_body_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    owner: EntityId,
    path: &str,
    body: OutputRef,
) -> Result<Option<Vec<u8>>> {
    let output = CodeRunRawOutput {
        path: path.to_owned(),
        ..CodeRunRawOutput::of_ref(body)
    };
    let occurrence = ResultOccurrence::of(Some(owner), &output)?.id();
    let held = owned_body_in_txn(&vault.store, rtxn, &owner, &occurrence)?.is_some();
    let withheld = vault.code_run_result_withheld_in_txn(rtxn, Some(owner), &output)?;
    if !held || withheld.is_some() {
        return Ok(None);
    }
    vault.code_run_result_body_in_txn(rtxn, &output)
}

/// [`held_body_in_txn`] in a snapshot of its own, when `still` holds there,
/// with the body pinned past the collector while it is read.
fn held_body(
    vault: &Vault,
    owner: EntityId,
    path: &str,
    body: OutputRef,
    still: impl FnOnce(&heed::RoTxn<'_>) -> Result<bool>,
) -> Result<Option<Vec<u8>>> {
    let _custody = vault.store.gate_custody_read_guard()?;
    let _pin = vault.pin_result_body(body.hash);
    let rtxn = vault.store.env.read_txn()?;
    if !still(&rtxn)? {
        return Ok(None);
    }
    held_body_in_txn(vault, &rtxn, owner, path, body)
}

/// Records the rung that answered the capsule at `key`, and the route it
/// went out on when it pinned one (PR-S1), once and in one write: a capsule
/// already finalized keeps its rung and its pin. An erased capsule, or one
/// whose actor is gone by now, takes neither: its route prompt is content an
/// erase clears (FIX 6144).
pub(crate) fn finalize_capsule(
    vault: &Vault,
    key: &(EntityId, u64, u64),
    binding: CapsuleRungBinding,
    route_pin: Option<ReplayRoutePin>,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let Some(mut capsule) = CAPSULES.get(&vault.store, txn, key)? else {
            return Ok(());
        };
        let Some(actor) = capsule.content.actor() else {
            return Ok(());
        };
        if capsule.binding.is_some() || erase::actor_gone_in_txn(vault, txn, &actor) {
            return Ok(());
        }
        capsule.binding = Some(binding);
        capsule.route_pin = route_pin;
        CAPSULES.put(vault, txn, key, &capsule)
    })
}

/// Every capsule of `attempt`, in lease generation then step order.
///
/// # Errors
///
/// Storage errors.
pub fn step_replay_capsules(vault: &Vault, attempt: EntityId) -> Result<Vec<StepReplayCapsule>> {
    let txn = vault.store.env.read_txn()?;
    step_replay_capsules_in_txn(vault, &txn, attempt)
}

/// [`step_replay_capsules`] in the caller's transaction. A row that does
/// not decode (one written before this capsule format) is no capsule, and is
/// counted in a warning.
pub(crate) fn step_replay_capsules_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    attempt: EntityId,
) -> Result<Vec<StepReplayCapsule>> {
    let mut capsules = Vec::new();
    let mut undecodable = 0_usize;
    for row in CAPSULES.iter_raw_from(&vault.store, rtxn, attempt.as_bytes())? {
        let (_, bytes) = row?;
        match CAPSULES.decode_value(&bytes) {
            Ok(capsule) => capsules.push(capsule),
            Err(_) => undecodable += 1,
        }
    }
    if undecodable > 0 {
        tracing::warn!(
            undecodable,
            "step replay capsule rows that do not decode read as none"
        );
    }
    Ok(capsules)
}

/// The capsule's start body (FIX 3694), read in the caller's transaction, as
/// stored: masked, its prefix row the run's row as the wall admitted it.
/// `None` when the capsule has no start, holds its content no longer (its
/// actor was erased), or its body is released, gone, withheld or no longer
/// its digest.
pub(crate) fn capsule_start_body(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    capsule: &StepReplayCapsule,
) -> Result<Option<Vec<u8>>> {
    let Some(capsule) = kept_in_txn(vault, rtxn, &capsule_key(capsule))? else {
        return Ok(None);
    };
    let Some(start) = &capsule.start else {
        return Ok(None);
    };
    let held = match held_body_in_txn(vault, rtxn, capsule.run, &start.path, start.body) {
        // Bytes that drifted from their row are no start, as bytes no longer
        // its digest are; a read that fails stays an error (FIX 4194).
        Err(error) if body_drifted(&error) => return Ok(None),
        held => held?,
    };
    let Some(bytes) = held else {
        return Ok(None);
    };
    Ok((*blake3::hash(&bytes).as_bytes() == start.digest).then_some(bytes))
}

/// The capsule's request as stored: the request it captured, each secret in
/// it its custody handle. `None` when the capsule holds its content no
/// longer (its actor was erased), when the wall withheld the request at its
/// capture (FIX 6254), or its body is released, gone, withheld, not its
/// stored hash or not a request; never an empty or rebuilt one.
pub(crate) fn capsule_request(
    vault: &Vault,
    capsule: &StepReplayCapsule,
) -> Result<Option<LlmRequest>> {
    let CapsuleRequest::Kept {
        body,
        path,
        stored_hash,
    } = &capsule.request
    else {
        return Ok(None);
    };
    let key = capsule_key(capsule);
    let still = |rtxn: &heed::RoTxn<'_>| -> Result<bool> {
        let row = kept_in_txn(vault, rtxn, &key)?;
        Ok(row.is_some_and(|row| row.request == capsule.request))
    };
    let Some(bytes) = held_body(vault, capsule.run, path, *body, still)? else {
        return Ok(None);
    };
    if blake3::hash(&bytes).as_bytes() != stored_hash {
        return Ok(None);
    }
    Ok(serde_json::from_slice(&bytes).ok())
}

/// A matched pair's rows.
pub(crate) fn fork_rows(vault: &Vault, pair: &[u8; 32]) -> Result<ForkRows> {
    let txn = vault.store.env.read_txn()?;
    fork_rows_in_txn(vault, &txn, pair)
}

/// [`fork_rows`] in the caller's transaction, so a reader that admits a pair
/// reads its forks on its own snapshot (FIX 3610).
pub(crate) fn fork_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pair: &[u8; 32],
) -> Result<ForkRows> {
    let mut rows = ForkRows::default();
    for ((_, _), row) in FORKS.scan_from(&vault.store, txn, pair)? {
        match row {
            ForkRow::Unavailable(reason) => rows.unavailable = Some(reason),
            ForkRow::Fork(receipt) => match receipt.treatment {
                ForkTreatment::WithSkill => rows.with_skill = Some(receipt),
                ForkTreatment::WithoutSkill => rows.without_skill = Some(receipt),
            },
        }
    }
    Ok(rows)
}

/// Writes one fork's receipt, replacing its earlier row.
pub(crate) fn put_fork(
    vault: &Vault,
    pair: &[u8; 32],
    receipt: &ContributionForkReceipt,
) -> Result<()> {
    let key = (*pair, fork_row_name(receipt.treatment).to_owned());
    vault.with_write_txn_grouped(|txn| FORKS.put(vault, txn, &key, &ForkRow::Fork(receipt.clone())))
}

/// Records why a pair is unavailable, so no later pass pays for it again.
pub(crate) fn put_unavailable(
    vault: &Vault,
    pair: &[u8; 32],
    reason: ContributionReplayUnavailable,
) -> Result<()> {
    let key = (*pair, UNAVAILABLE_ROW.to_owned());
    vault.with_write_txn_grouped(|txn| FORKS.put(vault, txn, &key, &ForkRow::Unavailable(reason)))
}

/// A fork's stored answer; `None` when its body is released (its capsule's
/// actor was erased), gone or withheld.
pub(crate) fn fork_response(
    vault: &Vault,
    run: EntityId,
    receipt: &ContributionForkReceipt,
) -> Result<Option<LlmResponse>> {
    let path = receipt.response_path.as_str();
    let Some(bytes) = held_body(vault, run, path, receipt.response, |_| Ok(true))? else {
        return Ok(None);
    };
    Ok(serde_json::from_slice(&bytes).ok())
}
