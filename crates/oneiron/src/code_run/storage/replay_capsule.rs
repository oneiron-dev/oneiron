//! The step replay capsule and contribution fork rows (FIX 3028): each
//! capsule's metadata keyed by its attempt, lease generation and step, each
//! matched pair's fork receipts or the reason it is unavailable, and the
//! request, start and response bodies they name, an engine step's fork's
//! executed bodies too ([`execution`], FIX 3607), the replay context its
//! step's checkpoint committed ([`context`], FIX 6351), and the route prompt
//! its answering rung put first ([`route_prompt`], FIX 6255), owned by the
//! original run. An owner verdict's pair also keeps its pending owner pair
//! beside its forks ([`owner_pair`], FIX 3609).
//!
//! Each body is written as the side-row wall admits it, in the writer that
//! puts its capsule ([`admit`]), and an erase of the capsule's actor
//! releases them all ([`erase`]). A read checks, in its own snapshot, that
//! the capsule still holds its content and that the run still holds the
//! body's occurrence, whoever else keeps the same bytes (FIX 6144).

mod admit;
mod context;
mod erase;
mod execution;
mod fork_erase;
mod owner_pair;
mod restore;
mod route_prompt;
mod spawn_erase;
mod start_parts;

use serde::{Deserialize, Serialize};

use super::super::contribution::{
    ContributionForkReceipt, ContributionReplayUnavailable, ForkTreatment, OwnerPair,
};
use super::super::replay::{CodeRunRawOutput, ResultOccurrence};
use super::super::replay_capsule::{CapsuleHost, CapsuleRequest, StepReplayCapsule};
use super::records::body_drifted;
use crate::compaction::output::OutputRef;
use crate::provenance::body::owned_body_in_txn;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, LlmRequest, LlmResponse, Result, Vault};

pub(crate) use self::admit::{put_staged_capsule, refresh_staged_request, store_fork_response};
pub(crate) use self::context::{
    capsule_context_body, join_step_context_in_txn, stage_step_context,
};
pub(crate) use self::erase::erase_capsule_actor_in_txn;
pub(crate) use self::erase::{actor_gone_in_store, actor_gone_in_txn};
pub(super) use self::erase::{capsule_bodies_in_txn, names_no_actor};
pub(crate) use self::execution::{fork_execution_outputs, store_fork_execution};
pub(crate) use self::fork_erase::ForkProvenance;
pub(crate) use self::fork_erase::{
    contribution_pair_erase_candidates_in_txn, erase_contribution_forks_in_txn,
};
pub(crate) use self::owner_pair::{
    bind_owner_pair_ask_in_txn, close_owner_pair_in_txn, judge_owner_pair_in_txn,
    owner_pair_in_txn, put_owner_pair,
};
pub(crate) use self::restore::retire_replay_bodies_in_rows;
pub(crate) use self::route_prompt::{capsule_route_prompt, finalize_capsule, route_prompt_at};
pub(super) use self::spawn_erase::erase_spawn_prefixes_in_txn;
pub(crate) use self::start_parts::{
    drop_step_start_in_rows, kept_step_start_in_txn, kept_step_starts_in_txn,
    release_step_start_in_txn, republish_step_start_in_rows, republish_step_start_in_txn,
    settle_start_bodies_in_rows, step_capsule_row, step_start_body_row, step_start_owners_in_txn,
};

/// Capsules. Key: id16(attempt) + be64(lease generation) + be64(step).
const CAPSULES: SideTable<(EntityId, u64, u64), StepReplayCapsule, Named> =
    SideTable::new(&side_table::CODE_RUN_REPLAY_CAPSULE);
/// Whether a masked copy of a `CODE_RUN_REPLAY_CAPSULE` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn code_run_replay_capsule_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<StepReplayCapsule, Named>(bytes)
}

/// Fork rows. Key: the experiment digest (opaque after erase) + the row's name.
const FORKS: SideTable<([u8; 32], String), ForkRow, Named> =
    SideTable::new(&side_table::CODE_RUN_CONTRIBUTION_FORK);

/// The row name of the reason a pair is unavailable.
const UNAVAILABLE_ROW: &str = "unavailable";

/// One row of a matched pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ForkRow {
    provenance: ForkProvenance,
    value: ForkValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ForkValue {
    Fork(ContributionForkReceipt),
    Unavailable(ContributionReplayUnavailable),
    /// An owner verdict's pending pair (FIX 3609).
    OwnerPair(Box<OwnerPair>),
}

/// A matched pair's rows as they stand.
#[derive(Debug, Default)]
pub(crate) struct ForkRows {
    pub(crate) unavailable: Option<ContributionReplayUnavailable>,
    pub(crate) with_skill: Option<ContributionForkReceipt>,
    pub(crate) without_skill: Option<ContributionForkReceipt>,
    pub(crate) owner_pair: Option<OwnerPair>,
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

/// What a fork writer kept, or why it kept nothing (FIX 6256). The writer
/// that meets the fence names the reason, and the runner keeps it as it is.
type ForkWrite<T> = std::result::Result<T, ContributionReplayUnavailable>;

/// The capsule at `key` and its actor, as a fork writer reads it in `txn`
/// (FIX 6256). A capsule row that is gone is `Unreadable`. A capsule whose
/// actor's erase took its content is `Erased`: its custody is retired.
fn fork_capsule_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &(EntityId, u64, u64),
) -> Result<ForkWrite<(StepReplayCapsule, EntityId)>> {
    let Some(capsule) = CAPSULES.get(&vault.store, txn, key)? else {
        return Ok(Err(ContributionReplayUnavailable::Unreadable));
    };
    let Some(actor) = capsule.content.actor() else {
        return Ok(Err(ContributionReplayUnavailable::Erased));
    };
    Ok(Ok((capsule, actor)))
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

/// Whether a capsule row of `attempt` at lease `generation` does not decode,
/// in the caller's transaction. [`step_replay_capsules_in_txn`] reads such a
/// row as none, so a reader that judges the attempt's newest step by those
/// capsules learns here that the newest may be the row it could not read.
pub(crate) fn undecodable_step_capsule_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    attempt: EntityId,
    generation: u32,
) -> Result<bool> {
    let mut prefix = attempt.as_bytes().to_vec();
    prefix.extend_from_slice(&u64::from(generation).to_be_bytes());
    for row in CAPSULES.iter_raw_from(&vault.store, rtxn, &prefix)? {
        let (_, bytes) = row?;
        if CAPSULES.decode_value(&bytes).is_err() {
            return Ok(true);
        }
    }
    Ok(false)
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
    if start.erased {
        return Ok(None);
    }
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
        erased: false,
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

/// Binds a single-call workflow step's answer to its capsule (FIX 3611):
/// `answer`, the digest and length of the text the call returned, on the
/// capsule at `key` whose request was sent as `request_hash`. Only a
/// finalized workflow capsule that still holds its content, for an actor
/// that is not erased, takes it, and only once: a bound answer stays as it
/// is. Whether the capsule binds `answer` now.
pub(crate) fn bind_capsule_answer(
    vault: &Vault,
    key: &(EntityId, u64, u64),
    request_hash: [u8; 32],
    answer: OutputRef,
) -> Result<bool> {
    vault.with_write_txn_grouped(|wtxn| {
        let Some(mut capsule) = CAPSULES.get(&vault.store, wtxn, key)? else {
            return Ok(false);
        };
        let Some(actor) = capsule.content.actor() else {
            return Ok(false);
        };
        if capsule.host != CapsuleHost::WorkflowStep
            || capsule.binding.is_none()
            || capsule.request_hash != request_hash
            || actor_gone_in_txn(vault, wtxn, &actor)
        {
            return Ok(false);
        }
        if let Some(bound) = capsule.answer {
            return Ok(bound == answer);
        }
        capsule.answer = Some(answer);
        CAPSULES.put(vault, wtxn, key, &capsule)?;
        Ok(true)
    })
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
        match row.value {
            ForkValue::Unavailable(reason) => rows.unavailable = Some(reason),
            ForkValue::Fork(receipt) => match receipt.treatment {
                ForkTreatment::WithSkill => rows.with_skill = Some(receipt),
                ForkTreatment::WithoutSkill => rows.without_skill = Some(receipt),
            },
            ForkValue::OwnerPair(pair) => rows.owner_pair = Some(*pair),
        }
    }
    Ok(rows)
}

/// Scores the exact fork still kept at its live pair, or reuses its first
/// committed score. An erase that moved it, or ran while the scorer
/// answered, can never recreate its old row. A fork no longer kept as it
/// was is `Unreadable`; a subject gone now is the fence's `Unfinished`
/// (FIX 6256).
pub(crate) fn put_fork(
    vault: &Vault,
    pair: &[u8; 32],
    receipt: &ContributionForkReceipt,
) -> Result<ForkWrite<ContributionForkReceipt>> {
    let key = (*pair, fork_row_name(receipt.treatment).to_owned());
    vault.with_write_txn_grouped(|txn| {
        let Some(mut row) = FORKS.get(&vault.store, txn, &key)? else {
            return Ok(Err(ContributionReplayUnavailable::Unreadable));
        };
        let ForkValue::Fork(kept) = &row.value else {
            return Ok(Err(ContributionReplayUnavailable::Unreadable));
        };
        let mut expected = receipt.clone();
        expected.score = kept.score;
        if *kept != expected {
            return Ok(Err(ContributionReplayUnavailable::Unreadable));
        }
        if let Err(reason) = row.provenance.fence_in_txn(vault, txn) {
            return Ok(Err(reason));
        }
        if kept.score.is_some() {
            return Ok(Ok(kept.clone()));
        }
        row.value = ForkValue::Fork(receipt.clone());
        FORKS.put(vault, txn, &key, &row)?;
        Ok(Ok(receipt.clone()))
    })
}

/// Records why a live pair is unavailable, so no later pass pays for it
/// again. The original subjects fence a late write after their erase.
pub(crate) fn put_unavailable(
    vault: &Vault,
    pair: &[u8; 32],
    provenance: &ForkProvenance,
    reason: ContributionReplayUnavailable,
) -> Result<()> {
    let key = (*pair, UNAVAILABLE_ROW.to_owned());
    vault.with_write_txn_grouped(|txn| {
        if !provenance.live_in_txn(vault, txn) {
            return Ok(());
        }
        FORKS.put(
            vault,
            txn,
            &key,
            &ForkRow {
                provenance: provenance.clone(),
                value: ForkValue::Unavailable(reason),
            },
        )
    })
}

/// A fork's stored answer; `None` when its body is released (its capsule's
/// actor was erased), gone or withheld.
pub(crate) fn fork_response(
    vault: &Vault,
    run: EntityId,
    receipt: &ContributionForkReceipt,
) -> Result<Option<LlmResponse>> {
    if receipt.response_erased {
        return Ok(None);
    }
    let path = receipt.response_path.as_str();
    let Some(bytes) = held_body(vault, run, path, receipt.response, |_| Ok(true))? else {
        return Ok(None);
    };
    Ok(serde_json::from_slice(&bytes).ok())
}
