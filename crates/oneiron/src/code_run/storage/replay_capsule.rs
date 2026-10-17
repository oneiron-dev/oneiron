//! The step replay capsule and contribution fork rows (FIX 3028): each
//! capsule's metadata keyed by its attempt, lease generation and step, each
//! matched pair's fork receipts or the reason it is unavailable, and the
//! request and response bodies they name, owned by the original run.

use serde::{Deserialize, Serialize};

use super::super::contribution::{
    ContributionForkReceipt, ContributionReplayUnavailable, ForkTreatment,
};
use super::super::replay::CodeRunRawOutput;
use super::super::replay_capsule::{CapsuleRungBinding, StepReplayCapsule};
use super::routing::ExecutorStorage;
use crate::compaction::output::OutputRef;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, LlmRequest, LlmResponse, Result, Vault};

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

/// Writes `bytes` byte for byte as a body `owner` holds at `path`.
fn store_owned_body(
    vault: &Vault,
    owner: EntityId,
    path: String,
    bytes: &[u8],
) -> Result<OutputRef> {
    let mut sink = vault.code_run_script_sink()?;
    sink.write(bytes)?;
    Ok(vault
        .publish_code_run_output(path, sink, true, Some(owner))?
        .output_ref())
}

/// The whole body `body` names, when it is still there, still its hash and
/// clean for a model to read again: a body under taint or one the secret
/// scan marked is withheld.
fn load_owned_body(
    vault: &Vault,
    owner: EntityId,
    path: &str,
    body: OutputRef,
) -> Result<Option<Vec<u8>>> {
    let output = CodeRunRawOutput {
        path: path.to_owned(),
        ..CodeRunRawOutput::of_ref(body)
    };
    let (taint, secret) =
        ExecutorStorage::Canonical(vault).code_run_result_taint(Some(owner), &output)?;
    if taint.is_tainted() || secret.is_some() {
        return Ok(None);
    }
    vault.get_raw_body(body)
}

/// Stores a capsule's request bytes, owned by its run.
pub(crate) fn store_capsule_request(
    vault: &Vault,
    run: EntityId,
    path: String,
    bytes: &[u8],
) -> Result<OutputRef> {
    store_owned_body(vault, run, path, bytes)
}

pub(crate) fn put_capsule(
    vault: &Vault,
    key: &(EntityId, u64, u64),
    capsule: &StepReplayCapsule,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| CAPSULES.put(vault, txn, key, capsule))
}

/// Records the rung that answered the capsule at `key`, once: a capsule
/// already finalized keeps its rung.
pub(crate) fn finalize_capsule(
    vault: &Vault,
    key: &(EntityId, u64, u64),
    binding: CapsuleRungBinding,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let Some(mut capsule) = CAPSULES.get(&vault.store, txn, key)? else {
            return Ok(());
        };
        if capsule.binding.is_some() {
            return Ok(());
        }
        capsule.binding = Some(binding);
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
    Ok(CAPSULES
        .scan_from(&vault.store, &txn, attempt.as_bytes())?
        .into_iter()
        .map(|(_, capsule)| capsule)
        .collect())
}

/// The capsule's request as it was captured; `None` when its body is gone,
/// withheld, no longer its hash or not a request.
pub(crate) fn capsule_request(
    vault: &Vault,
    capsule: &StepReplayCapsule,
) -> Result<Option<LlmRequest>> {
    let Some(bytes) = load_owned_body(vault, capsule.run, &capsule.request_path, capsule.request)?
    else {
        return Ok(None);
    };
    if *blake3::hash(&bytes).as_bytes() != capsule.request_hash {
        return Ok(None);
    }
    Ok(serde_json::from_slice(&bytes).ok())
}

/// A matched pair's rows.
pub(crate) fn fork_rows(vault: &Vault, pair: &[u8; 32]) -> Result<ForkRows> {
    let txn = vault.store.env.read_txn()?;
    let mut rows = ForkRows::default();
    for ((_, _), row) in FORKS.scan_from(&vault.store, &txn, pair)? {
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

/// Stores a fork's answer as a body the original run owns.
pub(crate) fn store_fork_response(
    vault: &Vault,
    run: EntityId,
    path: String,
    response: &LlmResponse,
) -> Result<OutputRef> {
    let bytes = serde_json::to_vec(response)
        .map_err(|error| crate::Error::InvalidConfig(format!("fork response: {error}")))?;
    store_owned_body(vault, run, path, &bytes)
}

/// A fork's stored answer; `None` when its body is gone or withheld.
pub(crate) fn fork_response(
    vault: &Vault,
    run: EntityId,
    receipt: &ContributionForkReceipt,
) -> Result<Option<LlmResponse>> {
    let Some(bytes) = load_owned_body(vault, run, &receipt.response_path, receipt.response)? else {
        return Ok(None);
    };
    Ok(serde_json::from_slice(&bytes).ok())
}
