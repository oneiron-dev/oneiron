//! A step start's publication in its capsule's writer (FIX 4192): the
//! estimate its body instances are minted for before the writer opens,
//! the lengths the writer's spill must hold, and the start published as
//! its pieces and its manifest.

use super::*;

/// About how large the step's start body is, read before the writer opens:
/// at most twice the run's row as stored (its bytes ride as MessagePack
/// integers), and the task.
pub(super) fn start_estimate(vault: &Vault, capture: &StepCapture<'_>) -> Result<usize> {
    if capture.start.is_none() {
        return Ok(0);
    }
    let rtxn = vault.store.env.read_txn()?;
    let row = REPLAY_RECORDS
        .get_borrowed(&vault.store, &rtxn, &capture.run)?
        .as_deref()
        .map_or(0, <[u8]>::len);
    Ok(row.saturating_mul(2).saturating_add(capture.task.len()))
}

/// The length of each body [`publish_start_in_txn`] publishes for `start`
/// in `txn`: each of its pieces the run does not hold yet for the actor,
/// then its manifest (FIX 4192). None without a start.
pub(super) fn start_lens_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: PieceScope,
    start: Option<&AdmittedStart>,
) -> Result<Vec<usize>> {
    start.map_or_else(
        || Ok(Vec::new()),
        |start| start.pieces.lens_in_txn(&vault.store, txn, scope),
    )
}

/// The step's start, admitted before, published as pieces the run owns for
/// the actor, its manifest the capsule's own body (FIX 4192). The capsule
/// names the digest of the whole start.
pub(super) fn publish_start_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    spill: &Spill,
    draft: &CapsuleDraft<'_>,
    start: Option<AdmittedStart>,
) -> Result<Option<ExecutorStepStart>> {
    let Some(AdmittedStart {
        bytes,
        bridge_start,
        pieces,
        ..
    }) = start
    else {
        return Ok(None);
    };
    let scope = PieceScope {
        run: draft.capture.run,
        actor: draft.actor,
    };
    Ok(Some(ExecutorStepStart {
        body: pieces.publish_in_txn(vault, wtxn, spill, scope, &draft.start_path)?,
        path: draft.start_path.clone(),
        digest: *blake3::hash(&bytes).as_bytes(),
        bridge_start,
        erased: false,
    }))
}
