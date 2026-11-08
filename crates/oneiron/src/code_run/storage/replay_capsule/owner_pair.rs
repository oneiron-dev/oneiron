//! An owner verdict's pending pair (FIX 3609), kept in its pair's fork rows
//! under `owner_pair`, beside the two forks it shows. It is kept once, after
//! both forks are kept, while the capsule holds its content and every
//! subject of the pair, the asked owner among them, is live. Its ask is
//! bound in the ask's admission, and the owner's word scores both forks in
//! the ask's settling commit, which reads the capsule and both answers the
//! run owns again first. An erase deletes it and retires its ask
//! ([`super::fork_erase`]).

use super::super::super::contribution::{
    ContributionForkReceipt, ContributionReplayUnavailable as Unavailable, ForkJudge, ForkScore,
    ForkTreatment, OwnerJudgment, OwnerPair, OwnerPairRoute,
};
use super::{
    FORKS, ForkProvenance, ForkRow, ForkValue, ForkWrite, body_drifted, fork_capsule_in_txn,
    fork_row_name, held_body_in_txn,
};
use crate::{EntityId, Result, Vault};

/// The row name of a pair's pending owner pair.
pub(super) const OWNER_PAIR_ROW: &str = "owner_pair";

/// A fork row's key: the pair's key and the row's name.
type ForkKey = ([u8; 32], String);

/// Keeps `owner_pair` for the live pair `pair`, once. Nothing is written
/// once its capsule is gone or another request (`Unreadable`), its actor's
/// erase took its content (`Erased`), or a subject of the pair, its actor
/// and the asked owner among them, is gone now: the fence's `Unfinished`,
/// never lasting (FIX 6256). A pending pair kept first is returned as it is.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_owner_pair(
    vault: &Vault,
    pair: &[u8; 32],
    provenance: &ForkProvenance,
    owner_pair: &OwnerPair,
) -> Result<ForkWrite<OwnerPair>> {
    let key = (*pair, OWNER_PAIR_ROW.to_owned());
    let capsule_key = (
        owner_pair.attempt,
        u64::from(owner_pair.lease_generation),
        owner_pair.step,
    );
    vault.with_write_txn_grouped(|txn| {
        if let Some(row) = FORKS.get(&vault.store, txn, &key)? {
            return Ok(match row.value {
                ForkValue::OwnerPair(kept) => Ok(*kept),
                ForkValue::Fork(_) | ForkValue::Unavailable(_) => Err(Unavailable::Unreadable),
            });
        }
        let (capsule, actor) = match fork_capsule_in_txn(vault, txn, &capsule_key)? {
            Ok(held) => held,
            Err(reason) => return Ok(Err(reason)),
        };
        if capsule.request_hash != owner_pair.capsule_request {
            return Ok(Err(Unavailable::Unreadable));
        }
        let provenance = provenance.with_actor(actor).with_actor(owner_pair.owner);
        if let Err(reason) = provenance.fence_in_txn(vault, txn) {
            return Ok(Err(reason));
        }
        let row = ForkRow {
            provenance,
            value: ForkValue::OwnerPair(Box::new(owner_pair.clone())),
        };
        FORKS.put(vault, txn, &key, &row)?;
        Ok(Ok(owner_pair.clone()))
    })
}

/// The pending pair whose opaque handle is `handle`, with its row's key, as
/// `txn` sees it. A row that does not decode names no pair.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn owner_pair_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    handle: EntityId,
) -> Result<Option<(ForkKey, OwnerPair)>> {
    for key in FORKS.scan_keys(&vault.store, txn, &[])? {
        if key.1 != OWNER_PAIR_ROW {
            continue;
        }
        let Some(bytes) = FORKS.get_bytes(&vault.store, txn, &key)? else {
            continue;
        };
        if let Ok(row) = FORKS.decode_value(&bytes)
            && let ForkValue::OwnerPair(pair) = row.value
            && pair.handle == handle
        {
            return Ok(Some((key, *pair)));
        }
    }
    Ok(None)
}

/// Binds the ask `ask` to the pending pair `handle` names, in the ask's
/// admission (or the approval that released it): its revision and the
/// question digest it was admitted with. Whether the pair is bound to that
/// ask now; a pair bound to another ask, judged, closed, gone or with a
/// subject gone binds nothing.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn bind_owner_pair_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    handle: EntityId,
    ask: EntityId,
    revision: u64,
    question_digest: [u8; 32],
) -> Result<bool> {
    let Some((key, mut pair)) = owner_pair_in_txn(vault, txn, handle)? else {
        return Ok(false);
    };
    match pair.route {
        OwnerPairRoute::Reserved => {}
        OwnerPairRoute::Asked { ask: bound, .. } => return Ok(bound == ask),
        OwnerPairRoute::Accepted { .. }
        | OwnerPairRoute::Judged(_)
        | OwnerPairRoute::Closed { .. } => return Ok(false),
    }
    let Some(mut row) = FORKS.get(&vault.store, txn, &key)? else {
        return Ok(false);
    };
    if !row.provenance.live_in_txn(vault, txn) {
        return Ok(false);
    }
    pair.route = OwnerPairRoute::Asked {
        ask,
        revision,
        question_digest,
    };
    row.value = ForkValue::OwnerPair(Box::new(pair));
    FORKS.put(vault, txn, &key, &row)?;
    Ok(true)
}

/// Keeps a word admitted by the ask's settling writer when a temporary
/// subject fence prevents scoring. It carries no owner proof; a retry uses
/// the existing capsule, provenance and held-answer checks.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn accept_owner_pair_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &ForkKey,
    with_passed: bool,
    without_passed: bool,
    judgment: OwnerJudgment,
) -> Result<()> {
    let Some(mut row) = FORKS.get(&vault.store, txn, key)? else {
        return Ok(());
    };
    let ForkValue::OwnerPair(pair) = &mut row.value else {
        return Ok(());
    };
    pair.route = OwnerPairRoute::Accepted {
        with_passed,
        without_passed,
        judgment,
    };
    FORKS.put(vault, txn, key, &row)
}

/// Closes the pending pair at `key` unscored, its ask `ask` settled at
/// `at`. A pair judged or closed already keeps its first close.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn close_owner_pair_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &ForkKey,
    ask: EntityId,
    at: u64,
) -> Result<()> {
    let Some(mut row) = FORKS.get(&vault.store, txn, key)? else {
        return Ok(());
    };
    let ForkValue::OwnerPair(pair) = &mut row.value else {
        return Ok(());
    };
    if matches!(
        pair.route,
        OwnerPairRoute::Judged(_) | OwnerPairRoute::Closed { .. }
    ) {
        return Ok(());
    }
    pair.route = OwnerPairRoute::Closed { ask, at };
    FORKS.put(vault, txn, key, &row)
}

/// Scores both forks of the pending pair at `key` by `judgment`, the fork
/// with the target `with_passed` and the one without it `without_passed`,
/// in the pair's one evidence mode, and keeps the pair judged. Nothing is
/// written unless every subject of the pair is live, its capsule still holds
/// its content at its request, and each fork is still the unscored fork it
/// showed, its answer still the body the run holds. The refusal names its
/// kind as the fork writers do (FIX 6256): a subject gone now is the
/// fence's `Unfinished`, content or an answer an erase retired is `Erased`,
/// and anything else no longer kept as shown is `Unreadable`.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn judge_owner_pair_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &ForkKey,
    with_passed: bool,
    without_passed: bool,
    judgment: OwnerJudgment,
) -> Result<ForkWrite<OwnerPair>> {
    let Some(mut row) = FORKS.get(&vault.store, txn, key)? else {
        return Ok(Err(Unavailable::Unreadable));
    };
    let ForkValue::OwnerPair(kept) = &row.value else {
        return Ok(Err(Unavailable::Unreadable));
    };
    let mut pair = OwnerPair::clone(kept);
    let capsule_key = (pair.attempt, u64::from(pair.lease_generation), pair.step);
    match fork_capsule_in_txn(vault, txn, &capsule_key)? {
        Ok((capsule, _)) if capsule.request_hash == pair.capsule_request => {}
        Ok(_) => return Ok(Err(Unavailable::Unreadable)),
        Err(reason) => return Ok(Err(reason)),
    }
    if let Err(reason) = row.provenance.fence_in_txn(vault, txn) {
        return Ok(Err(reason));
    }
    let mut scored = Vec::with_capacity(2);
    for (treatment, shown, passed) in [
        (ForkTreatment::WithSkill, &pair.with_skill, with_passed),
        (
            ForkTreatment::WithoutSkill,
            &pair.without_skill,
            without_passed,
        ),
    ] {
        let fork_key = (key.0, fork_row_name(treatment).to_owned());
        let Some(mut fork_row) = FORKS.get(&vault.store, txn, &fork_key)? else {
            return Ok(Err(Unavailable::Unreadable));
        };
        let ForkValue::Fork(fork) = &mut fork_row.value else {
            return Ok(Err(Unavailable::Unreadable));
        };
        if fork.treatment != treatment
            || fork.receipt != shown.receipt
            || fork.response != shown.response
            || fork.score.is_some()
        {
            return Ok(Err(Unavailable::Unreadable));
        }
        if fork.response_erased {
            return Ok(Err(Unavailable::Erased));
        }
        if !answer_held_in_txn(vault, txn, pair.run, fork)? {
            return Ok(Err(Unavailable::Unreadable));
        }
        fork.score = Some(ForkScore {
            mode: pair.mode,
            passed,
            judge: ForkJudge::Owner(judgment),
        });
        scored.push((fork_key, fork_row));
    }
    for (fork_key, fork_row) in &scored {
        FORKS.put(vault, txn, fork_key, fork_row)?;
    }
    pair.route = OwnerPairRoute::Judged(judgment);
    row.value = ForkValue::OwnerPair(Box::new(pair.clone()));
    FORKS.put(vault, txn, key, &row)?;
    Ok(Ok(pair))
}

/// Whether run `run` still holds `fork`'s answer, read in `txn`: an
/// occurrence released, under taint, withheld, gone or drifted from its row
/// is not held.
fn answer_held_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
    fork: &ContributionForkReceipt,
) -> Result<bool> {
    match held_body_in_txn(vault, txn, run, &fork.response_path, fork.response) {
        Err(error) if body_drifted(&error) => Ok(false),
        held => Ok(held?.is_some()),
    }
}
