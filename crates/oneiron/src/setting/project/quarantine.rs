//! The quarantine of a row its key's hook refused at projection ([`RefusedProjection::Quarantine`];
//! SETTING-PROJECTED-CALENDAR-SYSTEM-CLAIM = A, Engine ANSWER 21 Nov 13:08: the refusing machine
//! quarantines the act, reads the strictest value and stops retrying).
//!
//! Once a pass's rounds end, a row its key's hook still refuses, of a key that quarantines it,
//! is projected again, in a savepoint of the pass's write, standing `Quarantined`
//! ([`quarantined_of`]). Where this install holds no row, it is written as the key's quarantine
//! marker, which reads the key's strictest value, and the key's hook runs on that value, so no
//! feed or seat is installed. Where it holds one, the source it installed first, the row stays as
//! it is (REVIEW-10357 round 2 P1-4). Its projection is recorded, so no later pass reads it again until its own acts
//! move, or the acts of a row its key's hook judged it against ([`super::super::RefusalPeers`]):
//! the projection records the basis of each such row ([`PeerSeen`]), which [`moved_since`] reads.
//! A pass that reads it again projects the act's value and runs the hook again.

use super::*;

use super::super::RefusedProjection;
use super::refusal::{fold_basis, named_acts_in_txn};

thread_local! {
    /// Set while this thread's pass quarantines a row its key's hook refused here, for a key that
    /// quarantines such a row ([`quarantine_refused_row_in_txn`]): the row is written as the
    /// key's quarantine marker.
    static QUARANTINING_REFUSED_ROW: Cell<bool> = const { Cell::new(false) };
}

/// A row a quarantined row's key's hook judged it against, and the basis of its acts then
/// ([`fold_basis`]; all zero for a row no act names): a pass reads the quarantined row again once
/// the basis moves ([`moved_since`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerSeen {
    target: EntityId,
    basis: [u8; 32],
}

/// The value the act that heads the row `slot` sets, as JSON, where this install holds it: for a
/// key's peers that read a row quarantined here, which reads the key's strictest value
/// (REVIEW-10357 P1-2). `None` for a row no setting act heads, a clear, and a value beside its act
/// that is not here.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn head_act_value_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    slot: &RowKey,
) -> Result<Option<serde_json::Value>> {
    let Some(fold) = vault.setting_slot_fold_in_txn(txn, setting_slot_target(slot)?)? else {
        return Ok(None);
    };
    Ok(named_acts_in_txn(vault, txn, &fold)?
        .into_iter()
        .next()
        .and_then(|named| named.value))
}

/// Whether the pass writes the row of `spec` it projects as the key's quarantine marker: it
/// quarantines a row the hook refused, of a key that quarantines such a row.
pub(super) fn quarantines_refused_row(spec: &SettingSpec) -> bool {
    QUARANTINING_REFUSED_ROW.with(Cell::get)
        && matches!(
            spec.refused_projection,
            RefusedProjection::Quarantine { .. }
        )
}

/// Whether the acts of a row `peers` names moved since they were seen.
///
/// # Errors
///
/// Storage errors.
pub(super) fn peers_moved_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    peers: &[PeerSeen],
) -> Result<bool> {
    for peer in peers {
        if peer_basis_in_txn(vault, txn, peer.target)? != peer.basis {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The basis of the acts on `target` as a pass reads them, all zero where no act names it.
fn peer_basis_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, target: EntityId) -> Result<[u8; 32]> {
    Ok(vault
        .setting_slot_fold_in_txn(txn, target)?
        .map_or([0; 32], |fold| fold_basis(&fold)))
}

/// Quarantines the row of `target` that its key's hook refused in this pass, in a savepoint of
/// the pass's write `txn`, at `now`, where the key quarantines such a row
/// ([`RefusedProjection::Quarantine`]): the keys whose rows changed. `None` for a key that does
/// not, and where the hook refuses the marker too (logged): the next pass reads it again.
///
/// # Errors
///
/// Storage errors; the key's peers' read.
pub(super) fn quarantine_refused_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    target: EntityId,
    now: u64,
) -> Result<Option<Vec<&'static SettingSpec>>> {
    let Some(fold) = vault.setting_slot_fold_in_txn(txn, target)? else {
        return Ok(None);
    };
    let Some(spec) = fold
        .live
        .iter()
        .find_map(|head| head_of(head).ok())
        .and_then(|head| spec_named(&head.slot.name).ok())
        .filter(|spec| {
            matches!(
                spec.refused_projection,
                RefusedProjection::Quarantine { .. }
            )
        })
    else {
        return Ok(None);
    };
    QUARANTINING_REFUSED_ROW.with(|quarantining| quarantining.set(true));
    let quarantined = crate::batch::savepoint_in_txn(vault, txn, |savepoint| {
        let projected = project_target_in_txn(vault, savepoint, target, now)?;
        record_peers_in_txn(vault, savepoint, (target, spec), &fold)?;
        Ok(Some(projected))
    });
    QUARANTINING_REFUSED_ROW.with(|quarantining| quarantining.set(false));
    match quarantined {
        Ok(projected) => Ok(Some(
            projected
                .map(|projected| projected.changed)
                .unwrap_or_default(),
        )),
        Err(Error::InvalidConfig(reason)) => {
            tracing::warn!(
                reason = %reason,
                "a setting row its key quarantines was refused; the next pass reads it again"
            );
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Adds to the projection the pass just recorded for `target`, of `spec`, the rows its key's
/// hook judges the row of `fold`'s acts against, each with the basis of its acts now.
fn record_peers_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (target, spec): (EntityId, &SettingSpec),
    fold: &SettingSlotFold,
) -> Result<()> {
    let (Some(peers_of), Some(refused)) = (
        spec.refusal_peers,
        named_acts_in_txn(vault, txn, fold)?.into_iter().next(),
    ) else {
        return Ok(());
    };
    let key = target_key(target);
    let Some(mut projection) = PROJECTIONS.get(&vault.store, txn, &key)? else {
        return Ok(());
    };
    for slot in peers_of(vault, txn, &refused.slot, refused.value.as_ref())? {
        let peer = setting_slot_target(&slot)?;
        if peer == target || projection.peers.iter().any(|seen| seen.target == peer) {
            continue;
        }
        let basis = peer_basis_in_txn(vault, txn, peer)?;
        projection.peers.push(PeerSeen {
            target: peer,
            basis,
        });
    }
    PROJECTIONS.put(&vault.store, txn, &key, &projection)
}
