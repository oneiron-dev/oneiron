//! The rows a leave handoff stands on, folded with this vault's own (FIX
//! 3797, FIX 3798). Beside a removed person's notices the home sends the root
//! edges that hand its root on and every row they stand on that this env did
//! not fold. Judged on this env's stale roster alone, a ReRoot's standing is
//! a guess and a host root's own rotation is no proof; folded with this
//! vault's rows by the fold that folds its own log, under its observations,
//! posture and pin, each is judged as the home judged it. The fold runs in
//! memory and nothing is written: the rows are evidence for the notices
//! alone, never this vault's log.
//!
//! Only evidence that closes is judged (FIX 7919). Where a row names a
//! parent neither held nor carried, no chain cut out of the carried rows
//! stands in for the fold, so no sibling fork or retirement they carry is
//! left out. Below the checkpoint image this vault adopted, the verified
//! image answers for the rows it covers, and the carried rows fold past it
//! as this vault's own tail does. Any other gap is pending, named, and
//! proves nothing.

use super::*;
use crate::authority::checkpoint_adopt::cached_adopted_authority_checkpoint_in_txn;
use crate::authority::fold_resume::{StoredLog, fold_stored_log};
use crate::authority::pinned_root::read_pinned_root_in_txn;
use crate::authority::readonly_fold::{ArrivingFold, authority_view_with_rows_for_store_in_txn};
use crate::authority::sequence_observation::authority_local_observations_in_txn;

/// How [`Vault::roster_through_handoff`] judges a handoff.
pub(super) enum HandoffClosure {
    /// This vault's rows and the handoff's folded whole, or past the image
    /// this vault adopted, or this vault's own fold where the handoff
    /// carries no row it lacks: the authority vault id and the roster that
    /// fold reaches, `None` when it holds the root in conflict or refuses
    /// the handoff. A notice's signer stands only as a live Owner there.
    Folded(Option<(AuthorityVaultId, BTreeMap<AuthorityKey, FoldedDevice>)>),
    /// The rows do not close: a row names a parent neither held, carried
    /// nor covered by the image this vault adopted, or the fold past that
    /// image needs rows this vault does not hold. The rows the evidence
    /// lacks, ascending. No roster is judged on them.
    Pending(BTreeSet<AuthorityEntryHash>),
}

/// Folds `handoff`'s rows with this vault's, in memory, for the vault
/// `vault_id`. A row that does not decode, or one of another vault, refuses
/// the handoff: a carried Genesis never roots the fold.
pub(super) fn through_closure(
    vault: &Vault,
    vault_id: AuthorityVaultId,
    handoff: &[Vec<u8>],
) -> Result<HandoffClosure> {
    let mut carried = Vec::with_capacity(handoff.len());
    for bytes in handoff {
        let Ok(entry) = decode_authority_log_entry_body(bytes) else {
            return Ok(HandoffClosure::Folded(None));
        };
        let Ok(hash) = authority_entry_hash(&entry) else {
            return Ok(HandoffClosure::Folded(None));
        };
        carried.push((hash, bytes, entry));
    }
    let txn = vault.store.env.read_txn()?;
    let mut merged = history_in_txn(vault, &txn)?;
    // The carried rows this vault lacks.
    let mut fresh = BTreeMap::new();
    for (hash, bytes, entry) in carried {
        if merged.contains_key(&hash) {
            continue;
        }
        if entry.vault_id != Some(vault_id) {
            return Ok(HandoffClosure::Folded(None));
        }
        fresh.insert(hash, entry.clone());
        merged.insert(hash, (bytes.to_vec(), entry));
    }
    let missing: BTreeSet<AuthorityEntryHash> = merged
        .values()
        .flat_map(|(_, entry)| entry.parent_hashes.iter())
        .filter(|parent| !merged.contains_key(*parent))
        .copied()
        .collect();
    if !missing.is_empty() {
        return past_adopted_image(vault, &txn, vault_id, &fresh, missing);
    }
    if fresh.is_empty() {
        // Every carried row is held and the held rows close: this vault's
        // own fold is the whole evidence.
        let view = vault.authority_view_readonly_in_txn(&txn)?;
        return Ok(reached(&view, vault_id));
    }
    let entries: Vec<AuthorityLogEntry> = merged.into_values().map(|(_, entry)| entry).collect();
    let observations = authority_local_observations_in_txn(&vault.store, &txn, &entries)?;
    let peer_consent_roots =
        crate::federation::admitted_peer_consent_roots_for_store_in_txn(&vault.store, &txn)?;
    let pin = read_pinned_root_in_txn(&vault.store, &txn)?;
    drop(txn);
    let (fold, _) = fold_stored_log(
        StoredLog {
            entries: &entries,
            first_seen_at_secs: &BTreeMap::new(),
            now_secs: crate::unix_seconds_now(),
            peer_consent_roots: &peer_consent_roots,
            observations: &observations,
            posture: vault.privacy_posture(),
            pin: pin.as_ref(),
        },
        None,
    );
    Ok(reached(&fold, vault_id))
}

/// The handoff judged past the checkpoint image this vault adopted, when
/// every row `missing` names is one that image covers (FIX 7919): the
/// carried rows this vault lacks, `fresh`, fold as arriving rows past the
/// verified image, beside this vault's own tail, as its own fold folds
/// ([`authority_view_with_rows_for_store_in_txn`]). Pending, naming what is
/// lacking, on a vault that adopted no image, where a missing row lies
/// outside the image, or where that fold needs rows this vault does not
/// hold.
fn past_adopted_image(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    vault_id: AuthorityVaultId,
    fresh: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    missing: BTreeSet<AuthorityEntryHash>,
) -> Result<HandoffClosure> {
    let Some(adopted) = cached_adopted_authority_checkpoint_in_txn(&vault.store, txn)? else {
        return Ok(HandoffClosure::Pending(missing));
    };
    let uncovered: BTreeSet<AuthorityEntryHash> = missing
        .iter()
        .filter(|hash| !adopted.image().rows.contains_key(*hash))
        .copied()
        .collect();
    if !uncovered.is_empty() {
        return Ok(HandoffClosure::Pending(uncovered));
    }
    Ok(
        match authority_view_with_rows_for_store_in_txn(
            &vault.store,
            vault.privacy_posture(),
            txn,
            fresh,
        )? {
            ArrivingFold::Complete(view) => reached(&view, vault_id),
            ArrivingFold::NeedHistory(request) if request.missing.is_empty() => {
                HandoffClosure::Pending(missing)
            }
            ArrivingFold::NeedHistory(request) => HandoffClosure::Pending(request.missing),
        },
    )
}

/// The roster `fold` reaches for the vault `vault_id`: `None` when it holds
/// the root in conflict or folds another vault.
fn reached(fold: &AuthorityFold, vault_id: AuthorityVaultId) -> HandoffClosure {
    if fold.vault_root_is_conflicted() || fold.vault_id != Some(vault_id) {
        return HandoffClosure::Folded(None);
    }
    HandoffClosure::Folded(Some((vault_id, fold.roster.clone())))
}
