//! The rows a leave handoff stands on, folded with this vault's own (FIX
//! 3797, FIX 3798). Beside a removed person's notices the home sends the root
//! edges that hand its root on and every row they stand on that this env did
//! not fold. Judged on this env's stale roster alone, a ReRoot's standing is
//! a guess and a host root's own rotation is no proof; folded with this
//! vault's rows by the fold that folds its own log, under its observations,
//! posture and pin, each is judged as the home judged it. The fold runs in
//! memory and nothing is written: the rows are evidence for the notices
//! alone, never this vault's log.

use super::*;
use crate::authority::fold_resume::{StoredLog, fold_stored_log};
use crate::authority::pinned_root::read_pinned_root_in_txn;
use crate::authority::sequence_observation::authority_local_observations_in_txn;

/// How [`Vault::roster_through_handoff`] judges a handoff.
pub(super) enum HandoffClosure {
    /// This vault's rows and the handoff's folded whole: the authority vault
    /// id and the roster that fold reaches, `None` when it holds the root in
    /// conflict. A notice's signer stands only as a live Owner there.
    Folded(Option<(AuthorityVaultId, BTreeMap<AuthorityKey, FoldedDevice>)>),
    /// The handoff carries no row this vault lacks, or a row names a parent
    /// neither held nor carried (below an image this vault adopted and has
    /// not hydrated, or a home that does not hold it): its ReRoot chain
    /// ([`reroot_chain`]), for the folded roster to judge row by row.
    Edges(Vec<Vec<u8>>),
}

/// A carried row: its hash, its bytes and the entry they decode to.
type Carried<'a> = (AuthorityEntryHash, &'a Vec<u8>, AuthorityLogEntry);

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
    let held = merged.len();
    for (hash, bytes, entry) in &carried {
        if merged.contains_key(hash) {
            continue;
        }
        if entry.vault_id != Some(vault_id) {
            return Ok(HandoffClosure::Folded(None));
        }
        merged.insert(*hash, (bytes.to_vec(), entry.clone()));
    }
    let whole = merged.values().all(|(_, entry)| {
        entry
            .parent_hashes
            .iter()
            .all(|parent| merged.contains_key(parent))
    });
    if !whole || merged.len() == held {
        return Ok(HandoffClosure::Edges(reroot_chain(&carried)));
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
    if fold.vault_root_is_conflicted() || fold.vault_id != Some(vault_id) {
        return Ok(HandoffClosure::Folded(None));
    }
    Ok(HandoffClosure::Folded(Some((vault_id, fold.roster))))
}

/// The carried ReRoot rows on the chain to the last one, in chain order:
/// from its successor, each step back takes the ReRoot handing on to the key
/// the walk stands at. A row the chain does not reach, a parent the handoff
/// carried as evidence, is no step for a roster judged row by row.
fn reroot_chain(carried: &[Carried<'_>]) -> Vec<Vec<u8>> {
    let mut by_successor = BTreeMap::new();
    let mut tip = None;
    for (_, bytes, entry) in carried {
        if let AuthorityOp::ReRoot { new_device } = &entry.op {
            by_successor.insert(&new_device.key, (entry.signer_key(), *bytes));
            tip = Some(&new_device.key);
        }
    }
    let mut chain = Vec::new();
    while let Some((signer, bytes)) = tip.and_then(|key| by_successor.remove(key)) {
        chain.push(bytes.to_vec());
        tip = Some(signer);
    }
    chain.reverse();
    chain
}
