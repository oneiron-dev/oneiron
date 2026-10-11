//! A handoff retires its predecessor for good (engine-crates-03).
//!
//! A `ReRoot` revokes every key its parents' roster held live. The fold judges an
//! entry against its own ancestry, so a retired key that signs on a branch
//! without the handoff (parented to the genesis, say) still sees itself live
//! there, and could install a second root. Retirement is therefore judged
//! across branches: once a handoff retired a key, an entry that key signs, as
//! primary or co-signer, stands only inside that handoff's own ancestry.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// Refuses every entry signed by a key a standing handoff retired, outside
/// that handoff's ancestry, with its descendants. Returns the retired keys,
/// which stay revoked in the merged fold whichever branch survives.
///
/// The handoff that stands for a signer is the one whose ancestry holds every
/// entry that signer made at or below the handoff's sequence. A key's own
/// sequence orders what it signs, so a fork it signs later never displaces an
/// earlier handoff. When no handoff of a signer holds that history (two that
/// each miss the other, or a fork below the handoff's sequence), all of them
/// stand as retirements and refuse one another: the fold fails closed rather
/// than pick a root.
pub(super) fn reject_retired_signer_forks(
    states: &mut BTreeMap<AuthorityEntryHash, FoldState>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    issues: &mut Vec<AuthorityFoldIssue>,
) -> BTreeSet<AuthorityKey> {
    let mut handoffs = BTreeMap::<&AuthorityKey, Vec<AuthorityEntryHash>>::new();
    for hash in states.keys() {
        if matches!(entries[hash].op, AuthorityOp::ReRoot { .. }) {
            handoffs
                .entry(entries[hash].signer_key())
                .or_default()
                .push(*hash);
        }
    }
    if handoffs.is_empty() {
        return BTreeSet::new();
    }
    let within = |handoff: &AuthorityEntryHash, hash: &AuthorityEntryHash| {
        hash == handoff
            || ancestors
                .get(handoff)
                .is_some_and(|past| past.contains(hash))
    };
    let mut standing = Vec::new();
    for (signer, candidates) in handoffs {
        let signed: Vec<_> = states
            .keys()
            .filter(|hash| entries[*hash].signer_key() == signer)
            .collect();
        let holds_history = |handoff: &AuthorityEntryHash| {
            signed
                .iter()
                .all(|hash| entries[*hash].seq > entries[handoff].seq || within(handoff, hash))
        };
        match candidates
            .iter()
            .filter(|handoff| holds_history(handoff))
            .collect::<Vec<_>>()
            .as_slice()
        {
            [handoff] => standing.push(**handoff),
            _ => standing.extend(candidates),
        }
    }

    let mut retired_keys = BTreeSet::new();
    let mut rejected = BTreeSet::new();
    for handoff in &standing {
        // A handoff retires the keys live in its parents' roster. One its
        // ancestry had already retired stays with the handoff that did.
        let mut live = BTreeMap::<&AuthorityKey, bool>::new();
        for parent in &entries[handoff].parent_hashes {
            for (key, device) in states.get(parent).map(|state| &state.roster).into_iter().flatten() {
                *live.entry(key).or_insert(true) &= !device.revoked;
            }
        }
        let retired: BTreeSet<&AuthorityKey> = live
            .into_iter()
            .filter_map(|(key, live)| live.then_some(key))
            .collect();
        retired_keys.extend(retired.iter().map(|key| (*key).clone()));
        for (hash, _) in states.iter() {
            if !within(handoff, hash)
                && entry_signer_keys(&entries[hash]).any(|key| retired.contains(key))
            {
                rejected.insert(*hash);
            }
        }
    }
    states.retain(|hash, _| {
        if rejected.contains(hash) {
            issues.push(AuthorityFoldIssue::RetiredSigner(*hash));
            false
        } else if ancestors
            .get(hash)
            .is_some_and(|past| !past.is_disjoint(&rejected))
        {
            issues.push(AuthorityFoldIssue::InvalidAncestry(*hash));
            false
        } else {
            true
        }
    });
    retired_keys
}

/// The primary signer and every co-signer of `entry`.
pub(super) fn entry_signer_keys(entry: &AuthorityLogEntry) -> impl Iterator<Item = &AuthorityKey> {
    std::iter::once(&entry.signer.public_key).chain(entry.cosigns.iter().map(|cosign| &cosign.public_key))
}

impl AuthorityFold {
    /// Whether a row not yet in this fold is signed, as primary or co-signer,
    /// by a key a handoff retired. Such a key keeps no standing: its rows that
    /// stand are already here as the handoff's ancestry, because a handoff
    /// folds only once its whole ancestry does. Every door that admits signed
    /// authority rows from outside refuses one.
    pub(crate) fn signed_by_retired_key(
        &self,
        hash: &AuthorityEntryHash,
        entry: &AuthorityLogEntry,
    ) -> bool {
        !self.valid_entries.contains(hash)
            && entry_signer_keys(entry).any(|key| self.retired_keys.contains(key))
    }
}
