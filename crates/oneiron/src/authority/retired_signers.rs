//! A handoff retires its predecessor for good (engine-crates-03).
//!
//! A `ReRoot` hands the vault to a new key. The fold judges an entry against
//! its own ancestry, so a key the handoff superseded that signs on a branch
//! without the handoff (parented to the genesis, say) still sees itself live
//! there, and could install a second root. Retirement is therefore judged
//! across branches. Every key in a handoff's parents' roster, live or already
//! revoked, signs nothing that stands outside the handoff's line: its own
//! ancestry, and the ancestry of every later handoff that descends from it.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// The handoffs that stand and the keys each one retired.
#[derive(Debug, Default)]
pub(super) struct Retirements {
    fences: Vec<Fence>,
}

#[derive(Debug)]
struct Fence {
    vault_id: Option<AuthorityVaultId>,
    keys: BTreeSet<AuthorityKey>,
    /// The handoff, its ancestry, and every later handoff that descends from
    /// it with that handoff's ancestry. The successor root may merge an entry
    /// its predecessor's handoff missed; nothing else may.
    line: BTreeSet<AuthorityEntryHash>,
}

impl Fence {
    /// Whether `hash` is signed, as primary or co-signer, by a key this
    /// handoff retired, in its vault and outside its line. A genesis is never
    /// fenced: a second one is a root conflict, which the fold reports.
    fn signed_outside(
        &self,
        hash: &AuthorityEntryHash,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ) -> bool {
        entries.get(hash).is_some_and(|entry| {
            !matches!(entry.op, AuthorityOp::Genesis { .. })
                && entry.vault_id == self.vault_id
                && !self.line.contains(hash)
                && entry_signer_keys(entry).any(|key| self.keys.contains(key))
        })
    }

    /// Whether `hash` or an entry in its ancestry is signed outside the line.
    fn excludes(
        &self,
        hash: &AuthorityEntryHash,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    ) -> bool {
        self.signed_outside(hash, entries)
            || ancestors
                .get(hash)
                .is_some_and(|past| past.iter().any(|a| self.signed_outside(a, entries)))
    }
}

impl Retirements {
    /// Every key a standing handoff retired. They stay revoked in the merged
    /// fold whichever branch survives.
    pub(super) fn keys(&self) -> BTreeSet<AuthorityKey> {
        self.fences
            .iter()
            .flat_map(|fence| fence.keys.iter().cloned())
            .collect()
    }

    /// Whether `hash` stands on a retired key: it, or an entry in its
    /// ancestry, is signed by a key a standing handoff retired, outside that
    /// handoff's line. Such an entry proves nothing, restrictions included.
    pub(super) fn excludes(
        &self,
        hash: &AuthorityEntryHash,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    ) -> bool {
        self.fences
            .iter()
            .any(|fence| fence.excludes(hash, entries, ancestors))
    }
}

/// Refuses every entry that stands on a retired key (see
/// [`Retirements::excludes`]), and returns what the standing handoffs retired.
///
/// Which handoffs stand:
/// - Per signer, the one whose ancestry holds every entry that signer made at
///   or below the handoff's sequence. When none qualifies (two that each miss
///   the other, or a fork below the handoff's sequence), all of them stand
///   and refuse one another: the fold fails closed rather than pick a root.
/// - Across signers, a handoff that stands on a key another standing handoff
///   retired does not stand, unless that one stands on a key it retired: a
///   key a rotation superseded cannot fork a ReRoot that displaces the
///   rotation's successor. Two that fence each other both stand, and fail
///   closed.
pub(super) fn reject_retired_signer_forks(
    states: &mut BTreeMap<AuthorityEntryHash, FoldState>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    issues: &mut Vec<AuthorityFoldIssue>,
) -> Retirements {
    let handoffs: Vec<AuthorityEntryHash> = states
        .keys()
        .filter(|hash| matches!(entries[*hash].op, AuthorityOp::ReRoot { .. }))
        .copied()
        .collect();
    if handoffs.is_empty() {
        return Retirements::default();
    }
    let within = |handoff: &AuthorityEntryHash, hash: &AuthorityEntryHash| {
        hash == handoff
            || ancestors
                .get(handoff)
                .is_some_and(|past| past.contains(hash))
    };

    let mut by_signer = BTreeMap::<&AuthorityKey, Vec<AuthorityEntryHash>>::new();
    for hash in &handoffs {
        by_signer
            .entry(entries[hash].signer_key())
            .or_default()
            .push(*hash);
    }
    let mut standing = Vec::new();
    for (signer, candidates) in by_signer {
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

    let candidates: Vec<(AuthorityEntryHash, Fence)> = standing
        .iter()
        .map(|handoff| {
            (
                *handoff,
                fence_of(handoff, states, entries, ancestors, &handoffs),
            )
        })
        .collect();
    let fenced_by =
        |hash: &AuthorityEntryHash, fence: &Fence| fence.excludes(hash, entries, ancestors);
    let keep: Vec<bool> = candidates
        .iter()
        .map(|(handoff, own)| {
            !candidates.iter().any(|(other, fence)| {
                other != handoff && fenced_by(handoff, fence) && !fenced_by(other, own)
            })
        })
        .collect();
    let fences = candidates
        .into_iter()
        .zip(keep)
        .filter_map(|((_, fence), keep)| keep.then_some(fence))
        .collect();
    let retirements = Retirements { fences };

    let rejected: BTreeSet<AuthorityEntryHash> = states
        .keys()
        .filter(|hash| {
            retirements
                .fences
                .iter()
                .any(|fence| fence.signed_outside(hash, entries))
        })
        .copied()
        .collect();
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
    retirements
}

/// What `handoff` retires: every key in its parents' rosters, live or
/// revoked, other than the key it hands the vault to.
fn fence_of(
    handoff: &AuthorityEntryHash,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    handoffs: &[AuthorityEntryHash],
) -> Fence {
    let entry = &entries[handoff];
    let successor = match &entry.op {
        AuthorityOp::ReRoot { new_device } => Some(&new_device.key),
        _ => None,
    };
    let keys = entry
        .parent_hashes
        .iter()
        .filter_map(|parent| states.get(parent))
        .flat_map(|state| state.roster.keys())
        .filter(|key| Some(*key) != successor)
        .cloned()
        .collect();
    let mut line = BTreeSet::from([*handoff]);
    for later in handoffs {
        if later == handoff
            || ancestors
                .get(later)
                .is_some_and(|past| past.contains(handoff))
        {
            line.insert(*later);
            line.extend(ancestors.get(later).into_iter().flatten().copied());
        }
    }
    Fence {
        vault_id: entry.vault_id,
        keys,
        line,
    }
}

/// The primary signer and every co-signer of `entry`.
pub(super) fn entry_signer_keys(entry: &AuthorityLogEntry) -> impl Iterator<Item = &AuthorityKey> {
    std::iter::once(&entry.signer.public_key)
        .chain(entry.cosigns.iter().map(|cosign| &cosign.public_key))
}

/// Whether `entry` is already in the log at its own id. A resident row is
/// history, not a new signature: replaying it adds no authority, so no door
/// refuses it for its signer, whatever a clock-aware fold says of it now (the
/// stale-roster window drops expired approvals from `valid_entries`).
pub(crate) fn authority_row_resident(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    entry: &AuthorityLogEntry,
) -> crate::error::Result<bool> {
    let id = authority_log_entity_id(entry)?;
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
        return Ok(false);
    };
    Ok(raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .is_some_and(|body| decode_authority_log_entry_body(body).is_ok_and(|row| row == *entry)))
}

impl AuthorityFold {
    /// Whether a row not yet in this fold is signed, as primary or co-signer,
    /// by a key a handoff retired. Such a key keeps no standing: its rows that
    /// stand are already here in a handoff's line, because a handoff folds
    /// only once its whole ancestry does. Every door that admits signed
    /// authority rows refuses one.
    pub(crate) fn signed_by_retired_key(
        &self,
        hash: &AuthorityEntryHash,
        entry: &AuthorityLogEntry,
    ) -> bool {
        !self.valid_entries.contains(hash)
            && entry_signer_keys(entry).any(|key| self.retired_keys.contains(key))
    }
}
