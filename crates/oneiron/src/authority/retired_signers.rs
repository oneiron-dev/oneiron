//! A handoff retires its predecessor for good (engine-crates-03).
//!
//! A `ReRoot` hands the vault to a new key. The fold judges an entry against
//! its own ancestry, so a key the handoff superseded that signs on a branch
//! without the handoff (parented to the genesis, say) still sees itself live
//! there, and could install a second root. Retirement is therefore judged
//! across branches, and it fails closed:
//! - A handoff takes effect only on its own rows: it and its whole ancestry
//!   fold, and no confirmation collision prunes them. A pruned handoff
//!   installs nothing and retires nothing.
//! - Its fence holds every key in its parents' rosters, live or revoked,
//!   except its successor. Such a key signs nothing that stands outside the
//!   handoff and its own ancestry. No later handoff or merge widens that line,
//!   so a fenced key's signature counts toward no quorum.
//! - Handoffs that fence one another, directly or round a cycle, conflict (a
//!   fork, say): none installs its successor, and all their fences stay
//!   closed. A handoff or conflict that a closed fence fences yields: it
//!   installs nothing and retires nothing. The rest settle.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// The closed fences: those of the handoffs that settled or conflict.
#[derive(Debug, Default)]
pub(super) struct Retirements {
    fences: Vec<Fence>,
}

#[derive(Debug)]
struct Fence {
    handoff: AuthorityEntryHash,
    vault_id: Option<AuthorityVaultId>,
    keys: BTreeSet<AuthorityKey>,
    /// The handoff and its own ancestry.
    line: BTreeSet<AuthorityEntryHash>,
}

impl Fence {
    /// What `handoff` fences: every key in its parents' rosters, live or
    /// revoked, other than the key it hands the vault to.
    fn of(
        handoff: &AuthorityEntryHash,
        states: &BTreeMap<AuthorityEntryHash, FoldState>,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    ) -> Self {
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
        let mut line = ancestors.get(handoff).cloned().unwrap_or_default();
        line.insert(*handoff);
        Self {
            handoff: *handoff,
            vault_id: entry.vault_id,
            keys,
            line,
        }
    }

    /// Whether `hash` is signed, as primary or co-signer, by a key this
    /// handoff fences, in its vault and outside its line. A genesis is never
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
    /// Every key a closed fence holds. They stay revoked in the merged fold
    /// whichever branch survives.
    pub(super) fn keys(&self) -> BTreeSet<AuthorityKey> {
        self.fences
            .iter()
            .flat_map(|fence| fence.keys.iter().cloned())
            .collect()
    }

    /// The handoffs whose fences are closed, settled or in conflict.
    pub(super) fn handoffs(&self) -> BTreeSet<AuthorityEntryHash> {
        self.fences.iter().map(|fence| fence.handoff).collect()
    }

    /// Whether `hash` stands on a retired key: it, or an entry in its
    /// ancestry, is signed by a key a closed fence holds, outside that
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

/// Settles the handoffs in `states` (see the module doc), drops what they
/// refuse, and returns the closed fences. `contend` names the confirmations
/// that lose a collision among the rows it is shown. Fences close first, so a
/// fenced key's confirmation never wins one; a handoff whose own rows then
/// lose one is pruned, and the fold settles again without it.
pub(super) fn settle_handoffs(
    states: &mut BTreeMap<AuthorityEntryHash, FoldState>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    issues: &mut Vec<AuthorityFoldIssue>,
    contend: impl Fn(
        &BTreeMap<AuthorityEntryHash, FoldState>,
        &dyn Fn(&AuthorityEntryHash) -> bool,
    ) -> BTreeSet<AuthorityEntryHash>,
) -> Retirements {
    let mut pruned = BTreeMap::new();
    loop {
        let mut refused = pruned.clone();
        let retirements = close_fences(states, entries, ancestors, &mut refused);
        let gone = with_descendants(states, &refused, ancestors);
        let losers = contend(states, &|hash| !gone.contains(hash));
        let lost: Vec<_> = retirements
            .fences
            .iter()
            .filter(|fence| !fence.line.is_disjoint(&losers))
            .map(|fence| fence.handoff)
            .collect();
        if lost.is_empty() {
            for loser in losers {
                refused.insert(loser, AuthorityFoldIssue::InvalidEntry(loser));
            }
            let gone = with_descendants(states, &refused, ancestors);
            states.retain(|hash, _| {
                if let Some(issue) = refused.get(hash) {
                    issues.push(issue.clone());
                } else if gone.contains(hash) {
                    issues.push(AuthorityFoldIssue::InvalidAncestry(*hash));
                }
                !gone.contains(hash)
            });
            return retirements;
        }
        pruned.extend(
            lost.into_iter()
                .map(|handoff| (handoff, AuthorityFoldIssue::InvalidAncestry(handoff))),
        );
    }
}

/// Every row of `states` that `refused` names or that descends from one.
fn with_descendants(
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    refused: &BTreeMap<AuthorityEntryHash, AuthorityFoldIssue>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
) -> BTreeSet<AuthorityEntryHash> {
    states
        .keys()
        .filter(|hash| {
            refused.contains_key(*hash)
                || ancestors
                    .get(*hash)
                    .is_some_and(|past| refused.keys().any(|row| past.contains(row)))
        })
        .copied()
        .collect()
}

/// Decides which handoffs among the rows `refused` leaves settle, conflict or
/// yield, adds to `refused` every row a closed fence fences and every handoff
/// that does not settle, and returns the closed fences.
fn close_fences(
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    refused: &mut BTreeMap<AuthorityEntryHash, AuthorityFoldIssue>,
) -> Retirements {
    let gone = with_descendants(states, refused, ancestors);
    let fences: Vec<Fence> = states
        .keys()
        .filter(|hash| {
            !gone.contains(*hash) && matches!(entries[*hash].op, AuthorityOp::ReRoot { .. })
        })
        .map(|handoff| Fence::of(handoff, states, entries, ancestors))
        .collect();
    let count = fences.len();
    // fences_directly[i][j]: handoff i's fence fences handoff j or a row in
    // its ancestry; reach[i] is everything i fences, directly or through
    // others.
    let fences_directly: Vec<Vec<bool>> = fences
        .iter()
        .map(|fence| {
            fences
                .iter()
                .map(|other| fence.excludes(&other.handoff, entries, ancestors))
                .collect()
        })
        .collect();
    let reach: Vec<Vec<bool>> = (0..count)
        .map(|from| {
            let mut seen = vec![false; count];
            let mut stack = vec![from];
            while let Some(at) = stack.pop() {
                for next in (0..count).filter(|&next| fences_directly[at][next]) {
                    if !std::mem::replace(&mut seen[next], true) {
                        stack.push(next);
                    }
                }
            }
            seen
        })
        .collect();
    // A conflict: handoffs that fence one another round a cycle. It is
    // decided once every handoff that fences it from outside is: it yields
    // to a closed fence, and otherwise closes its own.
    let members: Vec<Vec<usize>> = (0..count)
        .map(|i| {
            (0..count)
                .filter(|&j| i == j || (reach[i][j] && reach[j][i]))
                .collect()
        })
        .collect();
    let fencers: Vec<Vec<usize>> = members
        .iter()
        .map(|own| {
            (0..count)
                .filter(|outer| {
                    !own.contains(outer) && own.iter().any(|&j| fences_directly[*outer][j])
                })
                .collect()
        })
        .collect();
    let mut closed: Vec<Option<bool>> = vec![None; count];
    while let Some(next) = (0..count).find(|&i| {
        closed[i].is_none() && fencers[i].iter().all(|&outer| closed[outer].is_some())
    }) {
        let shut = !fencers[next]
            .iter()
            .any(|&outer| closed[outer] == Some(true));
        for &member in &members[next] {
            closed[member] = Some(shut);
        }
    }
    let unsettled: Vec<AuthorityEntryHash> = (0..count)
        .filter(|&i| members[i].len() > 1 || closed[i] != Some(true))
        .map(|i| fences[i].handoff)
        .collect();
    let retirements = Retirements {
        fences: fences
            .into_iter()
            .zip(closed)
            .filter_map(|(fence, closed)| (closed == Some(true)).then_some(fence))
            .collect(),
    };
    for hash in states.keys().filter(|hash| !gone.contains(*hash)) {
        if retirements
            .fences
            .iter()
            .any(|fence| fence.signed_outside(hash, entries))
        {
            refused.insert(*hash, AuthorityFoldIssue::RetiredSigner(*hash));
        }
    }
    for handoff in unsettled {
        refused
            .entry(handoff)
            .or_insert(AuthorityFoldIssue::UnsettledHandoff(handoff));
    }
    retirements
}

/// The primary signer and every co-signer of `entry`.
pub(super) fn entry_signer_keys(entry: &AuthorityLogEntry) -> impl Iterator<Item = &AuthorityKey> {
    std::iter::once(&entry.signer.public_key)
        .chain(entry.cosigns.iter().map(|cosign| &cosign.public_key))
}

/// Whether `entry` is already in the log at its own id, stored as an
/// authority row. A resident row is history, not a new signature: replaying
/// it adds no authority, so no door refuses it for its signer, whatever a
/// clock-aware fold says of it now (the stale-roster window drops expired
/// approvals from `valid_entries`). A row of another kind carrying the same
/// bytes never entered the fold, so it is no history.
pub(crate) fn authority_row_resident(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    entry: &AuthorityLogEntry,
) -> crate::error::Result<bool> {
    let id = authority_log_entity_id(entry)?;
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
        return Ok(false);
    };
    Ok(crate::batch::EntityMetadataHeader::parse(&raw)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_AUTHORITY_LOG)
        && raw
            .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            .is_some_and(|body| {
                decode_authority_log_entry_body(body).is_ok_and(|row| row == *entry)
            }))
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
