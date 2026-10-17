//! A handoff retires its predecessor for good (engine-crates-03).
//!
//! A `ReRoot` hands the vault to a new key. The fold judges an entry against
//! its own ancestry, so a key the handoff superseded that signs on a branch
//! without the handoff (parented to the genesis, say) still sees itself live
//! there, and could install a second root. Retirement is therefore judged
//! across branches, and it fails closed:
//! - A handoff takes effect only on its own rows: it and its whole ancestry
//!   fold on their own, and no confirmation collision or concurrent tier
//!   floor prunes them. A pruned handoff installs nothing and retires nothing.
//! - Settlement does not depend on the order rows arrived in. A local
//!   sequence floor records only which of a signer's rows this vault saw
//!   first, so none applies inside a handoff's line: a sibling handoff that
//!   arrived first conflicts with it rather than refusing it. Floors still
//!   refuse every row outside such a line.
//! - Its fence holds every key in its parents' rosters, live or revoked,
//!   except its successor. Such a key signs nothing that stands outside the
//!   handoff and its own ancestry. No later handoff or merge widens that line,
//!   so a fenced key's signature counts toward no quorum.
//! - Handoffs that fence one another, directly or round a cycle, conflict (a
//!   fork, say): none installs its successor, and all their fences stay
//!   closed. A handoff or conflict that a closed fence fences yields: it
//!   installs nothing and retires nothing. The rest settle.
//! - An owner anchor's entries, its root and its marks, rest on no roster
//!   key, so no fence holds them, even when a roster enrolled the anchor's
//!   public key: anyone may enrol a public key. Those are the rows the anchor
//!   fold took, and a removal whose own proof took it through an anchor's
//!   chain; a root the fold refused makes no row the anchor's.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// The closed fences: those of the handoffs that settled or conflict.
#[derive(Debug, Default)]
pub(super) struct Retirements {
    fences: Vec<Fence>,
    /// The entries that folded through an owner anchor's branch.
    anchored: BTreeSet<AuthorityEntryHash>,
}

#[derive(Debug)]
struct Fence {
    handoff: AuthorityEntryHash,
    vault_id: Option<AuthorityVaultId>,
    keys: BTreeSet<AuthorityKey>,
    /// The handoff and its own ancestry.
    line: BTreeSet<AuthorityEntryHash>,
    /// The handoff is one of a conflict: its fence closed, but it installed
    /// no successor.
    conflict: bool,
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
            conflict: false,
        }
    }

    /// Whether `hash` is signed, as primary or co-signer, by a key this
    /// handoff fences, in its vault and outside its line. A genesis is never
    /// fenced: a second one is a root conflict, which the fold reports.
    fn signed_outside(
        &self,
        hash: &AuthorityEntryHash,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        anchored: &BTreeSet<AuthorityEntryHash>,
    ) -> bool {
        entries.get(hash).is_some_and(|entry| {
            !matches!(entry.op, AuthorityOp::Genesis { .. })
                && !anchored.contains(hash)
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
        anchored: &BTreeSet<AuthorityEntryHash>,
    ) -> bool {
        self.signed_outside(hash, entries, anchored)
            || ancestors.get(hash).is_some_and(|past| {
                past.iter()
                    .any(|a| self.signed_outside(a, entries, anchored))
            })
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

    /// Whether a conflict retired a root and installed no successor, so the
    /// roster has no settled root.
    pub(super) fn unsettled(&self) -> bool {
        self.fences.iter().any(|fence| fence.conflict)
    }

    /// Whether a restriction `hash` stands on a retired key: it, or an entry
    /// in its ancestry, is signed by a key a closed fence holds, outside that
    /// handoff's line. Such an entry proves nothing. The rows its own proof
    /// folded through an owner anchor's branch, `routed`, rest on no roster
    /// key (Sol code-R2 S2-F2); a row it took through the roster is the
    /// roster's, whatever root its branch names (Sol code-R3 S3-F1).
    pub(super) fn excludes(
        &self,
        hash: &AuthorityEntryHash,
        entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
        routed: &BTreeSet<AuthorityEntryHash>,
    ) -> bool {
        let anchored: BTreeSet<_> = self.anchored.union(routed).copied().collect();
        self.fences
            .iter()
            .any(|fence| fence.excludes(hash, entries, ancestors, &anchored))
    }
}

/// Settles the handoffs in `states` (see the module doc), drops what they
/// refuse, and returns the closed fences. Only `eligible` handoffs, those
/// valid on their own rows, take part when the fold has such a set; any other
/// handoff is refused at once and fences nothing. `contend` names the rows
/// that lose to a concurrent restriction (a confirmation collision) among the
/// rows it is shown, with why. Fences close first, so a
/// fenced key's row never wins one; a handoff whose own rows then lose one is
/// pruned, and the fold settles again without it until nothing more is.
pub(super) fn settle_handoffs(
    states: &mut BTreeMap<AuthorityEntryHash, FoldState>,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestors: &BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    eligible: Option<&BTreeSet<AuthorityEntryHash>>,
    issues: &mut Vec<AuthorityFoldIssue>,
    contend: impl Fn(
        &BTreeMap<AuthorityEntryHash, FoldState>,
        &dyn Fn(&AuthorityEntryHash) -> bool,
    ) -> BTreeMap<AuthorityEntryHash, AuthorityFoldIssue>,
) -> Retirements {
    let mut pruned: BTreeMap<_, _> = states
        .keys()
        .filter(|hash| {
            matches!(entries[*hash].op, AuthorityOp::ReRoot { .. })
                && eligible.is_some_and(|eligible| !eligible.contains(*hash))
        })
        .map(|handoff| (*handoff, AuthorityFoldIssue::UnsettledHandoff(*handoff)))
        .collect();
    loop {
        let mut refused = pruned.clone();
        let retirements = close_fences(states, entries, ancestors, &mut refused);
        let gone = with_descendants(states, &refused, ancestors);
        let losers = contend(states, &|hash| !gone.contains(hash));
        let lost: Vec<_> = retirements
            .fences
            .iter()
            .filter(|fence| losers.keys().any(|loser| fence.line.contains(loser)))
            .map(|fence| {
                let issue = losers
                    .get(&fence.handoff)
                    .cloned()
                    .unwrap_or(AuthorityFoldIssue::InvalidAncestry(fence.handoff));
                (fence.handoff, issue)
            })
            .collect();
        if lost.is_empty() {
            refused.extend(losers);
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
        pruned.extend(lost);
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
    let anchored: BTreeSet<_> = states
        .iter()
        .filter(|(hash, state)| state.anchor_entries.contains(*hash))
        .map(|(hash, _)| *hash)
        .collect();
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
                .map(|other| fence.excludes(&other.handoff, entries, ancestors, &anchored))
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
    while let Some(next) = (0..count)
        .find(|&i| closed[i].is_none() && fencers[i].iter().all(|&outer| closed[outer].is_some()))
    {
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
            .zip(&members)
            .filter_map(|((fence, closed), members)| {
                (closed == Some(true)).then_some(Fence {
                    conflict: members.len() > 1,
                    ..fence
                })
            })
            .collect(),
        anchored,
    };
    for hash in states.keys().filter(|hash| !gone.contains(*hash)) {
        if retirements
            .fences
            .iter()
            .any(|fence| fence.signed_outside(hash, entries, &retirements.anchored))
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

/// Whether a door reads `entry` as an owner anchor's row, which rests on no
/// roster key: a root record its own anchor signs, or a machine mark signed
/// alone by a key `anchor` names as the anchor of a root.
fn anchor_signed(entry: &AuthorityLogEntry, anchor: impl Fn(&[u8; 32]) -> bool) -> bool {
    entry.cosigns.is_empty()
        && match (&entry.op, &entry.signer.public_key) {
            (AuthorityOp::OwnerRoot(record), AuthorityKey::Ed25519(key)) => {
                *key == record.anchor_key
            }
            (AuthorityOp::MachineProfile(_), AuthorityKey::Ed25519(key)) => anchor(key),
            _ => false,
        }
}

/// The primary signer and every co-signer of `entry`.
pub(super) fn entry_signer_keys(entry: &AuthorityLogEntry) -> impl Iterator<Item = &AuthorityKey> {
    std::iter::once(&entry.signer.public_key)
        .chain(entry.cosigns.iter().map(|cosign| &cosign.public_key))
}

/// The row stored as authority history at `hash`'s id, if one is. A row of
/// another kind at that id, or one that does not decode, is none.
pub(crate) fn stored_authority_row(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    hash: &AuthorityEntryHash,
) -> crate::error::Result<Option<AuthorityLogEntry>> {
    let id = authority_log_entity_id_from_hash(hash)?;
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
        return Ok(None);
    };
    if crate::batch::EntityMetadataHeader::parse(&raw)
        .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_AUTHORITY_LOG)
    {
        return Ok(None);
    }
    Ok(raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .and_then(|body| decode_authority_log_entry_body(body).ok()))
}

/// The row at `hash` as a door's retired-standing walk reads it
/// ([`AuthorityFold::stands_on_retired_key`]): the stored row, else, on a
/// vault that adopted a checkpoint image (`evidence`), what the image holds
/// of it ([`super::adopted_evidence::AdoptedEvidence::ancestor`]): a covered
/// row's carried body, none for a covered row the image holds valid, and a
/// refusal naming any other history the vault neither stores nor reads
/// whole. With no adoption, a row not stored is none, as before.
pub(crate) fn door_ancestor_row(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    evidence: Option<&super::adopted_evidence::AdoptedEvidence>,
    hash: &AuthorityEntryHash,
) -> crate::error::Result<Option<AuthorityLogEntry>> {
    match stored_authority_row(store, txn, hash)? {
        Some(row) => Ok(Some(row)),
        None => evidence.map_or(Ok(None), |evidence| evidence.ancestor(hash)),
    }
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
    Ok(
        stored_authority_row(store, txn, &authority_entry_hash(entry)?)?
            .is_some_and(|row| row == *entry),
    )
}

impl AuthorityFold {
    /// Whether `entry` stands on a retired key: it, or, for a main-log row, a
    /// row in its ancestry that this fold does not hold, is signed by a key a
    /// handoff retired. Such a key keeps no standing: its rows that stand are
    /// already here in a handoff's line, because a handoff folds only once its
    /// whole ancestry does. The fold refuses such a row with its descendants,
    /// so a door refuses a new row that descends from one, whoever signs it.
    /// `row` reads an ancestor by hash, stored or arriving beside `entry`; the
    /// walk stops at rows this fold holds, whose ancestry it holds too. An
    /// approval the stale-roster window expired counts as held here: it stood
    /// in the settled fold, so no fence refused it, though it approves nothing
    /// now. On a vault that adopted a checkpoint image, a door's `row` is
    /// [`door_ancestor_row`]: it reads a covered ancestor from the image,
    /// stops at one the image holds valid, and refuses, naming the history,
    /// at one it can not read, so no ancestor is skipped there.
    ///
    /// An owner anchor's row is none (`anchor_signed`): its anchor names a
    /// root this fold holds or one arriving beneath it, so a root and its marks
    /// pass together on their first arrival. A held root counts on any branch:
    /// a mark parented beside it passes here, and the fold routes it through
    /// the roster and fences it there, so it stays inert (Wonder W2-F1).
    pub(crate) fn stands_on_retired_key(
        &self,
        hash: &AuthorityEntryHash,
        entry: &AuthorityLogEntry,
        row: &mut dyn FnMut(&AuthorityEntryHash) -> crate::error::Result<Option<AuthorityLogEntry>>,
    ) -> crate::error::Result<bool> {
        // A world's edit stands on no main-log row the fold refuses: it is
        // judged with each such row crossed (`refold_world_edits`), so only its
        // own signer counts here (Wonder P2 round 1, W4).
        if super::world_privacy::side_world(&entry.op).is_some() {
            return Ok(!self.valid_entries.contains(hash)
                && entry_signer_keys(entry).any(|key| self.retired_keys.contains(key)));
        }
        if self.retired_keys.is_empty() {
            return Ok(false);
        }
        let expired: BTreeSet<&AuthorityEntryHash> = self
            .issues
            .iter()
            .filter_map(|issue| match issue {
                AuthorityFoldIssue::StaleRosterApproval(hash) => Some(hash),
                _ => None,
            })
            .collect();
        let mut arriving = vec![(*hash, entry.clone())];
        let mut seen = BTreeSet::new();
        let mut stack = entry.parent_hashes.clone();
        while let Some(parent) = stack.pop() {
            if self.valid_entries.contains(&parent)
                || expired.contains(&parent)
                || !seen.insert(parent)
            {
                continue;
            }
            let Some(ancestor) = row(&parent)? else {
                continue;
            };
            stack.extend(ancestor.parent_hashes.iter().copied());
            arriving.push((parent, ancestor));
        }
        let anchors: BTreeSet<[u8; 32]> = arriving
            .iter()
            .filter_map(|(_, row)| match &row.op {
                AuthorityOp::OwnerRoot(record) => Some(record.anchor_key),
                _ => None,
            })
            .chain(self.root_anchors.keys().copied())
            .collect();
        Ok(arriving.iter().any(|(hash, row)| {
            !self.valid_entries.contains(hash)
                && !anchor_signed(row, |key| anchors.contains(key))
                && entry_signer_keys(row).any(|key| self.retired_keys.contains(key))
        }))
    }
}
