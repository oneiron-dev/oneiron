//! Pinned bounds on authority-fold work, and the store-door checks that keep
//! a stored log inside them (H72).
//!
//! The fold indexes every row's whole ancestry and probes each handoff by
//! folding its line again, so its work grows with the square of the log and
//! with the number of handoffs. Each signer may store a generous bound of
//! rows. The slip issuer's slip ops count toward no bound: every sign-in
//! mints one, so a busy owner's log gains thousands a year. The rows it
//! signs that only take authority away always land. A fold handed more than
//! its own bounds fails closed: it holds no root and reads as a conflicted
//! one, which every authority gate refuses.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::store::Store;

/// Most rows one signer may store. A slip issuer's slip ops and the rows it
/// signs that only restrict (revocations, burns, machine removals and
/// demotions) are never refused.
pub const MAX_AUTHORITY_ROWS_PER_SIGNER: usize = 2048;
/// Most handoffs (`ReRoot` rows) one fold holds. The fold probes each one by
/// folding its line again; a vault re-roots once per host move.
pub const MAX_AUTHORITY_FOLD_HANDOFFS: usize = 32;
/// Most counted rows one fold reads.
pub const MAX_AUTHORITY_FOLD_ENTRIES: usize = 4 * MAX_AUTHORITY_ROWS_PER_SIGNER;

#[cfg(test)]
thread_local! {
    static ROWS_PER_SIGNER_FOR_TEST: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// Runs `body` with every bound scaled to `rows` per signer on this thread,
/// so a test crosses them in a few rows.
#[cfg(test)]
pub(crate) fn with_rows_per_signer_for_test<T>(rows: usize, body: impl FnOnce() -> T) -> T {
    ROWS_PER_SIGNER_FOR_TEST.with(|bound| bound.set(Some(rows)));
    let result = body();
    ROWS_PER_SIGNER_FOR_TEST.with(|bound| bound.set(None));
    result
}

fn rows_per_signer() -> usize {
    #[cfg(test)]
    if let Some(rows) = ROWS_PER_SIGNER_FOR_TEST.with(std::cell::Cell::get) {
        return rows;
    }
    MAX_AUTHORITY_ROWS_PER_SIGNER
}

fn fold_entries_bound() -> usize {
    4 * rows_per_signer()
}

/// Most counted ancestor pairs one fold indexes: two full signers in one
/// chain.
pub(super) fn ancestor_edges_bound() -> usize {
    2 * rows_per_signer() * rows_per_signer()
}

impl AuthorityFold {
    /// True when the fold refused its log for exceeding a bound. Such a fold
    /// also reads as [`Self::vault_root_is_conflicted`], so every authority
    /// gate refuses it.
    #[must_use]
    pub fn authority_log_past_bound(&self) -> bool {
        self.authority_log_bound_signer().is_some()
    }

    /// The signer whose rows took the log past a fold bound, when the fold
    /// refused it.
    #[must_use]
    pub fn authority_log_bound_signer(&self) -> Option<&AuthorityKey> {
        self.issues.iter().find_map(|issue| match issue {
            AuthorityFoldIssue::FoldBudgetExceeded { signer } => Some(signer),
            _ => None,
        })
    }
}

/// A short, stable label for `key` in owner-facing refusals.
#[must_use]
pub(crate) fn authority_signer_label(key: &AuthorityKey) -> String {
    let (suite, bytes) = match key {
        AuthorityKey::Ed25519(bytes) => ("ed25519", &bytes[..]),
        AuthorityKey::P256(bytes) => ("p256", &bytes[..]),
    };
    let hex: String = bytes
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{suite}:{hex}")
}

/// The fold of a log past the bounds: no root, no roster, one typed issue
/// naming the signer that took it there.
pub(super) fn over_budget_fold(signer: AuthorityKey) -> AuthorityFold {
    let mut fold = fold_authority_log(&[]);
    fold.issues
        .push(AuthorityFoldIssue::FoldBudgetExceeded { signer });
    fold
}

fn is_slip_op(op: &AuthorityOp) -> bool {
    matches!(
        op,
        AuthorityOp::SlipMint(_) | AuthorityOp::SlipRevoke { .. } | AuthorityOp::SlipConsume { .. }
    )
}

fn is_handoff(entry: &AuthorityLogEntry) -> bool {
    matches!(entry.op, AuthorityOp::ReRoot { .. })
}

fn admits_device(op: &AuthorityOp) -> Option<&DeviceAuthority> {
    match op {
        AuthorityOp::EnrollDevice { device }
        | AuthorityOp::RotateKey {
            new_device: device, ..
        }
        | AuthorityOp::ReRoot { new_device: device } => Some(device),
        _ => None,
    }
}

/// The slip issuers, read from the log's structure alone, so the fold's
/// bounds and the store doors judge a row the same way: the genesis owner,
/// and each owner key named by a signed re-root, rotation or enrollment that
/// an admitter signed or cosigned. The admitters are the genesis owner and
/// each owner or admin key such a row names, the fold's own consent rule. The
/// set holds owner keys only: an admin key admits but issues nothing, and a
/// machine, agent or peer key, a stranger, and every signer of a log without
/// exactly one genesis owner count as any other signer.
///
/// Every key the fold holds as a live owner is in the set. Nothing leaves
/// it, so a revocation the fold refuses never drops the issuer, and slip
/// rows a door stored uncounted never come to count against the fold's
/// bounds. An owner key leaves the host-rooted roster only by a handoff, and
/// a key a handoff retired signs nothing new at the replicated door.
pub(super) fn slip_issuers<'a>(
    entries: impl Iterator<Item = &'a AuthorityLogEntry>,
) -> BTreeSet<AuthorityKey> {
    let mut admissions: Vec<&'a AuthorityLogEntry> = Vec::new();
    let mut roots = Vec::new();
    for entry in entries {
        if let AuthorityOp::Genesis { device, .. } = &entry.op {
            if device.key == *entry.signer_key()
                && device.roles & ROLE_OWNER != 0
                && verify_entry_signatures(entry).is_ok()
            {
                roots.push(&device.key);
            }
        } else if admits_device(&entry.op)
            .is_some_and(|device| device.roles & (ROLE_OWNER | ROLE_ADMIN) != 0)
        {
            admissions.push(entry);
        }
    }
    roots.sort();
    roots.dedup();
    let [root] = roots[..] else {
        return BTreeSet::new();
    };
    let mut admitters = BTreeSet::from([root.clone()]);
    let mut owners = BTreeSet::from([root.clone()]);
    let mut grew = true;
    while grew {
        grew = false;
        admissions.retain(|entry| {
            let signed_by_admitter = std::iter::once(&entry.signer)
                .chain(&entry.cosigns)
                .any(|signature| admitters.contains(&signature.public_key));
            if !signed_by_admitter {
                return true;
            }
            if verify_entry_signatures(entry).is_ok()
                && let Some(device) = admits_device(&entry.op)
            {
                if device.roles & ROLE_OWNER != 0 {
                    owners.insert(device.key.clone());
                }
                grew |= admitters.insert(device.key.clone());
            }
            false
        });
    }
    owners
}

/// The hashes of the rows no fold bound counts: the slip issuers' slip ops.
pub(super) fn uncounted_rows(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> BTreeSet<AuthorityEntryHash> {
    let issuers = slip_issuers(by_hash.values());
    by_hash
        .iter()
        .filter(|(_, entry)| is_slip_op(&entry.op) && issuers.contains(entry.signer_key()))
        .map(|(hash, _)| *hash)
        .collect()
}

/// Refuses, before any work, a log with more counted rows or handoffs than
/// one fold may read, naming the signer with the most of them.
pub(super) fn refuse_over_budget(entries: &[AuthorityLogEntry]) -> Option<AuthorityFold> {
    let issuers = slip_issuers(entries.iter());
    let mut counted = BTreeMap::<&AuthorityKey, usize>::new();
    let mut handoffs = BTreeMap::<&AuthorityKey, usize>::new();
    for entry in entries {
        if !(is_slip_op(&entry.op) && issuers.contains(entry.signer_key())) {
            *counted.entry(entry.signer_key()).or_default() += 1;
        }
        if is_handoff(entry) {
            *handoffs.entry(entry.signer_key()).or_default() += 1;
        }
    }
    let past = |by_signer: &BTreeMap<&AuthorityKey, usize>, bound| {
        (by_signer.values().sum::<usize>() > bound)
            .then(|| by_signer.iter().max_by_key(|(_, rows)| **rows))
            .flatten()
            .map(|(key, _)| over_budget_fold((*key).clone()))
    };
    past(&counted, fold_entries_bound()).or_else(|| past(&handoffs, MAX_AUTHORITY_FOLD_HANDOFFS))
}

/// Whether the local fold gives `entry`'s signer standing to store a row: a
/// key some valid row admitted, live, revoked or retired. A key no row
/// admitted signs no valid row, so its replicated rows wait for the
/// enrollment instead of being stored.
pub(crate) fn signer_has_standing(fold: &AuthorityFold, entry: &AuthorityLogEntry) -> bool {
    let signer = entry.signer_key();
    fold.roster.contains_key(signer) || fold.retired_keys.contains(signer)
}

/// Whether `entry`'s signer is a slip issuer by the stored log's structure,
/// though the fold may not hold it yet: an owner key a signed rotation
/// named, in the line a later handoff verifies. Its rows, that handoff
/// among them, land before the fold can admit it.
pub(crate) fn signer_is_slip_issuer(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entry: &AuthorityLogEntry,
) -> crate::error::Result<bool> {
    let mut admissions = Vec::new();
    for (_, body) in authority_log_rows_in_txn(store, txn)? {
        let stored = decode_authority_log_entry_body(&body)?;
        if matches!(stored.op, AuthorityOp::Genesis { .. }) || admits_device(&stored.op).is_some() {
            admissions.push(stored);
        }
    }
    Ok(slip_issuers(admissions.iter()).contains(entry.signer_key()))
}

/// `rows` (hash, body, entry), each after every row among them it names as
/// a parent, ties in the order given. A store door reads a row's slip
/// issuers from the rows already staged, so an import stages a complete
/// history this way whatever order its caller gave.
pub(super) fn parents_first(
    rows: Vec<(AuthorityEntryHash, Vec<u8>, AuthorityLogEntry)>,
) -> Vec<(AuthorityEntryHash, Vec<u8>, AuthorityLogEntry)> {
    let at: BTreeMap<_, _> = rows
        .iter()
        .enumerate()
        .map(|(index, (hash, ..))| (*hash, index))
        .collect();
    let mut waiting = vec![0_usize; rows.len()];
    let mut children = vec![Vec::new(); rows.len()];
    for (index, (.., entry)) in rows.iter().enumerate() {
        for parent in entry
            .parent_hashes
            .iter()
            .filter_map(|parent| at.get(parent))
        {
            waiting[index] += 1;
            children[*parent].push(index);
        }
    }
    let mut ready: BTreeSet<_> = (0..rows.len())
        .filter(|index| waiting[*index] == 0)
        .collect();
    let mut order = Vec::with_capacity(rows.len());
    while let Some(index) = ready.pop_first() {
        order.push(index);
        for child in &children[index] {
            waiting[*child] -= 1;
            if waiting[*child] == 0 {
                ready.insert(*child);
            }
        }
    }
    // Content addressing leaves no cycle; this only guards the invariant.
    let placed: BTreeSet<_> = order.iter().copied().collect();
    order.extend((0..rows.len()).filter(|index| !placed.contains(index)));
    let mut rows: Vec<_> = rows.into_iter().map(Some).collect();
    order
        .into_iter()
        .filter_map(|index| rows[index].take())
        .collect()
}

/// A row that only takes authority away: a revocation, a burn, or a machine
/// removal. It always lands when a slip issuer signed it.
fn only_restricts(op: &AuthorityOp) -> bool {
    matches!(op, AuthorityOp::RevokeDevice { .. })
        || super::revoke_proof::restrictive_withdrawal(op)
}

/// A machine revision that takes "yours" from a machine the local fold holds
/// as yours: a demotion, which only restricts.
fn demotes_machine(fold: &AuthorityFold, op: &AuthorityOp) -> bool {
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let AuthorityOp::MachineProfile(profile) = op else {
        return false;
    };
    profile.role != yours
        && fold
            .machines
            .get(&profile.machine)
            .is_some_and(|known| known.profile.role == yours)
}

/// What a store door does with an AUTHORITY_LOG row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityDoor {
    Lands,
    /// The row would take its signer past its bound, or the log past
    /// [`MAX_AUTHORITY_FOLD_HANDOFFS`].
    AtBound,
    /// A replicated row no slip issuer signed or cosigned. The fold applies
    /// no row without an owner's consent, so the row waits, as a stranger's
    /// does, instead of growing the log toward the fold's bounds.
    Unowned,
}

/// The door's verdict on storing `entry`. A row already stored always
/// lands. A slip issuer's slip ops and the rows it signs that only restrict
/// are never refused and count toward no bound, and its demotions land past
/// the bound. Every row any other key stores counts toward that key's bound,
/// whatever it does, and a handoff it signs is refused at once: the fold
/// applies no slip op, restriction or handoff such a key signs. The door
/// reads the issuers from the log as the fold's bounds do.
pub(crate) fn authority_door(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: crate::HostingPrivacyPosture,
    entry: &AuthorityLogEntry,
    hash: &AuthorityEntryHash,
    replicated: bool,
) -> crate::error::Result<AuthorityDoor> {
    let signer = entry.signer_key();
    let id = authority_log_entity_id_from_hash(hash)?;
    let mut rows = 1;
    let mut exempt = 0;
    let mut admissions = vec![entry.clone()];
    for (stored_id, body) in authority_log_rows_in_txn(store, txn)? {
        if stored_id == id {
            return Ok(AuthorityDoor::Lands);
        }
        let stored = decode_authority_log_entry_body(&body)?;
        if stored.signer_key() == signer {
            rows += 1;
            exempt += usize::from(is_slip_op(&stored.op) || only_restricts(&stored.op));
        }
        if matches!(stored.op, AuthorityOp::Genesis { .. }) || admits_device(&stored.op).is_some() {
            admissions.push(stored);
        }
    }
    let issuers = slip_issuers(admissions.iter());
    let owner_signed = std::iter::once(&entry.signer)
        .chain(&entry.cosigns)
        .any(|signature| issuers.contains(&signature.public_key))
        && verify_entry_signatures(entry).is_ok();
    if replicated && !owner_signed {
        return Ok(AuthorityDoor::Unowned);
    }
    let issuer = issuers.contains(signer);
    if issuer {
        if is_slip_op(&entry.op) || only_restricts(&entry.op) {
            return Ok(AuthorityDoor::Lands);
        }
        rows -= exempt;
    }
    if is_handoff(entry) {
        let handoffs = admissions
            .iter()
            .filter(|row| is_handoff(row) && issuers.contains(row.signer_key()))
            .count();
        if !issuer || handoffs > MAX_AUTHORITY_FOLD_HANDOFFS {
            return Ok(AuthorityDoor::AtBound);
        }
    }
    if rows <= rows_per_signer() {
        return Ok(AuthorityDoor::Lands);
    }
    if !issuer {
        return Ok(AuthorityDoor::AtBound);
    }
    let fold = authority_view_readonly_for_store_in_txn(store, posture, txn)?;
    Ok(if demotes_machine(&fold, &entry.op) {
        AuthorityDoor::Lands
    } else {
        AuthorityDoor::AtBound
    })
}
