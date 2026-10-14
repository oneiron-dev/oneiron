//! Pinned bounds on authority-fold work, and the store-door checks that keep
//! a stored log inside them (H72).
//!
//! The fold indexes every row's whole ancestry and probes each handoff by
//! folding its line again, so its work grows with the square of the log and
//! with the number of handoffs. Each signer may store a generous bound of
//! rows that add or widen authority; rows that only take authority away
//! always land. The slip issuer's slip ops count toward no bound: every
//! sign-in mints one, so a busy owner's log gains thousands a year. A fold
//! handed more than its own bounds fails closed: it holds no root and reads
//! as a conflicted one, which every authority gate refuses.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::store::Store;

/// Most rows that add or widen authority one signer may store. Rows that
/// only restrict (revocations, burns, machine removals and demotions) and
/// the slip issuer's slip ops are never refused.
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
/// an owner or admin in this chain signed or cosigned, less each key such a
/// signer revoked. The issuer a fold accepts is always one of them. A key no
/// such row names counts as any other signer, so a stranger's slip ops count
/// in full, and so does every slip op of a log without exactly one genesis
/// owner.
fn slip_issuers<'a>(
    entries: impl Iterator<Item = &'a AuthorityLogEntry>,
) -> BTreeSet<AuthorityKey> {
    let mut admissions = Vec::new();
    let mut revocations = Vec::new();
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
        } else if matches!(entry.op, AuthorityOp::RevokeDevice { .. }) {
            revocations.push(entry);
        }
    }
    roots.sort();
    roots.dedup();
    let [root] = roots[..] else {
        return BTreeSet::new();
    };
    let mut admitters = BTreeSet::from([root]);
    let mut owners = BTreeSet::from([root.clone()]);
    let signed_by = |entry: &AuthorityLogEntry, admitters: &BTreeSet<&AuthorityKey>| {
        std::iter::once(&entry.signer)
            .chain(&entry.cosigns)
            .any(|signature| admitters.contains(&signature.public_key))
    };
    let mut grew = true;
    while grew {
        grew = false;
        admissions.retain(|entry| {
            let entry: &'a AuthorityLogEntry = *entry;
            if !signed_by(entry, &admitters) {
                return true;
            }
            if verify_entry_signatures(entry).is_ok()
                && let Some(device) = admits_device(&entry.op)
            {
                if device.roles & ROLE_OWNER != 0 {
                    owners.insert(device.key.clone());
                }
                grew |= admitters.insert(&device.key);
            }
            false
        });
    }
    for entry in revocations {
        if let AuthorityOp::RevokeDevice { revoked_key } = &entry.op
            && signed_by(entry, &admitters)
            && verify_entry_signatures(entry).is_ok()
        {
            owners.remove(revoked_key);
        }
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

/// A row that only takes authority away: a revocation, a burn, or a machine
/// removal. It always lands, whatever its signer has stored.
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

/// Whether storing `entry` would take its signer past its bound of rows
/// that add or widen authority, or the log past
/// [`MAX_AUTHORITY_FOLD_HANDOFFS`]. A row already stored, one that only
/// restricts, and a slip issuer's slip op are never refused, and the issuer's
/// slip ops never count toward its bound. The door reads the issuer from the
/// log as the fold's bounds do.
pub(crate) fn door_refuses_past_budget(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: crate::HostingPrivacyPosture,
    entry: &AuthorityLogEntry,
    hash: &AuthorityEntryHash,
) -> crate::error::Result<bool> {
    if only_restricts(&entry.op) {
        return Ok(false);
    }
    let signer = entry.signer_key();
    let id = authority_log_entity_id_from_hash(hash)?;
    let mut rows = 1;
    let mut slips = 0;
    let mut handoffs = usize::from(is_handoff(entry));
    let mut admissions = vec![entry.clone()];
    for (stored_id, body) in authority_log_rows_in_txn(store, txn)? {
        if stored_id == id {
            return Ok(false);
        }
        let stored = decode_authority_log_entry_body(&body)?;
        handoffs += usize::from(is_handoff(&stored));
        if stored.signer_key() == signer && !only_restricts(&stored.op) {
            rows += 1;
            slips += usize::from(is_slip_op(&stored.op));
        }
        if matches!(
            stored.op,
            AuthorityOp::Genesis { .. } | AuthorityOp::RevokeDevice { .. }
        ) || admits_device(&stored.op).is_some()
        {
            admissions.push(stored);
        }
    }
    if slip_issuers(admissions.iter()).contains(signer) {
        if is_slip_op(&entry.op) {
            return Ok(false);
        }
        rows -= slips;
    }
    if rows <= rows_per_signer() && !(is_handoff(entry) && handoffs > MAX_AUTHORITY_FOLD_HANDOFFS) {
        return Ok(false);
    }
    let fold = authority_view_readonly_for_store_in_txn(store, posture, txn)?;
    Ok(!demotes_machine(&fold, &entry.op))
}
