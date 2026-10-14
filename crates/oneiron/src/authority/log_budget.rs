//! Pinned bounds on authority-fold work, and the store-door checks that keep
//! a stored log inside them (H72).
//!
//! The fold indexes every row's whole ancestry and probes each handoff by
//! folding its line again, so its work grows with the square of the log and
//! with the number of handoffs. A legitimate log is tens of rows and gains
//! about one per sign-in. Each signer may store a generous bound of rows that
//! add or widen authority; rows that only take authority away always land.
//! A fold handed more than its own bounds fails closed: it holds no root and
//! reads as a conflicted one, which every authority gate refuses.

use super::*;
use crate::store::Store;

/// Most rows that add or widen authority one signer may store. Rows that
/// only restrict (revocations, burns, machine removals and demotions) are
/// never refused. Two full signers still fit one fold's ancestor bound.
pub const MAX_AUTHORITY_ROWS_PER_SIGNER: usize = 2048;
/// Most handoffs (`ReRoot` rows) one fold holds. The fold probes each one by
/// folding its line again; a vault re-roots once per host move.
pub const MAX_AUTHORITY_FOLD_HANDOFFS: usize = 32;
/// Most rows one fold reads; its scheduling loop is quadratic in them.
pub const MAX_AUTHORITY_FOLD_ENTRIES: usize = 4 * MAX_AUTHORITY_ROWS_PER_SIGNER;
/// Most ancestor pairs one fold indexes: a single chain of 4096 rows, about
/// half a gigabyte of index.
pub(super) const MAX_AUTHORITY_ANCESTOR_EDGES: usize = 1 << 23;

impl AuthorityFold {
    /// True when the fold refused its log for exceeding a bound. Such a fold
    /// also reads as [`Self::vault_root_is_conflicted`], so every authority
    /// gate refuses it.
    #[must_use]
    pub fn authority_log_past_bound(&self) -> bool {
        self.issues
            .contains(&AuthorityFoldIssue::FoldBudgetExceeded)
    }
}

/// The fold of a log past the bounds: no root, no roster, one typed issue.
pub(super) fn over_budget_fold() -> AuthorityFold {
    let mut fold = fold_authority_log(&[]);
    fold.issues.push(AuthorityFoldIssue::FoldBudgetExceeded);
    fold
}

/// Refuses, before any work, a log with more rows or handoffs than one fold
/// may read.
pub(super) fn refuse_over_budget(entries: &[AuthorityLogEntry]) -> Option<AuthorityFold> {
    let handoffs = entries.iter().filter(|entry| is_handoff(entry)).count();
    (entries.len() > MAX_AUTHORITY_FOLD_ENTRIES || handoffs > MAX_AUTHORITY_FOLD_HANDOFFS)
        .then(over_budget_fold)
}

fn is_handoff(entry: &AuthorityLogEntry) -> bool {
    matches!(entry.op, AuthorityOp::ReRoot { .. })
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
fn demotes_machine(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: crate::HostingPrivacyPosture,
    op: &AuthorityOp,
) -> crate::error::Result<bool> {
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let AuthorityOp::MachineProfile(profile) = op else {
        return Ok(false);
    };
    if profile.role == yours {
        return Ok(false);
    }
    Ok(
        authority_view_readonly_for_store_in_txn(store, posture, txn)?
            .machines
            .get(&profile.machine)
            .is_some_and(|known| known.profile.role == yours),
    )
}

/// Whether storing `entry` would take its signer past
/// [`MAX_AUTHORITY_ROWS_PER_SIGNER`] rows that add or widen authority, or the
/// log past [`MAX_AUTHORITY_FOLD_HANDOFFS`]. A row already stored, and one
/// that only restricts, is never refused.
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
    let mut signed = 1;
    let mut handoffs = usize::from(is_handoff(entry));
    for (_, body) in authority_log_rows_in_txn(store, txn)? {
        let stored = decode_authority_log_entry_body(&body)?;
        if authority_entry_hash(&stored)? == *hash {
            return Ok(false);
        }
        signed +=
            usize::from(stored.signer_key() == entry.signer_key() && !only_restricts(&stored.op));
        handoffs += usize::from(is_handoff(&stored));
    }
    if signed <= MAX_AUTHORITY_ROWS_PER_SIGNER && handoffs <= MAX_AUTHORITY_FOLD_HANDOFFS {
        return Ok(false);
    }
    Ok(!demotes_machine(store, txn, posture, &entry.op)?)
}
