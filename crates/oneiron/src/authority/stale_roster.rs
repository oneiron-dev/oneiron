//! Clock-free expiry of approvals resting on a subsequently revoked roster.
//!
//! Expiry removes a reusable approval from the LIVE fold projection, not from
//! historical transition validation. Deleting its ancestry link would also
//! delete a descendant revocation or an independently authorized fresh rebind.
//! Spent confirm nonces and conflict poison likewise remain spent forever.
//! Roster-changing ops are not approvals here: Bind/RebindActor, federation
//! confirms and critical-write confirms carry the reusable approval facts.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// Earliest second at which each currently valid approval becomes stale.
/// A checked deadline at the u64 ceiling never arrives, just as the original
/// saturating-subtraction predicate could never exceed its window there.
fn stale_roster_approval_deadlines(
    entries: &[AuthorityLogEntry],
    fold: &AuthorityFold,
    first_seen: &BTreeMap<AuthorityEntryHash, u64>,
    window_secs: u64,
) -> BTreeMap<AuthorityEntryHash, u64> {
    let mut revoked_at = BTreeMap::<AuthorityKey, u64>::new();
    for entry in entries {
        let Ok(hash) = authority_entry_hash(entry) else {
            continue;
        };
        if !fold.valid_entries.contains(&hash) {
            continue;
        }
        let Some(seen) = first_seen.get(&hash).copied() else {
            continue;
        };
        let keys = match &entry.op {
            AuthorityOp::RevokeDevice { revoked_key } => vec![revoked_key.clone()],
            AuthorityOp::RotateKey { old_key, .. } => vec![old_key.clone()],
            AuthorityOp::ReRoot { new_device } => fold
                .roster
                .keys()
                .filter(|key| **key != new_device.key)
                .cloned()
                .collect(),
            _ => Vec::new(),
        };
        for key in keys {
            if fold.roster.get(&key).is_some_and(|device| device.revoked) {
                revoked_at
                    .entry(key)
                    .and_modify(|at| *at = (*at).min(seen))
                    .or_insert(seen);
            }
        }
    }
    entries
        .iter()
        .filter_map(|entry| {
            let approval = match &entry.op {
                AuthorityOp::BindActor { .. } | AuthorityOp::RebindActor { .. } => true,
                AuthorityOp::FederationConfirm(action) => {
                    action.kind != AuthorityConfirmKind::Revoke
                }
                AuthorityOp::CriticalWriteConfirm(action) => {
                    action.disposition == CriticalWriteConfirmDisposition::Clear
                }
                _ => false,
            };
            if !approval {
                return None;
            }
            let hash = authority_entry_hash(entry).ok()?;
            if !fold.valid_entries.contains(&hash) {
                return None;
            }
            let seen = first_seen.get(&hash)?;
            // A replayed approval cannot restart the grace window. The strict
            // `now - start > window` predicate first changes at start+window+1.
            let deadline = std::iter::once(&entry.signer)
                .chain(&entry.cosigns)
                .filter_map(|signature| revoked_at.get(&signature.public_key))
                .filter_map(|revoked| seen.min(revoked).checked_add(window_secs)?.checked_add(1))
                .min()?;
            Some((hash, deadline))
        })
        .collect()
}

fn expired_stale_roster_approvals(
    entries: &[AuthorityLogEntry],
    fold: &AuthorityFold,
    first_seen: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: Option<u64>,
    window_secs: u64,
) -> BTreeSet<AuthorityEntryHash> {
    let Some(now) = now_secs else {
        return BTreeSet::new();
    };
    stale_roster_approval_deadlines(entries, fold, first_seen, window_secs)
        .into_iter()
        .filter_map(|(hash, deadline)| (deadline <= now).then_some(hash))
        .collect()
}

/// First still-future stale-roster change after an exact fold. Called only on
/// a cache miss, so hot checks do not rescan the authority log.
pub(super) fn next_stale_roster_deadline(
    entries: &[AuthorityLogEntry],
    fold: &AuthorityFold,
    first_seen: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: u64,
    window_secs: u64,
) -> Option<u64> {
    stale_roster_approval_deadlines(entries, fold, first_seen, window_secs)
        .into_values()
        .filter(|deadline| *deadline > now_secs)
        .min()
}

/// Project after the structural DAG fold has reached its fixed point. All
/// authorization consumers use this projection, including the readonly fold.
pub(super) fn apply_stale_roster_window(
    entries: &[AuthorityLogEntry],
    mut fold: AuthorityFold,
    first_seen: &BTreeMap<AuthorityEntryHash, u64>,
    now_secs: Option<u64>,
    window_secs: u64,
) -> AuthorityFold {
    let expired = expired_stale_roster_approvals(entries, &fold, first_seen, now_secs, window_secs);
    if expired.is_empty() {
        return fold;
    }
    // A fresh independently authorized rebind must survive expiry of its old
    // parent approval. Match the winning tuple, not just the bound key. Equal
    // tuples from multiple valid entries are usable if one fresh approval
    // supports them; divergent tuples already failed closed during the merge.
    for (key, binding) in &mut fold.actor_bindings {
        let has_live_approval = entries.iter().any(|entry| {
            let Ok(hash) = authority_entry_hash(entry) else {
                return false;
            };
            if !fold.valid_entries.contains(&hash) || expired.contains(&hash) {
                return false;
            }
            match &entry.op {
                AuthorityOp::BindActor {
                    authority_key,
                    actor_ref,
                    actor_class,
                    epoch,
                }
                | AuthorityOp::RebindActor {
                    authority_key,
                    actor_ref,
                    actor_class,
                    epoch,
                } => {
                    authority_key == key
                        && *actor_ref == binding.actor_ref
                        && *actor_class == binding.actor_class
                        && *epoch == binding.epoch
                }
                _ => false,
            }
        });
        if !has_live_approval {
            binding.status = ActorBindingStatus::Revoked;
        }
    }
    fold.critical_write_confirms
        .retain(|_, confirm| !expired.contains(&confirm.authority_entry_hash));
    for hash in expired {
        fold.valid_entries.remove(&hash);
        fold.issues
            .push(AuthorityFoldIssue::StaleRosterApproval(hash));
    }
    fold
}
