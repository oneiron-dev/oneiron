//! Clock-free expiry of approvals resting on a subsequently revoked roster.
//!
//! Expiry removes a reusable approval from the LIVE fold projection, not from
//! historical transition validation. Deleting its ancestry link would also
//! delete a descendant revocation or an independently authorized fresh rebind.
//! Spent confirm nonces and conflict poison likewise remain spent forever.
//! Roster-changing ops are not approvals here: Bind/RebindActor, federation
//! confirms, critical-write confirms and every machine standing short of a
//! removal carry the reusable approval facts.
//!
//! A forked granting row (its `SequenceFork` recorded) whose signer or a
//! cosigner the final roster holds revoked expires at once, with no window
//! and no clock; owner handovers and residence directives join the approvals
//! there ([`revoked_fork_approvals`]), and so do a federation pact's Connect,
//! Rescope and Promote, whose pact is then held suspended while the expired
//! row still shapes it ([`suspend_pacts_of_expired_rows`]). The same rule
//! holds: no transition changes and no descendant goes.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// A row the stale-roster window reads: its signed entry, and its hash. A
/// caller that holds each row's hash already passes it in, so no row is
/// hashed again (FIX 12309); a bare entry is hashed here.
pub(super) trait LogRow {
    fn entry(&self) -> &AuthorityLogEntry;
    /// None where the entry does not hash, which the window skips.
    fn entry_hash(&self) -> Option<AuthorityEntryHash>;
}

impl LogRow for AuthorityLogEntry {
    fn entry(&self) -> &AuthorityLogEntry {
        self
    }

    fn entry_hash(&self) -> Option<AuthorityEntryHash> {
        authority_entry_hash(self).ok()
    }
}

impl LogRow for &AuthorityLogEntry {
    fn entry(&self) -> &AuthorityLogEntry {
        self
    }

    fn entry_hash(&self) -> Option<AuthorityEntryHash> {
        authority_entry_hash(self).ok()
    }
}

impl LogRow for (AuthorityEntryHash, &AuthorityLogEntry) {
    fn entry(&self) -> &AuthorityLogEntry {
        self.1
    }

    fn entry_hash(&self) -> Option<AuthorityEntryHash> {
        Some(self.0)
    }
}

/// Each row's first-seen seconds, as the window reads them: a map built for
/// one fold, or the persistent one a resumed fold's base shares (FIX 12308).
pub(super) trait FirstSeenMap {
    fn get(&self, hash: &AuthorityEntryHash) -> Option<&u64>;
}

impl FirstSeenMap for BTreeMap<AuthorityEntryHash, u64> {
    fn get(&self, hash: &AuthorityEntryHash) -> Option<&u64> {
        BTreeMap::get(self, hash)
    }
}

/// The machine profile `op` files on its machine's chain: a profile row's,
/// or the enrolment an owner's join of a machine born of a restore carries
/// inline, which the fold files under the join's own entry
/// (KIT-JOIN-ONE-R-ROW = A). A join of a held enrolment files none: the row
/// it joins filed it. Every reader of a roster revision's row reads it here,
/// so an inline join expires, renews and carries as a profile row does
/// (REVIEW-9539 round 2 P1, stale_roster.rs:141).
pub(super) fn filed_machine_profile(op: &AuthorityOp) -> Option<&MachineProfile> {
    match op {
        AuthorityOp::MachineProfile(profile)
        | AuthorityOp::RestoredMachineJoin(RestoredMachineJoin {
            enrolment: RestoredJoinEnrolment::Inline(profile),
            ..
        }) => Some(profile),
        _ => None,
    }
}

/// Whether `op` revokes a device, rotates a key, re-roots the vault or
/// appoints a successor root: the rows the window reads revocations from.
/// Over rows with none of these it expires no approval and finds no deadline.
pub(super) fn revokes_roster_key(op: &AuthorityOp) -> bool {
    matches!(
        op,
        AuthorityOp::RevokeDevice { .. }
            | AuthorityOp::RotateKey { .. }
            | AuthorityOp::ReRoot { .. }
            | AuthorityOp::RootAppointment(_)
    )
}

/// Whether a row of `op` is an approval the window weighs: a binding or a
/// rebinding, a federation confirm other than a revoke, a critical-write
/// clearance, or a machine standing short of a removal that names no owner
/// act. An owner answer rests on its carrier's act, never on a roster key,
/// so no roster revocation expires it (C3).
fn is_window_approval(op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::BindActor { .. } | AuthorityOp::RebindActor { .. } => true,
        AuthorityOp::FederationConfirm(action) => action.kind != AuthorityConfirmKind::Revoke,
        AuthorityOp::CriticalWriteConfirm(action) => {
            action.disposition == CriticalWriteConfirmDisposition::Clear
        }
        op => filed_machine_profile(op)
            .is_some_and(|profile| profile.role != MachineRole::Removed && profile.act.is_none()),
    }
}

/// Earliest second at which each currently valid approval becomes stale.
/// A checked deadline at the u64 ceiling never arrives, just as the original
/// saturating-subtraction predicate could never exceed its window there.
fn stale_roster_approval_deadlines<E: LogRow>(
    entries: &[E],
    fold: &AuthorityFold,
    first_seen: &dyn FirstSeenMap,
    window_secs: u64,
) -> BTreeMap<AuthorityEntryHash, u64> {
    let mut revoked_at = BTreeMap::<AuthorityKey, u64>::new();
    for row in entries {
        let entry = row.entry();
        let Some(hash) = row.entry_hash() else {
            continue;
        };
        // A device revocation the fold applied as a verified fact counts
        // where its row did not stay valid (Sol review F1 on #8608).
        if !fold.valid_entries.contains(&hash) && !fold.verified_device_revocations.contains(&hash)
        {
            continue;
        }
        let Some(seen) = first_seen.get(&hash).copied() else {
            continue;
        };
        let keys = match &entry.op {
            AuthorityOp::RevokeDevice { revoked_key } => vec![revoked_key.clone()],
            AuthorityOp::RotateKey { old_key, .. } => vec![old_key.clone()],
            AuthorityOp::ReRoot { new_device }
            | AuthorityOp::RootAppointment(RootAppointment {
                successor: new_device,
                ..
            }) => fold
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
        .filter_map(|row| {
            let entry = row.entry();
            if !is_window_approval(&entry.op) {
                return None;
            }
            let hash = row.entry_hash()?;
            // An anchor's mark rests on no roster key, even one a roster
            // enrolled under the anchor's public key and then revoked.
            if !fold.valid_entries.contains(&hash) || fold.anchor_entries.contains(&hash) {
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

fn expired_stale_roster_approvals<E: LogRow>(
    entries: &[E],
    fold: &AuthorityFold,
    first_seen: &dyn FirstSeenMap,
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

/// Whether a forked row of `op` expires at once when the final roster holds
/// its signer or a cosigner revoked: every approval the window weighs
/// ([`is_window_approval`]; a machine profile row is a restriction and never
/// forks, an owner's join that files one inline may), the owner handovers
/// and residence directives, whose readers take only valid rows, and a
/// federation pact's Connect, Rescope and Promote, whose pact reads no row
/// ([`suspend_pacts_of_expired_rows`]). A Disconnect or a Dissolve only takes
/// away and never forks.
fn expires_as_revoked_fork(op: &AuthorityOp) -> bool {
    is_window_approval(op)
        || matches!(
            op,
            AuthorityOp::OwnerHandover(_) | AuthorityOp::ResidenceDirective(_)
        )
        || matches!(
            op,
            AuthorityOp::FederationLifecycle(action) if matches!(
                action.kind,
                FederationLifecycleKind::Connect
                    | FederationLifecycleKind::Rescope
                    | FederationLifecycleKind::Promote
            )
        )
}

/// Whether lifecycle `action` set the ceiling `pact` stands on: a Connect or
/// a dual-signed re-pact whose epoch, scope commitment and nonce the pact
/// still carries. A Promote keeps the ceiling it found; a narrowing sets none.
fn sets_ceiling(action: &FederationLifecycleAction, pact: &FederationPactState) -> bool {
    matches!(
        action.kind,
        FederationLifecycleKind::Connect | FederationLifecycleKind::Rescope
    ) && action.effective_scope.is_none()
        && action.pact_epoch == pact.scope_epoch
        && action.scope_digest == Some(pact.scope_digest)
        && action.pact_nonce == pact.pact_nonce
}

/// Whether lifecycle `renewal` backs the peer `pact` is pinned to: its peer
/// vault, its grant, and the peer owner key its gesture verified. Equal
/// competitors may pin different peers, and the merge keeps the lesser
/// (`op_apply::merge_pact_states`), so a live row that pins another peer
/// renews no ceiling an expired row pinned. A re-pact keeps the pin it found
/// even when another key of the peer's roster signed its gesture
/// (`op_apply::apply_federation_lifecycle`), so such a re-pact backs no pin
/// either: a pact whose pin only expired rows back stays held until a row the
/// pinned key consents to, or an end (REVIEW-9609 round 2).
fn backs_peer_pin(renewal: &FederationLifecycleAction, pact: &FederationPactState) -> bool {
    renewal.peer_vault_id == pact.peer_vault_id
        && renewal.grant_ref == pact.grant_ref
        && renewal
            .gesture
            .as_ref()
            .is_some_and(|gesture| gesture.signer == pact.peer_owner_key)
}

/// Why a narrowing or a Promote of a pact the expiry holds suspended is
/// refused.
const PACT_HELD_SUSPENDED: &str = "this pact is held suspended: a narrowing or a promote would \
                                   keep the ceiling an expired row set; end or re-pact it";

/// The rows an end or a re-pact (`op`: a Disconnect, a Dissolve or a
/// dual-signed Rescope) of a pact the expiry holds suspended names beside the
/// heads: that pact's lifecycle rows the projection took out
/// (`StaleRosterApproval`) that no head holds in its ancestry. The pact rests
/// on them, and an expired row leaves the heads, so only with them in its
/// ancestry does the act find the pact at the epoch it keeps. The act ends
/// the pact or sets a new ceiling, so nothing an expired row set stands past
/// it. Empty for every other op.
///
/// # Errors
/// A narrowing or a Promote of a suspended pact: either would keep the
/// ceiling it holds, and the fold refuses both on a pact a merge suspended,
/// so the projected status refuses them here before anything is signed
/// (REVIEW-9609 round 2). Storage errors.
pub(super) fn suspended_pact_rows_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    op: &AuthorityOp,
) -> crate::error::Result<BTreeSet<AuthorityEntryHash>> {
    let AuthorityOp::FederationLifecycle(action) = op else {
        return Ok(BTreeSet::new());
    };
    if fold
        .federation_pacts
        .get(&action.pact_id)
        .is_none_or(|pact| pact.status != FederationPactStatus::Suspended)
    {
        return Ok(BTreeSet::new());
    }
    match action.kind {
        FederationLifecycleKind::Disconnect | FederationLifecycleKind::Dissolve => {}
        FederationLifecycleKind::Rescope if action.effective_scope.is_none() => {}
        FederationLifecycleKind::Rescope | FederationLifecycleKind::Promote => {
            return Err(crate::authority::authority_refused(PACT_HELD_SUSPENDED));
        }
        FederationLifecycleKind::Connect => return Ok(BTreeSet::new()),
    }
    let mut rows = BTreeSet::new();
    for issue in &fold.issues {
        let AuthorityFoldIssue::StaleRosterApproval(hash) = issue else {
            continue;
        };
        if let Some(entry) = super::retired_signers::stored_authority_row(store, txn, hash)?
            && matches!(
                &entry.op,
                AuthorityOp::FederationLifecycle(row) if row.pact_id == action.pact_id
            )
        {
            rows.insert(*hash);
        }
    }
    drop_rows_in_ancestry_in_txn(store, txn, &fold.append_heads, &mut rows)?;
    Ok(rows)
}

/// Takes out of `rows` each row that `heads` hold, a head itself or one in
/// a head's ancestry, walking the stored rows' parents down from the heads
/// until `rows` is empty. An act that names the heads holds those already,
/// and naming them again would only spend its parent count (REVIEW-9609
/// round 2). A row the walk cannot read, below an adopted image this vault
/// does not hold, ends its path, so a row the walk never reaches stays.
fn drop_rows_in_ancestry_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    heads: &BTreeSet<AuthorityEntryHash>,
    rows: &mut BTreeSet<AuthorityEntryHash>,
) -> crate::error::Result<()> {
    let mut seen = BTreeSet::new();
    let mut below: Vec<AuthorityEntryHash> = heads.iter().copied().collect();
    while !rows.is_empty() {
        let Some(hash) = below.pop() else {
            break;
        };
        if !seen.insert(hash) {
            continue;
        }
        rows.remove(&hash);
        if let Some(entry) = super::retired_signers::stored_authority_row(store, txn, &hash)? {
            below.extend(entry.parent_hashes.iter().copied());
        }
    }
    Ok(())
}

/// Holds suspended each active pact an expired lifecycle row still shapes:
/// the ceiling the pact stands on ([`sets_ceiling`]), or a narrowing that
/// stands, which may have lifted its own party's earlier one. A pact keeps
/// no record of the rows that set it up, so the rows read here are that
/// record: the ceiling's epoch, commitment and nonce, and each narrowing's
/// entry. Suspended confers nothing, and the fold still takes an honest
/// Disconnect, Dissolve or re-pact of it at the epoch it keeps. The grant's
/// binding stays: without one the grant would read as unpacted, the legacy
/// allow. A live row that sets the same ceiling (an equal competitor the
/// merge combined) and backs the pin renews it, as a live row renews a
/// binding's tuple. The pinned peer key needs live support too: a pact
/// whose pin an expired row backs and no live row backs stays held, even
/// once a re-pact another key of the peer signed moved its ceiling on
/// (REVIEW-9609 round 2). A pact that ended stays ended: an end confers
/// nothing, and reopening it would give back what it took.
fn suspend_pacts_of_expired_rows<E: LogRow>(
    entries: &[E],
    fold: &mut AuthorityFold,
    expired: &BTreeSet<AuthorityEntryHash>,
) {
    let lifecycle_rows: Vec<(AuthorityEntryHash, &FederationLifecycleAction)> = entries
        .iter()
        .filter_map(|row| match &row.entry().op {
            AuthorityOp::FederationLifecycle(action) => Some((row.entry_hash()?, action)),
            _ => None,
        })
        .collect();
    let mut held = BTreeSet::new();
    for (hash, action) in &lifecycle_rows {
        if !expired.contains(hash) {
            continue;
        }
        let Some(pact) = fold.federation_pacts.get(&action.pact_id) else {
            continue;
        };
        if pact.status != FederationPactStatus::Active {
            continue;
        }
        let shapes = if action.effective_scope.is_some() {
            pact.narrowings.contains_key(hash)
        } else {
            // Whether a live row of the pact does what `backs` asks.
            let live_row = |backs: &dyn Fn(&FederationLifecycleAction) -> bool| {
                lifecycle_rows.iter().any(|(other, renewal)| {
                    renewal.pact_id == action.pact_id
                        && fold.valid_entries.contains(other)
                        && !expired.contains(other)
                        && backs(renewal)
                })
            };
            (sets_ceiling(action, pact)
                && !live_row(&|renewal| {
                    sets_ceiling(renewal, pact) && backs_peer_pin(renewal, pact)
                }))
        };
        if shapes {
            held.insert(action.pact_id);
        }
    }
    for pact_id in held {
        if let Some(pact) = fold.federation_pacts.get_mut(&pact_id) {
            pact.status = FederationPactStatus::Suspended;
        }
    }
}

/// The valid granting rows the fold counted as forks of their signer's
/// sequence (`SequenceFork`) whose signer or any cosigner the final roster
/// holds revoked. Each expires at once, with no window: a revocation
/// projects onto the history concurrent with it, and a grant authorizes only
/// its causal descendants (ONE-REVOKE-DURABILITY), so a row its signer
/// withheld below its floor keeps nothing a revoked key consented to (case
/// C6, Engine RULING SEQ-FLOOR-S-WITHHELD-COSIGN-SHAPE = A). The set reads
/// rows only, no first-seen time and no clock, so every install and every
/// fold path, an image's adopter too, finds the same set.
fn revoked_fork_approvals<E: LogRow>(
    entries: &[E],
    fold: &AuthorityFold,
) -> BTreeSet<AuthorityEntryHash> {
    let forks: BTreeSet<AuthorityEntryHash> = fold
        .issues
        .iter()
        .filter_map(|issue| match issue {
            AuthorityFoldIssue::SequenceFork(hash) => Some(*hash),
            _ => None,
        })
        .collect();
    if forks.is_empty() {
        return BTreeSet::new();
    }
    let revoked = |key: &AuthorityKey| fold.roster.get(key).is_some_and(|device| device.revoked);
    entries
        .iter()
        .filter_map(|row| {
            let entry = row.entry();
            if !expires_as_revoked_fork(&entry.op) {
                return None;
            }
            let hash = row.entry_hash()?;
            (forks.contains(&hash)
                && fold.valid_entries.contains(&hash)
                && !fold.anchor_entries.contains(&hash)
                && std::iter::once(&entry.signer)
                    .chain(&entry.cosigns)
                    .any(|signature| revoked(&signature.public_key)))
            .then_some(hash)
        })
        .collect()
}

/// The valid approvals the stale-roster window could expire: each rests on a
/// key revoked since. Whether one has expired turns on an install's own
/// first-seen clock, so a portable checkpoint image declares them unresolved
/// rather than deciding them (OF-469, checkpoint v2).
pub(super) fn stale_roster_subject_approvals<E: LogRow>(
    entries: &[E],
    fold: &AuthorityFold,
) -> BTreeSet<AuthorityEntryHash> {
    let seen: BTreeMap<_, _> = entries
        .iter()
        .filter_map(|row| Some((row.entry_hash()?, 0)))
        .collect();
    stale_roster_approval_deadlines(entries, fold, &seen, 0)
        .into_keys()
        .collect()
}

/// First still-future stale-roster change after an exact fold. Called only on
/// a cache miss, so hot checks do not rescan the authority log.
pub(super) fn next_stale_roster_deadline<E: LogRow>(
    entries: &[E],
    fold: &AuthorityFold,
    first_seen: &dyn FirstSeenMap,
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
/// The approvals it expired come back beside: the valid entries it took out,
/// the window's on this install's clock and the revoked forks' at once
/// ([`revoked_fork_approvals`], with or without a clock). A pact an expired
/// row still shapes is held suspended ([`suspend_pacts_of_expired_rows`]).
pub(super) fn apply_stale_roster_window<E: LogRow>(
    entries: &[E],
    mut fold: AuthorityFold,
    first_seen: &dyn FirstSeenMap,
    now_secs: Option<u64>,
    window_secs: u64,
) -> (AuthorityFold, BTreeSet<AuthorityEntryHash>) {
    let mut expired =
        expired_stale_roster_approvals(entries, &fold, first_seen, now_secs, window_secs);
    expired.extend(revoked_fork_approvals(entries, &fold));
    if expired.is_empty() {
        return (fold, expired);
    }
    // A fresh independently authorized rebind must survive expiry of its old
    // parent approval. Match the winning tuple, not just the bound key. Equal
    // tuples from multiple valid entries are usable if one fresh approval
    // supports them; divergent tuples already failed closed during the merge.
    for (key, binding) in &mut fold.actor_bindings {
        let has_live_approval = entries.iter().any(|row| {
            let Some(hash) = row.entry_hash() else {
                return false;
            };
            if !fold.valid_entries.contains(&hash) || expired.contains(&hash) {
                return false;
            }
            match &row.entry().op {
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
    // A machine stands on the revision that won. Once that revision is
    // stale it is not live here, until a key still on the roster signs the
    // same standing again: a roster entry, never an anchor's copy of it, and
    // for the trusted chain only a mark it accepts (Sol code-R2 S2-F1). An
    // anchor's own chain rests on no roster key, so it never goes stale.
    let renewed = |revision: &MachineRevision, trusted: bool| {
        entries.iter().any(|row| {
            filed_machine_profile(&row.entry().op) == Some(&revision.profile)
                && row.entry_hash().is_some_and(|hash| {
                    fold.valid_entries.contains(&hash)
                        && !expired.contains(&hash)
                        && !fold.anchor_entries.contains(&hash)
                        && (!trusted || fold.accepted_roster_marks.contains(&hash))
                })
        })
    };
    for folded in fold.machines.values_mut() {
        for (revision, trusted) in [
            (folded.roster.as_mut(), false),
            (folded.roster_trusted.as_mut(), true),
        ] {
            if let Some(revision) = revision
                && expired.contains(&revision.entry)
            {
                revision.stale = !renewed(revision, trusted);
            }
        }
    }
    fold.critical_write_confirms
        .retain(|_, confirm| !expired.contains(&confirm.authority_entry_hash));
    suspend_pacts_of_expired_rows(entries, &mut fold, &expired);
    for hash in &expired {
        fold.valid_entries.remove(hash);
        fold.issues
            .push(AuthorityFoldIssue::StaleRosterApproval(*hash));
    }
    (fold, expired)
}

/// The valid roster marks a key P1 accepts signed, judged as the trusted chain
/// judges them (`ClaimIndex::accepted_roster`): each heads its machine's roster
/// chain in its own fold state, signed by a key owner-held there, and on a
/// hosted fold that key stays outside the host's custody on the merged history,
/// or an admitted owner answer, which custody never reaches
/// ([`MarkProof::accepted`], the one predicate the resumed folds share).
/// Owned marks and node profiles alike; an anchor's mark heads no roster chain.
/// Only these renew a stale trusted roster revision (Sol code-R2 S2-F1,
/// code-R3 S3-F2, code-R4 S4-F1); an answer's profile names its act, so it
/// renews no roster-signed revision.
pub(super) fn accepted_roster_marks(
    merged: &FoldState,
    entries: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    valid: &ValidEntries,
) -> BTreeSet<AuthorityEntryHash> {
    valid
        .iter()
        .filter(|hash| {
            let Some(profile) = entries
                .get(*hash)
                .and_then(|entry| filed_machine_profile(&entry.op))
            else {
                return false;
            };
            states
                .get(*hash)
                .and_then(|own| own.machines.get(&profile.machine))
                .and_then(|chains| chains.get(&MachineAdmitter::Roster))
                .is_some_and(|chain| {
                    chain.head.entry == **hash
                        && MarkProof::of(&chain.head).is_some_and(|proof| proof.accepted(merged))
                })
        })
        .copied()
        .collect()
}
