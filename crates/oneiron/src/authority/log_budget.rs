//! Pinned bounds on authority-fold work, and the store-door checks that keep
//! a stored log inside them (H72).
//!
//! The fold indexes every row's whole ancestry and probes each handoff by
//! folding its line again, so its work grows with the square of the log and
//! with the number of handoffs. Each signer may store a generous bound of
//! rows. The slip issuer's slip ops count toward no bound: every sign-in
//! mints one, so a busy owner's log gains thousands a year. The rows it
//! signs that only take authority away always land. Every door, local or
//! replicated, holds a row no owner, admin or install key signed: the fold
//! applies none. A fold handed more than its own bounds fails closed: it
//! holds no root and reads as a conflicted one, which every authority gate
//! refuses.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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

/// The log's consent structure, read from its signed rows alone, so the
/// fold's bounds and the store doors judge a row the same way.
#[derive(Debug, Default)]
pub(crate) struct AuthorityStructure {
    /// The verified genesis keys. A log with more than one has no admitters.
    roots: BTreeSet<AuthorityKey>,
    /// The keys whose signature vouches for a row: the genesis key, and
    /// each owner or admin key named by a signed re-root, rotation or
    /// enrollment that an admitter signed or cosigned, the fold's own
    /// consent rule.
    admitters: BTreeSet<AuthorityKey>,
    /// The slip issuers: the admitters that hold the owner role.
    issuers: BTreeSet<AuthorityKey>,
    /// Each machine and the install keys a slip issuer's revisions of it
    /// named. Such a key signs that machine's world edits.
    machine_keys: BTreeSet<(crate::EntityId, AuthorityKey)>,
}

fn signed_by(entry: &AuthorityLogEntry, keys: &BTreeSet<AuthorityKey>) -> bool {
    std::iter::once(&entry.signer)
        .chain(&entry.cosigns)
        .any(|signature| keys.contains(&signature.public_key))
}

fn is_consent_device(device: &DeviceAuthority) -> bool {
    device.roles & (ROLE_OWNER | ROLE_ADMIN) != 0
}

/// Every key the fold holds as a live owner is a slip issuer. Nothing
/// leaves the set, so a revocation the fold refuses never drops the
/// issuer, and slip rows a door stored uncounted never come to count
/// against the fold's bounds. An owner key leaves the host-rooted roster
/// only by a handoff, and a key a handoff retired signs nothing new at the
/// replicated door. A machine, agent or peer key, a stranger, and every
/// signer of a log without exactly one genesis key count as any other
/// signer.
pub(super) fn authority_structure<'a>(
    entries: impl Iterator<Item = &'a AuthorityLogEntry>,
) -> AuthorityStructure {
    let mut structure = AuthorityStructure::default();
    let mut root_roles = 0;
    let mut admissions: Vec<&'a AuthorityLogEntry> = Vec::new();
    let mut profiles = Vec::new();
    for entry in entries {
        match &entry.op {
            AuthorityOp::Genesis { device, .. } => {
                if device.key == *entry.signer_key()
                    && is_consent_device(device)
                    && verify_entry_signatures(entry).is_ok()
                {
                    structure.roots.insert(device.key.clone());
                    root_roles |= device.roles;
                }
            }
            AuthorityOp::MachineProfile(profile) => profiles.push((entry, profile)),
            op => {
                if admits_device(op).is_some_and(is_consent_device) {
                    admissions.push(entry);
                }
            }
        }
    }
    let Some(root) = structure
        .roots
        .first()
        .filter(|_| structure.roots.len() == 1)
    else {
        return structure;
    };
    structure.admitters.insert(root.clone());
    if root_roles & ROLE_OWNER != 0 {
        structure.issuers.insert(root.clone());
    }
    let mut grew = true;
    while grew {
        grew = false;
        admissions.retain(|entry| {
            if !signed_by(entry, &structure.admitters) {
                return true;
            }
            if verify_entry_signatures(entry).is_ok()
                && let Some(device) = admits_device(&entry.op)
            {
                if device.roles & ROLE_OWNER != 0 {
                    structure.issuers.insert(device.key.clone());
                }
                grew |= structure.admitters.insert(device.key.clone());
            }
            false
        });
    }
    for (entry, profile) in profiles {
        if structure.issuers.contains(entry.signer_key()) && verify_entry_signatures(entry).is_ok()
        {
            structure
                .machine_keys
                .insert((profile.machine, AuthorityKey::Ed25519(profile.machine_key)));
        }
    }
    structure
}

impl AuthorityStructure {
    /// Whether a key that may vouch for `entry` signed or cosigned it: an
    /// admitter, or, for a world edit, the install key of the machine it
    /// names, as its primary signer. A genesis vouches for itself when it is
    /// this log's only root. The caller verifies the signatures.
    fn vouches_for(&self, entry: &AuthorityLogEntry) -> bool {
        match &entry.op {
            AuthorityOp::Genesis { device, .. } => {
                device.key == *entry.signer_key()
                    && is_consent_device(device)
                    && self.roots.iter().all(|root| *root == device.key)
            }
            AuthorityOp::WorldPrivacy(edit) => self
                .machine_keys
                .contains(&(edit.machine, entry.signer_key().clone())),
            _ => signed_by(entry, &self.admitters),
        }
    }

    /// Whether `key` signs rows the fold may come to admit: an admitter, or
    /// an install key, though the local fold may not hold it yet.
    fn stands(&self, key: &AuthorityKey) -> bool {
        self.admitters.contains(key)
            || self
                .machine_keys
                .iter()
                .any(|(_, machine_key)| machine_key == key)
    }
}

/// The slip issuers of `entries`: see [`authority_structure`].
#[cfg(test)]
pub(super) fn slip_issuers(entries: &[AuthorityLogEntry]) -> BTreeSet<AuthorityKey> {
    authority_structure(entries.iter()).issuers
}

/// The hashes of the rows no fold bound counts: the slip issuers' slip ops.
pub(super) fn uncounted_rows(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> BTreeSet<AuthorityEntryHash> {
    let issuers = authority_structure(by_hash.values()).issuers;
    by_hash
        .iter()
        .filter(|(_, entry)| is_slip_op(&entry.op) && issuers.contains(entry.signer_key()))
        .map(|(hash, _)| *hash)
        .collect()
}

/// Refuses, before any work, a log with more counted rows or handoffs than
/// one fold may read, naming the signer with the most of them.
pub(super) fn refuse_over_budget(entries: &[AuthorityLogEntry]) -> Option<AuthorityFold> {
    let issuers = authority_structure(entries.iter()).issuers;
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

/// What the store doors read of the stored log: its consent structure, and
/// each signer's stored rows. Built once per authority generation.
#[derive(Debug)]
pub(crate) struct AuthorityDoorView {
    structure: AuthorityStructure,
    /// Per signer: its stored rows, and how many of them are slip ops or
    /// only restrict.
    rows: BTreeMap<AuthorityKey, (usize, usize)>,
    /// The stored handoffs a slip issuer signed.
    issuer_handoffs: usize,
}

#[cfg(test)]
thread_local! {
    static DOOR_VIEW_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
thread_local! {
    static DOOR_OPEN_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `body` with this thread's authority doors open, so a test can build
/// a log no door stores, such as one with a rival genesis.
#[cfg(test)]
pub(crate) fn with_authority_doors_open_for_test<T>(body: impl FnOnce() -> T) -> T {
    DOOR_OPEN_FOR_TEST.with(|open| open.set(true));
    let result = body();
    DOOR_OPEN_FOR_TEST.with(|open| open.set(false));
    result
}

/// How many door views this thread has built.
#[cfg(test)]
pub(crate) fn door_view_builds_for_test() -> usize {
    DOOR_VIEW_BUILDS.with(std::cell::Cell::get)
}

fn door_view(store: &Store, txn: &heed::RoTxn<'_>) -> crate::error::Result<Arc<AuthorityDoorView>> {
    super::readonly_fold::per_authority_generation(store, txn, &store.authority_door_view, || {
        #[cfg(test)]
        DOOR_VIEW_BUILDS.with(|builds| builds.set(builds.get() + 1));
        let mut entries = Vec::new();
        for (_, body) in authority_log_rows_in_txn(store, txn)? {
            entries.push(decode_authority_log_entry_body(&body)?);
        }
        let structure = authority_structure(entries.iter());
        let mut rows = BTreeMap::<AuthorityKey, (usize, usize)>::new();
        let mut issuer_handoffs = 0;
        for entry in &entries {
            let (stored, exempt) = rows.entry(entry.signer_key().clone()).or_default();
            *stored += 1;
            *exempt += usize::from(is_slip_op(&entry.op) || only_restricts(&entry.op));
            issuer_handoffs +=
                usize::from(is_handoff(entry) && structure.issuers.contains(entry.signer_key()));
        }
        Ok(AuthorityDoorView {
            structure,
            rows,
            issuer_handoffs,
        })
    })
}

/// Whether `entry`'s signer has standing to store a replicated row: a key
/// some valid row admitted (live, revoked or retired), a machine's install
/// key, or a key the stored log's structure admits though the fold does
/// not hold it yet, such as an owner key a pre-handoff rotation named. A
/// key none of these name signs no valid row, so its rows wait for the
/// enrollment instead of being stored.
pub(crate) fn signer_has_standing(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    entry: &AuthorityLogEntry,
) -> crate::error::Result<bool> {
    let signer = entry.signer_key();
    if fold.roster.contains_key(signer)
        || fold.retired_keys.contains(signer)
        || fold
            .machines
            .values()
            .any(|machine| AuthorityKey::Ed25519(machine.profile.machine_key) == *signer)
    {
        return Ok(true);
    }
    Ok(door_view(store, txn)?.structure.stands(signer))
}

/// A row the consent structure rests on: a genesis, an owner or admin
/// admission, or a machine revision.
fn is_structural(op: &AuthorityOp) -> bool {
    matches!(
        op,
        AuthorityOp::Genesis { .. } | AuthorityOp::MachineProfile(_)
    ) || admits_device(op).is_some_and(is_consent_device)
}

/// `rows` (hash, body, entry), each after every row among them it names as
/// a parent. A store door reads a row's slip issuers from the rows already
/// staged, so an import stages first the rows the consent structure rests
/// on, then their other ancestors, then the rest: every row outside that
/// closure is judged under the whole history's structure, whatever order
/// the caller gave. Ties keep the order given.
pub(super) fn parents_first(
    rows: Vec<(AuthorityEntryHash, Vec<u8>, AuthorityLogEntry)>,
) -> Vec<(AuthorityEntryHash, Vec<u8>, AuthorityLogEntry)> {
    let at: BTreeMap<_, _> = rows
        .iter()
        .enumerate()
        .map(|(index, (hash, ..))| (*hash, index))
        .collect();
    let parents = |index: usize| {
        rows[index]
            .2
            .parent_hashes
            .iter()
            .filter_map(|parent| at.get(parent).copied())
    };
    let mut rank = vec![2_u8; rows.len()];
    let mut stack: Vec<_> = (0..rows.len())
        .filter(|index| is_structural(&rows[*index].2.op))
        .collect();
    for index in &stack {
        rank[*index] = 0;
    }
    while let Some(index) = stack.pop() {
        for parent in parents(index) {
            if rank[parent] == 2 {
                rank[parent] = 1;
                stack.push(parent);
            }
        }
    }
    let mut waiting = vec![0_usize; rows.len()];
    let mut children = vec![Vec::new(); rows.len()];
    for (index, waiting) in waiting.iter_mut().enumerate() {
        for parent in parents(index) {
            *waiting += 1;
            children[parent].push(index);
        }
    }
    let mut ready: BTreeSet<_> = (0..rows.len())
        .filter(|index| waiting[*index] == 0)
        .map(|index| (rank[index], index))
        .collect();
    let mut order = Vec::with_capacity(rows.len());
    while let Some((_, index)) = ready.pop_first() {
        order.push(index);
        for child in &children[index] {
            waiting[*child] -= 1;
            if waiting[*child] == 0 {
                ready.insert((rank[*child], *child));
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

/// A machine revision that only restricts, judged against the machine the
/// local fold holds under the same keys: the demotion of a "yours" head
/// that is not conflicted, as the next revision, or an owned but not
/// "yours" revision no newer than the head. Such a sibling or older
/// revision never wins the merge, so concurrent demotions land in any
/// order, a removal included. A newer one could clear a conflict and
/// widen a world, so it counts.
fn restricts_machine(fold: &AuthorityFold, op: &AuthorityOp) -> bool {
    let AuthorityOp::MachineProfile(profile) = op else {
        return false;
    };
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    matches!(profile.role, MachineRole::Owned(_))
        && profile.role != yours
        && fold.machines.get(&profile.machine).is_some_and(|known| {
            known.profile.machine_key == profile.machine_key
                && known.profile.encryption_key == profile.encryption_key
                && (profile.revision <= known.profile.revision
                    || (known.profile.role == yours
                        && !known.conflicted
                        && Some(profile.revision) == known.profile.revision.checked_add(1)))
        })
}

/// What a store door does with an AUTHORITY_LOG row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityDoor {
    Lands,
    /// The row would take its signer past its bound, or the log past
    /// [`MAX_AUTHORITY_FOLD_HANDOFFS`].
    AtBound,
    /// No key that may vouch for the row signed it. The fold applies no row
    /// without an owner's or admin's consent, and no world edit but its
    /// machine's, so the row waits, as a stranger's does, instead of
    /// growing the log toward the fold's bounds.
    Unowned,
}

/// The door's verdict on storing `entry`, at every door, local or
/// replicated. A row already stored always lands. A slip issuer's slip ops
/// and the rows it signs that only restrict are never refused and count
/// toward no bound, and its machine demotions land past the bound. Every
/// row any other key stores counts toward that key's bound, whatever it
/// does, and a handoff it signs is refused at once: the fold applies no
/// slip op, restriction or handoff such a key signs. The door reads the
/// stored log's structure as the fold's bounds do.
pub(crate) fn authority_door(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: crate::HostingPrivacyPosture,
    entry: &AuthorityLogEntry,
) -> crate::error::Result<AuthorityDoor> {
    #[cfg(test)]
    if DOOR_OPEN_FOR_TEST.with(std::cell::Cell::get) {
        return Ok(AuthorityDoor::Lands);
    }
    if authority_row_resident(store, txn, entry)? {
        return Ok(AuthorityDoor::Lands);
    }
    let view = door_view(store, txn)?;
    if !view.structure.vouches_for(entry) || verify_entry_signatures(entry).is_err() {
        return Ok(AuthorityDoor::Unowned);
    }
    let signer = entry.signer_key();
    let issuer = view.structure.issuers.contains(signer);
    let (stored, exempt) = view.rows.get(signer).copied().unwrap_or_default();
    let mut rows = stored + 1;
    if issuer {
        if is_slip_op(&entry.op) || only_restricts(&entry.op) {
            return Ok(AuthorityDoor::Lands);
        }
        rows -= exempt;
    }
    if is_handoff(entry) && (!issuer || view.issuer_handoffs >= MAX_AUTHORITY_FOLD_HANDOFFS) {
        return Ok(AuthorityDoor::AtBound);
    }
    if rows <= rows_per_signer() {
        return Ok(AuthorityDoor::Lands);
    }
    if !issuer {
        return Ok(AuthorityDoor::AtBound);
    }
    let fold = authority_view_readonly_for_store_in_txn(store, posture, txn)?;
    Ok(if restricts_machine(&fold, &entry.op) {
        AuthorityDoor::Lands
    } else {
        AuthorityDoor::AtBound
    })
}
