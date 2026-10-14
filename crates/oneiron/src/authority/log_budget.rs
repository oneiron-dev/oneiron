//! Pinned bounds on authority-fold work, and the store-door checks that keep
//! a stored log inside them (H72).
//!
//! The fold indexes every row's whole ancestry and probes each handoff by
//! folding its line again, so its work grows with the square of the log and
//! with the number of handoffs. Every door, local or replicated, holds a row
//! no owner, admin or install key signed: the fold applies none. The owner's
//! work, any row a slip issuer signs or cosigns, never meets a bound (the
//! owner's rate law, rule 5): the fold's own bounds stay its limit, and the
//! log's headroom check warns the owner at half of what one fold holds. The slip issuer's
//! slip ops count toward no bound at all: every sign-in mints one, so a busy
//! owner's log gains thousands a year. Any other key stores up to the
//! `authority_log_signer_bound` policy row; past it, its rows wait, never
//! refused, a typed check asks the owner, and raising the row lands them on
//! the next drain. A key's first revocation of a device or binding the fold
//! holds live always lands. A fold handed more than its own bounds fails
//! closed: it holds no root and reads as a conflicted one, which every
//! authority gate refuses.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::*;
use crate::store::Store;

/// The fold's unit of bounds, and the default of the
/// `authority_log_signer_bound` policy row: the rows a key no slip issuer
/// vouches for stores before the rest wait.
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

/// The rows a signer stores before the rest wait, unless a slip issuer
/// signed or cosigned them: the policy row, or a test's scaled bound.
fn signer_bound(store: &Store, txn: &heed::RoTxn<'_>) -> crate::error::Result<usize> {
    #[cfg(test)]
    if let Some(rows) = ROWS_PER_SIGNER_FOR_TEST.with(std::cell::Cell::get) {
        return Ok(rows);
    }
    let bound = authority_observation_policy_in_txn(store, txn)?.log_signer_bound;
    Ok(usize::try_from(bound).unwrap_or(usize::MAX))
}

/// The counted rows and slip-issuer handoffs at which the log warns of its
/// fold's headroom: the policy rows, or a test's scaled bound for rows.
fn headroom(store: &Store, txn: &heed::RoTxn<'_>) -> crate::error::Result<(usize, usize)> {
    let policy = authority_observation_policy_in_txn(store, txn)?;
    let handoffs = usize::try_from(policy.log_headroom_handoffs).unwrap_or(usize::MAX);
    #[cfg(test)]
    if let Some(rows) = ROWS_PER_SIGNER_FOR_TEST.with(std::cell::Cell::get) {
        return Ok((rows, handoffs));
    }
    let rows = usize::try_from(policy.log_headroom_rows).unwrap_or(usize::MAX);
    Ok((rows, handoffs))
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

pub(super) fn admits_device(op: &AuthorityOp) -> Option<&DeviceAuthority> {
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
    pub(super) issuers: BTreeSet<AuthorityKey>,
    /// Each machine and the install keys a slip issuer's revisions of it
    /// named. Such a key signs that machine's world edits.
    machine_keys: BTreeSet<(crate::EntityId, AuthorityKey)>,
}

fn signed_by(entry: &AuthorityLogEntry, keys: &BTreeSet<AuthorityKey>) -> bool {
    std::iter::once(&entry.signer)
        .chain(&entry.cosigns)
        .any(|signature| keys.contains(&signature.public_key))
}

pub(super) fn is_consent_device(device: &DeviceAuthority) -> bool {
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
    let mut builder: StructureBuilder<'a> = StructureBuilder::default();
    for entry in entries {
        builder.push(entry);
    }
    builder.settle();
    builder.structure
}

/// [`authority_structure`] grown a row at a time, as an import stages its
/// rows: the same structure for the same rows, in any order. A row that
/// waits for a grant is filed under each key that could give it, so a
/// settle visits only the rows its new grants wake.
#[derive(Debug, Default)]
pub(super) struct StructureBuilder<'a> {
    pub(super) structure: AuthorityStructure,
    root_roles: u16,
    /// Admissions and machine revisions pushed since the last settle.
    fresh: Vec<&'a AuthorityLogEntry>,
    /// Owner and admin admissions no admitter has signed yet, under each
    /// key that signed them.
    admissions: BTreeMap<AuthorityKey, Vec<&'a AuthorityLogEntry>>,
    /// Machine revisions whose primary signer is no slip issuer yet, under
    /// that signer.
    profiles: BTreeMap<AuthorityKey, Vec<&'a AuthorityLogEntry>>,
    /// The grants [`Self::settle`] made since the caller last took them.
    pub(super) grown: Vec<Grant>,
}

/// What [`StructureBuilder::settle`] granted a key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Grant {
    Admitter(AuthorityKey),
    Issuer(AuthorityKey),
    InstallKey(crate::EntityId, AuthorityKey),
}

impl<'a> StructureBuilder<'a> {
    /// Adds `entry` unsettled.
    pub(super) fn push(&mut self, entry: &'a AuthorityLogEntry) {
        match &entry.op {
            AuthorityOp::Genesis { device, .. } => {
                if device.key == *entry.signer_key()
                    && is_consent_device(device)
                    && verify_entry_signatures(entry).is_ok()
                {
                    self.structure.roots.insert(device.key.clone());
                    self.root_roles |= device.roles;
                }
            }
            AuthorityOp::MachineProfile(_) => self.fresh.push(entry),
            op => {
                if admits_device(op).is_some_and(is_consent_device) {
                    self.fresh.push(entry);
                }
            }
        }
    }

    /// Admits what the rows pushed so far admit. A log with more than one
    /// root admits nothing.
    pub(super) fn settle(&mut self) {
        let Some(root) = self
            .structure
            .roots
            .first()
            .filter(|_| self.structure.roots.len() == 1)
            .cloned()
        else {
            self.structure.admitters.clear();
            self.structure.issuers.clear();
            self.structure.machine_keys.clear();
            return;
        };
        let (mut admitted, mut issued) = (Vec::new(), Vec::new());
        if self.root_roles & ROLE_OWNER != 0 && self.structure.issuers.insert(root.clone()) {
            issued.push(root.clone());
        }
        if self.structure.admitters.insert(root.clone()) {
            admitted.push(root);
        }
        for entry in std::mem::take(&mut self.fresh) {
            if matches!(entry.op, AuthorityOp::MachineProfile(_)) {
                self.file_profile(entry);
            } else if signed_by(entry, &self.structure.admitters) {
                self.admit(entry, &mut admitted, &mut issued);
            } else {
                for signature in std::iter::once(&entry.signer).chain(&entry.cosigns) {
                    self.admissions
                        .entry(signature.public_key.clone())
                        .or_default()
                        .push(entry);
                }
            }
        }
        loop {
            if let Some(key) = admitted.pop() {
                for entry in self.admissions.remove(&key).unwrap_or_default() {
                    self.admit(entry, &mut admitted, &mut issued);
                }
                self.grown.push(Grant::Admitter(key));
            } else if let Some(key) = issued.pop() {
                for entry in self.profiles.remove(&key).unwrap_or_default() {
                    self.file_profile(entry);
                }
                self.grown.push(Grant::Issuer(key));
            } else {
                break;
            }
        }
    }

    /// Admits the key an admission an admitter signed names.
    fn admit(
        &mut self,
        entry: &AuthorityLogEntry,
        admitted: &mut Vec<AuthorityKey>,
        issued: &mut Vec<AuthorityKey>,
    ) {
        let Some(device) = admits_device(&entry.op) else {
            return;
        };
        if verify_entry_signatures(entry).is_err() {
            return;
        }
        if device.roles & ROLE_OWNER != 0 && self.structure.issuers.insert(device.key.clone()) {
            issued.push(device.key.clone());
        }
        if self.structure.admitters.insert(device.key.clone()) {
            admitted.push(device.key.clone());
        }
    }

    /// Takes a machine revision's install key when a slip issuer signed it,
    /// or files it under its signer.
    fn file_profile(&mut self, entry: &'a AuthorityLogEntry) {
        let signer = entry.signer_key();
        if !self.structure.issuers.contains(signer) {
            self.profiles.entry(signer.clone()).or_default().push(entry);
            return;
        }
        if let AuthorityOp::MachineProfile(profile) = &entry.op
            && verify_entry_signatures(entry).is_ok()
        {
            let key = AuthorityKey::Ed25519(profile.machine_key);
            if self
                .structure
                .machine_keys
                .insert((profile.machine, key.clone()))
            {
                self.grown.push(Grant::InstallKey(profile.machine, key));
            }
        }
    }
}

impl AuthorityStructure {
    /// Whether a key that may vouch for `entry` signed or cosigned it: an
    /// admitter, or, for a world edit, the install key of the machine it
    /// names, as its primary signer. A genesis vouches for itself when it is
    /// this log's only root. The caller verifies the signatures.
    pub(super) fn vouches_for(&self, entry: &AuthorityLogEntry) -> bool {
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
    /// Per signer: its stored rows.
    rows: BTreeMap<AuthorityKey, usize>,
    /// Each signer's stored revocations, by what they revoke.
    revocations: BTreeSet<(AuthorityKey, Revoked)>,
    /// The stored rows a fold counts: all but the slip issuers' slip ops.
    counted: usize,
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
        let mut rows = BTreeMap::<AuthorityKey, usize>::new();
        let mut revocations = BTreeSet::new();
        let (mut counted, mut issuer_handoffs) = (0, 0);
        for entry in &entries {
            *rows.entry(entry.signer_key().clone()).or_default() += 1;
            if let Some(revoked) = Revoked::of(&entry.op) {
                revocations.insert((entry.signer_key().clone(), revoked));
            }
            let issuer = structure.issuers.contains(entry.signer_key());
            counted += usize::from(!(issuer && is_slip_op(&entry.op)));
            issuer_handoffs += usize::from(issuer && is_handoff(entry));
        }
        Ok(AuthorityDoorView {
            structure,
            rows,
            revocations,
            counted,
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

/// What a revocation takes away: a device, or an actor binding. A machine
/// revision is no revocation here: the fold applies one only from an owner
/// key, which is a slip issuer, so no other key's removal ever restricts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Revoked {
    Device(AuthorityKey),
    Binding(AuthorityKey),
}

impl Revoked {
    fn of(op: &AuthorityOp) -> Option<Self> {
        match op {
            AuthorityOp::RevokeDevice { revoked_key } => Some(Self::Device(revoked_key.clone())),
            AuthorityOp::RevokeActor { authority_key, .. } => {
                Some(Self::Binding(authority_key.clone()))
            }
            _ => None,
        }
    }

    /// Whether the local fold holds it live. A revocation of nothing
    /// changes nothing, so it can wait like any other row.
    fn is_live(&self, fold: &AuthorityFold) -> bool {
        match self {
            Self::Device(key) => fold.roster.get(key).is_some_and(|device| !device.revoked),
            Self::Binding(key) => fold
                .actor_bindings
                .get(key)
                .is_some_and(|binding| binding.status == ActorBindingStatus::Active),
        }
    }
}

/// What a store door does with an AUTHORITY_LOG row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityDoor {
    Lands,
    /// The row waits: its signer, which no slip issuer vouched for here, is
    /// at its bound, or it is a handoff no slip issuer signed, which the
    /// fold never applies. A replica retries it on every drain.
    AtBound,
    /// No key that may vouch for the row signed it. The fold applies no row
    /// without an owner's or admin's consent, and no world edit but its
    /// machine's, so the row waits, as a stranger's does, instead of
    /// growing the log toward the fold's bounds.
    Unowned,
}

/// The door's verdict on storing `entry`, at every door, local or
/// replicated. A row already stored always lands. The owner's work, a row a
/// slip issuer signs or cosigns, always lands, but a handoff only when a
/// slip issuer signs it. Any other key's row lands while its signer is under
/// the `authority_log_signer_bound` row, and past it only as its first
/// revocation of a device or actor binding the fold holds live; the rest
/// wait (rule 5: never refused). So such a key stores at most its bound and
/// one row per live thing it revokes, even when the fold refuses them all.
/// The door reads the stored log's structure as the fold's bounds do.
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
    let issuers = &view.structure.issuers;
    let signer = entry.signer_key();
    if is_handoff(entry) {
        return Ok(if issuers.contains(signer) {
            AuthorityDoor::Lands
        } else {
            AuthorityDoor::AtBound
        });
    }
    if signed_by(entry, issuers)
        || view.rows.get(signer).copied().unwrap_or_default() < signer_bound(store, txn)?
    {
        return Ok(AuthorityDoor::Lands);
    }
    if let Some(revoked) = Revoked::of(&entry.op)
        && !view
            .revocations
            .contains(&(signer.clone(), revoked.clone()))
    {
        let fold = authority_view_readonly_for_store_in_txn(store, posture, txn)?;
        if revoked.is_live(&fold) {
            return Ok(AuthorityDoor::Lands);
        }
    }
    Ok(AuthorityDoor::AtBound)
}

/// A typed OF-520 question about the authority log's bounds, read from the
/// stored log: evidence for the owner, never a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityLogCheck {
    /// [`Self::SIGNER_BOUND`] or [`Self::FOLD_HEADROOM`].
    pub kind: &'static str,
    /// The signer at its bound, for a signer-bound check.
    pub signer: Option<String>,
    /// The signer's stored rows, or the log's counted rows or slip-issuer
    /// handoffs.
    pub count: u64,
    /// The policy row `count` reached.
    pub threshold: u64,
}

impl AuthorityLogCheck {
    /// A key no slip issuer vouches for reached the
    /// `authority_log_signer_bound` row: its further rows wait until the
    /// owner raises the row, and then land on the next drain.
    pub const SIGNER_BOUND: &'static str = "authority_log_signer_bound";
    /// The log's counted rows, or its slip issuers' handoffs, reached their
    /// `authority_log_fold_headroom` policy row: by default half of what one
    /// fold holds (a one-chain log's 4,096 counted rows under the
    /// ancestor-pair bound, and 32 handoffs). The owner's work is never
    /// held, so past those bounds the fold fails closed.
    pub const FOLD_HEADROOM: &'static str = "authority_log_fold_headroom";
}

impl crate::Vault {
    /// The open checks on the stored authority log: each key no slip issuer
    /// vouches for that reached its bound, and the log's headroom once it
    /// reaches its policy rows.
    pub fn authority_log_checks(&self) -> crate::error::Result<Vec<AuthorityLogCheck>> {
        let txn = self.store.env.read_txn()?;
        let view = door_view(&self.store, &txn)?;
        let bound = signer_bound(&self.store, &txn)?;
        let mut checks: Vec<_> = view
            .rows
            .iter()
            .filter(|(signer, rows)| **rows >= bound && !view.structure.issuers.contains(*signer))
            .map(|(signer, rows)| AuthorityLogCheck {
                kind: AuthorityLogCheck::SIGNER_BOUND,
                signer: Some(authority_signer_label(signer)),
                count: *rows as u64,
                threshold: bound as u64,
            })
            .collect();
        let (rows_at, handoffs_at) = headroom(&self.store, &txn)?;
        for (count, at) in [(view.counted, rows_at), (view.issuer_handoffs, handoffs_at)] {
            if count >= at {
                checks.push(AuthorityLogCheck {
                    kind: AuthorityLogCheck::FOLD_HEADROOM,
                    signer: None,
                    count: count as u64,
                    threshold: at as u64,
                });
            }
        }
        Ok(checks)
    }
}
