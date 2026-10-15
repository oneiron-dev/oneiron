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
//! the next drain. An owner anchor this install does not pin is a stranger,
//! since a root needs nothing but a fresh key: every stranger's row shares
//! that one row (world privacy P6b, r23). A key's first revocation of a
//! device or binding the fold holds live always lands. A fold handed more
//! than its own bounds fails closed: it holds no root and reads as a
//! conflicted one, which every authority gate refuses.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::log_structure::{
    AuthorityStructure, LocalRoots, authority_structure, authority_structure_under,
    self_signed_root, signed_by,
};
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
    /// The stored rows that vouch only as a stranger's: anchors this
    /// install does not take as its own ([`AuthorityStructure::is_stranger`]).
    strangers: usize,
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
        let structure = authority_structure_under(&entries, LocalRoots::read_in_txn(store, txn)?);
        let mut rows = BTreeMap::<AuthorityKey, usize>::new();
        let mut revocations = BTreeSet::new();
        let (mut counted, mut issuer_handoffs, mut strangers) = (0, 0, 0);
        for entry in &entries {
            strangers += usize::from(structure.vouches_for(entry) && structure.is_stranger(entry));
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
            strangers,
        })
    })
}

/// Whether `entry`'s signer has standing to store a replicated row: a key
/// some valid row admitted (live, revoked or retired), a machine's install
/// key, a valid root's owner anchor, the anchor of the root record it is,
/// or a key the stored log's structure admits though the fold does not
/// hold it yet, such as an owner key a pre-handoff rotation named. A key
/// none of these name signs no valid row, so its rows wait for the
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
        || matches!(signer, AuthorityKey::Ed25519(key)
            if fold.machines.values().any(|machine| machine.names_key(key))
                || fold.root_anchors().contains_key(key))
        || self_signed_root(entry).is_some()
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
    /// at its bound, or it is a stranger's row past the bound all strangers'
    /// rows share, or it is a handoff no slip issuer signed, which the fold
    /// never applies. A replica retries it on every drain.
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
/// A stranger's row, which an anchor this install does not take as its own
/// vouches for, lands only while every such stored row together is under
/// that row, so fresh anchors never add a bound each. The door reads the
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
    // A self-signed root needs nothing but a fresh key, so an anchor this
    // install does not take as its own is a stranger: its rows, and its
    // machines', share one bound instead of one each (Astra #1422e F1; the
    // Engine, r23). Its own anchors' rows never meet it.
    if view.structure.is_stranger(entry) {
        return Ok(if view.strangers < signer_bound(store, txn)? {
            AuthorityDoor::Lands
        } else {
            AuthorityDoor::AtBound
        });
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
    /// [`Self::SIGNER_BOUND`], [`Self::UNPINNED_ROOTS`] or
    /// [`Self::FOLD_HEADROOM`].
    pub kind: &'static str,
    /// The signer at its bound, for a signer-bound check.
    pub signer: Option<String>,
    /// The signer's stored rows, the strangers' rows, or the log's counted
    /// rows or slip-issuer handoffs.
    pub count: u64,
    /// The policy row `count` reached.
    pub threshold: u64,
}

impl AuthorityLogCheck {
    /// A key no slip issuer vouches for reached the
    /// `authority_log_signer_bound` row: its further rows wait until the
    /// owner raises the row, and then land on the next drain.
    pub const SIGNER_BOUND: &'static str = "authority_log_signer_bound";
    /// The rows of anchors this install does not pin reached the
    /// `authority_log_signer_bound` row they share: their root records, their
    /// marks, and their machines' world rows. Further ones wait until this
    /// install pins their root or the owner raises the row, and then land on
    /// the next drain.
    pub const UNPINNED_ROOTS: &'static str = "authority_log_unpinned_roots";
    /// The log's counted rows, or its slip issuers' handoffs, reached their
    /// `authority_log_fold_headroom` policy row: by default half of what one
    /// fold holds (a one-chain log's 4,096 counted rows under the
    /// ancestor-pair bound, and 32 handoffs). The owner's work is never
    /// held, so past those bounds the fold fails closed.
    pub const FOLD_HEADROOM: &'static str = "authority_log_fold_headroom";
}

impl crate::Vault {
    /// The open checks on the stored authority log: each key no slip issuer
    /// vouches for that reached its bound, the strangers' shared bound, and
    /// the log's headroom once it reaches its policy rows.
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
        if view.strangers >= bound {
            checks.push(AuthorityLogCheck {
                kind: AuthorityLogCheck::UNPINNED_ROOTS,
                signer: None,
                count: view.strangers as u64,
                threshold: bound as u64,
            });
        }
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
