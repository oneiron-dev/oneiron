//! The authority log's fold bounds, and the store-door checks that keep a
//! stored log inside them (H72).
//!
//! The fold indexes every row's whole ancestry and probes each handoff by
//! folding its line again, so its work grows with the square of the log and
//! with the number of handoffs. Every door, local or replicated, holds a row
//! no owner, admin or install key signed: the fold applies none. The owner's
//! work, any row a slip issuer signs or cosigns, never meets a bound (the
//! owner's rate law, rule 5): the fold reads every row, and the log's counted
//! rows, handoffs and ancestor pairs each raise one typed headroom check at
//! their policy rows. The slip issuer's slip ops count toward no check:
//! every sign-in mints one, so a busy owner's log gains thousands a year.
//! Any other key stores up to the `authority_log_signer_bound` policy row;
//! past it, its rows wait, never refused, a typed check asks the owner, and
//! raising the row lands them on the next drain. An owner anchor this
//! install does not pin is a stranger, since a root needs nothing but a
//! fresh key: every stranger's row shares that one row (world privacy P6b,
//! r23). A key's first revocation of a device or binding the fold holds live
//! always lands. The fold refuses only a log whose projected peak passes the
//! `authority_log_fold_memory_floor` row: it holds no root and reads as a
//! conflicted one, which every authority gate refuses, and its typed issue
//! names the floor.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::adopted_evidence::AdoptedEvidence;
use super::log_structure::{
    AuthorityStructure, LocalRoots, authority_structure, authority_structure_under,
    self_signed_root, signed_by,
};
use super::*;
use crate::store::Store;

/// The default of the `authority_log_signer_bound` policy row: the rows a
/// key no slip issuer vouches for stores before the rest wait.
pub const MAX_AUTHORITY_ROWS_PER_SIGNER: usize = 2048;

/// What one fold holds at its peak, per row and per ancestor pair, measured
/// on the fleet (10-16) and rounded up: at most 11.6 KB a row with no
/// ancestors, and 252 to 626 bytes a pair (a confirm chain, then one agent
/// enrolled and bound per row). A row's state holds what its ancestors
/// added, so the pairs carry the states as well as the ancestry index.
const FOLD_BYTES_PER_ROW: u64 = 16 * 1024;
const FOLD_BYTES_PER_ANCESTOR_PAIR: u64 = 640;

#[cfg(test)]
thread_local! {
    static ROWS_PER_SIGNER_FOR_TEST: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
    static FOLD_MEMORY_FLOOR_FOR_TEST: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
    static PHYSICAL_MEMORY_FOR_TEST: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

/// The least the memory floor's default reaches, however small the machine.
const FOLD_MEMORY_FLOOR_MIN_BYTES: u64 = 1024 * 1024 * 1024;

/// Runs `body` with the signer bound and the row and pair headroom rows
/// scaled to `rows` per signer on this thread, so a test crosses them in a
/// few rows.
#[cfg(test)]
pub(crate) fn with_rows_per_signer_for_test<T>(rows: usize, body: impl FnOnce() -> T) -> T {
    ROWS_PER_SIGNER_FOR_TEST.with(|bound| bound.set(Some(rows)));
    let result = body();
    ROWS_PER_SIGNER_FOR_TEST.with(|bound| bound.set(None));
    result
}

/// Runs `body` with every fold on this thread under a memory floor of
/// `bytes`, the policy row's or the default's.
#[cfg(test)]
pub(crate) fn with_fold_memory_floor_for_test<T>(bytes: u64, body: impl FnOnce() -> T) -> T {
    FOLD_MEMORY_FLOOR_FOR_TEST.with(|floor| floor.set(Some(bytes)));
    let result = body();
    FOLD_MEMORY_FLOOR_FOR_TEST.with(|floor| floor.set(None));
    result
}

/// Runs `body` on this thread as on a machine with `bytes` of physical
/// memory.
#[cfg(test)]
pub(crate) fn with_physical_memory_for_test<T>(bytes: u64, body: impl FnOnce() -> T) -> T {
    PHYSICAL_MEMORY_FOR_TEST.with(|memory| memory.set(Some(bytes)));
    let result = body();
    PHYSICAL_MEMORY_FOR_TEST.with(|memory| memory.set(None));
    result
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

/// The counted rows, slip-issuer handoffs and counted ancestor pairs at
/// which the log raises its headroom checks: the policy rows, or a test's
/// scaled bound for rows and pairs.
fn headroom(store: &Store, txn: &heed::RoTxn<'_>) -> crate::error::Result<(u64, u64, u64)> {
    let policy = authority_observation_policy_in_txn(store, txn)?;
    #[cfg(test)]
    if let Some(rows) = ROWS_PER_SIGNER_FOR_TEST.with(std::cell::Cell::get) {
        let rows = rows as u64;
        return Ok((rows, policy.log_headroom_handoffs, 2 * rows * rows));
    }
    Ok((
        policy.log_headroom_rows,
        policy.log_headroom_handoffs,
        policy.log_headroom_ancestor_pairs,
    ))
}

/// The bytes a fold may project to hold at its peak: the policy row, else a
/// quarter of this machine's physical memory between 1 GiB and
/// [`DEFAULT_AUTHORITY_LOG_FOLD_MEMORY_FLOOR_BYTES`] (the cap when the
/// platform does not say), or a test's floor.
pub(super) fn fold_memory_floor(policy: Option<&AuthorityObservationPolicy>) -> u64 {
    #[cfg(test)]
    if let Some(bytes) = FOLD_MEMORY_FLOOR_FOR_TEST.with(std::cell::Cell::get) {
        return bytes;
    }
    policy
        .and_then(|policy| policy.log_fold_memory_floor_bytes)
        .unwrap_or_else(|| {
            physical_memory_bytes().map_or(DEFAULT_AUTHORITY_LOG_FOLD_MEMORY_FLOOR_BYTES, |bytes| {
                (bytes / 4).clamp(
                    FOLD_MEMORY_FLOOR_MIN_BYTES,
                    DEFAULT_AUTHORITY_LOG_FOLD_MEMORY_FLOOR_BYTES,
                )
            })
        })
}

/// This machine's physical memory, when the platform says.
fn physical_memory_bytes() -> Option<u64> {
    #[cfg(test)]
    if let Some(bytes) = PHYSICAL_MEMORY_FOR_TEST.with(std::cell::Cell::get) {
        return Some(bytes);
    }
    #[cfg(unix)]
    {
        // SAFETY: `sysconf` reads a configuration value and touches no memory
        // of ours.
        let (pages, page) = unsafe {
            (
                libc::sysconf(libc::_SC_PHYS_PAGES),
                libc::sysconf(libc::_SC_PAGESIZE),
            )
        };
        let pages = u64::try_from(pages).ok().filter(|pages| *pages > 0)?;
        let page = u64::try_from(page).ok().filter(|page| *page > 0)?;
        Some(pages.saturating_mul(page))
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// What a fold of `rows` rows indexing `pairs` ancestor pairs holds at its
/// peak.
pub(super) fn fold_projected_bytes(rows: usize, pairs: u64) -> u64 {
    (rows as u64)
        .saturating_mul(FOLD_BYTES_PER_ROW)
        .saturating_add(pairs.saturating_mul(FOLD_BYTES_PER_ANCESTOR_PAIR))
}

impl AuthorityFold {
    /// True when the fold refused its log at its memory floor. Such a fold
    /// also reads as [`Self::vault_root_is_conflicted`], so every authority
    /// gate refuses it.
    #[must_use]
    pub fn authority_log_past_bound(&self) -> bool {
        self.authority_log_memory_floor().is_some()
    }

    /// The memory floor, in bytes, that the fold's projected peak passed,
    /// when the fold refused its log there.
    #[must_use]
    pub fn authority_log_memory_floor(&self) -> Option<u64> {
        self.issues.iter().find_map(|issue| match issue {
            AuthorityFoldIssue::FoldMemoryFloor { floor_bytes } => Some(*floor_bytes),
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

/// The fold of a log past its memory floor: no root, no roster, one typed
/// issue naming the floor.
pub(super) fn memory_floor_fold(floor_bytes: u64) -> AuthorityFold {
    let mut fold = fold_authority_log(&[]);
    fold.issues
        .push(AuthorityFoldIssue::FoldMemoryFloor { floor_bytes });
    fold
}

pub(super) fn is_slip_op(op: &AuthorityOp) -> bool {
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
        .filter(|(_, entry)| is_uncounted(entry, &issuers))
        .map(|(hash, _)| *hash)
        .collect()
}

/// Whether no fold bound counts `entry` under `issuers`, the log's slip
/// issuers: it is one of their slip ops.
pub(super) fn is_uncounted(entry: &AuthorityLogEntry, issuers: &BTreeSet<AuthorityKey>) -> bool {
    is_slip_op(&entry.op) && issuers.contains(entry.signer_key())
}

/// What the store doors read of the stored log: its consent structure, and
/// each signer's stored rows. Built once per authority generation. On a vault
/// that adopted a checkpoint image (OF-469), the stored log is the image's
/// covered history and the raw rows past it: each covered row counts once,
/// from the image's summary and carried body, whether or not its raw bytes
/// are stored too.
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
    /// The adopted image's evidence the view read, for the doors' other
    /// readers in the same generation.
    pub(super) evidence: Option<Arc<AdoptedEvidence>>,
}

/// The per-signer and log-wide counts of a door view.
#[derive(Default)]
struct Tally {
    rows: BTreeMap<AuthorityKey, usize>,
    revocations: BTreeSet<(AuthorityKey, Revoked)>,
    counted: usize,
    issuer_handoffs: usize,
    strangers: usize,
}

impl Tally {
    /// Counts one row by its signer, whether it is a slip op, and its signed
    /// body when the door reads it whole. A row read only by its summary is
    /// no revocation, handoff or stranger's row: an adopted image carries the
    /// body of every such row.
    fn count(
        &mut self,
        structure: &AuthorityStructure,
        signer: &AuthorityKey,
        slip_op: bool,
        entry: Option<&AuthorityLogEntry>,
    ) {
        self.strangers += usize::from(
            entry.is_some_and(|entry| structure.vouches_for(entry) && structure.is_stranger(entry)),
        );
        *self.rows.entry(signer.clone()).or_default() += 1;
        if let Some(revoked) = entry.and_then(|entry| Revoked::of(&entry.op)) {
            self.revocations.insert((signer.clone(), revoked));
        }
        let issuer = structure.issuers.contains(signer);
        self.counted += usize::from(!(issuer && slip_op));
        self.issuer_handoffs += usize::from(issuer && entry.is_some_and(is_handoff));
    }
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

pub(super) fn door_view(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> crate::error::Result<Arc<AuthorityDoorView>> {
    super::readonly_fold::per_authority_generation(store, txn, &store.authority_door_view, || {
        #[cfg(test)]
        DOOR_VIEW_BUILDS.with(|builds| builds.set(builds.get() + 1));
        let evidence = AdoptedEvidence::read_in_txn(store, txn)?;
        let mut entries = Vec::new();
        for (id, body) in authority_log_rows_in_txn(store, txn)? {
            // A covered row counts once, from the image.
            if evidence
                .as_ref()
                .is_some_and(|evidence| evidence.covers_id(&id))
            {
                continue;
            }
            entries.push(decode_authority_log_entry_body(&body)?);
        }
        // The structure reads the image's carried rows as the stored rows
        // they stand for: it admits what the covered history admitted, never
        // what the folded roster now holds.
        let carried = evidence
            .iter()
            .flat_map(|evidence| evidence.bodies().values());
        let structure = authority_structure_under(
            carried.chain(&entries),
            LocalRoots::read_in_txn(store, txn)?,
        );
        let mut tally = Tally::default();
        for entry in &entries {
            tally.count(
                &structure,
                entry.signer_key(),
                is_slip_op(&entry.op),
                Some(entry),
            );
        }
        if let Some(evidence) = &evidence {
            for (hash, row) in evidence.rows() {
                tally.count(&structure, &row.signer, row.slip_op, evidence.body(hash));
            }
        }
        Ok(AuthorityDoorView {
            structure,
            rows: tally.rows,
            revocations: tally.revocations,
            counted: tally.counted,
            issuer_handoffs: tally.issuer_handoffs,
            strangers: tally.strangers,
            evidence: evidence.map(Arc::new),
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
    /// For a headroom check, what reached its row: [`Self::ROWS`],
    /// [`Self::HANDOFFS`] or [`Self::ANCESTOR_PAIRS`].
    pub scope: Option<&'static str>,
    /// The signer at its bound, for a signer-bound check.
    pub signer: Option<String>,
    /// The signer's stored rows, the strangers' rows, or the log's counted
    /// rows, slip-issuer handoffs or counted ancestor pairs.
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
    /// The log's counted rows, its slip issuers' handoffs, or its counted
    /// ancestor pairs reached their `authority_log_fold_headroom` policy row.
    /// The fold still reads them all; past the
    /// `authority_log_fold_memory_floor` row it refuses the log.
    pub const FOLD_HEADROOM: &'static str = "authority_log_fold_headroom";
    /// The scope of a headroom check on counted rows.
    pub const ROWS: &'static str = "rows";
    /// The scope of a headroom check on slip issuers' handoffs.
    pub const HANDOFFS: &'static str = "handoffs";
    /// The scope of a headroom check on counted ancestor pairs.
    pub const ANCESTOR_PAIRS: &'static str = "ancestor_pairs";
}

impl crate::Vault {
    /// The open checks on the stored authority log: each key no slip issuer
    /// vouches for that reached its bound, the strangers' shared bound, and
    /// one per headroom scope that reached its policy row.
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
                scope: None,
                signer: Some(authority_signer_label(signer)),
                count: *rows as u64,
                threshold: bound as u64,
            })
            .collect();
        if view.strangers >= bound {
            checks.push(AuthorityLogCheck {
                kind: AuthorityLogCheck::UNPINNED_ROOTS,
                scope: None,
                signer: None,
                count: view.strangers as u64,
                threshold: bound as u64,
            });
        }
        let (rows_at, handoffs_at, pairs_at) = headroom(&self.store, &txn)?;
        let pairs = self
            .authority_view_readonly_in_txn(&txn)?
            .counted_ancestor_pairs;
        for (scope, count, at) in [
            (AuthorityLogCheck::ROWS, view.counted as u64, rows_at),
            (
                AuthorityLogCheck::HANDOFFS,
                view.issuer_handoffs as u64,
                handoffs_at,
            ),
            (AuthorityLogCheck::ANCESTOR_PAIRS, pairs, pairs_at),
        ] {
            if count >= at {
                checks.push(AuthorityLogCheck {
                    kind: AuthorityLogCheck::FOLD_HEADROOM,
                    scope: Some(scope),
                    signer: None,
                    count,
                    threshold: at,
                });
            }
        }
        Ok(checks)
    }
}
