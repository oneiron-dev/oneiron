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
//! Nor does the owner's will this install carries under its own install key
//! (FIX 7930): known by key possession, never by a local or replicated flag.
//! Under the owner's reserve (below), any other key a slip issuer's consent
//! vouches for stores past the `authority_log_signer_bound` policy row too:
//! the count only asks, through a typed check, and holds no row (FIX 8564,
//! 8876). An owner anchor this
//! install does not pin is a stranger, since a root needs nothing but a
//! fresh key: every stranger's row shares that one row and waits past it,
//! never refused (world privacy P6b, r23). The fold refuses only a log whose
//! projected peak passes the `authority_log_fold_memory_floor` row: it holds
//! no root and reads as a conflicted one, which every authority gate refuses,
//! and its typed issue names the floor.
//!
//! So the doors keep the owner a reserve under that floor (FIX
//! [AUTHORITY-LOG-SIGNER-FLOOD], Astra F10): once the stored log's projected
//! peak passes the floor less an eighth of it, every row but the owner's work
//! waits, never refused, and the owner's work still lands. One admitted
//! machine that keeps signing then stops at the reserve, and the owner's
//! removal of it still folds. A waiting row lands on the next drain once the
//! owner raises the floor's row; until then a typed check names the reserve.
//! An adopted checkpoint image does not lower the projection: the door counts
//! the rows it covers as stored rows.

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
/// key no slip issuer vouches for stores before its typed check asks.
pub const MAX_AUTHORITY_ROWS_PER_SIGNER: usize = 2048;

/// Whether a vouched, non-stranger signer's stored rows past the
/// `authority_log_signer_bound` row only ask (FIX 8564, 8876; CALLS
/// `FIX 8564 8876 signer count advisory`): its row lands and
/// [`AuthorityLogCheck::SIGNER_BOUND`] names the count. No count cap replaces
/// it; strangers' shared bound and the fold's memory floor stay.
pub const AUTHORITY_LOG_SIGNER_COUNT_ADVISORY: bool = true;

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

/// The owner's reserve under the memory floor is the floor divided by this:
/// an eighth, so a log near an 8 GiB floor still has 1 GiB for the owner's
/// work once every other row waits. A row that is not the owner's work lands
/// only while the log with it stays under the reserve's start, its ancestry
/// added to every stored row that names it as a missing parent
/// ([`FoldProjection::bytes_with`]; Astra owner-reserve F1), so only the
/// owner's work enters the reserve. One of the owner's rows projects at most
/// 16 KiB plus 640 bytes for each row it can have as an ancestor: each stored
/// row and each distinct missing parent. On a floor at or above the default's
/// least (1 GiB) the reserve holds several such rows even when every stored
/// row is an ancestor of each; a floor row set to a few hundred KiB can leave
/// it too small for one.
const FOLD_MEMORY_OWNER_RESERVE_DIVISOR: u64 = 8;

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

/// The projected peak past which the doors keep the rest of the memory floor
/// for the owner's work: the floor the fold reads on this install, less its
/// owner reserve ([`FOLD_MEMORY_OWNER_RESERVE_DIVISOR`]).
fn owner_reserve_start(store: &Store, txn: &heed::RoTxn<'_>) -> crate::error::Result<u64> {
    let policy = authority_observation_policy_in_txn(store, txn)?;
    let floor = fold_memory_floor(Some(&policy));
    Ok(floor - floor / FOLD_MEMORY_OWNER_RESERVE_DIVISOR)
}

/// An upper bound on the peak a fold of `rows` projects
/// ([`fold_projected_bytes`]), `rows` being each stored row's entry hash, as
/// the fold keys its rows, and parents. A row's ancestor pairs are bounded
/// parents first: a row on one parent has that parent's bound and the parent
/// itself, exactly as the fold counts them; a join has the lesser of the same
/// sum over its parents and the rows bounded before it plus the log's missing
/// parents, since every ancestor of it is one or the other. A parent no row
/// is counts once, as the fold counts a missing parent. A one-signer chain is
/// bounded exactly. A parent still unbounded when its child is bounded closes
/// a cycle, which no signed history holds; the log is then bounded as if
/// every row had every row and every missing parent among its ancestors.
fn stored_fold_projection(
    rows: &BTreeMap<AuthorityEntryHash, &[AuthorityEntryHash]>,
) -> FoldProjection {
    let mut children = BTreeMap::<AuthorityEntryHash, Vec<AuthorityEntryHash>>::new();
    for (child, parents) in rows {
        for parent in *parents {
            children.entry(*parent).or_default().push(*child);
        }
    }
    let missing = rows
        .values()
        .flat_map(|parents| parents.iter())
        .filter(|parent| !rows.contains_key(*parent))
        .collect::<BTreeSet<_>>()
        .len() as u64;
    let most = (rows.len() as u64).saturating_add(missing);
    let mut bound = BTreeMap::<AuthorityEntryHash, u64>::new();
    let mut entered = BTreeSet::new();
    let mut cyclic = false;
    let mut pairs = 0_u64;
    for start in rows.keys() {
        let mut stack = vec![(*start, false)];
        while let Some((hash, parents_bounded)) = stack.pop() {
            let parents = rows[&hash];
            if parents_bounded {
                let mut through = |parent: &AuthorityEntryHash| {
                    if !rows.contains_key(parent) {
                        return 1;
                    }
                    bound.get(parent).map_or_else(
                        || {
                            cyclic = true;
                            most
                        },
                        |ancestors| ancestors.saturating_add(1),
                    )
                };
                let ancestors = match parents {
                    [parent] => through(parent),
                    _ => parents
                        .iter()
                        .map(&mut through)
                        .fold(0, u64::saturating_add)
                        .min((bound.len() as u64).saturating_add(missing)),
                };
                bound.insert(hash, ancestors);
                pairs = pairs.saturating_add(ancestors);
            } else if entered.insert(hash) {
                stack.push((hash, true));
                stack.extend(
                    parents
                        .iter()
                        .filter(|parent| rows.contains_key(*parent) && !entered.contains(*parent))
                        .map(|parent| (*parent, false)),
                );
            }
        }
    }
    if cyclic {
        pairs = (rows.len() as u64).saturating_mul(most);
    }
    FoldProjection {
        rows: rows.len(),
        pairs,
        missing,
        cyclic,
        bound,
        children,
    }
}

/// The stored log's projected fold peak ([`stored_fold_projection`]), with
/// what the door needs to bound the log with one more row in it.
#[derive(Debug)]
struct FoldProjection {
    rows: usize,
    pairs: u64,
    /// The distinct parents no stored row is.
    missing: u64,
    /// Whether the stored rows close a cycle (`pairs` then bounds every row
    /// with every row and missing parent).
    cyclic: bool,
    /// Each stored row's ancestor bound.
    bound: BTreeMap<AuthorityEntryHash, u64>,
    /// Each row a stored row names as a parent, stored or missing: the
    /// stored rows that name it.
    children: BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
}

impl FoldProjection {
    /// The stored log's projected peak.
    fn bytes(&self) -> u64 {
        fold_projected_bytes(self.rows, self.pairs)
    }

    /// The projected peak with the row `hash`, on `parents`, stored too
    /// (Astra owner-reserve F1). Its own ancestors are bounded as a stored
    /// row's are. Every stored row that has it among its ancestors counted it
    /// once, as a missing parent; once it is stored, each of them also has
    /// its ancestors, so each gains its bound. One row can so take a log
    /// from under the reserve's start past the floor: the rows a machine
    /// signs on a parent it withholds count that parent once until it comes.
    fn bytes_with(&self, hash: &AuthorityEntryHash, parents: &[AuthorityEntryHash]) -> u64 {
        if self.bound.contains_key(hash) {
            return self.bytes();
        }
        let rows = self.rows.saturating_add(1);
        let most = (self.rows as u64)
            .saturating_add(self.missing)
            .saturating_add(1);
        if self.cyclic {
            return fold_projected_bytes(rows, (rows as u64).saturating_mul(most));
        }
        let through = |parent: &AuthorityEntryHash| {
            self.bound
                .get(parent)
                .map_or(1, |ancestors| ancestors.saturating_add(1))
        };
        let own = match parents {
            [parent] => through(parent),
            _ => parents
                .iter()
                .map(through)
                .fold(0, u64::saturating_add)
                .min(most),
        };
        let mut descendants = BTreeSet::new();
        let mut next: Vec<_> = self.children.get(hash).into_iter().flatten().collect();
        while let Some(row) = next.pop() {
            if descendants.insert(*row) {
                next.extend(self.children.get(row).into_iter().flatten());
            }
        }
        let pairs = self
            .pairs
            .saturating_add(own)
            .saturating_add((descendants.len() as u64).saturating_mul(own));
        fold_projected_bytes(rows, pairs)
    }
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
        AuthorityOp::SlipMint(_)
            | AuthorityOp::SlipRevoke { .. }
            | AuthorityOp::SlipConsume { .. }
            | AuthorityOp::SlipGrantRevoke { .. }
            | AuthorityOp::RemovalArchiveConsume { .. }
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
    /// The stored rows a fold counts: all but the slip issuers' slip ops.
    counted: usize,
    /// The stored handoffs a slip issuer signed.
    issuer_handoffs: usize,
    /// The stored rows that vouch only as a stranger's: anchors this
    /// install does not take as its own ([`AuthorityStructure::is_stranger`]).
    strangers: usize,
    /// An upper bound on the peak a fold of every stored row projects
    /// ([`stored_fold_projection`]), which the owner reserve reads.
    projection: FoldProjection,
    /// The adopted image's evidence the view read, for the doors' other
    /// readers in the same generation.
    pub(super) evidence: Option<Arc<AdoptedEvidence>>,
}

/// The per-signer and log-wide counts of a door view.
#[derive(Default)]
struct Tally {
    rows: BTreeMap<AuthorityKey, usize>,
    counted: usize,
    issuer_handoffs: usize,
    strangers: usize,
}

impl Tally {
    /// Counts one row by its signer, whether it is a slip op, and its signed
    /// body when the door reads it whole. A row read only by its summary is
    /// no handoff or stranger's row: an adopted image carries the body of
    /// every such row.
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
        let issuer = structure.issuers.contains(signer);
        self.counted += usize::from(!(issuer && slip_op));
        self.issuer_handoffs += usize::from(issuer && entry.is_some_and(is_handoff));
    }
}

#[cfg(test)]
thread_local! {
    static DOOR_VIEW_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(any(test, oneiron_test_support))]
thread_local! {
    static DOOR_OPEN_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `body` with this thread's authority doors open, so a test can build
/// a log no door stores, such as one with a rival genesis.
#[cfg(any(test, oneiron_test_support))]
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
        let evidence = super::checkpoint_adopt::cached_adopted_evidence_in_txn(store, txn)?;
        let mut hashes = Vec::new();
        let mut entries = Vec::new();
        for (id, body) in authority_log_rows_in_txn(store, txn)? {
            // A covered row counts once, from the image.
            if evidence
                .as_ref()
                .is_some_and(|evidence| evidence.covers_id(&id))
            {
                continue;
            }
            let entry = decode_authority_log_entry_body(&body)?;
            hashes.push(authority_entry_hash(&entry)?);
            entries.push(entry);
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
        let mut parents: BTreeMap<_, &[AuthorityEntryHash]> = hashes
            .iter()
            .copied()
            .zip(entries.iter().map(|entry| entry.parent_hashes.as_slice()))
            .collect();
        if let Some(evidence) = &evidence {
            for (hash, row) in evidence.rows() {
                tally.count(&structure, &row.signer, row.slip_op, evidence.body(hash));
                parents.insert(*hash, row.parents.as_slice());
            }
        }
        let projection = stored_fold_projection(&parents);
        Ok(AuthorityDoorView {
            structure,
            rows: tally.rows,
            counted: tally.counted,
            issuer_handoffs: tally.issuer_handoffs,
            strangers: tally.strangers,
            projection,
            evidence,
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

/// What a store door does with an AUTHORITY_LOG row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityDoor {
    Lands,
    /// The row waits: it is a stranger's row past the bound all strangers'
    /// rows share, a handoff no slip issuer signed, which the fold never
    /// applies, or a row that is not the owner's work once the stored log
    /// reached the owner's reserve under the memory floor. A replica retries
    /// it on every drain.
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
/// slip issuer signs it. Under the owner's reserve, any other vouched key's
/// row lands too: past the
/// `authority_log_signer_bound` row its count only asks
/// ([`AUTHORITY_LOG_SIGNER_COUNT_ADVISORY`]), so a revocation lands as every
/// other row does. A stranger's row, which an anchor this install does not
/// take as its own vouches for, lands only while every such stored row
/// together is under that row, so fresh anchors never add a bound each; the
/// rest wait (rule 5: never refused). Once the stored log's projected peak
/// passes the owner's reserve under the memory floor
/// ([`FOLD_MEMORY_OWNER_RESERVE_DIVISOR`]), every row but the owner's work
/// waits and the owner's work lands ([`owner_work`]). The door reads the
/// stored log's structure as the fold's bounds do.
pub(crate) fn authority_door(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entry: &AuthorityLogEntry,
) -> crate::error::Result<AuthorityDoor> {
    #[cfg(any(test, oneiron_test_support))]
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
    // The owner's reserve (FIX [AUTHORITY-LOG-SIGNER-FLOOD], Astra F10): a
    // log past the memory floor folds to no root, and then the owner's own
    // removal of the key that filled it cannot fold. So past the reserve
    // only the owner's work lands; every other row waits for the owner to
    // raise the floor. The door judges the log with the row in it (Astra
    // owner-reserve F1).
    let with_entry = view
        .projection
        .bytes_with(&authority_entry_hash(entry)?, &entry.parent_hashes);
    if with_entry > owner_reserve_start(store, txn)?
        && !owner_work(store, txn, &view.structure, entry)?
    {
        return Ok(AuthorityDoor::AtBound);
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
        || AUTHORITY_LOG_SIGNER_COUNT_ADVISORY
        || view.rows.get(signer).copied().unwrap_or_default() < signer_bound(store, txn)?
        || carries_own_will(store, txn, entry)?
    {
        return Ok(AuthorityDoor::Lands);
    }
    Ok(AuthorityDoor::AtBound)
}

/// Whether `entry` is the owner's work, which lands past the owner's reserve
/// under the memory floor ([`FOLD_MEMORY_OWNER_RESERVE_DIVISOR`]): a row a
/// slip issuer signs or cosigns, a row an anchor this install takes as its
/// own signs (its root records and machine marks), or the owner's will this
/// install carries ([`carries_own_will`]). Another install's key passes none
/// of them at this door, and neither does a stranger's anchor. A result this
/// install signs answers a request its pickup takes from the log, whoever
/// carried it, so it is the owner's work only when its request is (Astra
/// owner-reserve F2): a request another machine carries never has this
/// install spend the reserve on its answer. That result waits with its
/// pickup's transaction, and the request stays pending.
fn owner_work(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    structure: &AuthorityStructure,
    entry: &AuthorityLogEntry,
) -> crate::error::Result<bool> {
    if signed_by(entry, &structure.issuers) || structure.is_own_anchor(entry.signer_key()) {
        return Ok(true);
    }
    if !carries_own_will(store, txn, entry)? {
        return Ok(false);
    }
    let AuthorityOp::OwnerWorkResult(result) = &entry.op else {
        return Ok(true);
    };
    let Some(request) = super::retired_signers::stored_authority_row(store, txn, &result.request)?
    else {
        return Ok(false);
    };
    Ok(signed_by(&request, &structure.issuers)
        || structure.is_own_anchor(request.signer_key())
        || carries_own_will(store, txn, &request)?)
}

/// Whether `entry` is the owner's will this install carries (FIX 7930): signed
/// by this install's own machine key, which only its own doors hold and sign
/// with after they revalidate the owner or an agent's Grant, and carrying
/// that will (an owner or delegated act, or owner work's request, result or
/// cancel), or the frontier join such an act rides on (FIX 7908), or a
/// custody request's permit piece (FIX 11866), or a membership execution
/// record it signed for a change no host issuer signed (FIX 12335), or the
/// world key wraps and residence results that work writes under this
/// install's key ([AUTHORITY-LOG-SIGNER-FLOOD]: key delivery after an
/// admission, a key minted in a world edit, a residence directive's end). Such a row leaves the lifetime signer bound, which still raises
/// its typed check, were the count not advisory; strangers, other installs' rows and a replica's retries
/// keep their treatment. No local or replicated flag is read. An install
/// whose key is not known yet keeps today's path
/// ([`AUTHORITY_NEW_CHECK_UNKNOWN_KEEP_CURRENT`]).
fn carries_own_will(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entry: &AuthorityLogEntry,
) -> crate::error::Result<bool> {
    let own = match crate::identity::read_machine_verifying_key_in_store_txn(store, txn) {
        Ok(own) => own,
        Err(_) if AUTHORITY_NEW_CHECK_UNKNOWN_KEEP_CURRENT => None,
        Err(error) => return Err(error),
    };
    let Some(own) = own else {
        return Ok(false);
    };
    if *entry.signer_key() != AuthorityKey::Ed25519(own) {
        return Ok(false);
    }
    Ok(match &entry.op {
        AuthorityOp::WorldPrivacy(_)
        | AuthorityOp::GrantTravelSet(_)
        | AuthorityOp::OwnerWorkRequest(_)
        | AuthorityOp::OwnerWorkResult(_)
        | AuthorityOp::OwnerWorkCancel(_)
        | AuthorityOp::ExportSupplementImported(_)
        | AuthorityOp::CheckpointPolicySet(_)
        | AuthorityOp::HomeNodePick(_)
        | AuthorityOp::OriginCut(_)
        | AuthorityOp::DeviceSuccession(_)
        | AuthorityOp::ConversationTrainingSet(_)
        | AuthorityOp::ConversationTrainingVaultSet(_)
        | AuthorityOp::AgentGrantAct(_)
        | AuthorityOp::MembershipExecution(_)
        | AuthorityOp::PolicySettingSet(_)
        | AuthorityOp::ExportAct(_)
        | AuthorityOp::FrontierJoin(_)
        | AuthorityOp::CustodyPermitPiece(_)
        | AuthorityOp::WorldKeyWraps(_)
        | AuthorityOp::ResidenceResult(_) => true,
        AuthorityOp::MachineProfile(profile) => profile.act.is_some(),
        _ => false,
    })
}

/// A typed OF-520 question about the authority log's bounds, read from the
/// stored log: evidence for the owner, never a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityLogCheck {
    /// [`Self::SIGNER_BOUND`], [`Self::UNPINNED_ROOTS`],
    /// [`Self::FOLD_HEADROOM`] or [`Self::OWNER_RESERVE`].
    pub kind: &'static str,
    /// For a headroom check, what reached its row: [`Self::ROWS`],
    /// [`Self::HANDOFFS`] or [`Self::ANCESTOR_PAIRS`].
    pub scope: Option<&'static str>,
    /// The signer at its bound, for a signer-bound check.
    pub signer: Option<String>,
    /// The signer's stored rows, the strangers' rows, the log's counted
    /// rows, slip-issuer handoffs or counted ancestor pairs, or, for the
    /// owner reserve, the stored log's projected fold peak in bytes.
    pub count: u64,
    /// The policy row `count` reached, or, for the owner reserve, the
    /// memory floor less the reserve, in bytes.
    pub threshold: u64,
}

impl AuthorityLogCheck {
    /// A key that is no slip issuer reached the `authority_log_signer_bound`
    /// row. Its further rows land as before: the check only asks
    /// ([`AUTHORITY_LOG_SIGNER_COUNT_ADVISORY`]).
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
    /// The stored log's projected fold peak passed the
    /// `authority_log_fold_memory_floor` row less the owner's reserve under
    /// it: every row but the owner's work waits until the owner raises that
    /// row, and then lands on the next drain.
    pub const OWNER_RESERVE: &'static str = "authority_log_owner_reserve";
    /// The scope of a headroom check on counted rows.
    pub const ROWS: &'static str = "rows";
    /// The scope of a headroom check on slip issuers' handoffs.
    pub const HANDOFFS: &'static str = "handoffs";
    /// The scope of a headroom check on counted ancestor pairs.
    pub const ANCESTOR_PAIRS: &'static str = "ancestor_pairs";
}

impl crate::Vault {
    /// The open checks on the stored authority log: each key no slip issuer
    /// vouches for that reached its bound, the strangers' shared bound, one
    /// per headroom scope that reached its policy row, and the owner's
    /// reserve under the memory floor once the log reached it.
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
        let reserve_start = owner_reserve_start(&self.store, &txn)?;
        let projected_bytes = view.projection.bytes();
        if projected_bytes > reserve_start {
            checks.push(AuthorityLogCheck {
                kind: AuthorityLogCheck::OWNER_RESERVE,
                scope: None,
                signer: None,
                count: projected_bytes,
                threshold: reserve_start,
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
