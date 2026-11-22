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
//! the rows it covers as stored rows. A stored row with a missing ancestor is
//! charged at its worst case from its arrival, so the later arrival of that
//! ancestor, the owner's or another's, never moves the projection by the
//! ancestor's own ancestry. Only a key the fold holds as a live owner does
//! the owner's work: a revoked or retired owner key, or one no roster holds,
//! has its rows wait at the reserve as a machine's do.
//! A slip issuer the fold holds as a live owner does the owner's work
//! whatever else its roster row holds: on a hosted vault the host's root
//! key (`ROLE_CLOUD`, `CloudCustodial`) is one, so its rows land past the
//! reserve as the owner's work, whether or not the vault also holds an
//! owner key of its own.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::adopted_evidence::AdoptedEvidence;
use super::log_structure::{
    AuthorityStructure, authority_structure, row_signatures_verified, self_signed_root, signed_by,
};
use super::*;
use crate::HostingPrivacyPosture;
use crate::store::Store;

mod door_rows;
#[cfg(oneiron_test_support)]
mod door_view_door;
mod log_check;
mod owner_reserve;
mod owner_signed_work;
mod policy_bounds;

#[cfg(oneiron_test_support)]
pub(crate) use door_view_door::{
    door_view_differs_from_rebuild_in_txn, staged_door_views_differ_from_rebuild,
};
pub use log_check::AuthorityLogCheck;
pub(crate) use log_check::authority_signer_label;
use owner_reserve::*;
pub(crate) use owner_reserve::{OwnerReserveHold, held_at_owner_reserve_in_txn};
pub(crate) use owner_signed_work::answers_the_owners_signed_work_in_txn;
use owner_signed_work::{an_owner_key_signs, answered_row};
use policy_bounds::signer_bound;
pub(super) use policy_bounds::{fold_memory_floor, memory_floor_fold};
#[cfg(test)]
pub(crate) use policy_bounds::{
    with_fold_memory_floor_for_test, with_physical_memory_for_test, with_rows_per_signer_for_test,
};

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

/// Whether `row` hands the vault to a new key: an open re-root, or a sealed
/// one whose public standing names a re-root. The store door's handoff rule
/// is storage, not effect, so it reads the kind: the verdict is the same
/// before and after the key arrives.
fn is_handoff(row: &FoldRow) -> bool {
    matches!(row.op(), Some(AuthorityOp::ReRoot { .. }))
        || matches!(
            row.public().map(AuthorityPublicRow::standing),
            Some(PublicStanding::ReRoot { .. })
        )
}

/// Whether `row` is a slip row: an open slip op, or a sealed mint whose
/// public standing names one. The fold's bounds and the door's tally exempt
/// the same rows, so the verdict is the same before and after the key
/// arrives.
pub(in crate::authority) fn is_slip_row(row: &FoldRow) -> bool {
    row.op().is_some_and(is_slip_op)
        || matches!(
            row.public().map(AuthorityPublicRow::standing),
            Some(PublicStanding::SlipMint)
        )
}

/// The slip issuers of `rows`: see [`authority_structure`].
#[cfg(test)]
pub(super) fn slip_issuers(rows: &[FoldRow]) -> BTreeSet<AuthorityKey> {
    authority_structure(rows.iter()).issuers
}

/// The hashes of the rows no fold bound counts: the slip issuers' slip rows.
pub(super) fn uncounted_rows(
    by_hash: &BTreeMap<AuthorityEntryHash, FoldRow>,
) -> BTreeSet<AuthorityEntryHash> {
    let issuers = authority_structure(by_hash.values()).issuers;
    by_hash
        .iter()
        .filter(|(_, row)| is_uncounted(row, &issuers))
        .map(|(hash, _)| *hash)
        .collect()
}

/// Whether no fold bound counts `row` under `issuers`, the log's slip
/// issuers: it is one of their slip rows.
pub(super) fn is_uncounted(row: &FoldRow, issuers: &BTreeSet<AuthorityKey>) -> bool {
    is_slip_row(row) && issuers.contains(row.signer_key())
}

/// What the store doors read of the stored log: its consent structure, and
/// each signer's stored rows. Built once per authority generation, from the
/// last such view and the rows stored since where it can be
/// ([`door_rows`]). On a vault
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
    projection: DoorProjection,
    /// The adopted image's evidence the view read, for the doors' other
    /// readers in the same generation.
    pub(super) evidence: Option<Arc<AdoptedEvidence>>,
    /// What the view read, for the next generation's view to extend.
    kept: door_rows::DoorRows,
}

impl AuthorityDoorView {
    /// Whether this install believes `entry`, as this view's structure reads
    /// it (`AuthorityStructure::believes`): the roster's rows and this
    /// install's own anchors' rows.
    pub(super) fn believes(&self, entry: &AuthorityLogEntry) -> bool {
        self.structure.believes(entry)
    }
}

/// The per-signer and log-wide counts of a door view.
#[derive(Debug, Clone, Default)]
struct Tally {
    rows: BTreeMap<AuthorityKey, usize>,
    counted: usize,
    issuer_handoffs: usize,
    strangers: usize,
}

impl Tally {
    /// Counts one row by its signer, whether it is a slip row, and the row
    /// itself when the door reads it whole. A row read only by its summary is
    /// no handoff or stranger's row: an adopted image carries the body of
    /// every such row.
    fn count(
        &mut self,
        structure: &AuthorityStructure,
        signer: &AuthorityKey,
        slip_op: bool,
        row: Option<&FoldRow>,
    ) {
        self.strangers += usize::from(
            row.is_some_and(|row| structure.vouches_for(row) && structure.is_stranger(row)),
        );
        *self.rows.entry(signer.clone()).or_default() += 1;
        let issuer = structure.issuers.contains(signer);
        self.counted += usize::from(!(issuer && slip_op));
        self.issuer_handoffs += usize::from(issuer && row.is_some_and(is_handoff));
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

#[cfg(oneiron_test_support)]
thread_local! {
    static DOOR_VIEW_ROWS_DECODED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many stored rows this thread's door views decoded.
#[cfg(oneiron_test_support)]
pub(crate) fn door_view_rows_decoded_for_test() -> u64 {
    DOOR_VIEW_ROWS_DECODED.with(std::cell::Cell::get)
}

pub(super) fn door_view(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> crate::error::Result<Arc<AuthorityDoorView>> {
    door_rows::door_view(store, txn)
}

/// Whether `row`'s signer has standing to store a replicated row: a key
/// some valid row admitted (live, revoked or retired), an install key the
/// roster's chain of a machine names, a valid root's owner anchor, the
/// anchor of the root record it is, or a key the stored log's structure
/// admits though the fold does not hold it yet, such as an owner key a
/// pre-handoff rotation named. An install key only an anchor's chain names
/// stands through the structure alone, as a stranger's when the anchor is
/// not this install's own, so its rows count against the stranger bounds
/// (Fable pass 29: the fold reads no unpinned anchor's chain for it). A key
/// none of these name signs no valid row, so its rows wait for the
/// enrollment instead of being stored.
pub(crate) fn signer_has_standing(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    row: &FoldRow,
) -> crate::error::Result<bool> {
    let signer = row.signer_key();
    if fold.roster.contains_key(signer)
        || fold.retired_keys.contains(signer)
        || matches!(signer, AuthorityKey::Ed25519(key)
            if fold.machines.values().any(|machine| machine.roster_names_key(key))
                || fold.root_anchors().contains_key(key))
        || self_signed_root(row).is_some()
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

/// The fold a store door judges an arriving row against, which the owner's
/// reserve reads for the standing of the row's owner keys
/// (OWNER-RESERVE-REVOKED-OWNER-KEY = A; OPUS-SECREAD-A #8360 N1).
pub(crate) enum DoorFold<'a> {
    /// The fold the door's preflight already holds: the replicated doors'
    /// fold for [`super::door_refuses_retired_standing`].
    Held(&'a AuthorityFold),
    /// A door that holds none, a local put: the snapshot's own fold under
    /// the vault's posture, read only when the reserve asks, beside the
    /// authority rows the put's batch carries when it names them. A local
    /// append or import stages its rows one by one, so a fold that needs
    /// history a later row of the batch supplies answers beside them, as
    /// the batch's preflight did (owner-reserve delta review F2).
    Snapshot(HostingPrivacyPosture, Option<super::RowsBeside<'a>>),
}

impl DoorFold<'_> {
    /// `body` on the fold. A snapshot's fold is read first, with `arriving`
    /// folded in where it needs history they supply, then the rows beside
    /// ([`super::preflight_authority_rows_beside_in_txn`]).
    fn read<T>(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        arriving: &[(AuthorityEntryHash, &FoldRow)],
        body: impl FnOnce(&AuthorityFold) -> T,
    ) -> crate::error::Result<T> {
        match self {
            Self::Held(fold) => Ok(body(fold)),
            Self::Snapshot(posture, beside) => {
                let view = match beside {
                    Some(beside) => {
                        super::history_admission::preflight_authority_rows_beside_in_txn(
                            store, *posture, txn, arriving, *beside,
                        )?
                    }
                    None => super::history_admission::preflight_authority_rows_in_txn(
                        store, *posture, txn, arriving,
                    )?,
                };
                Ok(body(&view))
            }
        }
    }
}

/// The door's verdict on storing `row`, at every door, local or
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
/// waits and the owner's work lands ([`owner_work`]): a key `fold` does not
/// hold as a live owner does none. The door reads the stored log's
/// structure as the fold's bounds do, and a row whose record does not open
/// here by its envelope and public standing, as its open kind is judged.
pub(crate) fn authority_door(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    row: &FoldRow,
    fold: DoorFold<'_>,
) -> crate::error::Result<AuthorityDoor> {
    #[cfg(any(test, oneiron_test_support))]
    if DOOR_OPEN_FOR_TEST.with(std::cell::Cell::get) {
        return Ok(AuthorityDoor::Lands);
    }
    if authority_row_resident(store, txn, row)? {
        return Ok(AuthorityDoor::Lands);
    }
    let view = door_view(store, txn)?;
    if !view.structure.vouches_for(row) || !row_signatures_verified(row) {
        return Ok(AuthorityDoor::Unowned);
    }
    // The owner's reserve (FIX [AUTHORITY-LOG-SIGNER-FLOOD], Astra F10): a
    // log past the memory floor folds to no root, and then the owner's own
    // removal of the key that filled it cannot fold. So past the reserve
    // only the owner's work lands; every other row waits for the owner to
    // raise the floor. The door judges the log with the row in it (Astra
    // owner-reserve F1).
    if held_at_owner_reserve(store, txn, &view, row, &fold)? {
        return Ok(AuthorityDoor::AtBound);
    }
    // A self-signed root needs nothing but a fresh key, so an anchor this
    // install does not take as its own is a stranger: its rows, and its
    // machines', share one bound instead of one each (Astra #1422e F1; the
    // Engine, r23). Its own anchors' rows never meet it.
    if view.structure.is_stranger(row) {
        return Ok(if view.strangers < signer_bound(store, txn)? {
            AuthorityDoor::Lands
        } else {
            AuthorityDoor::AtBound
        });
    }
    let issuers = &view.structure.issuers;
    let signer = row.signer_key();
    if is_handoff(row) {
        return Ok(if issuers.contains(signer) {
            AuthorityDoor::Lands
        } else {
            AuthorityDoor::AtBound
        });
    }
    if signed_by(row, issuers)
        || AUTHORITY_LOG_SIGNER_COUNT_ADVISORY
        || view.rows.get(signer).copied().unwrap_or_default() < signer_bound(store, txn)?
        || carries_own_will(store, txn, row)?
    {
        return Ok(AuthorityDoor::Lands);
    }
    Ok(AuthorityDoor::AtBound)
}

/// Whether `row` is the owner's work, which lands past the owner's reserve
/// under the memory floor ([`FOLD_MEMORY_OWNER_RESERVE_DIVISOR`]): a row a
/// slip issuer signs or cosigns, a row an anchor this install takes as its
/// own signs (its root records and machine marks), while `fold` holds the
/// issuer as a live owner and shows the anchor neither revoked nor retired
/// ([`signs_for_the_owner`]), or the
/// owner's will this install carries ([`carries_own_will`]). Another
/// install's key passes none of them at this door, and neither does a
/// stranger's anchor. A result this install signs answers a request or a
/// residence directive its pickup takes from the log, whoever carried or
/// signed it, so it is the owner's work only when that row is
/// ([`asks_the_owners_work`]; Astra owner-reserve F2, r2 F3): a request
/// another machine carries, or a directive another key signs, never has this
/// install spend the reserve on its answer. That result waits with its
/// pickup's transaction, and the row it answers stays pending.
fn owner_work(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    structure: &AuthorityStructure,
    fold: &DoorFold<'_>,
    hash: &AuthorityEntryHash,
    row: &FoldRow,
) -> crate::error::Result<bool> {
    let arriving = [(*hash, row)];
    if names_an_owner_key(structure, row)
        && fold.read(store, txn, &arriving, |view| {
            signs_for_the_owner(structure, view, row)
        })?
    {
        return Ok(true);
    }
    if !carries_own_will(store, txn, row)? {
        return Ok(false);
    }
    let asked = match row.op() {
        Some(AuthorityOp::OwnerWorkResult(result)) => result.request,
        Some(AuthorityOp::ResidenceResult(result)) => result.directive_entry,
        _ => return Ok(true),
    };
    asks_the_owners_work(store, txn, structure, fold, &arriving, &asked)
}

/// Whether a slip issuer of `structure` signs or cosigns `row`, or an
/// anchor this install takes as its own signs it: [`signs_for_the_owner`]
/// before the fold is read. Both read the signed envelope, so a row whose
/// record does not open here is judged as one that opens.
fn names_an_owner_key(structure: &AuthorityStructure, row: &FoldRow) -> bool {
    signed_by(row, &structure.issuers) || structure.is_own_anchor(row.signer_key())
}

/// Whether one of those keys signs `row` for the owner under `fold`: a
/// slip issuer `fold` holds as a live owner on its roster, or this install's
/// own anchor, neither retired by a handoff nor, for the anchor, revoked on
/// the roster (OWNER-RESERVE-REVOKED-OWNER-KEY = A; OPUS-SECREAD-A #8360 N1).
/// The structure's issuers never shrink ([`super::log_structure`]), so an
/// owner key the owner revoked stays one there, and so does a key a revoked
/// one enrolled in a row the fold refused: such a key is on no roster, so it
/// signs or cosigns nothing for the owner (owner-reserve delta review F1).
/// A revoked set read from the signed rows alone would let a stolen key
/// revoke the owner's own. Only the fold tells.
fn signs_for_the_owner(
    structure: &AuthorityStructure,
    fold: &AuthorityFold,
    row: &FoldRow,
) -> bool {
    an_owner_key_signs(structure, fold, row)
        || (structure.is_own_anchor(row.signer_key())
            && !fold.retired_keys.contains(row.signer_key())
            && !fold
                .roster
                .get(row.signer_key())
                .is_some_and(|device| device.revoked))
}

/// Whether the row `hash`, a request or a directive this install's pickup
/// answers, is the owner's work at this door: a slip issuer signed or
/// cosigned it, or an anchor this install takes as its own signed it, as
/// [`signs_for_the_owner`] reads `fold`, or this install carries
/// it ([`carries_own_will`]). The row is the stored one, else, on a vault
/// that adopted a checkpoint image, the body the image carries of that
/// covered row, judged the same way: the pickup takes such a request or
/// directive from the adopted fold, so its result is the owner's work when
/// the owner signed what it answers (FIX [OWNER-RESERVE-ADOPTED-OWNER-WORK]).
/// A row neither stored nor carried whole is not.
/// A row whose record does not open here is judged by its signed envelope,
/// and carries no will here.
fn asks_the_owners_work(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    structure: &AuthorityStructure,
    fold: &DoorFold<'_>,
    arriving: &[(AuthorityEntryHash, &FoldRow)],
    hash: &AuthorityEntryHash,
) -> crate::error::Result<bool> {
    let Some(asked) = answered_row(store, txn, hash)? else {
        return Ok(false);
    };
    if names_an_owner_key(structure, &asked)
        && fold.read(store, txn, arriving, |view| {
            signs_for_the_owner(structure, view, &asked)
        })?
    {
        return Ok(true);
    }
    carries_own_will(store, txn, &asked)
}

/// Whether the request `request` this install's pickup answers is the
/// owner's work at this door ([`asks_the_owners_work`], on this vault's
/// snapshot fold). The key wraps and
/// joins a pickup signs under this install's key land at the door as the
/// owner's will this install carries, whether or not the work then writes its
/// result, so a pickup for any other request asks
/// [`past_owner_reserve_in_txn`] before its work and again before it commits
/// (Astra owner-reserve r2 F2): a request another machine carries spends no
/// reserve on any row, and stays pending.
pub(crate) fn asks_the_owners_work_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    request: &AuthorityEntryHash,
) -> crate::error::Result<bool> {
    let view = door_view(store, txn)?;
    asks_the_owners_work(
        store,
        txn,
        &view.structure,
        &DoorFold::Snapshot(store.privacy_posture, None),
        &[],
        request,
    )
}

/// Whether the log in `txn`, with every row it staged, projects past the
/// owner's reserve's start under the memory floor.
pub(crate) fn past_owner_reserve_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> crate::error::Result<bool> {
    Ok(door_view(store, txn)?
        .projection
        .bytes_past(owner_reserve_start(store, txn)?)
        .is_some())
}

/// [`past_owner_reserve_in_txn`] after the carried work for `request`
/// staged its rows in `txn`. Past the reserve the work rolls back, so this
/// records it as a hold the reserve's typed check names (Astra owner-reserve
/// r3 F3); under it the work lands, and so ends that hold.
pub(crate) fn carried_work_past_owner_reserve_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    request: &AuthorityEntryHash,
) -> crate::error::Result<bool> {
    let view = door_view(store, txn)?;
    let Some(projected) = view.projection.bytes_past(owner_reserve_start(store, txn)?) else {
        end_owner_reserve_work_hold(store, request);
        return Ok(false);
    };
    hold_at_owner_reserve(
        store,
        &view.projection,
        OwnerReserveHold {
            entry: *request,
            work: true,
            projected,
        },
    );
    Ok(true)
}

/// Ends the hold of `request`'s carried work, once it landed or the request
/// left this install's work.
pub(crate) fn end_owner_reserve_work_hold(store: &Store, request: &AuthorityEntryHash) {
    if let Ok(mut held) = store.authority_owner_reserve_hold.lock()
        && held.is_some_and(|held| held.work && held.entry == *request)
    {
        *held = None;
    }
}

/// Whether `row` is the owner's will this install carries (FIX 7930): signed
/// by this install's own machine key, which only its own doors hold and sign
/// with after they revalidate the owner or an agent's Grant, and carrying
/// that will (an owner or delegated act, or owner work's request, result or
/// cancel), or the frontier join such an act rides on (FIX 7908), or a
/// custody request's permit piece (FIX 11866), or a membership execution
/// record it signed for a change no host issuer signed (FIX 12335), or the
/// world key wraps and residence results that work writes under this
/// install's key ([AUTHORITY-LOG-SIGNER-FLOOD]: key delivery after an
/// admission, a key minted in a world edit, a residence directive's end), or the
/// setting copy a move it carried wrote (stage 7a-4). Such a row leaves the lifetime signer bound, which still raises
/// its typed check, were the count not advisory; strangers, other installs' rows and a replica's retries
/// keep their treatment. No local or replicated flag is read. An install
/// whose key is not known yet keeps today's path
/// ([`AUTHORITY_NEW_CHECK_UNKNOWN_KEEP_CURRENT`]). A row whose record does
/// not open here carries no will here: what it wills takes its op.
fn carries_own_will(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    row: &FoldRow,
) -> crate::error::Result<bool> {
    let own = match crate::identity::read_machine_verifying_key_in_store_txn(store, txn) {
        Ok(own) => own,
        Err(_) if AUTHORITY_NEW_CHECK_UNKNOWN_KEEP_CURRENT => None,
        Err(error) => return Err(error),
    };
    let Some(own) = own else {
        return Ok(false);
    };
    if *row.signer_key() != AuthorityKey::Ed25519(own) {
        return Ok(false);
    }
    let Some(op) = row.op() else {
        return Ok(false);
    };
    Ok(match op {
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
        | AuthorityOp::SettingCopy(_)
        | AuthorityOp::SettingPackHead(_)
        | AuthorityOp::ExportAct(_)
        | AuthorityOp::FrontierJoin(_)
        | AuthorityOp::CustodyPermitPiece(_)
        | AuthorityOp::WorldKeyWraps(_)
        | AuthorityOp::ResidenceResult(_) => true,
        AuthorityOp::MachineProfile(profile) => profile.act.is_some(),
        _ => false,
    })
}
