//! First-seen sidecar keys and the per-vault logical observation clock.
//!
//! The sidecar sync keys and codec used by the readonly/backfill fold path,
//! plus the observation clock itself. The clock belongs to the vault that
//! observes: one [`AuthorityLocalClock`] lives behind a mutex on `StoreCore`,
//! so it dies with the handle and two vaults in one process cannot read each
//! other's anchor.

use std::time::Instant;

use crate::error::{Error, RecordError};
use crate::side_table::{self, Raw, SideTable};
use crate::store::StoreCore;

use super::*;

pub(crate) fn authority_first_seen_sync_key(hash: &AuthorityEntryHash) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut key = String::with_capacity("authlog:first_seen:".len() + AUTHORITY_HASH_LEN * 2);
    key.push_str("authlog:first_seen:");
    for byte in hash {
        key.push(char::from(HEX[usize::from(byte >> 4)]));
        key.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    key
}

pub(crate) fn authority_first_seen_backfill_sync_key() -> &'static str {
    "authlog:first_seen:backfill:v1"
}

pub(crate) fn authority_first_seen_clock_sync_key() -> &'static str {
    "authlog:first_seen:clock_floor"
}

/// The first-seen family's two `u64` (big-endian seconds) row shapes, addressed by tag inside
/// the shared `authlog:first_seen:` prefix: per-entry-hash sidecars (Key: hex64) and the
/// per-vault clock floor (Key: the literal `clock_floor`).
pub(crate) const AUTHORITY_FIRST_SEEN: SideTable<String, u64, Raw> =
    SideTable::new(&side_table::AUTHLOG_FIRST_SEEN_SIDECAR);
/// The one-shot sidecar-backfill marker (Key: the literal `backfill:v1`). The value is the
/// single pinned marker byte `[1]`; every reader checks presence only, so callers use
/// [`SideTable::contains`] rather than decoding it.
pub(crate) const AUTHORITY_FIRST_SEEN_BACKFILLED: SideTable<String, [u8; 1], Raw> =
    SideTable::new(&side_table::AUTHLOG_FIRST_SEEN_SIDECAR);

/// [`AUTHORITY_FIRST_SEEN`]'s key for one entry hash's sidecar row: the same spelling
/// [`authority_first_seen_sync_key`] gives the legacy raw-key callers, minus the shared prefix
/// the typed table already carries.
pub(crate) fn authority_first_seen_sidecar_key(hash: &AuthorityEntryHash) -> String {
    first_seen_suffix(&authority_first_seen_sync_key(hash))
}

/// [`AUTHORITY_FIRST_SEEN`]'s key for the per-vault clock floor row.
pub(crate) fn authority_first_seen_clock_key() -> String {
    first_seen_suffix(authority_first_seen_clock_sync_key())
}

/// [`AUTHORITY_FIRST_SEEN_BACKFILLED`]'s key for the one-shot backfill marker row.
pub(crate) fn authority_first_seen_backfill_key() -> String {
    first_seen_suffix(authority_first_seen_backfill_sync_key())
}

fn first_seen_suffix(full_key: &str) -> String {
    full_key
        .strip_prefix("authlog:first_seen:")
        .expect("every first-seen key carries the shared authlog:first_seen: prefix")
        .to_owned()
}

/// Verdict text carried by the [`Error::CorruptedIndex`] a readonly fold raises
/// when the one-shot first-seen migration has ALREADY run and an AUTHORITY_LOG
/// row still has no readable first-seen sidecar.
///
/// The migration is one-shot by its marker, so it will never regenerate that
/// row: the stale-roster clock for the affected entry is unrecoverable in
/// place. A fold cannot then decide whether an approval resting on a revoked
/// roster has outlived its window, and omitting the entry would let that
/// approval authorize forever. The only sound answer is to refuse the fold and
/// let the caller suspend whatever it was about to authorize.
pub(super) const AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT: &str =
    "authority first-seen sidecar missing or unreadable after backfill";

/// Whether `err` is the corrupt-sidecar verdict above.
pub(crate) fn is_corrupt_first_seen_sidecar(err: &Error) -> bool {
    matches!(err, Error::CorruptedIndex(msg) if *msg == AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT)
}

/// One vault's monotonic observation ANCHOR: the observed second count
/// `anchor_secs` and the [`Instant`] `anchor_instant` it was taken at.
///
/// The pair is an anchor, NOT a running total, and that is the whole point.
/// `Duration::as_secs` truncates, so a fold at 09:00:00.4 and another at
/// 09:00:00.9 each measure zero elapsed WHOLE seconds. Advancing the anchor on
/// every call would bank those zeros and discard the 0.4 s and 0.5 s remainders
/// forever — a caller folding faster than 1 Hz would freeze `now_secs` at its
/// first observation, so no stale-roster window would ever expire (an
/// approval resting on a revoked roster would authorize indefinitely). Keeping the anchor fixed makes each call measure real elapsed time
/// from ONE origin, so the sub-second remainders accumulate and the second
/// boundary is crossed exactly when it is crossed in wall time.
///
/// Unset until the first observation seeds it, and it dies with the vault
/// handle that owns it: a reopen starts a fresh anchor from the persisted
/// floor, which is exactly the old domain-release semantics with no registry
/// to release from.
#[derive(Default)]
pub(crate) struct AuthorityLocalClock {
    anchor: Option<AuthorityClockAnchor>,
}

struct AuthorityClockAnchor {
    anchor_instant: Instant,
    anchor_secs: u64,
}

impl AuthorityLocalClock {
    /// This handle's anchored reading at `now`, when it holds an anchor: the
    /// clock it has measured since it seeded from a floor it read whole. It
    /// seeds none and rebases none.
    fn anchored_secs(&self, now: Instant) -> Option<u64> {
        self.anchor.as_ref().map(|anchor| {
            anchor.anchor_secs.saturating_add(
                now.saturating_duration_since(anchor.anchor_instant)
                    .as_secs(),
            )
        })
    }

    /// The anchor as it stands, for [`Self::restore_anchor`].
    pub(super) fn anchor_state(&self) -> Option<(Instant, u64)> {
        self.anchor
            .as_ref()
            .map(|anchor| (anchor.anchor_instant, anchor.anchor_secs))
    }

    /// Puts back an anchor [`Self::anchor_state`] read, undoing a seed a
    /// write that did not commit took.
    pub(super) fn restore_anchor(&mut self, state: Option<(Instant, u64)>) {
        self.anchor = state.map(|(anchor_instant, anchor_secs)| AuthorityClockAnchor {
            anchor_instant,
            anchor_secs,
        });
    }

    /// The monotone observation this vault reports for `candidate_wall_secs`,
    /// measured from `now` on the monotonic clock. Reachable from `authority`
    /// only: the store path goes through `authority_observation_secs`, and the
    /// tests that supply an exact monotonic instant live under this module.
    pub(super) fn observation_secs_at(
        &mut self,
        previous_floor: u64,
        candidate_wall_secs: u64,
        now: Instant,
    ) -> u64 {
        match self.anchor.as_mut() {
            Some(anchor) => {
                let elapsed = now
                    .saturating_duration_since(anchor.anchor_instant)
                    .as_secs();
                let anchored = anchor.anchor_secs.saturating_add(elapsed);
                // The persisted floor is the only thing that may REBASE the
                // anchor: a floor above the anchor-derived value means another
                // writer (or a reopen) advanced local observation past this
                // vault's origin, so the floor becomes the new origin and `now`
                // its instant. Rebasing here is safe precisely because it is
                // monotone upward — observation never runs backward.
                if previous_floor > anchored {
                    anchor.anchor_secs = previous_floor;
                    anchor.anchor_instant = now;
                    return previous_floor;
                }
                anchored
            }
            None => {
                // A reopen resumes the persisted logical clock. Wall-clock
                // changes while closed cannot age an approval. The wall
                // value is only an arbitrary origin for a vault that has
                // never recorded an observation.
                let observed = if previous_floor == 0 {
                    candidate_wall_secs
                } else {
                    previous_floor
                };
                self.anchor = Some(AuthorityClockAnchor {
                    anchor_instant: now,
                    anchor_secs: observed,
                });
                observed
            }
        }
    }
}

/// The monotone observation `store`'s vault reports for `candidate_wall_secs`.
pub(crate) fn authority_observation_secs(
    store: &StoreCore,
    previous_floor: u64,
    candidate_wall_secs: u64,
) -> u64 {
    store
        .authority_local_clock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .observation_secs_at(previous_floor, candidate_wall_secs, Instant::now())
}

/// This handle's anchored reading now, when it holds one.
pub(super) fn authority_anchored_secs(store: &StoreCore) -> Option<u64> {
    store
        .authority_local_clock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .anchored_secs(Instant::now())
}

/// What an authority reading does over a present floor that does not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityClockCorruptPolicy {
    /// A handle that holds an anchor reads its anchored clock, measured from
    /// a floor it read whole, and writes no floor; one that holds none
    /// answers [`RecordError::AuthorityClockCorrupt`], but inside an owner's
    /// restriction-only act ([`restriction_only_clock`]). Never zero, and the
    /// damaged row stays until the owner's repair replaces it.
    AnchoredElseCorrupt,
}

/// The one rule over a damaged floor (CALLS `FIX 10106 authority clock
/// corrupt policy`).
pub(crate) const AUTHORITY_CLOCK_CORRUPT_POLICY: AuthorityClockCorruptPolicy =
    AuthorityClockCorruptPolicy::AnchoredElseCorrupt;

thread_local! {
    /// How many restriction-only acts this thread is inside.
    static RESTRICTION_ONLY: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// An owner's restriction-only act (an erase or a revoke) in progress on this
/// thread (FIX 10106): over a damaged clock floor it reads the best proven
/// lower bound ([`authority_clock_lower_bound_in_txn`]), or none, in place of
/// [`RecordError::AuthorityClockCorrupt`], and writes no floor, so the act
/// lands, never replaces the damaged bytes and revives nothing. Only the
/// door of such an act enters it, for the act's own synchronous run.
#[must_use = "the act reads the restriction clock only while this is held"]
pub struct RestrictionOnlyClock(());

/// Enters [`RestrictionOnlyClock`] on this thread until the guard drops.
pub fn restriction_only_clock() -> RestrictionOnlyClock {
    RESTRICTION_ONLY.with(|depth| depth.set(depth.get() + 1));
    RestrictionOnlyClock(())
}

impl Drop for RestrictionOnlyClock {
    fn drop(&mut self) {
        RESTRICTION_ONLY.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

fn in_restriction_only_act() -> bool {
    RESTRICTION_ONLY.with(|depth| depth.get() > 0)
}

/// The highest second this vault proves it observed without its floor: the
/// handle's anchored reading, the floor's high-water copy, the latest
/// first-seen stamp and the latest repair receipt (`clock_repair`). None when
/// nothing here proves one.
pub(crate) fn authority_clock_lower_bound_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> crate::error::Result<Option<u64>> {
    let evidence = super::clock_repair::clock_evidence_in_txn(store, txn)?;
    Ok(evidence.lower_bound())
}

/// The reading over a damaged floor ([`AUTHORITY_CLOCK_CORRUPT_POLICY`]):
/// this handle's anchored one; else, inside a restriction-only act, the best
/// proven lower bound or none (zero); else `corrupt`.
fn reading_over_damaged_floor(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    corrupt: Error,
) -> crate::error::Result<u64> {
    match AUTHORITY_CLOCK_CORRUPT_POLICY {
        AuthorityClockCorruptPolicy::AnchoredElseCorrupt => {
            if let Some(anchored) = authority_anchored_secs(store) {
                return Ok(anchored);
            }
            if in_restriction_only_act() {
                return Ok(authority_clock_lower_bound_in_txn(store, txn)?.unwrap_or(0));
            }
            Err(corrupt)
        }
    }
}

/// The verdict on a present authority clock floor that does not decode (FIX
/// 10106).
pub(crate) fn authority_clock_corrupt() -> Error {
    Error::Record(RecordError::AuthorityClockCorrupt)
}

/// [`AUTHORITY_FIRST_SEEN`]'s key for the floor's high-water copy: the same
/// second, written in the same writer as every floor, so a damaged floor row
/// leaves the vault its own record of what it committed (FIX 10106).
pub(crate) fn authority_clock_high_water_key() -> String {
    "clock_floor_high_water".to_owned()
}

/// Writes `floor` as the authority clock floor and its high-water copy.
pub(crate) fn put_authority_clock_floor_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    floor: u64,
) -> crate::error::Result<()> {
    AUTHORITY_FIRST_SEEN.put(store, wtxn, &authority_first_seen_clock_key(), &floor)?;
    AUTHORITY_FIRST_SEEN.put(store, wtxn, &authority_clock_high_water_key(), &floor)
}

/// The persisted authority clock floor, read strictly in `txn` (FIX 10106):
/// None only when no floor row exists, a vault that has observed nothing
/// yet. A present row that does not decode is
/// [`RecordError::AuthorityClockCorrupt`], never zero; a storage error stays
/// one.
pub(crate) fn read_authority_clock_floor_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> crate::error::Result<Option<u64>> {
    match AUTHORITY_FIRST_SEEN.get_bytes(store, txn, &authority_first_seen_clock_key())? {
        None => Ok(None),
        Some(bytes) => AUTHORITY_FIRST_SEEN
            .decode_value(&bytes)
            .map(Some)
            .map_err(|_| authority_clock_corrupt()),
    }
}

/// The authority clock's reading for `candidate_wall_secs` in `txn`: the
/// floor read strictly ([`read_authority_clock_floor_in_txn`]), raised
/// through [`authority_observation_secs`]. Over a damaged floor it is this
/// handle's anchored reading, a clock it measured from a floor it read whole;
/// with no anchor it is [`RecordError::AuthorityClockCorrupt`], but inside a
/// restriction-only act (CALLS `FIX 10106 authority clock corrupt policy`).
/// Pure: it writes nothing.
pub(crate) fn authority_clock_reading_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    candidate_wall_secs: u64,
) -> crate::error::Result<u64> {
    match read_authority_clock_floor_in_txn(store, txn) {
        Ok(floor) => Ok(authority_observation_secs(
            store,
            floor.unwrap_or(0),
            candidate_wall_secs,
        )),
        Err(error) if is_authority_clock_corrupt(&error) => {
            reading_over_damaged_floor(store, txn, error)
        }
        Err(error) => Err(error),
    }
}

/// [`authority_clock_reading_in_txn`] for a writer that commits the reading
/// as the floor, with its high-water copy, as every authority write path
/// does, so a reopen never reads below it. A damaged floor is never
/// overwritten here: over one the reading is the anchored one (or, inside a
/// restriction-only act, the proven lower bound), written nowhere, and only
/// the owner's repair replaces the row (`clock_repair`).
pub(crate) fn advance_authority_clock_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    candidate_wall_secs: u64,
) -> crate::error::Result<u64> {
    let floor = match read_authority_clock_floor_in_txn(store, wtxn) {
        Ok(floor) => floor.unwrap_or(0),
        Err(error) if is_authority_clock_corrupt(&error) => {
            return reading_over_damaged_floor(store, wtxn, error);
        }
        Err(error) => return Err(error),
    };
    let observed = authority_observation_secs(store, floor, candidate_wall_secs);
    if observed != floor {
        put_authority_clock_floor_in_txn(store, wtxn, observed)?;
    }
    Ok(observed)
}

/// The batch authority put's floor write (`batch::types`), strict as it was:
/// a damaged floor is [`RecordError::AuthorityClockCorrupt`], but inside a
/// restriction-only act, where the observation is the best proven lower
/// bound, or none, and no floor is written.
pub(crate) fn advance_authority_clock_strict_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    candidate_wall_secs: u64,
) -> crate::error::Result<u64> {
    let floor = match read_authority_clock_floor_in_txn(store, wtxn) {
        Ok(floor) => floor.unwrap_or(0),
        Err(error) if is_authority_clock_corrupt(&error) && in_restriction_only_act() => {
            return Ok(authority_clock_lower_bound_in_txn(store, wtxn)?.unwrap_or(0));
        }
        Err(error) => return Err(error),
    };
    let observed = authority_observation_secs(store, floor, candidate_wall_secs);
    if observed != floor {
        put_authority_clock_floor_in_txn(store, wtxn, observed)?;
    }
    Ok(observed)
}

/// Whether `error` is the damaged-floor verdict
/// ([`authority_clock_corrupt`]).
pub(crate) fn is_authority_clock_corrupt(error: &Error) -> bool {
    matches!(error, Error::Record(RecordError::AuthorityClockCorrupt))
}

/// `Vault::instant_in_txn`'s reading, in unix seconds, for a reader that
/// holds a `Store` and no `Vault` (FIX 7461): the persisted floor read
/// through `txn`, raised through [`authority_observation_secs`]
/// ([`authority_clock_reading_in_txn`]). Pure, as that reading is: it writes
/// nothing back.
pub(crate) fn authority_instant_secs_for_store_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> crate::error::Result<u64> {
    authority_clock_reading_in_txn(store, txn, store.clock.now_recorded_at())
}

/// Production writes go through [`AUTHORITY_FIRST_SEEN`]'s typed door (`u64`'s
/// built-in big-endian [`crate::side_table::RawValue`]); this raw encoder
/// stays only for `credential_door::tests`, which pins the clock floor by
/// writing the legacy raw `sync_state` row directly.
#[cfg(test)]
pub(crate) fn encode_authority_first_seen_secs(secs: u64) -> [u8; 8] {
    secs.to_be_bytes()
}

pub(crate) fn decode_authority_first_seen_secs(raw: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(raw.try_into().ok()?))
}
