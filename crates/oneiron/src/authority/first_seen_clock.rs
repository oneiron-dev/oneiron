//! First-seen sidecar keys and the process-local logical clock domains.
//!
//! The sidecar sync keys and codec used by the readonly/backfill fold path,
//! plus the process-local observation clock. The clock's backing static lives
//! in [`authority_local_clocks`] and must exist exactly once crate-wide.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use crate::error::Error;

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

/// Verdict text carried by the [`Error::CorruptedIndex`] a readonly fold raises
/// when the one-shot first-seen migration has ALREADY run and an AUTHORITY_LOG
/// row still has no readable first-seen sidecar.
///
/// The migration is one-shot by its marker, so it will never regenerate that
/// row: the delay clock for the affected entry is unrecoverable in place. A
/// fold cannot then decide whether a delayable widen — a rotation, a recovery
/// reboot — has elapsed, and BOTH guesses are unsafe (assume elapsed and a
/// widen skips its veto window; assume pending and a rotation's RETIRED key
/// stays live). The only sound answer is to refuse the fold and let the caller
/// suspend whatever it was about to authorize.
pub(crate) const AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT: &str =
    "authority first-seen sidecar missing or unreadable after backfill";

/// Whether `err` is the corrupt-sidecar verdict above.
pub(crate) fn is_corrupt_first_seen_sidecar(err: &Error) -> bool {
    matches!(err, Error::CorruptedIndex(msg) if *msg == AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT)
}

/// Verdict text carried when a readonly fold's delay decision would rest on a
/// first-seen time this vault has never actually OBSERVED.
///
/// First-seen is a LOCAL observation, and the only local record of it is the
/// sidecar. Before the one-shot migration runs there is no such record for a
/// legacy row, so the readonly fold can only guess — and the peer-claimed
/// `learned_at` in the entity header is not a permissible guess: it is written
/// by whoever shipped the row. A legacy `EnrollDevice` carrying `learned_at =
/// 0` would otherwise read as first seen in 1970, i.e. matured before it
/// arrived, and a child `BindActor` on the newly owner-capable key would fold
/// ACTIVE with no veto window at all.
///
/// So the fold assumes the safe end — first seen NOW, the maximum remaining
/// delay — and that leaves every affected delayable widen pending. Pending is
/// fail-closed for the ops that only GRANT, but `RotateKey` and
/// `RecoveryReboot` also REVOKE: an un-applied rotation keeps the RETIRED key
/// in the roster with its actor binding live. Whenever an indeterminate row
/// actually lands in `pending_widens`, the fold therefore refuses instead of
/// authorizing on a roster it cannot pin down.
///
/// Unlike [`AUTHORITY_FIRST_SEEN_SIDECAR_CORRUPT`] this state is recoverable
/// and self-healing: one [`Vault::authority_fold`] runs the migration, records
/// the local observation, and the delay runs out from there.
pub(crate) const AUTHORITY_FIRST_SEEN_INDETERMINATE: &str =
    "authority first-seen time is not locally observed yet (pre-migration authority log)";

/// Whether `err` is the indeterminate-first-seen verdict above.
pub(crate) fn is_indeterminate_first_seen(err: &Error) -> bool {
    matches!(err, Error::CorruptedIndex(msg) if *msg == AUTHORITY_FIRST_SEEN_INDETERMINATE)
}

/// One clock domain's monotonic ANCHOR: the observed second count
/// `anchor_secs` and the [`Instant`] `anchor_instant` it was taken at.
///
/// The pair is an anchor, NOT a running total, and that is the whole point.
/// `Duration::as_secs` truncates, so a fold at 09:00:00.4 and another at
/// 09:00:00.9 each measure zero elapsed WHOLE seconds. Advancing the anchor on
/// every call would bank those zeros and discard the 0.4 s and 0.5 s remainders
/// forever — a caller folding faster than 1 Hz would freeze `now_secs` at its
/// first observation, so no veto delay would ever mature and every owner verb
/// resting on a delayable widen would wedge (fail-safe, but an availability
/// hole). Keeping the anchor fixed makes each call measure real elapsed time
/// from ONE origin, so the sub-second remainders accumulate and the second
/// boundary is crossed exactly when it is crossed in wall time.
struct AuthorityLocalClock {
    anchor_instant: Instant,
    anchor_secs: u64,
}

fn authority_local_clocks() -> &'static Mutex<BTreeMap<usize, AuthorityLocalClock>> {
    static LOCAL_CLOCKS: OnceLock<Mutex<BTreeMap<usize, AuthorityLocalClock>>> = OnceLock::new();
    LOCAL_CLOCKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(crate) fn authority_observation_secs_for_domain(
    clock_domain: usize,
    previous_floor: u64,
    candidate_wall_secs: u64,
) -> u64 {
    let now = Instant::now();
    let mut clocks = authority_local_clocks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match clocks.get_mut(&clock_domain) {
        Some(clock) => {
            let elapsed = now
                .saturating_duration_since(clock.anchor_instant)
                .as_secs();
            let anchored = clock.anchor_secs.saturating_add(elapsed);
            // The persisted floor is the only thing that may REBASE the anchor:
            // a floor above the anchor-derived value means another writer (or a
            // reopen) advanced local observation past this domain's origin, so
            // the floor becomes the new origin and `now` its instant. Rebasing
            // here is safe precisely because it is monotone upward — it can
            // delay a widen, never skip one.
            if previous_floor > anchored {
                clock.anchor_secs = previous_floor;
                clock.anchor_instant = now;
                return previous_floor;
            }
            anchored
        }
        None => {
            let observed = candidate_wall_secs.max(previous_floor);
            clocks.insert(
                clock_domain,
                AuthorityLocalClock {
                    anchor_instant: now,
                    anchor_secs: observed,
                },
            );
            observed
        }
    }
}

pub(crate) fn release_authority_clock_domain(clock_domain: usize) {
    let mut clocks = authority_local_clocks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clocks.remove(&clock_domain);
}

pub(crate) fn encode_authority_first_seen_secs(secs: u64) -> [u8; 8] {
    secs.to_be_bytes()
}

pub(crate) fn decode_authority_first_seen_secs(raw: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(raw.try_into().ok()?))
}
