//! An off-record room's own secret custody (ROOM-LOCAL-CUSTODY; the lead's
//! ruling of 21 Nov, "fingerprint only on save").
//!
//! A secret the side-row wall lifts from a row an off-record room writes is
//! kept here, in memory, and the row holds its room handle
//! (`[secret r0123456789abcdef.1]`)
//! instead of the value. Nothing of it is written anywhere: no custody record,
//! no key file, no known-value fingerprint, no overlay row, so no snapshot,
//! capture or promotion carries it. The room's close wipes every value, and a
//! dropped overlay wipes what is left. A save moves each secret a saved row
//! holds into the vault's own custody, which only then fingerprints it.
//!
//! A room handle is the sigil [`ROOM_SECRET_SIGIL`], the room's tag and the
//! handle's ordinal in the room: `r0123456789abcdef.1`. The dot puts it
//! outside the durable short-id grammar (letters and digits,
//! [`oneiron_contracts::entity_id::MIN_PRESENTATION_PREFIX_LEN`]): a base door
//! refuses it at its parse and never resolves it to a record of its own. Its
//! own sigil keeps it apart from the room's entity aliases (`s1`). The tag is
//! 64 random bits drawn once per room, so two rooms never spell a handle
//! alike: a handle one room gave meets nothing another room keeps, in a row
//! or a call (REVIEW-10003). The ordinal only grows, so a handle is never
//! named twice in one room. The spelling holds no value and is no secret
//! shape, so a whole field may hold it bare, as a base one holds `sc12`.
//!
//! A value is kept with the write that lifted it (REVIEW-10003 round 2): the
//! write's segment stages it, its commit keeps it, and its abort wipes it, so
//! a refused write leaves no copy behind. The values a room keeps count in
//! its byte budget and in what it retains, beside its rows.

use zeroize::Zeroizing;

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{Error, OffRecordError, Result};

use super::ACTIVE_SEGMENT;
use super::lifecycle::{OverlayLifecycleState, SessionOverlay};

/// Leading sigil of a room's custody handle: `r`, the room's tag, a dot and
/// the handle's ordinal, `[secret r0123456789abcdef.1]` in a row's text.
pub const ROOM_SECRET_SIGIL: &str = "r";

/// How many lowercase hex digits spell a room's tag: its 64 bits.
pub const ROOM_SECRET_TAG_DIGITS: usize = 16;

/// Whether `text` is a room's custody handle, whole: the sigil, a tag of
/// [`ROOM_SECRET_TAG_DIGITS`] lowercase hex digits, a dot and the ordinal's
/// digits.
#[must_use]
pub fn is_room_secret_handle(text: &str) -> bool {
    let Some((tag, ordinal)) = text
        .strip_prefix(ROOM_SECRET_SIGIL)
        .and_then(|rest| rest.split_once('.'))
    else {
        return false;
    };
    tag.len() == ROOM_SECRET_TAG_DIGITS
        && tag.bytes().all(room_tag_digit)
        && !ordinal.is_empty()
        && ordinal.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether `bytes` spell a room's custody handle anywhere: the sigil after a
/// byte that is no ASCII letter or digit, a tag of [`ROOM_SECRET_TAG_DIGITS`]
/// lowercase hex digits, a dot and a digit. A row's encoding read this way
/// names each room handle it holds, bare or in `[secret …]`, in a body of
/// its own too (REVIEW-10003 round 2). A text that only looks like one reads
/// as one, which only refuses.
#[must_use]
pub fn holds_room_secret_handle(bytes: &[u8]) -> bool {
    let sigil = ROOM_SECRET_SIGIL.as_bytes()[0];
    bytes.iter().enumerate().any(|(at, &byte)| {
        let tag = at + 1..at + 1 + ROOM_SECRET_TAG_DIGITS;
        byte == sigil
            && at
                .checked_sub(1)
                .and_then(|before| bytes.get(before))
                .is_none_or(|before| !before.is_ascii_alphanumeric())
            && bytes
                .get(tag.clone())
                .is_some_and(|digits| digits.iter().copied().all(room_tag_digit))
            && bytes.get(tag.end) == Some(&b'.')
            && bytes.get(tag.end + 1).is_some_and(u8::is_ascii_digit)
    })
}

/// A digit of a room's tag: lowercase hex.
const fn room_tag_digit(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'f')
}

/// The secrets one room keeps, each by its handle.
#[derive(Default)]
pub(super) struct RoomSecrets {
    /// The room's tag in its handles, drawn at the first secret it keeps.
    tag: Option<u64>,
    /// The last ordinal a handle took: it only grows.
    last: u64,
    held: Vec<RoomSecret>,
}

/// One secret a room keeps, wiped when it goes.
struct RoomSecret {
    /// The room's record of it: an id no base row holds, minted here.
    record: EntityId,
    handle: String,
    /// The reason the wall gave when it lifted the value.
    reason: &'static str,
    value: Zeroizing<Vec<u8>>,
    /// The install nonce of the write segment that kept it, until that
    /// segment commits; its abort wipes the value.
    staged: Option<u64>,
}

impl RoomSecret {
    /// The bytes it holds: its value and its handle.
    fn bytes(&self) -> usize {
        self.value.len().saturating_add(self.handle.len())
    }
}

/// A copy of one secret a room keeps, for a reader inside the room: the
/// room's compare of a row it holds with a call made again, or a save that
/// moves it into the vault's custody. The value is wiped when it drops.
pub struct KeptRoomSecret {
    /// The room's record of it, which no base row names.
    pub record: EntityId,
    /// Its room handle, bare (`r0123456789abcdef.1`).
    pub handle: String,
    /// The reason the wall gave when it lifted the value.
    pub reason: &'static str,
    /// The value, wiped when the copy drops.
    pub value: Zeroizing<Vec<u8>>,
}

impl RoomSecrets {
    /// Wipes every value; the ordinal stays, so no handle is named again.
    fn wipe(&mut self) {
        self.held.clear();
    }

    /// The bytes every value it keeps holds, with its handle.
    fn bytes(&self) -> usize {
        self.held
            .iter()
            .map(RoomSecret::bytes)
            .fold(0, usize::saturating_add)
    }
}

impl SessionOverlay {
    /// Keeps `value`, which the wall lifted for `reason`, in this room's own
    /// custody and answers its room handle: the handle it already has when
    /// the room keeps it, else a new one.
    /// Only a room whose rows still stage keeps a secret: a live one, or one
    /// sealing on record while its last writer drains. A sealed (on-record),
    /// closing or closed room refuses, so nothing outlives the close that
    /// wipes it.
    ///
    /// A new value is staged with the write segment this thread holds for
    /// the room: the segment's commit keeps it, and its abort wipes it, so a
    /// write the room refuses leaves no copy (REVIEW-10003 round 2). It
    /// counts in the room's byte budget beside the rows the room stages.
    ///
    /// # Errors
    ///
    /// The room is not live, the value does not fit the room's budget, or a
    /// lock is poisoned.
    pub fn keep_room_secret(&self, value: &[u8], reason: &'static str) -> Result<String> {
        let (staged, rows) = self.staging_segment();
        let lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if !matches!(
            lifecycle.state,
            OverlayLifecycleState::Live | OverlayLifecycleState::Sealing
        ) {
            return Err(Error::OffRecord(
                OffRecordError::OffRecordOverlayLeaseClosed {
                    generation: lifecycle.generation,
                },
            ));
        }
        let mut secrets = self.lock_room_secrets()?;
        if let Some(kept) = secrets.held.iter().find(|kept| *kept.value == value) {
            return Ok(kept.handle.clone());
        }
        let ordinal = secrets
            .last
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("room secret ordinal"))?;
        let tag = *secrets.tag.get_or_insert_with(rand::random::<u64>);
        let handle = format!("{ROOM_SECRET_SIGIL}{tag:016x}.{ordinal}");
        let attempted_bytes = rows
            .saturating_add(secrets.bytes())
            .saturating_add(value.len())
            .saturating_add(handle.len());
        if attempted_bytes > self.budget_bytes {
            return Err(Error::OffRecord(OffRecordError::OffRecordOverlayFull {
                budget_bytes: self.budget_bytes,
                attempted_bytes,
            }));
        }
        secrets.last = ordinal;
        secrets.held.push(RoomSecret {
            record: EntityId::now(),
            handle: handle.clone(),
            reason,
            value: Zeroizing::new(value.to_vec()),
            staged,
        });
        drop(secrets);
        drop(lifecycle);
        // The host's charge follows what the room retains, its kept values
        // too.
        self.charge_now();
        Ok(handle)
    }

    /// The install nonce of the write segment this thread holds for this
    /// room, if any, and the bytes the room's rows take as that segment
    /// stages them; with none, as they stand published.
    fn staging_segment(&self) -> (Option<u64>, usize) {
        let staged = ACTIVE_SEGMENT
            .try_with(|slot| {
                let slot = slot.try_borrow().ok()?;
                let segment = slot
                    .as_ref()
                    .filter(|segment| std::ptr::eq(segment.overlay.as_ref(), self))?;
                Some((
                    segment.nonce,
                    segment
                        .preview
                        .bytes_used
                        .saturating_add(segment.journal_bytes),
                ))
            })
            .ok()
            .flatten();
        match staged {
            Some((nonce, rows)) => (Some(nonce), rows),
            None => (None, self.state.load().bytes_used),
        }
    }

    /// Settles the values the write segment `nonce` kept: its commit keeps
    /// them, and its abort wipes them, since no row holds their handles. A
    /// poisoned lock still settles.
    pub(super) fn settle_room_secrets(&self, nonce: u64, committed: bool) {
        let mut secrets = self
            .room_secrets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if committed {
            for kept in &mut secrets.held {
                if kept.staged == Some(nonce) {
                    kept.staged = None;
                }
            }
        } else {
            secrets.held.retain(|kept| kept.staged != Some(nonce));
        }
    }

    /// The bytes the values this room keeps hold, with their handles: what
    /// its byte budget and its retained bytes count of them beside its rows.
    /// A poisoned lock still counts.
    pub(super) fn room_secret_bytes(&self) -> usize {
        self.room_secrets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .bytes()
    }

    /// The value this room keeps under `handle` (bare), if it keeps
    /// one: never a value another room keeps, and nothing once the room is
    /// closed.
    ///
    /// # Errors
    ///
    /// A poisoned lock.
    pub fn room_secret(&self, handle: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .lock_room_secrets()?
            .held
            .iter()
            .find(|kept| kept.handle == handle)
            .map(|kept| kept.value.clone()))
    }

    /// A copy of every secret this room keeps now, in the order it kept
    /// them; none once it is closed.
    ///
    /// # Errors
    ///
    /// A poisoned lock.
    pub fn kept_room_secrets(&self) -> Result<Vec<KeptRoomSecret>> {
        Ok(self
            .lock_room_secrets()?
            .held
            .iter()
            .map(|kept| KeptRoomSecret {
                record: kept.record,
                handle: kept.handle.clone(),
                reason: kept.reason,
                value: kept.value.clone(),
            })
            .collect())
    }

    /// How many secrets this room keeps now.
    ///
    /// # Errors
    ///
    /// A poisoned lock.
    pub fn room_secret_count(&self) -> Result<usize> {
        Ok(self.lock_room_secrets()?.held.len())
    }

    /// Wipes every secret this room keeps, at its close. A poisoned lock
    /// still wipes: the values go whatever a panicking holder left.
    pub(super) fn wipe_room_secrets(&self) {
        self.room_secrets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .wipe();
    }

    fn lock_room_secrets(&self) -> Result<std::sync::MutexGuard<'_, RoomSecrets>> {
        self.room_secrets
            .lock()
            .map_err(|_| Error::InvariantViolation("room secrets mutex poisoned"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_keeps_one_handle_and_the_close_wipes_it() -> Result<()> {
        let overlay = SessionOverlay::new(1 << 20);
        let first = overlay.keep_room_secret(b"ghp_room_secret_value", "test.reason")?;
        assert!(is_room_secret_handle(&first), "{first}");
        assert_eq!(
            overlay.keep_room_secret(b"ghp_room_secret_value", "test.reason")?,
            first
        );
        let second = overlay.keep_room_secret(b"another value", "test.reason")?;
        assert_ne!(second, first);
        assert_eq!(
            overlay.room_secret(&first)?.as_deref().map(Vec::as_slice),
            Some(&b"ghp_room_secret_value"[..])
        );
        overlay.close()?;
        assert_eq!(overlay.room_secret_count()?, 0);
        assert!(overlay.room_secret(&first)?.is_none());
        assert!(overlay.kept_room_secrets()?.is_empty());
        assert!(
            overlay
                .keep_room_secret(b"after the close", "test.reason")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn a_room_handle_is_no_durable_short_id() {
        assert!(is_room_secret_handle("r0123456789abcdef.12"));
        for other in [
            "r",
            "r12",
            "sc12",
            "r0123456789abcdef.",
            "r0123456789abcde.1",
            "r0123456789ABCDEF.1",
        ] {
            assert!(!is_room_secret_handle(other), "{other}");
        }
        assert!(
            oneiron_contracts::entity_id::parse_presentation_id("r0123456789abcdef.12").is_err()
        );
    }

    #[test]
    fn a_room_handle_is_found_in_a_rows_bytes() {
        for held in [
            &b"step output: [secret r0123456789abcdef.12]\n"[..],
            b"\xb3r0123456789abcdef.1",
            b"r0123456789abcdef.1",
        ] {
            assert!(holds_room_secret_handle(held), "{held:?}");
        }
        for other in [
            &b"step output: [secret sc12]"[..],
            b"[secret r1]",
            b"for0123456789abcdef.1",
            b"r0123456789abcdef.",
            b"r0123456789ABCDEF.1",
        ] {
            assert!(!holds_room_secret_handle(other), "{other:?}");
        }
    }

    /// REVIEW-10003 round 2: a write segment that aborts wipes the values it
    /// kept; one that commits keeps them.
    #[test]
    fn an_aborted_write_keeps_no_secret_and_a_committed_one_keeps_its_own() -> Result<()> {
        let overlay = SessionOverlay::new(1 << 20);
        let aborted = overlay.install_txn_segment()?;
        overlay.keep_room_secret(b"ghp_room_aborted", "test.reason")?;
        assert_eq!(overlay.room_secret_count()?, 1);
        drop(aborted);
        assert_eq!(overlay.room_secret_count()?, 0);

        let committed = overlay.install_txn_segment()?;
        let handle = overlay.keep_room_secret(b"ghp_room_committed", "test.reason")?;
        committed.commit()?;
        let after = overlay.install_txn_segment()?;
        drop(after);
        assert!(overlay.room_secret(&handle)?.is_some());
        assert_eq!(overlay.room_secret_count()?, 1);
        Ok(())
    }

    /// REVIEW-10003 round 2: a value counts in the room's byte budget, so a
    /// room keeps no value past it.
    #[test]
    fn a_value_past_the_rooms_budget_is_refused() -> Result<()> {
        let overlay = SessionOverlay::new(64);
        assert!(
            overlay
                .keep_room_secret(&[b'k'; 64], "test.reason")
                .is_err()
        );
        overlay.keep_room_secret(b"ghp_small", "test.reason")?;
        assert!(
            overlay
                .keep_room_secret(&[b'v'; 40], "test.reason")
                .is_err()
        );
        assert_eq!(overlay.room_secret_count()?, 1);
        Ok(())
    }

    /// REVIEW-10003: two rooms never spell a handle alike, so one room's
    /// handle names nothing in another.
    #[test]
    fn two_rooms_give_their_first_secrets_different_handles() -> Result<()> {
        let first = SessionOverlay::new(1 << 20).keep_room_secret(b"ghp_room_a", "test.reason")?;
        let other = SessionOverlay::new(1 << 20);
        let second = other.keep_room_secret(b"ghp_room_b", "test.reason")?;
        assert!(is_room_secret_handle(&first) && is_room_secret_handle(&second));
        assert_ne!(first, second);
        assert!(other.room_secret(&first)?.is_none());
        Ok(())
    }
}
