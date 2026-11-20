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

use zeroize::Zeroizing;

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{Error, OffRecordError, Result};

use super::lifecycle::{OverlayLifecycleState, SessionOverlay};

/// Leading sigil of a room's custody handle: `r`, the room's tag, a dot and
/// the handle's ordinal, `[secret r0123456789abcdef.1]` in a row's text.
pub const ROOM_SECRET_SIGIL: &str = "r";

/// How many lowercase hex digits spell a room's tag: its 64 bits.
const ROOM_TAG_DIGITS: usize = 16;

/// Whether `text` is a room's custody handle, whole: the sigil, a tag of
/// [`ROOM_TAG_DIGITS`] lowercase hex digits, a dot and the ordinal's digits.
#[must_use]
pub fn is_room_secret_handle(text: &str) -> bool {
    let Some((tag, ordinal)) = text
        .strip_prefix(ROOM_SECRET_SIGIL)
        .and_then(|rest| rest.split_once('.'))
    else {
        return false;
    };
    tag.len() == ROOM_TAG_DIGITS
        && tag
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        && !ordinal.is_empty()
        && ordinal.bytes().all(|byte| byte.is_ascii_digit())
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
    /// A value a write kept that did not commit stays until the close: no
    /// row holds its handle, and the same value written again takes it.
    ///
    /// # Errors
    ///
    /// The room is not live, or a lock is poisoned.
    pub fn keep_room_secret(&self, value: &[u8], reason: &'static str) -> Result<String> {
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
        secrets.last = secrets
            .last
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("room secret ordinal"))?;
        let tag = *secrets.tag.get_or_insert_with(rand::random::<u64>);
        let handle = format!("{ROOM_SECRET_SIGIL}{tag:016x}.{}", secrets.last);
        secrets.held.push(RoomSecret {
            record: EntityId::now(),
            handle: handle.clone(),
            reason,
            value: Zeroizing::new(value.to_vec()),
        });
        drop(secrets);
        drop(lifecycle);
        Ok(handle)
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
