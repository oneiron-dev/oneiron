//! The NOTE title rows (KS7-2, FIX 6075), under the NOTE each names. A
//! reservation's key is `hex32(author) ":" hex64(digest)`, the digest being
//! the blake3 hash of the NOTE's normalized title, and the NOTE's reverse
//! row holds that key whole, so the checkpoint copy splits the key out of
//! both: the NOTE's compartment keeps the digest as the key spells it (and
//! a reservation's NOTE id) at a locator that names no author, and the
//! author's part holds only the author's id. A restore spells each row back
//! byte for byte from both halves, and leaves it out when the author does
//! not open: no row names an author the checkpoint cannot. The live rows
//! keep their layout. The NOTE getter reads them.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::RoTxn;

use super::{TITLE_BY_NOTE, TITLE_RESERVATION};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{HexId, SideKey};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OwnerRef, RowLocator, RowPart, Unresolved,
};

/// The field a title row's author part fills, with the author's 16 id bytes.
const AUTHOR: &str = "author";

/// A reservation's locator path, before its NOTE and its slot: the
/// reservation's own key names its author, so its NOTE half sits at its
/// table's prefix and this path instead.
const RESERVATION: &str = "reservation ";

/// A title digest's length as a reservation key spells it: 64 hex
/// characters.
const DIGEST_HEX_LEN: usize = 64;

/// The author a reservation key leads with: `hex32(author) ":" ...`.
fn author_of(key: &[u8]) -> Option<EntityId> {
    let (hex, rest) = key.split_at_checked(32)?;
    rest.first().filter(|byte| **byte == b':')?;
    let hex = std::str::from_utf8(hex).ok()?;
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}

/// Whether `digest` is a title digest as the live index spells it: 64
/// lower-case hex characters.
fn is_digest(digest: &[u8]) -> bool {
    digest.len() == DIGEST_HEX_LEN
        && digest
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// A reservation key's author and digest, each in the one spelling the live
/// index writes; `None` for any other spelling, which the split refuses
/// rather than spell back differently.
fn split_key(key: &[u8]) -> Option<(EntityId, &[u8])> {
    let author = author_of(key)?;
    let digest = key.get(33..)?;
    is_digest(digest).then_some((author, digest))
}

/// The full reservation key, prefix included, that `author` and `digest`
/// spell: a reservation row's key, and its NOTE's reverse row's value.
fn reservation_key(author: &EntityId, digest: &[u8]) -> Vec<u8> {
    let mut key = TITLE_RESERVATION.decl().prefix.to_vec();
    key.extend_from_slice(author.to_hex().as_bytes());
    key.push(b':');
    key.extend_from_slice(digest);
    key
}

/// A reservation's locator path: its NOTE, and its slot among that NOTE's
/// parts.
fn reservation_path(note: &EntityId, slot: usize) -> String {
    format!("{RESERVATION}{} {slot}", note.to_hex())
}

/// A title row's author part: only the author's id, naming the NOTE half
/// at `at`.
fn author_part(author: EntityId, at: &RowLocator) -> ActorPart {
    ActorPart {
        actor_entity: author,
        content_locator: at.clone(),
        field: AUTHOR.to_owned(),
        bytes: author.as_bytes().to_vec(),
    }
}

/// Each title row under the NOTE it names, split from its author. A
/// reservation's NOTE half is its digest then its stored value, at its
/// table's prefix and a slot naming its NOTE, and the projection reads the
/// row at its own key (`image_keys`). A reverse row's NOTE half is its
/// digest, at its own key, which names only the NOTE. A row whose key or
/// value is not in the live index's one spelling is unclassified.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
    let prefix = TITLE_RESERVATION.decl().prefix;
    for row in rows::typed_rows(dbs, txn, TITLE_RESERVATION, out)? {
        let owner = OwnerRef::entity(&row.value);
        let Some((author, digest)) = split_key(row.key.as_bytes()) else {
            out.unclassified(row.at, Some(owner), Unresolved::Undecodable);
            continue;
        };
        let mut value = digest.to_vec();
        value.extend_from_slice(&row.bytes);
        let parts = out.owner(owner);
        let at = RowLocator {
            db: row.at.db,
            key: prefix.to_vec(),
            path: reservation_path(&row.value, parts.rows.len()),
        };
        parts.actor_parts.push(author_part(author, &at));
        parts.image_keys.insert(at.clone(), row.at.key);
        parts.rows.push(RowPart::NoActor { at, value });
    }
    for row in rows::typed_rows(dbs, txn, TITLE_BY_NOTE, out)? {
        let owner = OwnerRef::entity(&row.key.0);
        let split = row
            .value
            .strip_prefix(prefix)
            .and_then(split_key)
            .filter(|_| row.at.key == TITLE_BY_NOTE.key_bytes(&row.key));
        let Some((author, digest)) = split else {
            out.unclassified(row.at, Some(owner), Unresolved::Undecodable);
            continue;
        };
        let value = digest.to_vec();
        let parts = out.owner(owner);
        parts.actor_parts.push(author_part(author, &row.at));
        parts.rows.push(RowPart::NoActor { at: row.at, value });
    }
    Ok(())
}

pub(crate) fn owns(at: &RowLocator) -> bool {
    at.in_table(TITLE_RESERVATION.decl()) || at.in_table(TITLE_BY_NOTE.decl())
}

/// A title row's NOTE half, as the capture wrote it.
enum Half<'a> {
    /// A reservation's: its digest, then its stored value (the NOTE's id).
    Reservation(&'a [u8], &'a [u8]),
    /// A NOTE's reverse row's, at the row's own key: its reservation's
    /// digest.
    ByNote(&'a [u8]),
}

impl<'a> Half<'a> {
    /// `value` at `at`, refusing any other shape: a reverse row's half is a
    /// digest at the row's own key, and a reservation's is a digest and a
    /// NOTE id at the table's prefix and a slot naming that NOTE.
    fn read(at: &RowLocator, value: &'a [u8]) -> Result<Self> {
        if at.in_table(TITLE_BY_NOTE.decl()) && at.path.is_empty() && is_digest(value) {
            return Ok(Self::ByNote(value));
        }
        let (digest, stored) = value
            .split_at_checked(DIGEST_HEX_LEN)
            .ok_or_else(rows::bad_part)?;
        let note = TITLE_RESERVATION
            .decode_value(stored)
            .map_err(|_| rows::bad_part())?;
        let slot = at
            .path
            .rsplit_once(' ')
            .and_then(|(_, slot)| slot.parse::<usize>().ok());
        let named = slot.is_some_and(|slot| at.path == reservation_path(&note, slot));
        if at.key == TITLE_RESERVATION.decl().prefix && is_digest(digest) && named {
            Ok(Self::Reservation(digest, stored))
        } else {
            Err(rows::bad_part())
        }
    }
}

/// A title row's NOTE half with its author's part put back: the row's own
/// key and value, byte for byte as the live index wrote them. `None` when
/// the author did not open: the row goes, and no author is made up.
pub(crate) fn join(
    at: &RowLocator,
    value: &[u8],
    parts: &[&ActorPart],
) -> Result<Option<(RowLocator, Vec<u8>)>> {
    let half = Half::read(at, value)?;
    let part = match parts {
        [] => return Ok(None),
        [part] => *part,
        _ => return Err(rows::bad_part()),
    };
    if part.field != AUTHOR || part.bytes.as_slice() != part.actor_entity.as_bytes().as_slice() {
        return Err(rows::bad_part());
    }
    let author = part.actor_entity;
    let row = match half {
        Half::Reservation(digest, stored) => {
            let key = reservation_key(&author, digest);
            (RowLocator::row(at.db, key), stored.to_vec())
        }
        Half::ByNote(digest) => (at.clone(), reservation_key(&author, digest)),
    };
    Ok(Some(row))
}

/// Refuses a restored title row unless it is in the live index's one
/// spelling: a reservation keyed `hex32(author) ":" hex64(digest)` holding
/// a NOTE id, or a NOTE's reverse row holding such a reservation key whole.
pub(crate) fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    let prefix = TITLE_RESERVATION.decl().prefix;
    let spelled = if at.in_table(TITLE_RESERVATION.decl()) {
        rows::check_row(TITLE_RESERVATION, at, value)?;
        at.key.strip_prefix(prefix).and_then(split_key).is_some()
    } else {
        rows::check_row(TITLE_BY_NOTE, at, value)?;
        let note = at
            .key
            .strip_prefix(TITLE_BY_NOTE.decl().prefix)
            .and_then(HexId::decode_key);
        note.is_some_and(|note| TITLE_BY_NOTE.key_bytes(&note) == at.key)
            && value.strip_prefix(prefix).and_then(split_key).is_some()
    };
    spelled.then_some(()).ok_or_else(rows::bad_part)
}
