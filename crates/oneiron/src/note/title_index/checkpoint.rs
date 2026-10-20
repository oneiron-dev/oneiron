//! The NOTE title rows (KS7-2), under the NOTE each names. A reservation's
//! key leads with its author and a NOTE's current reservation is that key,
//! so each row names its author: the NOTE's compartment keeps a placeholder
//! and the author's part holds the row, written back only when the author
//! opens. The NOTE getter reads them.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::RoTxn;

use super::{TITLE_BY_NOTE, TITLE_RESERVATION};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{self, Captured, OwnerRef, RowLocator, Unresolved};

/// The author a reservation key leads with: `hex32(author) ":" ...`.
fn author_of(key: &[u8]) -> Option<EntityId> {
    let (hex, rest) = key.split_at_checked(32)?;
    rest.first().filter(|byte| **byte == b':')?;
    let hex = std::str::from_utf8(hex).ok()?;
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}

pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
    let prefix = TITLE_RESERVATION.decl().prefix;
    for row in rows::typed_rows(dbs, txn, TITLE_RESERVATION, out)? {
        let owner = OwnerRef::entity(&row.value);
        match author_of(row.key.as_bytes()) {
            Some(author) => rows::actor_keyed(out, owner, author, &row.at, prefix, &row.bytes)?,
            None => out.unclassified(row.at, Some(owner), Unresolved::Undecodable),
        }
    }
    for row in rows::typed_rows(dbs, txn, TITLE_BY_NOTE, out)? {
        let owner = OwnerRef::entity(&row.key.0);
        match row.value.strip_prefix(prefix).and_then(author_of) {
            Some(author) => {
                rows::actor_keyed(out, owner, author, &row.at, &row.at.key, &row.bytes)?;
            }
            None => out.unclassified(row.at, Some(owner), Unresolved::Undecodable),
        }
    }
    Ok(())
}

pub(crate) fn owns(at: &RowLocator) -> bool {
    at.in_table(TITLE_RESERVATION.decl()) || at.in_table(TITLE_BY_NOTE.decl())
}

pub(crate) fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(TITLE_RESERVATION.decl()) {
        rows::check_row(TITLE_RESERVATION, at, value)
    } else {
        rows::check_row(TITLE_BY_NOTE, at, value)
    }
}
