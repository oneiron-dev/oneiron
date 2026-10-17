//! The attempt records (`job_records`), with the intake events their rows
//! carry. A row stored before the wall, or while the owner's switch was off,
//! is written again as a new write of it is: an inbound surface event first
//! through the intake door, which admits the event's fields by the side-row
//! wall, then the whole row through the attempt queue's own door, which
//! admits its payload and its authored members. Each secret they place goes
//! to custody and leaves its handle. A hit no rule places refuses the door
//! and files an `unplaceable` proposal; one in a member neither door reads
//! files a `no_door` proposal. The row's keys and indexes stay as they are.

use std::borrow::Cow;
use std::ops::Bound;

use heed::{RoTxn, RwTxn};

use super::super::write_payload_hit;
use super::{Done, LiftCause, Page, hex};
use crate::Vault;
use crate::attempt_queue::{AttemptId, decode_record};
use crate::error::Result;

/// The attempt rows after `after` (an attempt id; empty at the start), up to
/// `limit`.
pub(super) fn census(vault: &Vault, txn: &RoTxn<'_>, after: &[u8], limit: usize) -> Result<Page> {
    let start = if after.is_empty() {
        Bound::Unbounded
    } else {
        Bound::Excluded(after)
    };
    let mut page = Page {
        read: 0,
        hits: Vec::new(),
        next: None,
    };
    let mut read = 0;
    for row in vault
        .store
        .attempt_records
        .range(txn, &(start, Bound::Unbounded))?
    {
        let (key, raw) = row?;
        read += 1;
        if hit(&key, &raw).is_some() {
            page.hits.push(key.to_vec());
        }
        if read == limit {
            page.next = Some(key.into_owned());
            break;
        }
    }
    page.read = u64::try_from(read).unwrap_or(u64::MAX);
    Ok(page)
}

/// Reads attempt row `key` again in the writer's transaction and writes it
/// again through its doors when it still holds a hit.
pub(super) fn lift(vault: &Vault, txn: &mut RwTxn<'_>, key: &[u8]) -> Result<Done> {
    let Some(raw) = vault
        .store
        .attempt_records
        .get(txn, key)?
        .map(Cow::into_owned)
    else {
        return Ok(Done::Clean);
    };
    let Some(reason) = hit(key, &raw) else {
        return Ok(Done::Clean);
    };
    let mut record = decode_record(&raw, AttemptId::from_bytes(key)?)?;
    if record.kind == crate::surface_event::SURFACE_EVENT_ATTEMPT_KIND
        && let Some(payload) =
            crate::surface_event::lift_intake_payload_in_txn(vault, txn, &record.payload)?
    {
        record.payload = payload;
    }
    let stored = crate::attempt_queue::encode_admitted_signal_record(vault, txn, &mut record)?;
    vault.store.attempt_records.put(txn, key, &stored)?;
    Ok(match hit(key, &stored) {
        Some(left) => Done::Propose(LiftCause::NoDoor, left),
        None => Done::Masked {
            history: false,
            reason,
        },
    })
}

/// `attempt:<id, hex>`.
pub(super) fn path(key: &[u8]) -> String {
    format!("attempt:{}", hex(key))
}

/// Whether attempt row `key` is still stored.
pub(super) fn exists(vault: &Vault, txn: &RoTxn<'_>, key: &[u8]) -> Result<bool> {
    Ok(vault.store.attempt_records.get(txn, key)?.is_some())
}

/// The door's reason for a hit in a stored row: in its named body, or in its
/// payload read as a body.
fn hit(key: &[u8], raw: &[u8]) -> Option<&'static str> {
    write_payload_hit(raw.get(1..).unwrap_or_default()).or_else(|| {
        let record = decode_record(raw, AttemptId::from_bytes(key).ok()?).ok()?;
        write_payload_hit(&record.payload)
    })
}
