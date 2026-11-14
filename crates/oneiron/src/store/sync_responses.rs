//! The host's row-held responses in `sync_state` under body custody (KS-2B2,
//! FIX 5683 part B2; owner KEY STORE = A): the HTTP idempotency cache's
//! entries and the media jobs a restart keeps, each with its clips.
//!
//! Each row is one body instance of KS-2B1's response client, bound lazily
//! the first time a checkpoint carries it: no live read or write touches
//! custody. This module is the engine's own reading of those rows, so the
//! checkpoint, the erase and the activation need no host code:
//!
//! - [`IdempotencyEntry`] is the cache row's codec, the one the host writes
//!   and reads. Its erased form keeps the entry's time, status and stamps and
//!   no request, header, target or response: a host answers it as a typed
//!   "response erased", never a miss and never a second run of the request.
//! - A media job row is the host's own named encoding; this module reads
//!   its stamps and masks its typed request and end (`media`). A clip's
//!   bytes rest in a row of their own beside it, a part.
//! - [`ResponseStamps`] names a row's owners as the host stamps them in the
//!   write that keeps it: an HTTP entry's caller beside the rows it served
//!   and re-admits, a media job's actor, subject and sources from its
//!   submit. A payer is never an owner. A stamp the host could not name
//!   stays absent: the row is still kept, and bound with what it names.
//!
//! The erase of an owner, from the provenance door alone, scrubs every such
//! row its stamps name in the erase's own writer: an entry and a job keep
//! their erased forms, a job's clips go. An entry the host marks
//! [`IdempotencyEntry::erase_drops`] goes at its stamped caller's erase
//! instead (FIX 7357). A delete (the cache's expiry, a job's cancel or
//! removal) is a delete: the next binding pass drops the binding and keeps
//! every key.

mod media;

use serde::{Deserialize, Serialize};

use self::media::media_job_carriage;
pub use self::media::media_job_erased_state;
#[cfg(feature = "sync")]
pub(crate) use self::media::media_job_put_fenced_in_txn;
pub(crate) use self::media::{media_job_owners, media_job_scan};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, SideTableDbs};
use crate::store::{
    ResponseCarriage, ResponseFamily, ResponseRead, ResponseScan, opaque_retired_at,
};

#[doc(hidden)]
pub use oneiron_records::store::sync_responses::{IdempotencyEntry, ResponseStamps};

/// What a checkpoint carries of the cache entry `value`: the whole entry,
/// with its erased form as the stub a retired instance keeps. No response
/// for an erased entry; an entry that does not decode, or whose erased form
/// does not encode, is carried whole as an opaque response, whose retired
/// form is the erased marker (FIX 9390).
pub(crate) fn http_scan(value: &[u8]) -> ResponseScan {
    let Ok(entry) = IdempotencyEntry::decode(value) else {
        return ResponseScan::opaque_row();
    };
    if entry.erased {
        return ResponseScan::NotResponse;
    }
    // The stub keeps whose erase drops it, for a restore to drop it too
    // (FIX 7470).
    let mut stub = entry.erased_form();
    stub.erase_drops = entry.erase_drops;
    match stub.encode() {
        Ok(stub) => ResponseScan::Decoded(ResponseCarriage::whole(stub)),
        Err(_) => ResponseScan::opaque_row(),
    }
}

/// The cache row `key` holds as `value`, read before the host decodes it
/// (FIX 9390): its bytes, or `ResponseErased` for the erased marker of a
/// retired entry that never decoded, which the host answers as its erased
/// entry, never a miss and never a second run.
///
/// # Errors
///
/// `ResponseErased` for the erased marker.
#[doc(hidden)]
pub fn http_response_read<'a>(key: &[u8], value: &'a [u8]) -> Result<&'a [u8]> {
    ResponseRead::of(ResponseFamily::Http, key, value).present()
}

/// When the erased marker the cache row `value` holds was stamped retired,
/// in wall seconds since the Unix epoch (FIX 10710): the host expires that
/// entry from then as it expires any other from its creation. `None` for
/// any other row, and for a marker that kept no time, which never expires.
/// Only the time is read, never the response.
#[doc(hidden)]
pub fn http_opaque_retired_at(value: &[u8]) -> Option<u64> {
    opaque_retired_at(value)
}

/// The media job row `key` holds as `value`, read before the host decodes
/// it (FIX 9390): its bytes, or `ResponseErased` for the erased marker of a
/// retired job that never decoded, which the host answers as an erased job,
/// never taken up, resumed or resubmitted.
///
/// # Errors
///
/// `ResponseErased` for the erased marker.
#[doc(hidden)]
pub fn media_response_read<'a>(key: &[u8], value: &'a [u8]) -> Result<&'a [u8]> {
    ResponseRead::of(ResponseFamily::MediaJob, key, value).present()
}

/// The caller whose own erase drops the cache entry `stub` holds rather
/// than leaving its erased form (FIX 7357, 7470); `None` for an entry no
/// erase drops, and one that does not decode.
pub(crate) fn http_erase_drop_caller(stub: &[u8]) -> Option<EntityId> {
    let entry = IdempotencyEntry::decode(stub).ok()?;
    if !entry.erase_drops {
        return None;
    }
    entry.stamps.actor
}

/// Who owns the cache entry `value`'s response; none for one that does not
/// decode.
pub(crate) fn http_owners(value: &[u8]) -> Vec<EntityId> {
    IdempotencyEntry::decode(value)
        .map(|entry| entry.owners())
        .unwrap_or_default()
}

/// What a `models:media-job:v1:` key names, past its prefix: a job's row,
/// or one of its clips, by the full key of the job's row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MediaKey {
    Job,
    /// A clip: its job's row key is the key's first `job` bytes.
    Part {
        job: usize,
    },
}

/// What the media key `key` names; `None` for one under the prefix that is
/// neither.
pub(crate) fn media_key(key: &[u8]) -> Option<MediaKey> {
    let prefix = side_table::MODEL_MEDIA_JOB.prefix;
    let rest = key.strip_prefix(prefix)?;
    let Some(colon) = rest.iter().position(|&byte| byte == b':') else {
        return Some(MediaKey::Job);
    };
    let index = rest[colon..].strip_prefix(b":part:")?;
    (!index.is_empty() && index.iter().all(u8::is_ascii_digit)).then_some(MediaKey::Part {
        job: prefix.len() + colon,
    })
}

/// What a checkpoint carries of a clip's row `value`: its bytes, with an
/// empty stub. `None` for an empty one.
pub(crate) fn media_part_carriage(value: &[u8]) -> Option<Vec<u8>> {
    (!value.is_empty()).then(Vec::new)
}

/// Whether `value` spells `owner`'s hex id anywhere: every stamp and source
/// ref these rows hold is one, so a row that does not names no owner.
fn names(value: &[u8], hex: &[u8]) -> bool {
    value.windows(hex.len()).any(|window| window == hex)
}

/// The erase of `owner` takes every host response its stamps name, in the
/// erase's own writer (KS-2B2): each cache entry keeps its erased form and
/// answers "response erased", save one stamped with `owner` that the host
/// marked to drop at its caller's erase, which goes (FIX 7357); each media
/// job keeps its erased form, its request scrubbed and its end terminal, and
/// its clips go. A row that does not decode names no owner and stays as it
/// is. Images' copies retire through the rows' obligations.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_sync_response_owner_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    owner: &EntityId,
) -> Result<()> {
    let hex = owner.to_hex();
    let rows = dbs.side_sync_state()?;
    let mut scrubbed: Vec<(String, Vec<u8>)> = Vec::new();
    let mut gone: Vec<String> = Vec::new();
    let http = prefix_str(side_table::HTTP_IDEMPOTENCY_REPLY.prefix)?;
    for row in rows.prefix_iter(wtxn, http)? {
        let (key, value) = row?;
        if !names(&value, hex.as_bytes()) {
            continue;
        }
        if let Ok(entry) = IdempotencyEntry::decode(&value)
            && !entry.erased
            && entry.owners().contains(owner)
        {
            if entry.dropped_by(owner) {
                gone.push(key.into_owned());
            } else if let Ok(stub) = entry.erased_form().encode() {
                scrubbed.push((key.into_owned(), stub));
            }
        }
    }
    let media = prefix_str(side_table::MODEL_MEDIA_JOB.prefix)?;
    let mut jobs = Vec::new();
    for row in rows.prefix_iter(wtxn, media)? {
        let (key, value) = row?;
        if media_key(key.as_bytes()) != Some(MediaKey::Job) || !names(&value, hex.as_bytes()) {
            continue;
        }
        if media_job_owners(&value).contains(owner)
            && let Some(stub) = media_job_carriage(&value)
        {
            jobs.push(key.to_string());
            scrubbed.push((key.into_owned(), stub));
        }
    }
    for job in &jobs {
        for row in rows.prefix_iter(wtxn, &format!("{job}:part:"))? {
            gone.push(row?.0.into_owned());
        }
    }
    for (key, stub) in scrubbed {
        rows.put(wtxn, &key, &stub)?;
    }
    for key in gone {
        rows.delete(wtxn, &key)?;
    }
    crate::store::erase_invocation_claim_owner_in_txn(dbs, wtxn, owner)?;
    Ok(())
}

/// A declared prefix as the text a `sync_state` key is.
fn prefix_str(prefix: &'static [u8]) -> Result<&'static str> {
    std::str::from_utf8(prefix)
        .map_err(|_| Error::InvariantViolation("non-UTF-8 sync_state prefix"))
}
