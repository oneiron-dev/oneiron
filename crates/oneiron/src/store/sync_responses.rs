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

pub use self::media::media_job_erased_state;
#[cfg(feature = "sync")]
pub(crate) use self::media::media_job_put_fenced_in_txn;
pub(crate) use self::media::{media_job_carriage, media_job_owners};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, SideTableDbs};

/// Who owns a host row's response, as the host stamps it in the write that
/// keeps the row: the actor that asked, the subject the response is about,
/// and the rows it was made from. A payer is never one. Each is absent when
/// the host could not name it, and the row is kept all the same.
#[doc(hidden)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseStamps {
    #[serde(default)]
    pub actor: Option<EntityId>,
    #[serde(default)]
    pub subject: Option<EntityId>,
    #[serde(default)]
    pub sources: Vec<EntityId>,
}

impl ResponseStamps {
    /// Every owner the stamps name, each once.
    pub(crate) fn ids(&self) -> Vec<EntityId> {
        let mut ids: Vec<EntityId> = self
            .actor
            .iter()
            .chain(self.subject.iter())
            .chain(self.sources.iter())
            .copied()
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

/// One HTTP idempotency cache entry (`sync_state /
/// http:idempotency:<hex-principal>:<hex-key>`), in the compact encoding the
/// host keeps it in.
#[doc(hidden)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyEntry {
    pub created_at_secs: u64,
    pub request_body: Vec<u8>,
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub response_body: Vec<u8>,
    /// The method and request target this entry answers.
    #[serde(default)]
    pub request_target: Option<String>,
    /// The rows the response was derived from, as hex ids.
    #[serde(default)]
    pub served_rows: Vec<String>,
    /// The rows a replay re-admits, as hex ids.
    #[serde(default)]
    pub replay_admits: Option<Vec<String>>,
    /// Who owns the response beside those rows: its caller, when the
    /// request's credential names one (KS-2B2).
    #[serde(default)]
    pub stamps: ResponseStamps,
    /// An erase of an owner took the request and the response: the entry
    /// answers "response erased" until it expires (KS-2B2).
    #[serde(default)]
    pub erased: bool,
    /// The erase of its stamped caller drops the entry rather than leaving
    /// its erased form: a self-hosted non-core keyed route's verified
    /// individual caller's, as the host marks it (FIX 7357). Any other
    /// owner's erase leaves the erased form, as for every entry. Kept last
    /// and written only when set, so every other entry's row is as before.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub erase_drops: bool,
}

impl IdempotencyEntry {
    /// The entry a raw row holds.
    ///
    /// # Errors
    ///
    /// A row that does not decode.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("http idempotency entry"))
    }

    /// The row this entry is kept as.
    ///
    /// # Errors
    ///
    /// An entry that does not encode.
    pub fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec(self).map_err(|_| Error::CorruptedIndex("http idempotency entry"))
    }

    /// Who owns the response: the stamped caller, and the rows it served
    /// and re-admits. An id that does not parse names no one.
    fn owners(&self) -> Vec<EntityId> {
        let mut owners = self.stamps.ids();
        owners.extend(
            self.served_rows
                .iter()
                .chain(self.replay_admits.iter().flatten())
                .filter_map(|hex| EntityId::from_hex(hex).ok()),
        );
        owners.sort_unstable();
        owners.dedup();
        owners
    }

    /// Whether the erase of `owner` drops this entry rather than leaving
    /// its erased form: `owner` is the caller it is stamped with, and the
    /// host marked it [`Self::erase_drops`] (FIX 7357).
    fn dropped_by(&self, owner: &EntityId) -> bool {
        self.erase_drops && self.stamps.actor.as_ref() == Some(owner)
    }

    /// The entry an erase leaves: its time, so it still expires; its
    /// status and stamps; nothing of the request, its target or headers,
    /// or the response.
    fn erased_form(&self) -> Self {
        Self {
            created_at_secs: self.created_at_secs,
            status: self.status,
            stamps: self.stamps.clone(),
            erased: true,
            ..Self::default()
        }
    }
}

/// What a checkpoint carries of the cache entry `value`: the whole entry,
/// with its erased form as the stub a retired instance keeps. `None` for an
/// erased entry, which holds no response, and for one that does not decode.
pub(crate) fn http_carriage(value: &[u8]) -> Option<Vec<u8>> {
    let entry = IdempotencyEntry::decode(value).ok()?;
    if entry.erased {
        return None;
    }
    entry.erased_form().encode().ok()
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
    Ok(())
}

/// A declared prefix as the text a `sync_state` key is.
fn prefix_str(prefix: &'static [u8]) -> Result<&'static str> {
    std::str::from_utf8(prefix)
        .map_err(|_| Error::InvariantViolation("non-UTF-8 sync_state prefix"))
}
