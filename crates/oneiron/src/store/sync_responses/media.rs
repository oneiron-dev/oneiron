//! A media job row's stamps, mask and fenced write (KS-2B2). The host keeps
//! a job (`sync_state / models:media-job:v1:<ticket>`) in its own named
//! encoding; this module reads four of its fields by name and leaves every
//! other one as the host wrote it:
//!
//! - `request`, the call as its caller sent it ([`MediaRequest`]);
//! - `ended`, where the job ended once a poll saw it ([`MediaJobState`]);
//! - `stamps`, its owners from its submit ([`ResponseStamps`]);
//! - `erased`, set once an erase of an owner took its content.
//!
//! The erased form keeps the job's model, operation, provider handle, payer
//! and receipt, the request's model and envelope, and the end's shape (each
//! part's kind, the usage counts), and scrubs the rest: the request's parts,
//! references, params and voice, each part's text, bytes, URI and vector,
//! the provider's raw usage, and a failure's detail. Its end is terminal: a
//! job that had not ended is failed, so a restore or a restart never takes
//! it up, resumes or resubmits it, and the host answers every poll of it
//! with [`media_job_erased_state`].

use rmpv::Value;
use serde::Serialize;

use super::ResponseStamps;
use crate::entity_id::EntityId;
use crate::llm::media::{MediaJobState, MediaPart, MediaRequest};
use crate::llm::{FatalLlmError, LlmError};

const REQUEST: &str = "request";
const ENDED: &str = "ended";
const STAMPS: &str = "stamps";
const ERASED: &str = "erased";

/// What every poll of an erased job answers: it ended, and nothing of it is
/// left to give. The wire says so, typed (FIX 6296).
#[doc(hidden)]
#[must_use]
pub fn media_job_erased_state() -> MediaJobState {
    MediaJobState::Failed {
        error: LlmError::Fatal(FatalLlmError::ResponseErased),
    }
}

/// The job row `value` as its named map; `None` for one that is not one.
fn job_map(value: &[u8]) -> Option<Vec<(Value, Value)>> {
    match rmpv::decode::read_value(&mut &value[..]).ok()? {
        Value::Map(entries) => Some(entries),
        _ => None,
    }
}

/// The value of the field `name` among `entries`.
fn field<'v>(entries: &'v [(Value, Value)], name: &str) -> Option<&'v Value> {
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}

/// Sets the field `name` among `entries` to `value`, adding it when absent.
fn set_field(entries: &mut Vec<(Value, Value)>, name: &str, value: Value) {
    match entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(name))
    {
        Some((_, slot)) => *slot = value,
        None => entries.push((Value::from(name), value)),
    }
}

/// The field value `value` holds, typed.
fn typed<T: serde::de::DeserializeOwned>(value: &Value) -> Option<T> {
    let mut raw = Vec::new();
    rmpv::encode::write_value(&mut raw, value).ok()?;
    rmp_serde::from_slice(&raw).ok()
}

/// `value` as a field value, in the host's named encoding.
fn untyped<T: Serialize>(value: &T) -> Option<Value> {
    let raw = rmp_serde::to_vec_named(value).ok()?;
    rmpv::decode::read_value(&mut raw.as_slice()).ok()
}

/// Whether the job row `entries` was erased.
fn erased(entries: &[(Value, Value)]) -> bool {
    field(entries, ERASED).and_then(Value::as_bool) == Some(true)
}

/// Who owns the job row `value`'s content, by the stamps its submit wrote:
/// none for a row with no stamps and for one that does not decode. Its
/// payer is never one.
pub(crate) fn media_job_owners(value: &[u8]) -> Vec<EntityId> {
    job_map(value)
        .and_then(|entries| field(&entries, STAMPS).and_then(typed::<ResponseStamps>))
        .map(|stamps| stamps.ids())
        .unwrap_or_default()
}

/// A part with its content scrubbed and its kind kept.
fn scrubbed_part(part: &MediaPart) -> MediaPart {
    match part {
        MediaPart::Text { .. } => MediaPart::Text {
            text: String::new(),
        },
        MediaPart::Image { media_type, .. } => MediaPart::Image {
            media_type: media_type.clone(),
            bytes: Vec::new(),
        },
        MediaPart::Audio { media_type, .. } => MediaPart::Audio {
            media_type: media_type.clone(),
            bytes: Vec::new(),
        },
        MediaPart::Video { media_type, .. } => MediaPart::Video {
            media_type: media_type.clone(),
            bytes: Vec::new(),
            uri: None,
        },
        MediaPart::Embedding { .. } => MediaPart::Embedding { vector: Vec::new() },
    }
}

/// The end an erase leaves: an answer's shape without its content, and
/// for any other end, or none, the erased failure.
fn erased_end(ended: Option<MediaJobState>) -> MediaJobState {
    match ended {
        Some(MediaJobState::Done { mut response }) => {
            response.parts = response.parts.iter().map(scrubbed_part).collect();
            response.usage.raw_provider = serde_json::Value::Null;
            MediaJobState::Done { response }
        }
        _ => media_job_erased_state(),
    }
}

/// What a checkpoint carries of the job row `value`: the whole row, with
/// its erased form as the stub a retired instance keeps. `None` for an
/// erased row, which holds no content, and for one that does not decode.
pub(crate) fn media_job_carriage(value: &[u8]) -> Option<Vec<u8>> {
    let mut entries = job_map(value)?;
    if erased(&entries) {
        return None;
    }
    let mut request: MediaRequest = typed(field(&entries, REQUEST)?)?;
    request.parts.clear();
    request.references.clear();
    request.params.clear();
    request.voice = None;
    let ended = match field(&entries, ENDED) {
        None | Some(Value::Nil) => None,
        Some(ended) => Some(typed::<MediaJobState>(ended)?),
    };
    set_field(&mut entries, REQUEST, untyped(&request)?);
    set_field(&mut entries, ENDED, untyped(&erased_end(ended))?);
    set_field(&mut entries, ERASED, Value::Boolean(true));
    let mut stub = Vec::new();
    rmpv::encode::write_value(&mut stub, &Value::Map(entries)).ok()?;
    Some(stub)
}

/// Keeps the job row `row` at `key` and each of its clips `parts` beside it
/// in `wtxn`, unless an erase took the row already: then nothing is
/// written, so a late end or a retried one never puts erased content back,
/// and `false` is returned.
///
/// # Errors
///
/// Storage errors; a key that is not a job's row, or a part key that is not
/// one of its clips.
#[cfg(feature = "sync")]
pub(crate) fn media_job_put_fenced_in_txn(
    dbs: &impl crate::side_table::SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    key: &str,
    row: &[u8],
    parts: &[(String, Vec<u8>)],
) -> crate::error::Result<bool> {
    let clip = |part: &str| {
        super::media_key(part.as_bytes()) == Some(super::MediaKey::Part { job: key.len() })
            && part.starts_with(key)
    };
    if super::media_key(key.as_bytes()) != Some(super::MediaKey::Job)
        || !parts.iter().all(|(part, _)| clip(part))
    {
        return Err(crate::error::Error::InvariantViolation(
            "a media job put outside its rows",
        ));
    }
    let fenced = dbs
        .side_sync_state()?
        .get(wtxn, key)?
        .and_then(|kept| job_map(&kept))
        .is_some_and(|entries| erased(&entries));
    if fenced {
        return Ok(false);
    }
    for (part, bytes) in parts {
        crate::side_table::host_sync_state_put(dbs, wtxn, part, bytes)?;
    }
    crate::side_table::host_sync_state_put(dbs, wtxn, key, row)?;
    Ok(true)
}
