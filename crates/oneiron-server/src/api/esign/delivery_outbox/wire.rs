//! The outbox's file codec: the envelope the vault writes, the sender's ack,
//! the lease an envelope names, and the names its files go by.

use oneiron::attempt_queue::{AttemptId, AttemptRecord};
use oneiron::blob_artifact::esign::EsignNotice;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest as _, Sha256};

use super::{
    ACK_SUFFIX, CHANNEL, DELIVERY_KIND, ENVELOPE_SUFFIX, FILE_PREFIX, LEASE_OWNER, LEASE_SECS,
    SCHEMA_VERSION,
};

/// The envelope the vault writes for one lease.
#[derive(Serialize)]
struct Envelope<'a> {
    schema_version: u32,
    kind: &'a str,
    channel: &'a str,
    dedupe_key: &'a str,
    attempt_id: String,
    lease_owner: &'a str,
    attempt_count: u32,
    leased_at: u64,
    lease_expires_at: u64,
    payload_sha256: &'a str,
    payload: &'a RawValue,
}

/// The lease an envelope on disk names.
#[derive(Deserialize)]
pub(super) struct Fence {
    attempt_id: String,
    pub(super) attempt_count: u32,
}

/// The sender's answer to one envelope.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ack {
    schema_version: u32,
    dedupe_key: String,
    pub(super) attempt_id: String,
    lease_owner: String,
    attempt_count: u32,
    payload_sha256: String,
    pub(super) status: AckStatus,
    #[serde(default)]
    pub(super) reason: Option<String>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum AckStatus {
    Ok,
    Failed,
}

impl AckStatus {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
        }
    }
}

/// What one queued intent exports: its key, its file stem and its frozen
/// payload.
pub(super) struct Export<'a> {
    dedupe_key: &'a str,
    pub(super) stem: String,
    payload: &'a RawValue,
    payload_sha256: String,
}

pub(super) enum FileRole {
    Envelope,
    Ack,
}

/// The intent `row` exports, or `None` for a row that is not an e-sign
/// notice with a dedupe key.
pub(super) fn export(row: &AttemptRecord) -> Option<Export<'_>> {
    let dedupe_key = row.dedupe_key.as_deref()?;
    let text = std::str::from_utf8(&row.payload).ok()?;
    if serde_json::from_str::<EsignNotice>(text).is_err() {
        return None;
    }
    let payload: &RawValue = serde_json::from_str(text).ok()?;
    Some(Export {
        dedupe_key,
        stem: stem_of(dedupe_key),
        payload,
        payload_sha256: hex(&Sha256::digest(payload.get().as_bytes())),
    })
}

pub(super) fn envelope_bytes(
    row: &AttemptRecord,
    export: &Export<'_>,
) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&Envelope {
        schema_version: SCHEMA_VERSION,
        kind: DELIVERY_KIND,
        channel: CHANNEL,
        dedupe_key: export.dedupe_key,
        attempt_id: hex(row.id.as_bytes()),
        lease_owner: LEASE_OWNER,
        attempt_count: row.attempt_count,
        leased_at: row.updated_at,
        lease_expires_at: row.updated_at.saturating_add(LEASE_SECS),
        payload_sha256: &export.payload_sha256,
        payload: export.payload,
    })
}

/// Whether `ack` echoes `row`'s lease whole: this outbox's owner, the lease
/// generation, the dedupe key its file is named by, and the payload's hash.
pub(super) fn ack_binds(ack: &Ack, row: &AttemptRecord, stem: &str) -> bool {
    let Some(export) = export(row) else {
        return false;
    };
    ack.lease_owner == LEASE_OWNER
        && ack.attempt_count == row.attempt_count
        && ack.dedupe_key == export.dedupe_key
        && export.stem == stem
        && ack.payload_sha256 == export.payload_sha256
}

/// A well-formed ack and the try it names.
pub(super) fn parse_ack(bytes: &[u8]) -> Option<(Ack, AttemptId)> {
    let ack: Ack = serde_json::from_slice(bytes).ok()?;
    let id = parse_attempt_id(&ack.attempt_id)?;
    let shaped = ack.schema_version == SCHEMA_VERSION
        && match ack.status {
            AckStatus::Ok => ack.reason.is_none(),
            AckStatus::Failed => ack
                .reason
                .as_deref()
                .is_some_and(|reason| !reason.is_empty()),
        };
    shaped.then_some((ack, id))
}

/// The lease an envelope on disk names.
pub(super) fn parse_fence(bytes: &[u8]) -> Option<(Fence, AttemptId)> {
    let fence: Fence = serde_json::from_slice(bytes).ok()?;
    let id = parse_attempt_id(&fence.attempt_id)?;
    Some((fence, id))
}

/// The file stem of an intent: the prefix and the lower-hex BLAKE3 of
/// `esign.delivery\0` and its dedupe key.
fn stem_of(dedupe_key: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DELIVERY_KIND.as_bytes());
    hasher.update(&[0]);
    hasher.update(dedupe_key.as_bytes());
    format!("{FILE_PREFIX}{}", hasher.finalize().to_hex())
}

/// The stem and role of an outbox file's name; `None` for any other file
/// (the lock, a temporary, the sender's own).
pub(super) fn parse_name(name: &str) -> Option<(String, FileRole)> {
    let rest = name.strip_prefix(FILE_PREFIX)?;
    let (key, role) = match rest.strip_suffix(ACK_SUFFIX) {
        Some(key) => (key, FileRole::Ack),
        None => (rest.strip_suffix(ENVELOPE_SUFFIX)?, FileRole::Envelope),
    };
    (key.len() == 64 && is_lower_hex(key)).then(|| (format!("{FILE_PREFIX}{key}"), role))
}

fn parse_attempt_id(text: &str) -> Option<AttemptId> {
    if text.len() != 32 || !is_lower_hex(text) {
        return None;
    }
    let bytes = (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    AttemptId::from_bytes(&bytes).ok()
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
