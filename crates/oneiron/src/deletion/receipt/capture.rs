//! The audited classification of a corrupt CLAIM (FIX 7800, ARCH-0038).
//!
//! An owner's maintenance pass may select a stored CLAIM whose non-empty body fails its strict
//! capture decode. Classifying it appends one REDACTION_AUDIT row of a second strict shape, the
//! repair event: ids, two times and a closed code, signed under the receipt transcript (OD-6).
//! It records a classification, never a deletion: it carries no completion time, no sweep, final
//! row or erase reader takes it for an erase receipt, and the typed receipt decoder refuses it,
//! which keeps it on this device (`reverse_remat_skip_redaction_receipt_mirror`). The erase it
//! unblocks names it, per record, in that erase's own `capture_failures`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::super::receipt_grammar::{
    validate_opaque_uuid, validate_receipt_scope, validate_receipt_verification,
};
use super::{RedactionScope, receipt_attestation};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};

/// The one event a repair event records.
const CORRUPT_CLAIM_RECLASSIFIED: &str = "corrupt_claim_reclassified";

/// The closed code a classification and the erase it unblocks record.
pub(crate) const CAPTURE_FAILED: &str = "capture_failed";

/// The pinned repair event keys in their one encoded order: `verification` last, as the
/// attestation transcript's tail splice needs.
const REPAIR_EVENT_KEYS: [&str; 7] = [
    "event",
    "request_id",
    "scope",
    "recorded_at",
    "generation",
    "error_code",
    "verification",
];

/// One record whose hard erase took the audited capture exception: its id, the closed
/// `capture_failed` code and the repair event that classified it, all opaque.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CaptureFailure {
    pub(crate) entity_id: String,
    pub(crate) error_code: String,
    pub(crate) repair_receipt: String,
}

impl CaptureFailure {
    pub(crate) fn new(entity: &EntityId, repair_receipt: &EntityId) -> Self {
        Self {
            entity_id: entity.to_hex(),
            error_code: CAPTURE_FAILED.to_owned(),
            repair_receipt: repair_receipt.to_hex(),
        }
    }
}

/// The repair event body (`rmp_serde::to_vec_named`, field order = [`REPAIR_EVENT_KEYS`]).
#[derive(Serialize)]
struct CorruptClaimRepairEvent {
    event: &'static str,
    request_id: String,
    scope: RedactionScope,
    recorded_at: u64,
    generation: u64,
    error_code: &'static str,
    verification: BTreeMap<String, String>,
}

/// Encodes the repair event classifying the CLAIM `claim`, whose stored header says it was
/// learned at `generation`, as the body of entity `event_id` stamped `recorded_at`, signed by
/// this device. No byte of the CLAIM, its predicate or the decoder's message rides it.
pub(crate) fn encode_corrupt_claim_repair_event(
    claim: &EntityId,
    generation: u64,
    request_id: String,
    recorded_at: u64,
    event_id: &EntityId,
    identity: &crate::identity::DeviceIdentity,
) -> Result<Vec<u8>> {
    let mut event = CorruptClaimRepairEvent {
        event: CORRUPT_CLAIM_RECLASSIFIED,
        request_id,
        scope: RedactionScope::entity(claim),
        recorded_at,
        generation,
        error_code: CAPTURE_FAILED,
        verification: BTreeMap::new(),
    };
    let unsigned = rmp_serde::to_vec_named(&event)
        .map_err(|_| Error::InvariantViolation("corrupt claim repair event encode"))?;
    event.verification = receipt_attestation(&unsigned, event_id, recorded_at, identity);
    let body = rmp_serde::to_vec_named(&event)
        .map_err(|_| Error::InvariantViolation("corrupt claim repair event encode"))?;
    validate_corrupt_claim_repair_event(&body)?;
    Ok(body)
}

/// Whether `body` is a valid repair event, which no erase reader counts as a receipt.
pub(crate) fn is_corrupt_claim_repair_event(body: &[u8]) -> bool {
    validate_corrupt_claim_repair_event(body).is_ok()
}

/// Strictly validates a repair event: one string-keyed map of exactly the pinned keys in their
/// order, no trailing bytes, the closed event and code, an opaque request id, an ids-only scope
/// naming one record, two times and exactly the four attestation entries.
fn validate_corrupt_claim_repair_event(body: &[u8]) -> Result<()> {
    let invalid = |reason| Error::Sync(SyncError::InvalidRedactionReceiptBody(reason));
    let mut cursor = std::io::Cursor::new(body);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid("body is not valid MessagePack"))?;
    if cursor.position() != body.len() as u64 {
        return Err(invalid("trailing bytes after body map"));
    }
    let rmpv::Value::Map(entries) = value else {
        return Err(invalid("body must be a string-keyed MessagePack map"));
    };
    if entries.len() != REPAIR_EVENT_KEYS.len() {
        return Err(invalid("a repair event carries exactly its pinned fields"));
    }
    for ((key, value), expected) in entries.into_iter().zip(REPAIR_EVENT_KEYS) {
        if key.as_str() != Some(expected) {
            return Err(invalid("a repair event carries its pinned fields in order"));
        }
        match expected {
            "event" if value.as_str() == Some(CORRUPT_CLAIM_RECLASSIFIED) => {}
            "error_code" if value.as_str() == Some(CAPTURE_FAILED) => {}
            "recorded_at" | "generation" if value.as_u64().is_some() => {}
            "request_id" => {
                validate_opaque_uuid(&value, "request_id must be an opaque UUID string")?;
            }
            "scope" => validate_repair_scope(value)?,
            "verification" => validate_receipt_verification(value)?,
            _ => return Err(invalid("a repair event field fails its pinned grammar")),
        }
    }
    Ok(())
}

/// A repair event's scope: the receipt scope grammar, naming the one record it classifies and
/// no revision.
fn validate_repair_scope(value: rmpv::Value) -> Result<()> {
    let one_record = value.as_map().is_some_and(|entries| {
        entries.iter().all(|(key, ids)| match key.as_str() {
            Some("entity_ids") => ids.as_array().is_some_and(|ids| ids.len() == 1),
            _ => ids.as_array().is_some_and(Vec::is_empty),
        })
    });
    validate_receipt_scope(value)?;
    if !one_record {
        return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
            "a repair event's scope names the one record it classifies",
        )));
    }
    Ok(())
}
