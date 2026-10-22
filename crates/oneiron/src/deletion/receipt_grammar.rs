//! The pinned REDACTION_AUDIT body grammar (ONE-1134, ONE-1140, FIX 5844):
//! the one structural validator every receipt row passes, whether this
//! device wrote it or a sync replay door admits it. An erase's initial
//! receipt, its sweep row and its overall final row share it.

use super::receipt::{
    ATT_KEY_CLIENT, ATT_KEY_PK, ATT_KEY_SIG, ATT_KEY_V, ATT_VERSION, CAPTURE_FAILED,
};
use crate::error::{Error, Result, SyncError};

/// Pinned contracts.ts `redactionAuditReceipt.fields` key set — the wire
/// shape every REDACTION_AUDIT blob crossing a sync replay door must satisfy
/// (ONE-1134). Mirrors [`super::receipt::RedactionAuditReceipt`]'s `to_vec_named` encoding:
/// one string-keyed MessagePack map carrying exactly these fields.
///
/// Un-cfg'd since ONE-1087: the sweep executor validates every receipt body
/// it reads, and the completion row it appends, on EVERY build.
const RECEIPT_BODY_KEYS: [&str; 17] = [
    "request_id",
    "scope",
    "reason",
    "requested_at",
    "soft_complete_at",
    "hard_purge_complete_at",
    "sweep_queued_at",
    "sweep_deadline_at",
    "sweep_complete_at",
    "affected_revision_ids",
    "actor_ref",
    "room_ref",
    "room_role",
    "erase_complete_at",
    "custody_retirements",
    "capture_failures",
    "verification",
];

/// Structurally validates a REDACTION_AUDIT body arriving through
/// a sync replay door against the pinned contracts.ts
/// `redactionAuditReceipt` field set. Fail-closed rules:
///
/// * the body must be exactly one string-keyed MessagePack map (no
///   positional-array encoding, no trailing bytes);
/// * keys must be drawn from [`RECEIPT_BODY_KEYS`], no duplicates, no
///   unknown fields (a field outside the pinned set is a divergence from
///   the minimization contract — "opaque identifiers + timestamps only");
/// * required: every field except the optional sweep timestamps and room
///   authority fields; sweep timestamps may also be nil;
/// * `request_id`, `scope.entity_ids[]`, `scope.revision_ids[]`, and
///   `affected_revision_ids[]` must parse as opaque UUIDs (GDPR Art. 5(2)
///   minimization: free text here would smuggle names/content into an
///   immutable, replicated audit record);
/// * `reason` must be one of the pinned receipt-writing DeleteReason
///   literals `user_hard_delete | gdpr_delete | policy_delete`
///   (`user_delete` writes no receipt, so it can never legitimately appear);
/// * the three completion timestamps must be non-negative integers;
/// * `erase_complete_at`, set on an erase's overall final row alone, must be
///   nil or a non-negative integer (FIX 5844);
/// * `custody_retirements` must be an array of the value-free names of the
///   custody retirements the erase owes (`<kind tag>.<item hex>.<through
///   hex>`, ids and a generation only), strictly ascending; an empty array is
///   the explicit `not required`;
/// * `capture_failures`, present only when the erase took the audited
///   corrupt-CLAIM exception (FIX 7800), must be a non-empty array of
///   ids-only records, strictly ascending by id;
/// * `verification` carries EXACTLY the four attestation entries pinned by
///   ONE-1140 (OD-6): `att_client` (16 lowercase hex), `att_pk` (64
///   lowercase hex), `att_sig` (128 lowercase hex), `att_v` (`"1"`) —
///   string values only, no other keys. This VERSIONS the M4 "must be
///   empty" pin; anything outside that grammar is still an unvalidated
///   content channel into the immutable record ("never retains what it
///   erased") and is rejected;
/// * `verification` must be the FINAL map entry in bytes: the attestation
///   transcript is the byte prefix up to the verification VALUE
///   (tail-splice, OD-6), so a body that orders it elsewhere can never
///   reproduce the signed bytes.
pub(crate) fn validate_redaction_receipt_body(body: &[u8]) -> Result<()> {
    use rmpv::Value;

    let mut cursor = std::io::Cursor::new(body);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::Sync(SyncError::InvalidRedactionReceiptBody(
            "body is not valid MessagePack",
        ))
    })?;
    if cursor.position() != body.len() as u64 {
        return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
            "trailing bytes after body map",
        )));
    }
    let Value::Map(entries) = value else {
        return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
            "body must be a string-keyed MessagePack map",
        )));
    };

    // OD-6 tail-splice precondition: `verification` is the FINAL entry in
    // bytes (decoded entry order IS byte order — the map was read from a
    // contiguous buffer with no trailing bytes).
    match entries.last() {
        Some((key, _)) if key.as_str() == Some("verification") => {}
        _ => {
            return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                "verification must be the final body map entry",
            )));
        }
    }

    let mut seen = [false; RECEIPT_BODY_KEYS.len()];
    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                "body keys must be strings",
            )));
        };
        let Some(index) = RECEIPT_BODY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                "body key is not in the pinned redactionAuditReceipt field set",
            )));
        };
        if seen[index] {
            return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                "duplicate body key",
            )));
        }
        seen[index] = true;

        match RECEIPT_BODY_KEYS[index] {
            "request_id" => {
                validate_opaque_uuid(&value, "request_id must be an opaque UUID string")?;
            }
            "scope" => validate_receipt_scope(value)?,
            "reason" => match value.as_str() {
                Some("user_hard_delete" | "gdpr_delete" | "policy_delete") => {}
                _ => {
                    return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                        "reason must be user_hard_delete | gdpr_delete | policy_delete",
                    )));
                }
            },
            "requested_at" | "soft_complete_at" | "hard_purge_complete_at" => {
                if value.as_u64().is_none() {
                    return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                        "timestamps must be non-negative integers",
                    )));
                }
            }
            "sweep_queued_at" | "sweep_deadline_at" | "sweep_complete_at" => {
                if !value.is_nil() && value.as_u64().is_none() {
                    return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                        "optional sweep timestamps must be nil or non-negative integers",
                    )));
                }
            }
            "erase_complete_at" => {
                if !value.is_nil() && value.as_u64().is_none() {
                    return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                        "erase_complete_at must be nil or a non-negative integer",
                    )));
                }
            }
            "custody_retirements" => validate_custody_retirements(&value)?,
            "capture_failures" => validate_capture_failures(&value)?,
            "affected_revision_ids" => {
                validate_opaque_uuid_array(
                    &value,
                    "affected_revision_ids must be an array of opaque UUID strings",
                )?;
            }
            "actor_ref" | "room_ref" => {
                validate_opaque_uuid(&value, "room authority references must be opaque UUIDs")?;
            }
            "room_role" => match value.as_str() {
                Some("owner" | "admin" | "member") => {}
                _ => {
                    return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                        "invalid room deletion role",
                    )));
                }
            },
            "verification" => {
                // ONE-1140 (OD-6): the M4 "must be empty" pin is VERSIONED —
                // verification now carries EXACTLY the four attestation
                // entries, hex-grammar-checked. Everything else stays an
                // unvalidated content channel into the immutable,
                // replicated, purge-exempt REDACTION_AUDIT record — the
                // divergence gate would then PROTECT smuggled erased
                // content (minimization: "never retains what it erased").
                validate_receipt_verification(value)?;
            }
            _ => unreachable!("index is drawn from RECEIPT_BODY_KEYS"),
        }
    }

    let room_fields = &seen[10..13];
    if room_fields.iter().any(|present| *present) && !room_fields.iter().all(|present| *present) {
        return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
            "room authority fields must appear together",
        )));
    }
    for (index, key) in RECEIPT_BODY_KEYS.iter().enumerate() {
        let optional = matches!(
            *key,
            "sweep_queued_at"
                | "sweep_deadline_at"
                | "sweep_complete_at"
                | "actor_ref"
                | "room_ref"
                | "room_role"
                | "capture_failures"
        );
        if !optional && !seen[index] {
            return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                "missing required receipt field",
            )));
        }
    }
    Ok(())
}

/// Validates `custody_retirements` (FIX 5844): the names of the custody
/// retirements an erase owes, each one custody writes, strictly ascending,
/// so one binding has one encoding. Nothing else may ride the immutable
/// record here: no key, wrap, value or fingerprint.
fn validate_custody_retirements(value: &rmpv::Value) -> Result<()> {
    const INVALID: Error = Error::Sync(SyncError::InvalidRedactionReceiptBody(
        "custody_retirements must be ascending custody retirement names",
    ));
    let Some(items) = value.as_array() else {
        return Err(INVALID);
    };
    let mut last: Option<&str> = None;
    for item in items {
        let Some(name) = item.as_str() else {
            return Err(INVALID);
        };
        if !crate::store::Store::erase_retirement_name_valid(name)
            || last.is_some_and(|last| last >= name)
        {
            return Err(INVALID);
        }
        last = Some(name);
    }
    Ok(())
}

/// Validates `capture_failures` (FIX 7800): each record whose capture took the
/// audited corrupt-CLAIM exception, as a map of exactly its opaque `entity_id`,
/// the closed `capture_failed` `error_code` and its repair event's opaque
/// `repair_receipt`, strictly ascending by id. A receipt with none omits the
/// field, so an empty array is refused: one binding has one encoding.
fn validate_capture_failures(value: &rmpv::Value) -> Result<()> {
    const INVALID: Error = Error::Sync(SyncError::InvalidRedactionReceiptBody(
        "capture_failures must be ascending ids-only capture failure records",
    ));
    let Some(items) = value.as_array().filter(|items| !items.is_empty()) else {
        return Err(INVALID);
    };
    let mut last: Option<&str> = None;
    for item in items {
        let Some(fields) = item.as_map().filter(|fields| fields.len() == 3) else {
            return Err(INVALID);
        };
        let mut id = None;
        let mut code = false;
        let mut repair = false;
        for (key, field) in fields {
            let Some(text) = field.as_str() else {
                return Err(INVALID);
            };
            match key.as_str() {
                Some("entity_id") if id.is_none() && uuid::Uuid::parse_str(text).is_ok() => {
                    id = Some(text);
                }
                Some("error_code") if !code && text == CAPTURE_FAILED => code = true,
                Some("repair_receipt") if !repair && uuid::Uuid::parse_str(text).is_ok() => {
                    repair = true;
                }
                _ => return Err(INVALID),
            }
        }
        let Some(id) = id.filter(|_| code && repair) else {
            return Err(INVALID);
        };
        if last.is_some_and(|last| last >= id) {
            return Err(INVALID);
        }
        last = Some(id);
    }
    Ok(())
}

/// Validates the receipt `scope` field: a map carrying exactly
/// `entity_ids` + `revision_ids`, both arrays of opaque UUID strings
/// (contracts.ts: "entity UUIDs / revision UUIDs … Opaque IDs only; no
/// names or content").
pub(super) fn validate_receipt_scope(value: rmpv::Value) -> Result<()> {
    let rmpv::Value::Map(entries) = value else {
        return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
            "scope must be a map",
        )));
    };
    let mut seen_entity_ids = false;
    let mut seen_revision_ids = false;
    for (key, value) in entries {
        match key.as_str() {
            Some("entity_ids") => {
                if seen_entity_ids {
                    return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                        "duplicate scope key",
                    )));
                }
                seen_entity_ids = true;
                validate_opaque_uuid_array(
                    &value,
                    "scope.entity_ids must be an array of opaque UUID strings",
                )?;
            }
            Some("revision_ids") => {
                if seen_revision_ids {
                    return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                        "duplicate scope key",
                    )));
                }
                seen_revision_ids = true;
                validate_opaque_uuid_array(
                    &value,
                    "scope.revision_ids must be an array of opaque UUID strings",
                )?;
            }
            _ => {
                return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                    "scope key is not entity_ids | revision_ids",
                )));
            }
        }
    }
    if !(seen_entity_ids && seen_revision_ids) {
        return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
            "scope must carry entity_ids and revision_ids",
        )));
    }
    Ok(())
}

/// Validates the receipt `verification` map against the ONE-1140 (OD-6)
/// attestation grammar: EXACTLY four string entries — `att_client` str(16),
/// `att_pk` str(64), `att_sig` str(128), all lowercase hex, plus
/// `att_v == "1"`. No duplicates, no unknown keys, no other shapes.
pub(super) fn validate_receipt_verification(value: rmpv::Value) -> Result<()> {
    let rmpv::Value::Map(fields) = value else {
        return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
            "verification must be a map",
        )));
    };
    if fields.len() != 4 {
        return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
            "verification must carry exactly the four att_ entries",
        )));
    }
    let mut seen = [false; 4];
    for (key, value) in fields {
        let Some(key) = key.as_str() else {
            return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                "verification keys must be strings",
            )));
        };
        let Some(value) = value.as_str() else {
            return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                "verification values must be strings",
            )));
        };
        let index = match key {
            ATT_KEY_CLIENT => 0,
            ATT_KEY_PK => 1,
            ATT_KEY_SIG => 2,
            ATT_KEY_V => 3,
            _ => {
                return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                    "verification key is not in the pinned att_ set",
                )));
            }
        };
        if seen[index] {
            return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                "duplicate verification key",
            )));
        }
        seen[index] = true;
        match key {
            ATT_KEY_CLIENT if value.len() == 16 && is_lower_hex(value) => {}
            ATT_KEY_PK if value.len() == 64 && is_lower_hex(value) => {}
            ATT_KEY_SIG if value.len() == 128 && is_lower_hex(value) => {}
            ATT_KEY_V if value == ATT_VERSION => {}
            _ => {
                return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(
                    "verification value fails the pinned att_ grammar",
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn is_lower_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn validate_opaque_uuid(value: &rmpv::Value, reason: &'static str) -> Result<()> {
    let valid = value
        .as_str()
        .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok());
    if !valid {
        return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(reason)));
    }
    Ok(())
}

fn validate_opaque_uuid_array(value: &rmpv::Value, reason: &'static str) -> Result<()> {
    let Some(items) = value.as_array() else {
        return Err(Error::Sync(SyncError::InvalidRedactionReceiptBody(reason)));
    };
    for item in items {
        validate_opaque_uuid(item, reason)?;
    }
    Ok(())
}
