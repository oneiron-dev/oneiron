use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::sweep_queue::HardEraseSweepExtras;
use super::tombstone::DeleteReason;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RedactionScope {
    pub entity_ids: Vec<String>,
    pub revision_ids: Vec<String>,
}

impl RedactionScope {
    pub(crate) fn entity(entity_id: &EntityId) -> Self {
        Self {
            entity_ids: vec![entity_id.to_hex()],
            revision_ids: Vec::new(),
        }
    }
}

/// The pinned REDACTION_AUDIT body shape (`rmp_serde::to_vec_named`, field
/// order = the pinned [`RECEIPT_BODY_KEYS`] order). `Deserialize` exists for
/// the ONE-1087 sweep executor, whose receipt finalization is the SINGLE
/// sanctioned mutation of an otherwise-immutable receipt: the monotone
/// `sweep_complete_at` None→Some transition on the OWN node's receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RedactionAuditReceipt {
    pub(crate) request_id: String,
    pub(crate) scope: RedactionScope,
    pub(crate) reason: String,
    pub(crate) requested_at: u64,
    pub(crate) soft_complete_at: u64,
    pub(crate) hard_purge_complete_at: u64,
    pub(crate) sweep_queued_at: Option<u64>,
    pub(crate) sweep_complete_at: Option<u64>,
    pub(crate) affected_revision_ids: Vec<String>,
    pub(crate) verification: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub(crate) struct RedactionReceiptInput {
    pub request_id: String,
    pub scope: RedactionScope,
    pub reason: DeleteReason,
    pub requested_at: u64,
    pub soft_complete_at: u64,
    pub hard_purge_complete_at: u64,
    pub sweep_queued_at: Option<u64>,
}

// ─── Receipt origin attestation (ONE-1140, OD-6) ─────────────────────────────
//
// The receipt body's `verification` map — the M4-pinned extension point
// ("verification must be empty UNTIL the audit-chain proof schema is
// pinned") — now carries EXACTLY four attestation entries (this versions
// the M4 pin; values are lowercase-hex strings, BTreeMap iteration = sorted
// keys = deterministic encoding):
//
//   "att_client" → str(16)  client_id hex (BE nibble order, `{:016x}`)
//   "att_pk"     → str(64)  Ed25519 verifying key hex
//   "att_sig"    → str(128) Ed25519 signature hex
//   "att_v"      → str(1)   "1"
//
// Signature transcript (byte-exact):
//   msg = RECEIPT_ATT_DOMAIN || entity_id:16
//         || envelope_header:25 ([type:1][occurred_start:8 BE]
//            [occurred_end:8 BE][learned_at:8 BE], exactly the stored bytes)
//         || body_msgpack_with_verification_EMPTY
//
// The signer encodes with `verification = {}` (those bytes ARE the
// transcript tail), signs, then re-encodes with the four att_ entries. The
// verifier reconstructs the tail by splicing: `verification` is required to
// be the FINAL map entry in bytes (rmp_serde named-struct order guarantees
// it for the legitimate writer; the validator enforces it), so
// `body[..verification_value_offset] || 0x80` reproduces the signed bytes
// — same top-level map header both ways, no re-serialization
// canonicalization trap.

/// Attestation transcript domain separator (OD-6 literal).
pub(crate) const RECEIPT_ATT_DOMAIN: &[u8] = b"oneiron/receipt-att/v1";
pub(crate) const ATT_KEY_CLIENT: &str = "att_client";
pub(crate) const ATT_KEY_PK: &str = "att_pk";
pub(crate) const ATT_KEY_SIG: &str = "att_sig";
pub(crate) const ATT_KEY_V: &str = "att_v";
/// Attestation schema version literal carried in `att_v`.
pub(crate) const ATT_VERSION: &str = "1";
/// MessagePack fixmap(0) — the empty `verification` the transcript tail
/// carries in place of the four att_ entries.
#[cfg(feature = "sync")]
pub(crate) const ATT_EMPTY_MAP_BYTE: u8 = 0x80;

/// The pinned 25 B REDACTION_AUDIT envelope header: receipts are point
/// events (`occurred_start == occurred_end == learned_at`), all three
/// timestamps u64 BE. Shared by the receipt writer and the attestation
/// transcript so the signed header bytes are EXACTLY the stored bytes.
pub(crate) fn receipt_envelope_header(learned_at: u64) -> [u8; 25] {
    let mut header = [0u8; 25];
    header[0] = crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
    header[1..9].copy_from_slice(&learned_at.to_be_bytes());
    header[9..17].copy_from_slice(&learned_at.to_be_bytes());
    header[17..25].copy_from_slice(&learned_at.to_be_bytes());
    header
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Encodes a REDACTION_AUDIT receipt body, signed by this device (OD-6).
///
/// `receipt_id` and `input.hard_purge_complete_at` (the envelope
/// `learned_at`) are bound into the transcript so a valid receipt cannot be
/// transplanted under another entity id or a shifted envelope.
pub(crate) fn encode_redaction_audit_receipt(
    input: RedactionReceiptInput,
    receipt_id: &EntityId,
    identity: &crate::identity::DeviceIdentity,
) -> Result<Vec<u8>> {
    use ed25519_dalek::Signer;

    let envelope_learned_at = input.hard_purge_complete_at;
    let mut receipt = RedactionAuditReceipt {
        request_id: input.request_id,
        scope: input.scope,
        reason: input.reason.as_str().to_owned(),
        requested_at: input.requested_at,
        soft_complete_at: input.soft_complete_at,
        hard_purge_complete_at: input.hard_purge_complete_at,
        sweep_queued_at: input.sweep_queued_at,
        sweep_complete_at: None,
        affected_revision_ids: Vec::new(),
        verification: BTreeMap::new(),
    };

    // Transcript tail: the body bytes with verification EMPTY.
    let body_unsigned = rmp_serde::to_vec_named(&receipt)
        .map_err(|_| Error::InvariantViolation("redaction audit receipt encode"))?;
    let header = receipt_envelope_header(envelope_learned_at);
    let mut msg =
        Vec::with_capacity(RECEIPT_ATT_DOMAIN.len() + 16 + header.len() + body_unsigned.len());
    msg.extend_from_slice(RECEIPT_ATT_DOMAIN);
    msg.extend_from_slice(receipt_id.as_bytes());
    msg.extend_from_slice(&header);
    msg.extend_from_slice(&body_unsigned);
    let signature = identity.signing_key.sign(&msg);

    receipt.verification.insert(
        ATT_KEY_CLIENT.to_owned(),
        format!("{:016x}", identity.client_id),
    );
    receipt.verification.insert(
        ATT_KEY_PK.to_owned(),
        hex_lower(&identity.signing_key.verifying_key().to_bytes()),
    );
    receipt
        .verification
        .insert(ATT_KEY_SIG.to_owned(), hex_lower(&signature.to_bytes()));
    receipt
        .verification
        .insert(ATT_KEY_V.to_owned(), ATT_VERSION.to_owned());

    rmp_serde::to_vec_named(&receipt)
        .map_err(|_| Error::InvariantViolation("redaction audit receipt encode"))
}

/// Decodes a REDACTION_AUDIT receipt BODY (post-envelope bytes).
pub(crate) fn decode_redaction_audit_receipt(body: &[u8]) -> Result<RedactionAuditReceipt> {
    rmp_serde::from_slice(body).map_err(|_| Error::CorruptedIndex("redaction audit receipt body"))
}

/// ONE-1087 replay-door exception for the SINGLE sanctioned receipt
/// mutation: the sweep executor's monotone `sweep_complete_at` None→Some
/// finalization on the OWN node's receipt (LMDB-only — the CRDT mirror
/// keeps the pre-finalization bytes by design).
///
/// Returns `true` iff `incoming` is the stale PRE-finalization echo of the
/// FINALIZED `local` receipt: identical 25 B entity envelope, decodable
/// bodies, `local.sweep_complete_at = Some(_)` vs
/// `incoming.sweep_complete_at = None`, and every OTHER field equal. The
/// doors treat that one shape as an idempotent skip (never quarantine,
/// never overwrite local) — without it every boot would re-quarantine the
/// own-receipt CRDT round-trip after a sweep. ANY other divergence —
/// including incoming `Some` over local `None`, which only a crafted
/// update can produce (replicas never finalize a foreign receipt) — stays
/// on the M4-07 quarantine path. Fail closed: any decode failure → `false`.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn redaction_receipt_is_stale_finalization_echo(local: &[u8], incoming: &[u8]) -> bool {
    use crate::batch::ENTITY_METADATA_HEADER_LEN as H;
    if local.len() < H || incoming.len() < H || local[..H] != incoming[..H] {
        return false;
    }
    let (Ok(local_rec), Ok(incoming_rec)) = (
        decode_redaction_audit_receipt(&local[H..]),
        decode_redaction_audit_receipt(&incoming[H..]),
    ) else {
        return false;
    };
    if local_rec.sweep_complete_at.is_none() || incoming_rec.sweep_complete_at.is_some() {
        return false;
    }
    let definalized = RedactionAuditReceipt {
        sweep_complete_at: None,
        ..local_rec
    };
    definalized == incoming_rec
}

/// Pinned contracts.ts `redactionAuditReceipt.fields` key set — the wire
/// shape every REDACTION_AUDIT blob crossing a sync replay door must satisfy
/// (ONE-1134). Mirrors [`RedactionAuditReceipt`]'s `to_vec_named` encoding:
/// one string-keyed MessagePack map carrying exactly these fields.
///
/// Un-cfg'd since ONE-1087: the sweep executor's receipt finalization
/// self-validates its rewritten body on EVERY build, not just sync ones.
const RECEIPT_BODY_KEYS: [&str; 10] = [
    "request_id",
    "scope",
    "reason",
    "requested_at",
    "soft_complete_at",
    "hard_purge_complete_at",
    "sweep_queued_at",
    "sweep_complete_at",
    "affected_revision_ids",
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
/// * required: every field except `sweep_queued_at` / `sweep_complete_at`
///   (the two contract-optional timestamps, which may also be nil);
/// * `request_id`, `scope.entity_ids[]`, `scope.revision_ids[]`, and
///   `affected_revision_ids[]` must parse as opaque UUIDs (GDPR Art. 5(2)
///   minimization: free text here would smuggle names/content into an
///   immutable, replicated audit record);
/// * `reason` must be one of the pinned receipt-writing DeleteReason
///   literals `user_hard_delete | gdpr_delete | policy_delete`
///   (`user_delete` writes no receipt, so it can never legitimately appear);
/// * the three completion timestamps must be non-negative integers;
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
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidRedactionReceiptBody("body is not valid MessagePack"))?;
    if cursor.position() != body.len() as u64 {
        return Err(Error::InvalidRedactionReceiptBody(
            "trailing bytes after body map",
        ));
    }
    let Value::Map(entries) = value else {
        return Err(Error::InvalidRedactionReceiptBody(
            "body must be a string-keyed MessagePack map",
        ));
    };

    // OD-6 tail-splice precondition: `verification` is the FINAL entry in
    // bytes (decoded entry order IS byte order — the map was read from a
    // contiguous buffer with no trailing bytes).
    match entries.last() {
        Some((key, _)) if key.as_str() == Some("verification") => {}
        _ => {
            return Err(Error::InvalidRedactionReceiptBody(
                "verification must be the final body map entry",
            ));
        }
    }

    let mut seen = [false; RECEIPT_BODY_KEYS.len()];
    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidRedactionReceiptBody(
                "body keys must be strings",
            ));
        };
        let Some(index) = RECEIPT_BODY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::InvalidRedactionReceiptBody(
                "body key is not in the pinned redactionAuditReceipt field set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidRedactionReceiptBody("duplicate body key"));
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
                    return Err(Error::InvalidRedactionReceiptBody(
                        "reason must be user_hard_delete | gdpr_delete | policy_delete",
                    ));
                }
            },
            "requested_at" | "soft_complete_at" | "hard_purge_complete_at" => {
                if value.as_u64().is_none() {
                    return Err(Error::InvalidRedactionReceiptBody(
                        "timestamps must be non-negative integers",
                    ));
                }
            }
            "sweep_queued_at" | "sweep_complete_at" => {
                if !value.is_nil() && value.as_u64().is_none() {
                    return Err(Error::InvalidRedactionReceiptBody(
                        "optional sweep timestamps must be nil or non-negative integers",
                    ));
                }
            }
            "affected_revision_ids" => {
                validate_opaque_uuid_array(
                    &value,
                    "affected_revision_ids must be an array of opaque UUID strings",
                )?;
            }
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

    for (index, key) in RECEIPT_BODY_KEYS.iter().enumerate() {
        let optional = matches!(*key, "sweep_queued_at" | "sweep_complete_at");
        if !optional && !seen[index] {
            return Err(Error::InvalidRedactionReceiptBody(
                "missing required receipt field",
            ));
        }
    }
    Ok(())
}

/// Validates the receipt `scope` field: a map carrying exactly
/// `entity_ids` + `revision_ids`, both arrays of opaque UUID strings
/// (contracts.ts: "entity UUIDs / revision UUIDs … Opaque IDs only; no
/// names or content").
fn validate_receipt_scope(value: rmpv::Value) -> Result<()> {
    let rmpv::Value::Map(entries) = value else {
        return Err(Error::InvalidRedactionReceiptBody("scope must be a map"));
    };
    let mut seen_entity_ids = false;
    let mut seen_revision_ids = false;
    for (key, value) in entries {
        match key.as_str() {
            Some("entity_ids") => {
                if seen_entity_ids {
                    return Err(Error::InvalidRedactionReceiptBody("duplicate scope key"));
                }
                seen_entity_ids = true;
                validate_opaque_uuid_array(
                    &value,
                    "scope.entity_ids must be an array of opaque UUID strings",
                )?;
            }
            Some("revision_ids") => {
                if seen_revision_ids {
                    return Err(Error::InvalidRedactionReceiptBody("duplicate scope key"));
                }
                seen_revision_ids = true;
                validate_opaque_uuid_array(
                    &value,
                    "scope.revision_ids must be an array of opaque UUID strings",
                )?;
            }
            _ => {
                return Err(Error::InvalidRedactionReceiptBody(
                    "scope key is not entity_ids | revision_ids",
                ));
            }
        }
    }
    if !(seen_entity_ids && seen_revision_ids) {
        return Err(Error::InvalidRedactionReceiptBody(
            "scope must carry entity_ids and revision_ids",
        ));
    }
    Ok(())
}

/// Validates the receipt `verification` map against the ONE-1140 (OD-6)
/// attestation grammar: EXACTLY four string entries — `att_client` str(16),
/// `att_pk` str(64), `att_sig` str(128), all lowercase hex, plus
/// `att_v == "1"`. No duplicates, no unknown keys, no other shapes.
fn validate_receipt_verification(value: rmpv::Value) -> Result<()> {
    let rmpv::Value::Map(fields) = value else {
        return Err(Error::InvalidRedactionReceiptBody(
            "verification must be a map",
        ));
    };
    if fields.len() != 4 {
        return Err(Error::InvalidRedactionReceiptBody(
            "verification must carry exactly the four att_ entries",
        ));
    }
    let mut seen = [false; 4];
    for (key, value) in fields {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidRedactionReceiptBody(
                "verification keys must be strings",
            ));
        };
        let Some(value) = value.as_str() else {
            return Err(Error::InvalidRedactionReceiptBody(
                "verification values must be strings",
            ));
        };
        let index = match key {
            ATT_KEY_CLIENT => 0,
            ATT_KEY_PK => 1,
            ATT_KEY_SIG => 2,
            ATT_KEY_V => 3,
            _ => {
                return Err(Error::InvalidRedactionReceiptBody(
                    "verification key is not in the pinned att_ set",
                ));
            }
        };
        if seen[index] {
            return Err(Error::InvalidRedactionReceiptBody(
                "duplicate verification key",
            ));
        }
        seen[index] = true;
        match key {
            ATT_KEY_CLIENT if value.len() == 16 && is_lower_hex(value) => {}
            ATT_KEY_PK if value.len() == 64 && is_lower_hex(value) => {}
            ATT_KEY_SIG if value.len() == 128 && is_lower_hex(value) => {}
            ATT_KEY_V if value == ATT_VERSION => {}
            _ => {
                return Err(Error::InvalidRedactionReceiptBody(
                    "verification value fails the pinned att_ grammar",
                ));
            }
        }
    }
    Ok(())
}

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(feature = "sync")]
fn hex_decode_lower(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !is_lower_hex(s) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// The attestation fields of a validated receipt body plus the byte offset
/// of the `verification` VALUE — the splice point for transcript
/// reconstruction (OD-6).
#[cfg(feature = "sync")]
pub(crate) struct ReceiptAttestationParts {
    pub(crate) client_id: u64,
    pub(crate) pubkey: [u8; 32],
    pub(crate) signature: [u8; 64],
    pub(crate) verification_value_offset: usize,
}

/// Reads a MessagePack map header (fixmap / map16 / map32) off the cursor.
/// The only low-level decode this module hand-rolls: rmpv reads whole
/// values, and the verifier needs the byte OFFSET of the final entry's
/// value, so the top-level header + per-entry walk track positions.
#[cfg(feature = "sync")]
fn read_msgpack_map_len(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u64> {
    use std::io::Read;
    let mut first = [0u8; 1];
    cursor
        .read_exact(&mut first)
        .map_err(|_| Error::InvalidRedactionReceiptBody("body is not valid MessagePack"))?;
    match first[0] {
        b @ 0x80..=0x8f => Ok(u64::from(b & 0x0f)),
        0xde => {
            let mut len = [0u8; 2];
            cursor
                .read_exact(&mut len)
                .map_err(|_| Error::InvalidRedactionReceiptBody("body is not valid MessagePack"))?;
            Ok(u64::from(u16::from_be_bytes(len)))
        }
        0xdf => {
            let mut len = [0u8; 4];
            cursor
                .read_exact(&mut len)
                .map_err(|_| Error::InvalidRedactionReceiptBody("body is not valid MessagePack"))?;
            Ok(u64::from(u32::from_be_bytes(len)))
        }
        _ => Err(Error::InvalidRedactionReceiptBody(
            "body must be a string-keyed MessagePack map",
        )),
    }
}

/// Cursor-parses a receipt body (already structurally validated by
/// [`validate_redaction_receipt_body`]) and extracts the attestation
/// fields plus the verification-value byte offset. The transcript tail is
/// then `body[..verification_value_offset] || ATT_EMPTY_MAP_BYTE` — sound
/// because the validator pinned `verification` as the FINAL entry in bytes
/// with no trailing bytes; a non-canonical re-encoding simply fails the
/// signature (fail closed), never a false accept.
#[cfg(feature = "sync")]
pub(crate) fn receipt_attestation_parts(body: &[u8]) -> Result<ReceiptAttestationParts> {
    const MALFORMED: Error =
        Error::InvalidRedactionReceiptBody("attestation fields failed re-parse");

    let mut cursor = std::io::Cursor::new(body);
    let entry_count = read_msgpack_map_len(&mut cursor)?;
    let mut parts: Option<ReceiptAttestationParts> = None;
    for _ in 0..entry_count {
        let key = rmpv::decode::read_value(&mut cursor).map_err(|_| MALFORMED)?;
        let is_verification = key.as_str() == Some("verification");
        let value_offset = usize::try_from(cursor.position()).map_err(|_| MALFORMED)?;
        let value = rmpv::decode::read_value(&mut cursor).map_err(|_| MALFORMED)?;
        if !is_verification {
            continue;
        }
        let rmpv::Value::Map(fields) = value else {
            return Err(MALFORMED);
        };
        let mut client_id = None;
        let mut pubkey = None;
        let mut signature = None;
        for (att_key, att_value) in &fields {
            let (Some(att_key), Some(att_value)) = (att_key.as_str(), att_value.as_str()) else {
                return Err(MALFORMED);
            };
            match att_key {
                ATT_KEY_CLIENT => {
                    client_id = Some(u64::from_str_radix(att_value, 16).map_err(|_| MALFORMED)?);
                }
                ATT_KEY_PK => {
                    let bytes: [u8; 32] = hex_decode_lower(att_value)
                        .ok_or(MALFORMED)?
                        .try_into()
                        .map_err(|_| MALFORMED)?;
                    pubkey = Some(bytes);
                }
                ATT_KEY_SIG => {
                    let bytes: [u8; 64] = hex_decode_lower(att_value)
                        .ok_or(MALFORMED)?
                        .try_into()
                        .map_err(|_| MALFORMED)?;
                    signature = Some(bytes);
                }
                _ => {}
            }
        }
        parts = Some(ReceiptAttestationParts {
            client_id: client_id.ok_or(MALFORMED)?,
            pubkey: pubkey.ok_or(MALFORMED)?,
            signature: signature.ok_or(MALFORMED)?,
            verification_value_offset: value_offset,
        });
    }
    if cursor.position() != body.len() as u64 {
        return Err(MALFORMED);
    }
    parts.ok_or(MALFORMED)
}

fn validate_opaque_uuid(value: &rmpv::Value, reason: &'static str) -> Result<()> {
    let valid = value
        .as_str()
        .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok());
    if !valid {
        return Err(Error::InvalidRedactionReceiptBody(reason));
    }
    Ok(())
}

fn validate_opaque_uuid_array(value: &rmpv::Value, reason: &'static str) -> Result<()> {
    let Some(items) = value.as_array() else {
        return Err(Error::InvalidRedactionReceiptBody(reason));
    };
    for item in items {
        validate_opaque_uuid(item, reason)?;
    }
    Ok(())
}

impl Vault {
    /// Writes a REDACTION_AUDIT receipt as a normal entity-envelope record
    /// (contracts.ts `redactionAuditReceipt.storage`), maintaining the same
    /// index footprint `apply_put` gives every other envelope write. The
    /// receipt is a point event (`occurred_start == occurred_end ==
    /// learned_at`), so per the `apply_put` convention it gets a
    /// `temporal_occurred_start` row but NO `temporal_occurred_end` row and
    /// no `temporal_long_intervals` row. Maintenance kinds carry no short ID.
    fn put_redaction_audit_receipt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt_id: &EntityId,
        learned_at: u64,
        body: &[u8],
    ) -> Result<()> {
        crate::off_record::FloorWrites::new(&self.store)
            .append_redaction_audit(wtxn, receipt_id, learned_at, body)
    }

    pub(super) fn write_redaction_receipt_and_sweep_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt_id: &EntityId,
        input: RedactionReceiptInput,
        sweep_extras: HardEraseSweepExtras,
    ) -> Result<Vec<u8>> {
        let sweep_key = if let Some(queued_at) = input.sweep_queued_at {
            self.enqueue_hard_erase_sweep_in_txn(
                wtxn,
                input.scope.clone(),
                sweep_extras,
                queued_at,
            )?
        } else {
            Vec::new()
        };

        // ONE-1140 (OD-2/OD-6): every receipt is signed at mint. The device
        // identity (client id + Ed25519 keypair) is lazily self-provisioned
        // in THIS txn — all receipt-mint paths funnel through here, so this
        // is the single in-txn hook.
        let identity = crate::identity::ensure_device_identity_in_txn(self, wtxn)?;
        let hard_purge_complete_at = input.hard_purge_complete_at;
        let body = encode_redaction_audit_receipt(input, receipt_id, &identity)?;
        self.put_redaction_audit_receipt_in_txn(wtxn, receipt_id, hard_purge_complete_at, &body)?;
        Ok(sweep_key)
    }
}
