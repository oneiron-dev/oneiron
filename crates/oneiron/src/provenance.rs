//! `edge.provenance` Claim module (EDGE-PROVENANCE = C, pinned decisions
//! D10/D12/D13/D15).
//!
//! Under model C the 26 B provenanced edge caches ONLY the two hot flags
//! (`confirmation_status` + `actor_class`). The FULL provenance record —
//! actor entity, source revision / body snapshot, confidence, supersession,
//! validity window — is a CLAIM with predicate [`PREDICATE_EDGE_PROVENANCE`],
//! and that Claim is the SOURCE OF TRUTH. The edge's two flags are a DERIVED
//! CACHE of the Claim (`confirmation_status` ← `supersession_status`,
//! `actor_class` ← the validated class of `actor_entity_ref`).
//!
//! Storage shape (contracts.ts `edgeProvenanceClaim`):
//!
//! * subject — the provenanced edge, addressed as a 33-byte [`EdgeRef`]
//!   `(source_id 16 B ‖ edge_kind u8 ‖ target_id 16 B)`, byte-identical to
//!   the LMDB edge key (`Store::encode_edge_key`);
//! * predicate — the literal `"edge.provenance"`;
//! * value — a MessagePack map carrying EXACTLY the seven pinned snake_case
//!   fields in [`EDGE_PROVENANCE_BODY_KEYS`];
//! * stored as — a normal CLAIM entity (type byte 0, 25 B envelope +
//!   MessagePack body) written through the `pub(crate)` reserved-namespace
//!   door (D17/D18, ONE-1104);
//! * link edge — `claim_of` (u8 = 5, structural 12 B) from the Claim to the
//!   subject edge's SOURCE entity (D12); the authoritative 33-byte EdgeRef
//!   lives in the Claim body's `subj`.
//!
//! Envelope mapping (D15): the Claim entity's `occurred` interval is an
//! index-key derivation of the validity window — absent `valid_from` →
//! `occurred.start = learned_at`; absent `valid_to` → `occurred.end =
//! u64::MAX` (open intervals sort last in `temporal_occurred_end` /
//! `temporal_long_intervals`). Authoritative optionality stays in the
//! MessagePack body. The `temporal_long_intervals` migration guard
//! (`store.rs` step 7) only compares a schema-version key and never inspects
//! row timestamps, so `u64::MAX` end keys use the current `(24, 8)` row shape
//! and cannot trip it; the reopen spec test pins this. A derived envelope
//! with `start > end` (e.g. `valid_to` earlier than `learned_at` with no
//! `valid_from`) is rejected fail-closed with
//! [`Error::InvalidProvenanceBody`] — never silently reordered.
//!
//! Flag writes (D10): [`restamp_edge_flags`] is the ONLY 26-byte stamp
//! primitive and it stays `pub(crate)`. The single public door to provenance
//! flags is [`crate::Vault::put_edge_provenance`] — flags without a Claim
//! would be an unauditable cache, so no public raw-flag API exists.

use heed::RwTxn;
use rmpv::Value;

use crate::claim::{ClaimSubject, EDGE_REF_LEN as CLAIM_EDGE_REF_LEN, unit_interval_f32};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::types::{
    EDGE_VALUE_SEMANTIC_LEN, EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, EDGE_VALUE_STRUCTURAL_LEN,
    ENTITY_ID_LEN, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, EdgeActorClass, EdgeConfirmationStatus,
    EdgeKind, EdgeProvenanceFlags, EntityId,
};

/// The pinned predicate for edge-provenance Claims (contracts.ts
/// `edgeProvenanceClaim.predicate`). Lives in the reserved `edge.*`
/// namespace: only the engine's provenance path may write it (D17).
pub const PREDICATE_EDGE_PROVENANCE: &str = "edge.provenance";

/// Byte length of an encoded [`EdgeRef`]:
/// `(source_id 16 B, edge_kind u8, target_id 16 B)` = 33 B.
pub const EDGE_REF_LEN: usize = CLAIM_EDGE_REF_LEN;

/// Pinned ON-DISK MessagePack key set for the `edge.provenance` value record
/// (contracts.ts `edgeProvenanceClaim.fields`). Order is canonical: the
/// encoder emits present fields in this order. Exactly these seven keys —
/// required: `actor_entity_ref`, `confidence`, `supersession_status`;
/// optional: `source_revision_ref`, `body_snapshot_ref`, `valid_from`,
/// `valid_to`.
pub const EDGE_PROVENANCE_BODY_KEYS: [&str; 7] = [
    "actor_entity_ref",
    "source_revision_ref",
    "body_snapshot_ref",
    "confidence",
    "supersession_status",
    "valid_from",
    "valid_to",
];

pub(crate) const KEY_ACTOR_ENTITY_REF: &str = EDGE_PROVENANCE_BODY_KEYS[0];
pub(crate) const KEY_SOURCE_REVISION_REF: &str = EDGE_PROVENANCE_BODY_KEYS[1];
pub(crate) const KEY_BODY_SNAPSHOT_REF: &str = EDGE_PROVENANCE_BODY_KEYS[2];
pub(crate) const KEY_CONFIDENCE: &str = EDGE_PROVENANCE_BODY_KEYS[3];
pub(crate) const KEY_SUPERSESSION_STATUS: &str = EDGE_PROVENANCE_BODY_KEYS[4];
pub(crate) const KEY_VALID_FROM: &str = EDGE_PROVENANCE_BODY_KEYS[5];
pub(crate) const KEY_VALID_TO: &str = EDGE_PROVENANCE_BODY_KEYS[6];

/// A 33-byte reference addressing one directed edge:
/// `(source_id 16 B, edge_kind u8, target_id 16 B)`.
///
/// The encoding is byte-identical to the LMDB `edges_out` key produced by
/// `Store::encode_edge_key(source, kind, target)` — the spec test pins the
/// alignment so the two layouts cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EdgeRef {
    /// Edge source entity id (bytes 0..16).
    pub source: EntityId,
    /// Edge kind discriminant (byte 16).
    pub kind: EdgeKind,
    /// Edge target entity id (bytes 17..33).
    pub target: EntityId,
}

impl EdgeRef {
    /// Creates an edge reference from its three components.
    #[must_use]
    pub fn new(source: EntityId, kind: EdgeKind, target: EntityId) -> Self {
        Self {
            source,
            kind,
            target,
        }
    }

    /// Encodes the pinned 33-byte layout: source @ 0..16, kind u8 @ 16,
    /// target @ 17..33.
    #[must_use]
    pub fn encode(&self) -> [u8; EDGE_REF_LEN] {
        let mut out = [0_u8; EDGE_REF_LEN];
        out[..ENTITY_ID_LEN].copy_from_slice(self.source.as_bytes());
        out[ENTITY_ID_LEN] = self.kind as u8;
        out[ENTITY_ID_LEN + 1..].copy_from_slice(self.target.as_bytes());
        out
    }

    /// Decodes a 33-byte EdgeRef, rejecting wrong lengths, unregistered kind
    /// bytes, and reserved entity-id byte patterns with
    /// [`Error::InvalidProvenanceBody`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != EDGE_REF_LEN {
            return Err(Error::InvalidProvenanceBody("EdgeRef must be 33 bytes"));
        }
        let source = entity_id_from(&bytes[..ENTITY_ID_LEN], "EdgeRef source id")?;
        let kind = EdgeKind::try_from_u8(bytes[ENTITY_ID_LEN]).ok_or(
            Error::InvalidProvenanceBody("EdgeRef kind byte is not a registered EdgeKind"),
        )?;
        let target = entity_id_from(&bytes[ENTITY_ID_LEN + 1..], "EdgeRef target id")?;
        Ok(Self {
            source,
            kind,
            target,
        })
    }
}

impl From<EdgeRef> for ClaimSubject {
    fn from(value: EdgeRef) -> Self {
        Self::Edge {
            source: value.source,
            kind: value.kind,
            target: value.target,
        }
    }
}

fn entity_id_from(bytes: &[u8], context: &'static str) -> Result<EntityId> {
    let arr: [u8; ENTITY_ID_LEN] = bytes
        .try_into()
        .map_err(|_| Error::InvalidProvenanceBody(context))?;
    EntityId::from_bytes(arr).map_err(|_| Error::InvalidProvenanceBody(context))
}

/// Authoritative supersession status of an `edge.provenance` Claim
/// (contracts.ts `supersession_status`: proposed | confirmed | disputed |
/// retracted). Serialized as u8 in the MessagePack value record; mirrors
/// the edge's cached [`EdgeConfirmationStatus`] flag one-to-one.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SupersessionStatus {
    Proposed = 0,
    Confirmed = 1,
    Disputed = 2,
    Retracted = 3,
}

impl SupersessionStatus {
    /// Converts a raw byte into a status, rejecting values above 3.
    #[must_use]
    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Proposed),
            1 => Some(Self::Confirmed),
            2 => Some(Self::Disputed),
            3 => Some(Self::Retracted),
            _ => None,
        }
    }
}

/// Decoded `edge.provenance` value record — EXACTLY the seven pinned fields
/// (contracts.ts `edgeProvenanceClaim.fields`).
///
/// The derived `actor_class` edge flag is NOT a body field: it is
/// caller-supplied at write time and validated against the actor entity's
/// kind (D13).
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct EdgeProvenanceClaimBody {
    /// `actor_entity_ref` — required 16-byte EntityRef: the PERSON / agent /
    /// MACHINE entity that confirmed, promoted, or cut the edge.
    pub actor_entity_ref: EntityId,
    /// `source_revision_ref` — optional 16-byte RevisionRef (opaque UUID):
    /// the Loro revision the assertion was read at.
    pub source_revision_ref: Option<[u8; 16]>,
    /// `body_snapshot_ref` — optional 16-byte BodySnapshotRef (opaque UUID):
    /// pointer to the exact body bytes the actor saw (ARCH-0038 sweep seam).
    pub body_snapshot_ref: Option<[u8; 16]>,
    /// `confidence` — required, finite in `[0, 1]`. Ranks competing
    /// provenance Claims; never lives on the edge bytes.
    pub confidence: f32,
    /// `supersession_status` — required; derives the edge's
    /// `confirmation_status` flag (identity mirror).
    pub supersession_status: SupersessionStatus,
    /// `valid_from` — optional bi-temporal valid-time start (Unix s).
    pub valid_from: Option<u64>,
    /// `valid_to` — optional bi-temporal valid-time end (Unix s). Null =
    /// still valid.
    pub valid_to: Option<u64>,
}

impl EdgeProvenanceClaimBody {
    /// Creates a value record from the three required fields; the four
    /// optional fields start absent.
    #[must_use]
    pub fn new(
        actor_entity_ref: EntityId,
        confidence: f32,
        supersession_status: SupersessionStatus,
    ) -> Self {
        Self {
            actor_entity_ref,
            source_revision_ref: None,
            body_snapshot_ref: None,
            confidence,
            supersession_status,
            valid_from: None,
            valid_to: None,
        }
    }
}

/// Encodes the value record as a MessagePack map carrying the present
/// [`EDGE_PROVENANCE_BODY_KEYS`] in canonical order. Encoding performs no
/// validation — every write path re-validates through
/// [`decode_edge_provenance_body`], the single validator.
pub(crate) fn encode_edge_provenance_value(body: &EdgeProvenanceClaimBody) -> Value {
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(EDGE_PROVENANCE_BODY_KEYS.len());
    entries.push((
        Value::from(KEY_ACTOR_ENTITY_REF),
        Value::Binary(body.actor_entity_ref.as_bytes().to_vec()),
    ));
    if let Some(revision) = body.source_revision_ref {
        entries.push((
            Value::from(KEY_SOURCE_REVISION_REF),
            Value::Binary(revision.to_vec()),
        ));
    }
    if let Some(snapshot) = body.body_snapshot_ref {
        entries.push((
            Value::from(KEY_BODY_SNAPSHOT_REF),
            Value::Binary(snapshot.to_vec()),
        ));
    }
    entries.push((Value::from(KEY_CONFIDENCE), Value::F32(body.confidence)));
    entries.push((
        Value::from(KEY_SUPERSESSION_STATUS),
        Value::from(body.supersession_status as u8),
    ));
    if let Some(valid_from) = body.valid_from {
        entries.push((Value::from(KEY_VALID_FROM), Value::from(valid_from)));
    }
    if let Some(valid_to) = body.valid_to {
        entries.push((Value::from(KEY_VALID_TO), Value::from(valid_to)));
    }
    Value::Map(entries)
}

/// Decodes and structurally validates an `edge.provenance` value record —
/// the single validator. Fail-closed rules:
///
/// * the value must be a MessagePack map;
/// * keys must be strings drawn from [`EDGE_PROVENANCE_BODY_KEYS`], no
///   duplicates, no unknown keys;
/// * required: `actor_entity_ref`, `confidence`, `supersession_status`;
/// * `actor_entity_ref` must be 16-byte binary holding a valid entity id;
/// * `source_revision_ref` / `body_snapshot_ref` must be 16-byte binary;
/// * `confidence` must be a finite number in `[0, 1]`;
/// * `supersession_status` must be an integer `u8 ≤ 3`;
/// * `valid_from` / `valid_to` must be non-negative integers fitting `u64`,
///   with `valid_from ≤ valid_to` when both are present.
pub fn decode_edge_provenance_body(value: &Value) -> Result<EdgeProvenanceClaimBody> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidProvenanceBody(
            "value must be a MessagePack map",
        ));
    };

    let mut actor_entity_ref: Option<EntityId> = None;
    let mut source_revision_ref: Option<[u8; 16]> = None;
    let mut body_snapshot_ref: Option<[u8; 16]> = None;
    let mut confidence: Option<f32> = None;
    let mut supersession_status: Option<SupersessionStatus> = None;
    let mut valid_from: Option<u64> = None;
    let mut valid_to: Option<u64> = None;

    let mut seen = [false; EDGE_PROVENANCE_BODY_KEYS.len()];
    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidProvenanceBody("keys must be strings"));
        };
        let Some(index) = EDGE_PROVENANCE_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidProvenanceBody(
                "key is not in the pinned EDGE_PROVENANCE_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidProvenanceBody("duplicate key"));
        }
        seen[index] = true;

        match EDGE_PROVENANCE_BODY_KEYS[index] {
            "actor_entity_ref" => {
                actor_entity_ref = Some(entity_ref_from(
                    value,
                    "actor_entity_ref must be a valid 16-byte entity id",
                )?);
            }
            "source_revision_ref" => {
                source_revision_ref = Some(opaque_ref_from(
                    value,
                    "source_revision_ref must be 16-byte binary",
                )?);
            }
            "body_snapshot_ref" => {
                body_snapshot_ref = Some(opaque_ref_from(
                    value,
                    "body_snapshot_ref must be 16-byte binary",
                )?);
            }
            "confidence" => {
                confidence = Some(unit_interval_f32(value).ok_or(Error::InvalidProvenanceBody(
                    "confidence must be finite in [0, 1]",
                ))?);
            }
            "supersession_status" => {
                let status = value
                    .as_u64()
                    .and_then(|raw| u8::try_from(raw).ok())
                    .and_then(SupersessionStatus::try_from_u8)
                    .ok_or(Error::InvalidProvenanceBody(
                        "supersession_status must be an integer u8 <= 3",
                    ))?;
                supersession_status = Some(status);
            }
            "valid_from" => {
                valid_from = Some(value.as_u64().ok_or(Error::InvalidProvenanceBody(
                    "valid_from must be a non-negative integer",
                ))?);
            }
            "valid_to" => {
                valid_to = Some(value.as_u64().ok_or(Error::InvalidProvenanceBody(
                    "valid_to must be a non-negative integer",
                ))?);
            }
            _ => unreachable!("index resolved from EDGE_PROVENANCE_BODY_KEYS"),
        }
    }

    let actor_entity_ref = actor_entity_ref.ok_or(Error::InvalidProvenanceBody(
        "missing required field actor_entity_ref",
    ))?;
    let confidence = confidence.ok_or(Error::InvalidProvenanceBody(
        "missing required field confidence",
    ))?;
    let supersession_status = supersession_status.ok_or(Error::InvalidProvenanceBody(
        "missing required field supersession_status",
    ))?;
    if let (Some(from), Some(to)) = (valid_from, valid_to)
        && from > to
    {
        return Err(Error::InvalidProvenanceBody("valid_from exceeds valid_to"));
    }

    Ok(EdgeProvenanceClaimBody {
        actor_entity_ref,
        source_revision_ref,
        body_snapshot_ref,
        confidence,
        supersession_status,
        valid_from,
        valid_to,
    })
}

/// Structural validation entry point for an `edge.provenance` value record.
/// See [`decode_edge_provenance_body`] for the rules.
pub(crate) fn validate_edge_provenance_value(value: &Value) -> Result<()> {
    decode_edge_provenance_body(value).map(|_| ())
}

fn entity_ref_from(value: &Value, context: &'static str) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidProvenanceBody(context));
    };
    let arr: [u8; ENTITY_ID_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidProvenanceBody(context))?;
    EntityId::from_bytes(arr).map_err(|_| Error::InvalidProvenanceBody(context))
}

fn opaque_ref_from(value: &Value, context: &'static str) -> Result<[u8; 16]> {
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidProvenanceBody(context));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidProvenanceBody(context))
}

/// Derives the edge's cached `confirmation_status` flag from the Claim's
/// authoritative `supersession_status` — a direct identity mirror over
/// `{proposed=0, confirmed=1, disputed=2, retracted=3}` (contracts.ts
/// `derivesEdgeFlags[0]`).
#[must_use]
pub fn derive_confirmation_status(status: SupersessionStatus) -> EdgeConfirmationStatus {
    match status {
        SupersessionStatus::Proposed => EdgeConfirmationStatus::Proposed,
        SupersessionStatus::Confirmed => EdgeConfirmationStatus::Confirmed,
        SupersessionStatus::Disputed => EdgeConfirmationStatus::Disputed,
        SupersessionStatus::Retracted => EdgeConfirmationStatus::Retracted,
    }
}

/// Validates a CALLER-SUPPLIED `actor_class` against the actor entity's
/// kind (D13): PERSON (4) admits `{human=0, agent=1}` — users and AI agents
/// share one table (ARCH-0002), so PERSON alone cannot distinguish them;
/// MACHINE (82) admits `{system=2}`; every other kind is rejected with
/// [`Error::ActorClassMismatch`]. NEVER defaults.
pub fn validate_actor_class(actor_entity_type: u8, actor_class: EdgeActorClass) -> Result<()> {
    let allowed = match actor_entity_type {
        ENTITY_TYPE_PERSON => matches!(actor_class, EdgeActorClass::Human | EdgeActorClass::Agent),
        ENTITY_TYPE_MACHINE => matches!(actor_class, EdgeActorClass::System),
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(Error::ActorClassMismatch {
            actor_entity_type,
            actor_class: actor_class as u8,
        })
    }
}

/// The 26-byte stamp primitive (D10): rewrites ONLY the two hot-flag bytes
/// at offsets 24/25 of the subject edge's value, preserving the first 24
/// bytes (weight + created_at + VAD) verbatim, and writes IDENTICAL bytes to
/// both `edges_out` and `edges_in`.
///
/// `pub(crate)` by design — the only public door to provenance flags is the
/// `edge.provenance` Claim lifecycle ([`crate::Vault::put_edge_provenance`]);
/// a flag without its truth-Claim would be unauditable.
pub(crate) fn restamp_edge_flags(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    subject: &EdgeRef,
    flags: EdgeProvenanceFlags,
) -> Result<()> {
    let key_out = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
    let key_in = Store::encode_edge_key(&subject.target, subject.kind, &subject.source);

    let existing = store
        .edges_out
        .get(wtxn, &key_out)?
        .map(<[u8]>::to_vec)
        .ok_or(Error::EdgeNotFound)?;
    let mut value = match existing.len() {
        EDGE_VALUE_SEMANTIC_LEN | EDGE_VALUE_SEMANTIC_PROVENANCED_LEN => {
            let mut value = existing;
            value.resize(EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, 0);
            value
        }
        EDGE_VALUE_STRUCTURAL_LEN => {
            return Err(Error::ProvenanceOnStructuralEdge {
                kind: subject.kind as u8,
            });
        }
        _ => return Err(Error::CorruptedIndex("edge value")),
    };
    value[24] = flags.confirmation_status as u8;
    value[25] = flags.actor_class as u8;

    store.edges_out.put(wtxn, &key_out, &value)?;
    store.edges_in.put(wtxn, &key_in, &value)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::validate_predicate;
    use crate::error::ErrorKind;

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 16]).expect("test entity id")
    }

    #[test]
    fn predicate_constant_pins_contract_literal() {
        assert_eq!(PREDICATE_EDGE_PROVENANCE, "edge.provenance");
        // Reserved on every public path; writable only through the door.
        assert!(matches!(
            validate_predicate(PREDICATE_EDGE_PROVENANCE, false),
            Err(Error::ReservedPredicate { .. })
        ));
        validate_predicate(PREDICATE_EDGE_PROVENANCE, true)
            .expect("the provenance door must admit the pinned predicate");
    }

    #[test]
    fn body_keys_pin_seven_snake_case_literals() {
        assert_eq!(
            EDGE_PROVENANCE_BODY_KEYS,
            [
                "actor_entity_ref",
                "source_revision_ref",
                "body_snapshot_ref",
                "confidence",
                "supersession_status",
                "valid_from",
                "valid_to",
            ]
        );
    }

    #[test]
    fn edge_ref_codec_pins_byte_offsets_and_aligns_with_edge_key() {
        let source = entity(0x11);
        let target = entity(0x22);
        let edge_ref = EdgeRef::new(source, EdgeKind::Mentions, target);

        let encoded = edge_ref.encode();
        assert_eq!(encoded.len(), 33);
        assert_eq!(EDGE_REF_LEN, 33);
        // Pinned offsets: source @ 0..16, kind u8 @ 16, target @ 17..33.
        assert_eq!(&encoded[..16], source.as_bytes());
        assert_eq!(encoded[16], 9, "Mentions discriminant must be 9");
        assert_eq!(&encoded[17..33], target.as_bytes());
        // Byte-identical to the LMDB edge key layout.
        assert_eq!(
            encoded,
            Store::encode_edge_key(&source, EdgeKind::Mentions, &target)
        );

        assert_eq!(EdgeRef::decode(&encoded).expect("round trip"), edge_ref);

        // Wrong lengths.
        for len in [0_usize, 16, 32, 34] {
            assert!(matches!(
                EdgeRef::decode(&vec![0x11_u8; len]),
                Err(Error::InvalidProvenanceBody(_))
            ));
        }
        // Unregistered kind byte.
        let mut bad_kind = encoded;
        bad_kind[16] = 200;
        assert!(matches!(
            EdgeRef::decode(&bad_kind),
            Err(Error::InvalidProvenanceBody(_))
        ));
        // Reserved entity-id bytes (all zero source).
        let mut reserved = encoded;
        reserved[..16].copy_from_slice(&[0x00; 16]);
        assert!(matches!(
            EdgeRef::decode(&reserved),
            Err(Error::InvalidProvenanceBody(_))
        ));
    }

    #[test]
    fn encode_emits_canonical_snake_case_keys_and_decode_round_trips() {
        let mut body =
            EdgeProvenanceClaimBody::new(entity(0x31), 0.75, SupersessionStatus::Confirmed);
        body.source_revision_ref = Some([0x41; 16]);
        body.body_snapshot_ref = Some([0x42; 16]);
        body.valid_from = Some(100);
        body.valid_to = Some(200);

        let value = encode_edge_provenance_value(&body);
        let Value::Map(entries) = &value else {
            panic!("encoded value must be a map");
        };
        let keys: Vec<&str> = entries
            .iter()
            .map(|(k, _)| k.as_str().expect("string key"))
            .collect();
        // Full body carries EXACTLY the seven pinned keys in canonical order.
        assert_eq!(
            keys,
            [
                "actor_entity_ref",
                "source_revision_ref",
                "body_snapshot_ref",
                "confidence",
                "supersession_status",
                "valid_from",
                "valid_to",
            ]
        );
        // supersession_status is stored as the integer u8, not a string.
        assert_eq!(entries[4].1.as_u64(), Some(1));
        assert_eq!(decode_edge_provenance_body(&value).expect("decode"), body);

        // Minimal body: only the three required keys.
        let minimal = EdgeProvenanceClaimBody::new(entity(0x32), 1.0, SupersessionStatus::Proposed);
        let value = encode_edge_provenance_value(&minimal);
        let Value::Map(entries) = &value else {
            panic!("encoded value must be a map");
        };
        let keys: Vec<&str> = entries
            .iter()
            .map(|(k, _)| k.as_str().expect("string key"))
            .collect();
        assert_eq!(
            keys,
            ["actor_entity_ref", "confidence", "supersession_status"]
        );
        let decoded = decode_edge_provenance_body(&value).expect("decode minimal");
        assert_eq!(decoded, minimal);
        assert_eq!(decoded.source_revision_ref, None);
        assert_eq!(decoded.valid_to, None);
    }

    #[test]
    fn decode_negative_matrix_fail_closed() {
        let actor = entity(0x33);
        let base = || -> Vec<(Value, Value)> {
            vec![
                (
                    Value::from("actor_entity_ref"),
                    Value::Binary(actor.as_bytes().to_vec()),
                ),
                (Value::from("confidence"), Value::F32(0.5)),
                (Value::from("supersession_status"), Value::from(0_u8)),
            ]
        };
        let without = |key: &str| -> Value {
            Value::Map(
                base()
                    .into_iter()
                    .filter(|(k, _)| k.as_str() != Some(key))
                    .collect(),
            )
        };
        let replacing = |key: &str, replacement: Value| -> Value {
            Value::Map(
                base()
                    .into_iter()
                    .map(|(k, v)| {
                        if k.as_str() == Some(key) {
                            (k, replacement.clone())
                        } else {
                            (k, v)
                        }
                    })
                    .collect(),
            )
        };
        let with_extra = |key: &str, value: Value| -> Value {
            let mut entries = base();
            entries.push((Value::from(key), value));
            Value::Map(entries)
        };

        let cases: Vec<(&str, Value)> = vec![
            ("non-map value", Value::from("not a map")),
            (
                "unknown camelCase key",
                with_extra("actorEntityRef", Value::Binary(vec![0x33; 16])),
            ),
            ("missing actor_entity_ref", without("actor_entity_ref")),
            ("missing confidence", without("confidence")),
            (
                "missing supersession_status",
                without("supersession_status"),
            ),
            (
                "confidence NaN",
                replacing("confidence", Value::F32(f32::NAN)),
            ),
            ("confidence -0.1", replacing("confidence", Value::F64(-0.1))),
            ("confidence 1.1", replacing("confidence", Value::F64(1.1))),
            (
                "supersession_status 4",
                replacing("supersession_status", Value::from(4_u8)),
            ),
            (
                "supersession_status 255",
                replacing("supersession_status", Value::from(255_u8)),
            ),
            (
                "supersession_status negative",
                replacing("supersession_status", Value::from(-1_i64)),
            ),
            (
                "supersession_status as string",
                replacing("supersession_status", Value::from("proposed")),
            ),
            (
                "actor ref 15 bytes",
                replacing("actor_entity_ref", Value::Binary(vec![0x33; 15])),
            ),
            (
                "actor ref 17 bytes",
                replacing("actor_entity_ref", Value::Binary(vec![0x33; 17])),
            ),
            (
                "actor ref not binary",
                replacing("actor_entity_ref", Value::from("stringy")),
            ),
            (
                "actor ref reserved all-zero id",
                replacing("actor_entity_ref", Value::Binary(vec![0x00; 16])),
            ),
            (
                "source_revision_ref 17 bytes",
                with_extra("source_revision_ref", Value::Binary(vec![0x41; 17])),
            ),
            (
                "body_snapshot_ref 15 bytes",
                with_extra("body_snapshot_ref", Value::Binary(vec![0x42; 15])),
            ),
            (
                "valid_from negative",
                with_extra("valid_from", Value::from(-5_i64)),
            ),
            (
                "valid_to not an integer",
                with_extra("valid_to", Value::from("soon")),
            ),
            ("duplicate key", {
                let mut entries = base();
                entries.push((Value::from("confidence"), Value::F32(0.9)));
                Value::Map(entries)
            }),
            ("valid_from exceeds valid_to", {
                let mut entries = base();
                entries.push((Value::from("valid_from"), Value::from(200_u64)));
                entries.push((Value::from("valid_to"), Value::from(100_u64)));
                Value::Map(entries)
            }),
        ];

        for (name, value) in cases {
            let err = decode_edge_provenance_body(&value)
                .expect_err(&format!("case {name}: decode must be rejected"));
            assert_eq!(
                err.kind(),
                ErrorKind::InvalidProvenanceBody,
                "case {name}: got {err:?}"
            );
        }

        // The valid base decodes — proving the matrix rejects for the stated
        // reason, not because the scaffold is broken.
        decode_edge_provenance_body(&Value::Map(base())).expect("base case must decode");
    }

    #[test]
    fn derive_confirmation_status_is_identity_mirror() {
        // The pinned {0,1,2,3} identity mirror (contracts.ts
        // derivesEdgeFlags[0]) — both the variant mapping and the numeric
        // values are asserted so a permuted mapping fails.
        let cases = [
            (
                SupersessionStatus::Proposed,
                EdgeConfirmationStatus::Proposed,
                0_u8,
            ),
            (
                SupersessionStatus::Confirmed,
                EdgeConfirmationStatus::Confirmed,
                1,
            ),
            (
                SupersessionStatus::Disputed,
                EdgeConfirmationStatus::Disputed,
                2,
            ),
            (
                SupersessionStatus::Retracted,
                EdgeConfirmationStatus::Retracted,
                3,
            ),
        ];
        for (status, expected_flag, byte) in cases {
            assert_eq!(status as u8, byte);
            let derived = derive_confirmation_status(status);
            assert_eq!(derived, expected_flag);
            assert_eq!(derived as u8, byte);
        }
    }

    #[test]
    fn validate_actor_class_pins_d13_matrix() {
        // PERSON (type byte 4) → {human=0, agent=1}.
        validate_actor_class(4, EdgeActorClass::Human).expect("PERSON+human");
        validate_actor_class(4, EdgeActorClass::Agent).expect("PERSON+agent");
        // MACHINE (type byte 82) → {system=2}.
        validate_actor_class(82, EdgeActorClass::System).expect("MACHINE+system");

        let rejected = [
            (4_u8, EdgeActorClass::System, 2_u8),
            (82, EdgeActorClass::Human, 0),
            (82, EdgeActorClass::Agent, 1),
            // Non-actor kinds never derive a class — typed error, no default.
            (0, EdgeActorClass::Human, 0),    // CLAIM
            (1, EdgeActorClass::System, 2),   // TURN
            (12, EdgeActorClass::Agent, 1),   // ORG
            (120, EdgeActorClass::System, 2), // REDACTION_AUDIT
            (200, EdgeActorClass::System, 2), // unregistered byte
        ];
        for (actor_type, class, class_byte) in rejected {
            let err = validate_actor_class(actor_type, class)
                .expect_err("mismatched actor class must be rejected");
            match err {
                Error::ActorClassMismatch {
                    actor_entity_type,
                    actor_class,
                } => {
                    assert_eq!(actor_entity_type, actor_type);
                    assert_eq!(actor_class, class_byte);
                }
                other => panic!("expected ActorClassMismatch, got {other:?}"),
            }
        }
    }
}
