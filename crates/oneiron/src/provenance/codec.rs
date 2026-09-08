//! Edge-provenance value record and its fail-closed MessagePack gate.

use super::actor_substrate::actor_class_from_u8;
use super::{
    EDGE_PROVENANCE_BODY_KEYS, KEY_ACTOR_CLASS, KEY_ACTOR_ENTITY_REF, KEY_BODY_SNAPSHOT_REF,
    KEY_CONFIDENCE, KEY_REASONING_EFFORT, KEY_SOURCE_REVISION_REF, KEY_SUBSTRATE_REF,
    KEY_SUPERSESSION_STATUS, KEY_VALID_FROM, KEY_VALID_TO, REASONING_EFFORT_MAX_BYTES,
    SupersessionStatus,
};
use crate::claim::unit_interval_f32;
use crate::edge::{EdgeActorClass, EdgeConfirmationStatus};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use rmpv::Value;

/// Decoded `edge.provenance` value record — EXACTLY the ten pinned fields
/// (contracts.ts `edgeProvenanceClaim.fields` + the ratified ONE-1138 bump).
///
/// `actor_class` stays caller-supplied at write time and validated against
/// the actor entity's kind (D13); since ONE-1138 (the ONE-1112 C2
/// relocation) the validated value is persisted as a body key on NEW claims
/// (legacy claims keep it on the wrapper's `evid` — see
/// `resolve_persisted_actor_class`).
#[derive(Debug, Clone, PartialEq)]
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
    /// `substrate_ref` — optional 16-byte EntityRef → the MODEL entity
    /// (type byte 121, maintenance band) for the model substrate that
    /// produced THIS write (ONE-1138): actor = WHO, substrate = WITH-WHAT.
    /// Model name + version live ON the MODEL entity (dedup), never inline.
    /// Absent = unrecorded-and-valid.
    pub substrate_ref: Option<EntityId>,
    /// `reasoning_effort` — optional small inline scalar: the
    /// reasoning-effort setting the substrate ran at for THIS write
    /// (ONE-1138). Inlined because it varies per write; everything that does
    /// not (model name, version) dedups onto the referenced MODEL entity.
    /// Non-empty string of at most [`REASONING_EFFORT_MAX_BYTES`] bytes.
    /// Absent = unrecorded-and-valid.
    pub reasoning_effort: Option<String>,
    /// `actor_class` — the write-time validated actor class (ONE-1112 C2
    /// relocation): `{human=0, agent=1, system=2}`. REQUIRED on new-shape
    /// claims (the writer injects the validated caller-supplied class);
    /// absent only on legacy pre-bump claims, which carry it on the
    /// wrapper's `evid` instead. Both-present or neither-present fails
    /// closed — see `resolve_persisted_actor_class`.
    pub actor_class: Option<EdgeActorClass>,
}

impl EdgeProvenanceClaimBody {
    /// Creates a value record from the three required fields; the optional
    /// fields start absent.
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
            substrate_ref: None,
            reasoning_effort: None,
            actor_class: None,
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
    if let Some(substrate) = body.substrate_ref {
        entries.push((
            Value::from(KEY_SUBSTRATE_REF),
            Value::Binary(substrate.as_bytes().to_vec()),
        ));
    }
    if let Some(effort) = &body.reasoning_effort {
        entries.push((
            Value::from(KEY_REASONING_EFFORT),
            Value::from(effort.as_str()),
        ));
    }
    if let Some(actor_class) = body.actor_class {
        entries.push((Value::from(KEY_ACTOR_CLASS), Value::from(actor_class as u8)));
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
///   with `valid_from ≤ valid_to` when both are present;
/// * `substrate_ref` must be 16-byte binary holding a valid entity id
///   (referential MODEL-kind validation happens on the write path);
/// * `reasoning_effort` must be a non-empty UTF-8 string of at most
///   [`REASONING_EFFORT_MAX_BYTES`] bytes;
/// * `actor_class` must be an integer `u8 ≤ 2` (`{human=0, agent=1,
///   system=2}`); its required-on-new-shape rule is enforced at the wrapper
///   level by `resolve_persisted_actor_class`.
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
    let mut substrate_ref: Option<EntityId> = None;
    let mut reasoning_effort: Option<String> = None;
    let mut actor_class: Option<EdgeActorClass> = None;

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
            "substrate_ref" => {
                substrate_ref = Some(entity_ref_from(
                    value,
                    "substrate_ref must be a valid 16-byte entity id",
                )?);
            }
            "reasoning_effort" => {
                let effort = value.as_str().ok_or(Error::InvalidProvenanceBody(
                    "reasoning_effort must be a UTF-8 string",
                ))?;
                if effort.is_empty() || effort.len() > REASONING_EFFORT_MAX_BYTES {
                    return Err(Error::InvalidProvenanceBody(
                        "reasoning_effort must be non-empty and at most 32 bytes",
                    ));
                }
                reasoning_effort = Some(effort.to_owned());
            }
            "actor_class" => {
                let class = value
                    .as_u64()
                    .and_then(|raw| u8::try_from(raw).ok())
                    .and_then(actor_class_from_u8)
                    .ok_or(Error::InvalidProvenanceBody(
                        "actor_class must be an integer u8 <= 2",
                    ))?;
                actor_class = Some(class);
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
        substrate_ref,
        reasoning_effort,
        actor_class,
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
