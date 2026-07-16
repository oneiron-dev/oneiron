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
//! * value — a MessagePack map carrying EXACTLY the ten pinned snake_case
//!   fields in [`EDGE_PROVENANCE_BODY_KEYS`] (the ONE-1138 vocabulary bump:
//!   the original seven + `substrate_ref` + `reasoning_effort` +
//!   `actor_class`, moved together as ONE sync-versioning event);
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
//! Flag writes (D10): `restamp_edge_flags` is the ONLY 26-byte stamp
//! primitive and it stays `pub(crate)`. The single public door to provenance
//! flags is the Claim lifecycle ([`crate::Vault::put_edge_provenance`],
//! [`crate::Vault::supersede_edge_provenance`],
//! [`crate::Vault::retract_edge_provenance`]) — flags without a Claim would
//! be an unauditable cache, so no public raw-flag API exists.
//!
//! # Lifecycle (retract + supersede, contracts.ts `retractionRules` + D14)
//!
//! A provenance Claim is **LIVE** iff its wrapping Claim's `life` status is
//! `active`. Closed Claims (`superseded` / `retracted`) are never deleted —
//! they stay readable as history.
//!
//! * **SUPERSEDE** — "a newer edge.provenance Claim … takes precedence; the
//!   prior Claim gets valid_to set (closed, not deleted). Confidence breaks
//!   ties among live Claims." Per D14, "newer" is the Claim ENTITY's
//!   envelope `learned_at` (u64); `source_revision_ref` is opaque. Writing a
//!   provenance Claim for an EdgeRef therefore:
//!   - REJECTS (typed [`Error::ProvenancePrecedenceViolation`]) when the
//!     incoming `learned_at` is OLDER than the live frontier — an older
//!     Claim can never take precedence, and the engine refuses to write a
//!     dead-on-arrival assertion;
//!   - CLOSES every live Claim whose `learned_at` is strictly older than
//!     the incoming one (`life` = superseded; `valid_to` set to the incoming
//!     `learned_at` when the record had no `valid_to` of its own — an
//!     already-closed validity window is preserved, never extended);
//!   - lets equal-`learned_at` Claims COEXIST live (the contract's
//!     "confidence breaks ties among live Claims" requires a live cohort);
//!   - the explicit [`crate::Vault::supersede_edge_provenance`] form closes
//!     its named prior Claim even on a `learned_at` tie.
//!
//! * **WINNER / DERIVE** — "whenever the Claim changes, re-stamp the edge's
//!   two hot flags from it." With multiple live Claims the stamp source is
//!   the WINNER under the total D14 order: greatest `learned_at`, then
//!   greatest `confidence` ([`f32::total_cmp`]), then greatest claim-id
//!   bytes (engine-defined final tiebreak so the winner is deterministic).
//!   See `winner_index`.
//!
//! * **RETRACT** — "set supersession_status = retracted (and typically
//!   valid_to = now). The edge is KEPT with confirmation_status = retracted
//!   … the edge is not physically removed on retraction." One transaction
//!   sets the record's `supersession_status` = retracted and `valid_to` =
//!   `now`, mirrors `life` = retracted / `to` = `now` on the wrapper,
//!   re-puts the Claim with the envelope `occurred.end` refreshed per D15,
//!   and restamps the edge: from the live WINNER when other live Claims
//!   remain, else `confirmation_status` = retracted with the retracted
//!   Claim's own persisted `actor_class`.
//!
//! * **Close-instant validation** — closing can never invert a validity
//!   window: when the effective `valid_to` would precede `valid_from` (or
//!   the derived envelope start), the operation fails typed
//!   ([`Error::InvalidProvenanceBody`]) — never silently reordered.
//!
//! * **DELETE (ARCH-0038, D16)** — hard-deleting (any receipt-writing
//!   reason) or SoftErasing a provenance Claim removes/scrubs the TRUTH the
//!   edge flags cache. "The derived edge flag follows the Claim": the delete
//!   path captures the EdgeRef + sweep refs pre-purge, and post-purge
//!   refreshes the subject edge in the same transaction — restamped from the
//!   D14 winner among the REMAINING live Claims; else, when a RETRACTED
//!   `edge.provenance` Claim for the same EdgeRef still survives, the 26 B
//!   retracted dampening stamp is KEPT (the withdrawn provenance stays
//!   dampened — the retracted Claim is still readable truth, so the flag
//!   remains auditable), mirroring RETRACT's own None-branch; only when NO
//!   provenance Claim of ANY lifecycle survives is the edge downgraded
//!   26 B → 24 B bare via `downgrade_edge_to_bare` (a cached flag without
//!   any truth-Claim is unauditable). The captured `body_snapshot_ref` /
//!   `source_revision_ref` ride the queued historical-carrier sweep row's
//!   scope (executor = ONE-1091, deferred; cross-device propagation =
//!   ONE-1090, deferred).
//!
//! # Persisted `actor_class` (refresh seam + ONE-1138 relocation)
//!
//! The edge's `actor_class` flag derives from `actor_entity_ref` (contracts
//! `derivesEdgeFlags[1]`), but D13 makes the {human, agent} split for PERSON
//! actors CALLER-SUPPLIED at write time — it is not recoverable from storage
//! alone. So that a later winner-refresh (retract/supersede/D16 delete) can
//! restamp a HISTORICAL Claim's flags without defaulting, the write path
//! persists the write-time validated class ON the value record itself as the
//! `actor_class` body key (ONE-1112 C2 relocation, part of the ONE-1138
//! vocabulary bump). Validation is unchanged: caller-supplied, validated
//! against the actor entity's StructuralKind, never derived by default.
//!
//! TRANSITION SEMANTICS (ONE-1138, pinned): pre-bump claims persisted the
//! class on the wrapping Claim's `evid` field as the engine-owned map
//! `{"actor_class": u8}`. Those claims are NEVER invalidated — the decoder
//! accepts the legacy evid form when the body key is absent. Going forward,
//! writers write the BODY key ONLY and leave `evid` to evidence purity. A
//! claim carrying the class in BOTH places is ambiguous and fails closed
//! ([`Error::InvalidProvenanceBody`]); a claim carrying it in NEITHER fails
//! the same way — never a defaulted class. See
//! `resolve_persisted_actor_class`.

use heed::RwTxn;
use rmpv::Value;

use crate::Vault;
use crate::batch::BatchOp;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::apply_ops;
use crate::claim::ClaimApprovalStatus;
use crate::claim::ClaimBody;
use crate::claim::ClaimLifecycleStatus;
use crate::claim::encode_claim_body;
use crate::claim::validate_claim_body_bytes;
use crate::claim::{ClaimSubject, EDGE_REF_LEN as CLAIM_EDGE_REF_LEN, unit_interval_f32};
use crate::edge::EdgeValueLayout;
use crate::edge::edge_value_layout_for_kind;
use crate::edge::{
    EDGE_VALUE_SEMANTIC_LEN, EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, EDGE_VALUE_STRUCTURAL_LEN,
    EdgeActorClass, EdgeConfirmationStatus, EdgeKind, EdgeProvenanceFlags,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::ppr;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::registry::ENTITY_TYPE_MODEL;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::CLAIM_OF_DEFAULT_WEIGHT;
use crate::vault::MAX_EDGE_QUERY_RESULTS;
use crate::vault::edge_kind_prefix;
use crate::vault::parse_edge_record;
use crate::vault::require_key_len;

/// The pinned predicate for edge-provenance Claims (contracts.ts
/// `edgeProvenanceClaim.predicate`). Lives in the reserved `edge.*`
/// namespace: only the engine's provenance path may write it (D17).
pub const PREDICATE_EDGE_PROVENANCE: &str = "edge.provenance";

/// Byte length of an encoded [`EdgeRef`]:
/// `(source_id 16 B, edge_kind u8, target_id 16 B)` = 33 B.
pub const EDGE_REF_LEN: usize = CLAIM_EDGE_REF_LEN;

/// Pinned ON-DISK MessagePack key set for the `edge.provenance` value record
/// (contracts.ts `edgeProvenanceClaim.fields` + the ratified ONE-1138
/// vocabulary bump). Order is canonical: the encoder emits present fields in
/// this order. Exactly these ten keys — required: `actor_entity_ref`,
/// `confidence`, `supersession_status`; optional: `source_revision_ref`,
/// `body_snapshot_ref`, `valid_from`, `valid_to`, `substrate_ref`,
/// `reasoning_effort`, `actor_class` (`actor_class` is required on NEW-shape
/// claims at the wrapper level — see `resolve_persisted_actor_class`).
///
/// The decoder is FAIL-CLOSED on unknown keys, so growing this set is a
/// sync-versioning event (old nodes reject new keys). ONE-1138 was pinned as
/// the LAST cheap bump: validator, negative-test matrix, and the docs pin
/// moved together, exactly once, before multi-device reality.
pub const EDGE_PROVENANCE_BODY_KEYS: [&str; 10] = [
    "actor_entity_ref",
    "source_revision_ref",
    "body_snapshot_ref",
    "confidence",
    "supersession_status",
    "valid_from",
    "valid_to",
    "substrate_ref",
    "reasoning_effort",
    "actor_class",
];

pub(crate) const KEY_ACTOR_ENTITY_REF: &str = EDGE_PROVENANCE_BODY_KEYS[0];
pub(crate) const KEY_SOURCE_REVISION_REF: &str = EDGE_PROVENANCE_BODY_KEYS[1];
pub(crate) const KEY_BODY_SNAPSHOT_REF: &str = EDGE_PROVENANCE_BODY_KEYS[2];
pub(crate) const KEY_CONFIDENCE: &str = EDGE_PROVENANCE_BODY_KEYS[3];
pub(crate) const KEY_SUPERSESSION_STATUS: &str = EDGE_PROVENANCE_BODY_KEYS[4];
pub(crate) const KEY_VALID_FROM: &str = EDGE_PROVENANCE_BODY_KEYS[5];
pub(crate) const KEY_VALID_TO: &str = EDGE_PROVENANCE_BODY_KEYS[6];
pub(crate) const KEY_SUBSTRATE_REF: &str = EDGE_PROVENANCE_BODY_KEYS[7];
pub(crate) const KEY_REASONING_EFFORT: &str = EDGE_PROVENANCE_BODY_KEYS[8];
pub(crate) const KEY_ACTOR_CLASS: &str = EDGE_PROVENANCE_BODY_KEYS[9];

/// Maximum byte length of an inline `reasoning_effort` scalar. contracts.ts
/// pins the field as a small inline "scalar"; the engine encodes it as a
/// short MessagePack string (LLM-API convention values like "low" /
/// "medium" / "high" / "xhigh"), validated non-empty and at most this many
/// bytes. The exact scalar encoding is flagged for ratification
/// (OWNER-DECISION, ONE-1138 PR).
pub const REASONING_EFFORT_MAX_BYTES: usize = 32;

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

/// Validates a CALLER-SUPPLIED `actor_class` against the actor entity's
/// kind (D13): PERSON (4) admits `{human=0, agent=1}` — users and AI agents
/// share one table (ARCH-0002), so PERSON alone cannot distinguish them;
/// MACHINE (82) admits `{system=2}`; AGENT_DEF (17) admits `{agent=1}` — a
/// dispatched agent's substantive writes carry its definition's entity id as
/// the envelope actor (N1 resolution 2026-07-10; milestone bookkeeping rides
/// the system/Dreamer envelope instead); every other kind is rejected with
/// [`Error::ActorClassMismatch`]. NEVER defaults.
pub fn validate_actor_class(actor_entity_type: u8, actor_class: EdgeActorClass) -> Result<()> {
    let allowed = match actor_entity_type {
        ENTITY_TYPE_PERSON => matches!(actor_class, EdgeActorClass::Human | EdgeActorClass::Agent),
        ENTITY_TYPE_MACHINE => matches!(actor_class, EdgeActorClass::System),
        ENTITY_TYPE_AGENT_DEF => matches!(actor_class, EdgeActorClass::Agent),
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

/// LEGACY engine-internal `evid` key that persisted the WRITE-TIME validated
/// `actor_class` on the wrapping Claim BEFORE the ONE-1138 vocabulary bump
/// (see the module docs' "Persisted actor_class" section). Pre-bump claims
/// carrying it still decode; writers now write the `actor_class` BODY key
/// only and leave `evid` to evidence purity.
pub(crate) const EVIDENCE_KEY_ACTOR_CLASS: &str = "actor_class";

/// Encodes the LEGACY persisted actor-class evidence: the engine-owned
/// MessagePack map `{"actor_class": u8}` stored in the wrapping Claim's
/// `evid` field by pre-ONE-1138 writers. Kept so tests can fabricate
/// pre-bump claims; production writers no longer call it.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "legacy pre-ONE-1138 codec kept for fabricating pre-bump claims in tests"
    )
)]
pub(crate) fn encode_actor_class_evidence(actor_class: EdgeActorClass) -> Value {
    Value::Map(vec![(
        Value::from(EVIDENCE_KEY_ACTOR_CLASS),
        Value::from(actor_class as u8),
    )])
}

/// Decodes the persisted actor-class evidence fail-closed: the value must be
/// exactly the engine-owned map `{"actor_class": u8 <= 2}`. A provenance
/// Claim without it cannot participate in flag refresh — typed error, never
/// a defaulted class (D13).
pub(crate) fn decode_actor_class_evidence(evidence: Option<&Value>) -> Result<EdgeActorClass> {
    let Some(Value::Map(entries)) = evidence else {
        return Err(Error::InvalidProvenanceBody(
            "provenance claim is missing its persisted actor_class evidence",
        ));
    };
    let mut actor_class: Option<EdgeActorClass> = None;
    for (key, value) in entries {
        if key.as_str() != Some(EVIDENCE_KEY_ACTOR_CLASS) {
            return Err(Error::InvalidProvenanceBody(
                "unknown key in provenance actor_class evidence",
            ));
        }
        if actor_class.is_some() {
            return Err(Error::InvalidProvenanceBody(
                "duplicate actor_class evidence key",
            ));
        }
        let parsed = value
            .as_u64()
            .and_then(|raw| u8::try_from(raw).ok())
            .and_then(actor_class_from_u8)
            .ok_or(Error::InvalidProvenanceBody(
                "actor_class evidence must be an integer u8 <= 2",
            ))?;
        actor_class = Some(parsed);
    }
    actor_class.ok_or(Error::InvalidProvenanceBody(
        "provenance claim is missing its persisted actor_class evidence",
    ))
}

fn actor_class_from_u8(value: u8) -> Option<EdgeActorClass> {
    match value {
        0 => Some(EdgeActorClass::Human),
        1 => Some(EdgeActorClass::Agent),
        2 => Some(EdgeActorClass::System),
        _ => None,
    }
}

/// Resolves the persisted write-time `actor_class` of a stored
/// `edge.provenance` Claim under the pinned ONE-1138 transition semantics:
///
/// * NEW shape — `actor_class` in the value record body, wrapper `evid`
///   absent → the body value wins;
/// * LEGACY shape (pre-bump, never invalidated) — body key absent, the
///   engine-owned `{"actor_class": u8}` map on the wrapper's `evid` →
///   decoded via the unchanged legacy codec;
/// * BOTH places → ambiguous, fails closed
///   ([`Error::InvalidProvenanceBody`]) — two sources of truth for a flag
///   refresh are never reconciled silently;
/// * NEITHER place → fails closed the same way — a provenance Claim without
///   a persisted class cannot participate in flag refresh; the class is
///   never defaulted (D13).
pub(crate) fn resolve_persisted_actor_class(
    record: &EdgeProvenanceClaimBody,
    evidence: Option<&Value>,
) -> Result<EdgeActorClass> {
    match (record.actor_class, evidence) {
        (Some(_), Some(_)) => Err(Error::InvalidProvenanceBody(
            "actor_class present in both the value record and the wrapper evid (ambiguous)",
        )),
        (Some(class), None) => Ok(class),
        (None, evidence) => decode_actor_class_evidence(evidence),
    }
}

/// MessagePack body key for a MODEL entity's model name (ONE-1138).
pub(crate) const MODEL_BODY_KEY_NAME: &str = "name";
/// MessagePack body key for a MODEL entity's model version (ONE-1138).
pub(crate) const MODEL_BODY_KEY_VERSION: &str = "version";
/// Maximum byte length of a MODEL entity's `name` / `version` string.
pub const MODEL_SUBSTRATE_FIELD_MAX_BYTES: usize = 256;

/// Validates one MODEL substrate descriptor string (`name` / `version`):
/// non-empty UTF-8, at most [`MODEL_SUBSTRATE_FIELD_MAX_BYTES`] bytes.
pub(crate) fn validate_model_substrate_field(value: &str, context: &'static str) -> Result<()> {
    if value.is_empty() || value.len() > MODEL_SUBSTRATE_FIELD_MAX_BYTES {
        return Err(Error::InvalidModelSubstrate(context));
    }
    Ok(())
}

/// Encodes the engine-authored MODEL entity body (type byte 121): the
/// MessagePack map `{"name": str, "version": str}`. Model name + version
/// live ON the MODEL entity so provenance records dedup to a 16-byte
/// `substrate_ref` instead of inlining them per write (ONE-1138).
pub(crate) fn encode_model_entity_body(name: &str, version: &str) -> Result<Vec<u8>> {
    validate_model_substrate_field(name, "model name must be non-empty and at most 256 bytes")?;
    validate_model_substrate_field(
        version,
        "model version must be non-empty and at most 256 bytes",
    )?;
    let value = Value::Map(vec![
        (Value::from(MODEL_BODY_KEY_NAME), Value::from(name)),
        (Value::from(MODEL_BODY_KEY_VERSION), Value::from(version)),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("model entity body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes a stored MODEL entity body fail-closed: exactly one MessagePack
/// map (no trailing bytes) carrying exactly the `name` + `version` string
/// keys, both passing [`validate_model_substrate_field`]. MODEL entities are
/// engine-authored, so a body that fails this decode is on-disk corruption.
pub(crate) fn decode_model_entity_body(bytes: &[u8]) -> Result<(String, String)> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::CorruptedIndex("model entity body"))?;
    if !cursor.is_empty() {
        return Err(Error::CorruptedIndex("model entity body"));
    }
    let Value::Map(entries) = value else {
        return Err(Error::CorruptedIndex("model entity body"));
    };
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    for (key, value) in &entries {
        let slot = match key.as_str() {
            Some(MODEL_BODY_KEY_NAME) => &mut name,
            Some(MODEL_BODY_KEY_VERSION) => &mut version,
            _ => return Err(Error::CorruptedIndex("model entity body")),
        };
        if slot.is_some() {
            return Err(Error::CorruptedIndex("model entity body"));
        }
        let text = value
            .as_str()
            .ok_or(Error::CorruptedIndex("model entity body"))?;
        if text.is_empty() || text.len() > MODEL_SUBSTRATE_FIELD_MAX_BYTES {
            return Err(Error::CorruptedIndex("model entity body"));
        }
        *slot = Some(text.to_owned());
    }
    match (name, version) {
        (Some(name), Some(version)) => Ok((name, version)),
        _ => Err(Error::CorruptedIndex("model entity body")),
    }
}

/// D14 precedence key of one live provenance Claim, used to pick the
/// deterministic flag-stamp WINNER.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProvenancePrecedence {
    /// The Claim ENTITY's envelope `learned_at` (D14: "later
    /// source_revision_ref" = envelope learned_at; the ref is opaque).
    pub(crate) learned_at: u64,
    /// The record's `confidence` — breaks `learned_at` ties.
    pub(crate) confidence: f32,
    /// Final engine-defined tiebreak: greatest claim-id bytes win, making
    /// the order total and the winner deterministic.
    pub(crate) claim_id: EntityId,
}

/// Returns the index of the WINNER among live provenance Claims under the
/// documented total D14 order: greatest `learned_at`, then greatest
/// `confidence` (`f32::total_cmp` — confidence is validated finite in
/// `[0, 1]`), then greatest claim-id bytes. `None` for an empty slate.
pub(crate) fn winner_index(candidates: &[ProvenancePrecedence]) -> Option<usize> {
    candidates
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| {
            a.learned_at
                .cmp(&b.learned_at)
                .then_with(|| a.confidence.total_cmp(&b.confidence))
                .then_with(|| a.claim_id.as_bytes().cmp(b.claim_id.as_bytes()))
        })
        .map(|(index, _)| index)
}

/// Closes a value record for SUPERSESSION: `valid_to` is set to `close_at`
/// ONLY when the record had no `valid_to` of its own — an explicit,
/// already-closed validity window is preserved, never extended. The
/// `supersession_status` is untouched (the enum has no "superseded" state;
/// closure lives in the wrapper's `life` + the validity window). Fails typed
/// when the effective window would be inverted.
pub(crate) fn close_record_for_supersession(
    record: &EdgeProvenanceClaimBody,
    close_at: u64,
) -> Result<EdgeProvenanceClaimBody> {
    let mut closed = record.clone();
    if closed.valid_to.is_none() {
        closed.valid_to = Some(close_at);
    }
    ensure_record_window(&closed)?;
    Ok(closed)
}

/// Applies the contract's RETRACT rule to a value record:
/// `supersession_status` = retracted and `valid_to` = `now` (the literal
/// "set supersession_status = retracted (and typically valid_to = now)" —
/// retraction is a deliberate withdrawal AT `now`, so an explicit prior
/// `valid_to` is overwritten). Fails typed when `valid_from` exceeds `now`.
pub(crate) fn retract_record(
    record: &EdgeProvenanceClaimBody,
    now: u64,
) -> Result<EdgeProvenanceClaimBody> {
    let mut retracted = record.clone();
    retracted.supersession_status = SupersessionStatus::Retracted;
    retracted.valid_to = Some(now);
    ensure_record_window(&retracted)?;
    Ok(retracted)
}

fn ensure_record_window(record: &EdgeProvenanceClaimBody) -> Result<()> {
    if let (Some(from), Some(to)) = (record.valid_from, record.valid_to)
        && from > to
    {
        return Err(Error::InvalidProvenanceBody(
            "closing valid_to precedes valid_from",
        ));
    }
    Ok(())
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
        .map(|value| value.to_vec())
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

/// The D16 downgrade primitive: when deleting / SoftErasing an
/// `edge.provenance` Claim leaves NO surviving truth-Claim of any lifecycle
/// for an edge, the 26-byte provenanced value drops to the 24-byte bare
/// semantic layout — the first 24 bytes (weight + created_at + VAD) are
/// preserved verbatim and IDENTICAL bytes are written to both `edges_out`
/// and `edges_in`. A cached flag without ANY truth-Claim is unauditable; a
/// surviving RETRACTED Claim instead KEEPS the 26 B retracted dampening stamp
/// (the caller restamps it), so the downgrade fires only when neither an
/// active nor a retracted provenance Claim remains.
///
/// Returns whether the edge bytes changed: an already-bare 24-byte value is
/// the desired end state (idempotent no-op). A structural subject kind or a
/// non-contract value length fails typed — never a silent skip.
pub(crate) fn downgrade_edge_to_bare(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    subject: &EdgeRef,
) -> Result<bool> {
    let key_out = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
    let key_in = Store::encode_edge_key(&subject.target, subject.kind, &subject.source);

    let existing = store
        .edges_out
        .get(wtxn, &key_out)?
        .map(|value| value.to_vec())
        .ok_or(Error::EdgeNotFound)?;
    let value = match existing.len() {
        EDGE_VALUE_SEMANTIC_PROVENANCED_LEN => {
            let mut value = existing;
            value.truncate(EDGE_VALUE_SEMANTIC_LEN);
            value
        }
        EDGE_VALUE_SEMANTIC_LEN => return Ok(false),
        EDGE_VALUE_STRUCTURAL_LEN => {
            return Err(Error::ProvenanceOnStructuralEdge {
                kind: subject.kind as u8,
            });
        }
        _ => return Err(Error::CorruptedIndex("edge value")),
    };

    store.edges_out.put(wtxn, &key_out, &value)?;
    store.edges_in.put(wtxn, &key_in, &value)?;
    Ok(true)
}

/// One stored `edge.provenance` Claim loaded for a lifecycle operation
/// (retract / supersede / winner refresh).
pub(crate) struct StoredProvenanceClaim {
    id: EntityId,
    /// Envelope `occurred.start`, preserved verbatim on closing re-puts.
    occurred_start: u64,
    /// Envelope `learned_at` — the D14 precedence key. NEVER changed by a
    /// lifecycle re-put.
    learned_at: u64,
    /// The 33-byte EdgeRef the Claim addresses (from its `subj`).
    subject: EdgeRef,
    /// The wrapping type-0 Claim body.
    wrapper: ClaimBody,
    /// The decoded 10-key `edge.provenance` value record (ONE-1138).
    record: EdgeProvenanceClaimBody,
    /// The write-time validated actor class, resolved from the record's
    /// `actor_class` body key (new shape) or the wrapper's legacy `evid`
    /// map (pre-ONE-1138 claims) — see the provenance module docs.
    pub(crate) actor_class: EdgeActorClass,
}

impl StoredProvenanceClaim {
    /// This Claim's D14 precedence key.
    pub(crate) fn precedence(&self) -> ProvenancePrecedence {
        ProvenancePrecedence {
            learned_at: self.learned_at,
            confidence: self.record.confidence,
            claim_id: self.id,
        }
    }

    /// The edge flags this Claim derives (contracts.ts `derivesEdgeFlags`):
    /// `confirmation_status` ← `supersession_status` identity mirror;
    /// `actor_class` ← the persisted write-time validated class.
    pub(crate) fn flags(&self) -> EdgeProvenanceFlags {
        EdgeProvenanceFlags {
            confirmation_status: derive_confirmation_status(self.record.supersession_status),
            actor_class: self.actor_class,
        }
    }
}

/// Builds the re-put payload for a CLOSED provenance Claim: the wrapper's
/// `val` is replaced with the closed record, `to` mirrors the effective
/// `valid_to`, `life` becomes `lifecycle`, and the envelope keeps its
/// original `occurred.start` and `learned_at` (the D14 precedence key) while
/// `occurred.end` refreshes to the effective `valid_to` per D15. Fails typed
/// when the refreshed envelope would be inverted.
fn closed_claim_put_payload(
    claim: &StoredProvenanceClaim,
    closed_record: &EdgeProvenanceClaimBody,
    lifecycle: ClaimLifecycleStatus,
) -> Result<(TimeRange, u64, ClaimBody, Vec<u8>)> {
    let valid_to = closed_record.valid_to.ok_or(Error::InvariantViolation(
        "closed provenance record must carry valid_to",
    ))?;
    let occurred = TimeRange {
        start: claim.occurred_start,
        end: valid_to,
    };
    if occurred.start > occurred.end {
        return Err(Error::InvalidProvenanceBody(
            "closing valid_to precedes the claim's occurred start",
        ));
    }
    let mut wrapper = claim.wrapper.clone();
    wrapper.value = encode_edge_provenance_value(closed_record);
    wrapper.valid_to = Some(valid_to);
    wrapper.lifecycle = lifecycle;
    let data = encode_claim_body(&wrapper)?;
    validate_claim_body_bytes(&data, true)?;
    Ok((occurred, claim.learned_at, wrapper, data))
}

impl Vault {
    /// Writes an `edge.provenance` Claim for an EXISTING semantic edge,
    /// applies the contract's SUPERSEDE lifecycle to prior live Claims, and
    /// re-stamps the edge's two hot flags from the deterministic WINNER —
    /// the atomic provenanced-write API and (with
    /// [`Vault::supersede_edge_provenance`] and
    /// [`Vault::retract_edge_provenance`]) the ONLY public door to
    /// provenance flags (D10: the Claim is truth; the 26-byte stamp
    /// primitive stays `pub(crate)`).
    ///
    /// One LMDB write transaction performs ALL of:
    ///
    /// 1. write-once id gate — `claim_id` must not already name a stored
    ///    entity ([`Error::ProvenanceClaimIdInUse`]; re-putting an existing
    ///    id would resurrect a closed Claim in place — the lifecycle
    ///    operations are the only mutators of a stored provenance Claim);
    /// 2. subject-edge gate — `subject.kind` must be a SEMANTIC kind
    ///    ([`Error::ProvenanceOnStructuralEdge`] otherwise) and the edge must
    ///    already exist ([`Error::EdgeNotFound`]; the path never upserts — it
    ///    would have to invent `weight`/`created_at`);
    /// 3. actor gate (D13) — `body.actor_entity_ref` must exist
    ///    ([`Error::EntityNotFound`]) and the CALLER-SUPPLIED `actor_class`
    ///    must be compatible with the actor entity's kind
    ///    ([`Error::ActorClassMismatch`]; never defaulted). The validated
    ///    class is persisted as the value record's `actor_class` BODY key
    ///    (ONE-1138 / ONE-1112 C2 relocation — the wrapper's `evid` stays
    ///    empty) so a later winner refresh can restamp a HISTORICAL Claim's
    ///    flags (see the provenance module docs). A caller-set
    ///    `body.actor_class` that CONFLICTS with the `actor_class` parameter
    ///    is rejected typed ([`Error::InvalidProvenanceBody`]);
    /// 4. substrate gate (ONE-1138) — when `body.substrate_ref` is present
    ///    it must name a stored MODEL (type byte 121) entity
    ///    ([`Error::InvalidModelSubstrate`] otherwise); absent =
    ///    unrecorded-and-valid;
    /// 5. supersession (retractionRules SUPERSEDE + D14) — an incoming
    ///    `learned_at` OLDER than the live frontier for this EdgeRef is
    ///    rejected typed ([`Error::ProvenancePrecedenceViolation`]); every
    ///    live Claim STRICTLY older than the incoming one is closed in the
    ///    same transaction (`life` = superseded, `valid_to` set to the
    ///    incoming `learned_at` when absent, envelope `occurred.end`
    ///    refreshed per D15 — closed, not deleted, still readable);
    ///    equal-`learned_at` Claims COEXIST live;
    /// 6. the Claim entity (type 0, predicate
    ///    [`crate::provenance::PREDICATE_EDGE_PROVENANCE`], `subj` = the
    ///    33-byte EdgeRef, `val` = the pinned 10-key record) is written
    ///    through the `pub(crate)` reserved-namespace door with full ONE-1104
    ///    structural validation;
    /// 7. a `claim_of` edge (u8 = 5, structural 12 B) is written from the
    ///    Claim to the subject edge's SOURCE entity (D12);
    /// 8. the subject edge value is re-stamped to 26 bytes from the WINNER
    ///    among post-write live Claims under the documented total D14 order
    ///    (greatest `learned_at`, then `confidence`, then claim-id bytes) —
    ///    NOT necessarily this Claim — with IDENTICAL bytes in `edges_out`
    ///    and `edges_in` and the first 24 bytes preserved verbatim;
    /// 9. PPR caches for the subject edge's endpoints are invalidated.
    ///
    /// The Claim envelope's `occurred` interval derives from the validity
    /// window per D15: absent `valid_from` → `learned_at`; absent `valid_to`
    /// → `u64::MAX`. A derived interval with `start > end` is rejected with
    /// [`Error::InvalidProvenanceBody`] — never reordered. The wrapping
    /// Claim stores `conf` = `body.confidence` and `from`/`to` =
    /// `valid_from`/`valid_to` (claim-layer mirrors of the authoritative
    /// 10-key record) with `appr` = `auto`, `life` = `active`.
    pub fn put_edge_provenance(
        &self,
        claim_id: &EntityId,
        subject: &EdgeRef,
        body: &EdgeProvenanceClaimBody,
        actor_class: EdgeActorClass,
        learned_at: u64,
    ) -> Result<()> {
        self.write_edge_provenance(claim_id, subject, body, actor_class, learned_at, None)
    }

    /// Explicitly supersedes the live `edge.provenance` Claim
    /// `prior_claim_id` with the NEWER Claim `new_claim_id` for the SAME
    /// EdgeRef (retractionRules SUPERSEDE + D14): one write transaction
    /// writes the new Claim exactly like [`Vault::put_edge_provenance`],
    /// closes the named prior (`life` = superseded, `valid_to` set to
    /// `learned_at` when the record had none, envelope `occurred.end`
    /// refreshed — the prior Claim entity stays readable), closes any other
    /// live Claim strictly older than `learned_at`, and re-stamps the edge
    /// from the deterministic WINNER among the surviving live Claims.
    ///
    /// Unlike the implicit path, the named prior is closed even on a
    /// `learned_at` tie.
    ///
    /// Typed failure modes (nothing is written on any of them):
    /// * `prior_claim_id == new_claim_id` →
    ///   [`Error::ProvenanceSelfSupersession`];
    /// * `new_claim_id` already names a stored entity →
    ///   [`Error::ProvenanceClaimIdInUse`] (claim ids are write-once);
    /// * prior entity missing → [`Error::EntityNotFound`];
    /// * prior is not a type-0 Claim or its predicate is not
    ///   `edge.provenance` → [`Error::NotAProvenanceClaim`];
    /// * prior addresses a different EdgeRef than `subject` →
    ///   [`Error::ProvenanceSubjectMismatch`];
    /// * prior is no longer live → [`Error::ProvenanceClaimAlreadyClosed`];
    /// * `learned_at` older than the live frontier →
    ///   [`Error::ProvenancePrecedenceViolation`].
    pub fn supersede_edge_provenance(
        &self,
        prior_claim_id: &EntityId,
        new_claim_id: &EntityId,
        subject: &EdgeRef,
        body: &EdgeProvenanceClaimBody,
        actor_class: EdgeActorClass,
        learned_at: u64,
    ) -> Result<()> {
        self.write_edge_provenance(
            new_claim_id,
            subject,
            body,
            actor_class,
            learned_at,
            Some(prior_claim_id),
        )
    }

    /// Retracts a live `edge.provenance` Claim (retractionRules RETRACT):
    /// ONE write transaction sets the value record's `supersession_status` =
    /// retracted and `valid_to` = `now`, mirrors `life` = retracted / `to` =
    /// `now` on the wrapping Claim, re-puts the Claim with the envelope
    /// `occurred.end` refreshed per D15, and re-stamps the subject edge:
    ///
    /// * other live Claims remain → flags refresh from the deterministic
    ///   D14 WINNER among them (greatest `learned_at`, then `confidence`,
    ///   then claim-id bytes);
    /// * no live Claim remains → `confirmation_status` = retracted (3) with
    ///   the retracted Claim's own persisted `actor_class` — "the edge is
    ///   KEPT … the edge is not physically removed on retraction".
    ///
    /// Typed failure modes (nothing is written on any of them): missing
    /// claim → [`Error::EntityNotFound`]; not an `edge.provenance` Claim →
    /// [`Error::NotAProvenanceClaim`]; already closed (double-retract /
    /// retract-after-supersede) → [`Error::ProvenanceClaimAlreadyClosed`];
    /// `now` earlier than the record's `valid_from` (or derived envelope
    /// start) → [`Error::InvalidProvenanceBody`]; subject edge missing →
    /// [`Error::EdgeNotFound`].
    pub fn retract_edge_provenance(&self, claim_id: &EntityId, now: u64) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;

        let claim = self.load_provenance_claim_in_txn(&wtxn, claim_id)?;
        if claim.wrapper.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::ProvenanceClaimAlreadyClosed {
                lifecycle: claim.wrapper.lifecycle.as_str(),
            });
        }
        let retracted = retract_record(&claim.record, now)?;
        let (occurred, learned_at, retracted_claim_body, data) =
            closed_claim_put_payload(&claim, &retracted, ClaimLifecycleStatus::Retracted)?;

        // The subject edge must still exist — the retraction KEEPS it and
        // only refreshes the two flag bytes.
        let subject = claim.subject;
        let edge_key = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
        if self.store.edges_out.get(&wtxn, &edge_key)?.is_none() {
            return Err(Error::EdgeNotFound);
        }

        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        crate::gate::check_edge_provenance_claim_policy(
            &self.store,
            &wtxn,
            &retracted_claim_body,
            &retracted,
            claim.actor_class,
            &policy,
        )?;

        // Flags refresh: the D14 winner among REMAINING live Claims, else
        // the contract's retracted stamp with this Claim's persisted class.
        let survivors = self.live_edge_provenance_claims_in_txn(&wtxn, &subject, Some(claim_id))?;
        let precedence: Vec<ProvenancePrecedence> = survivors
            .iter()
            .map(StoredProvenanceClaim::precedence)
            .collect();
        let flags = match winner_index(&precedence) {
            Some(index) => survivors[index].flags(),
            None => EdgeProvenanceFlags {
                confirmation_status: EdgeConfirmationStatus::Retracted,
                actor_class: claim.actor_class,
            },
        };

        self.batch_in()
            .put_reserved_claim(claim_id, occurred, learned_at, &data)
            .apply(&mut wtxn)?;
        restamp_edge_flags(&self.store, &mut wtxn, &subject, flags)?;
        ppr::invalidate_ppr_for_edge(&self.store, &mut wtxn, &subject.source, &subject.target)?;
        // The edge bytes changed without an edge BatchOp in this txn, so the
        // graph version is bumped explicitly (apply_ops does it for edge ops).
        ppr::increment_graph_version(&self.store, &mut wtxn)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Engine-authored get-or-create door for MODEL substrate entities
    /// (type byte 121, maintenance band — ONE-1138 ratified): a MODEL entity
    /// is "written when a substrate first appears in a write path", keyed by
    /// `(name, version)`. Model name + version live ON the MODEL entity so
    /// provenance records dedup to a 16-byte ref — the returned id is what
    /// [`EdgeProvenanceClaimBody`]'s `substrate_ref` should carry.
    ///
    /// Behavior, all in ONE write transaction:
    /// * an existing MODEL entity whose body matches `(name, version)` →
    ///   its id is returned and NOTHING is written (idempotent get);
    /// * otherwise a new MODEL entity (engine-shaped MessagePack body
    ///   `{"name", "version"}`) is created through the engine-internal
    ///   maintenance door with the full `apply_put` index footprint
    ///   (type_index, temporal point event at `now`, reserved `mo`
    ///   short-id);
    /// * `name` / `version` must be non-empty and at most
    ///   [`crate::provenance::MODEL_SUBSTRATE_FIELD_MAX_BYTES`] bytes —
    ///   [`Error::InvalidModelSubstrate`] otherwise;
    /// * a stored type-121 entity whose body fails the engine-shape decode
    ///   is on-disk corruption → [`Error::CorruptedIndex`], never skipped.
    ///
    /// Public puts of type byte 121 stay rejected with
    /// [`Error::MaintenanceKindNotWritable`]: this method is the ONLY public
    /// door, and it only ever writes the engine-shaped body.
    pub fn ensure_model_substrate(&self, name: &str, version: &str, now: u64) -> Result<EntityId> {
        validate_model_substrate_field(name, "model name must be non-empty and at most 256 bytes")?;
        validate_model_substrate_field(
            version,
            "model version must be non-empty and at most 256 bytes",
        )?;
        let body = encode_model_entity_body(name, version)?;

        let mut wtxn = self.store.env.write_txn()?;

        // GET: scan the MODEL partition of type_index — one row per distinct
        // substrate, so the partition stays tiny — for a (name, version)
        // match. The scan and the create share the write transaction, so the
        // get-or-create is race-free under LMDB's single-writer model.
        let mut existing: Option<EntityId> = None;
        for entry in self
            .store
            .type_index
            .prefix_iter(&wtxn, &[ENTITY_TYPE_MODEL])?
        {
            let (key, _) = entry?;
            require_key_len(&key, 17, "type index key")?;
            let id = EntityId::from_bytes(
                key[1..17]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("type index key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("type index key"))?;
            let raw = self
                .store
                .entities
                .get(&wtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("type index row without entity"))?;
            let (stored_name, stored_version) =
                decode_model_entity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if stored_name == name && stored_version == version {
                existing = Some(id);
                break;
            }
        }
        if let Some(id) = existing {
            return Ok(id);
        }

        // CREATE: engine-internal maintenance door (allow_maintenance), the
        // same admit flag the sync replay path uses for REDACTION_AUDIT —
        // public puts of the byte keep failing MaintenanceKindNotWritable.
        let id = EntityId::now();
        let ops = vec![BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_MODEL,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            data: body,
            allow_maintenance: true,
            allow_reserved_predicate: false,
        }];
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        wtxn.commit()?;
        Ok(id)
    }

    /// Shared implementation of [`Vault::put_edge_provenance`] (implicit
    /// supersession) and [`Vault::supersede_edge_provenance`] (explicit
    /// prior). See those methods for the full documented semantics.
    fn write_edge_provenance(
        &self,
        claim_id: &EntityId,
        subject: &EdgeRef,
        body: &EdgeProvenanceClaimBody,
        actor_class: EdgeActorClass,
        learned_at: u64,
        explicit_prior: Option<&EntityId>,
    ) -> Result<()> {
        if explicit_prior == Some(claim_id) {
            return Err(Error::ProvenanceSelfSupersession);
        }

        // ONE-1138 / ONE-1112 C2: the validated caller-supplied class is
        // persisted as the record's `actor_class` BODY key. A caller-set
        // body class that disagrees with the parameter is ambiguous —
        // rejected, never reconciled silently.
        if let Some(body_class) = body.actor_class
            && body_class != actor_class
        {
            return Err(Error::InvalidProvenanceBody(
                "body actor_class conflicts with the caller-supplied actor_class parameter",
            ));
        }
        let mut record = body.clone();
        record.actor_class = Some(actor_class);

        // Pure validation before any transaction is opened. Encoding does
        // not validate; the decode validator is the single gate.
        let value = encode_edge_provenance_value(&record);
        validate_edge_provenance_value(&value)?;

        // Provenance only attaches to SEMANTIC kinds — a static property of
        // the kind, checked before any I/O.
        if edge_value_layout_for_kind(subject.kind, false) == EdgeValueLayout::Structural {
            return Err(Error::ProvenanceOnStructuralEdge {
                kind: subject.kind as u8,
            });
        }

        // D15 envelope sentinels (index-key derivation only; the
        // authoritative optionality stays in the MessagePack body).
        let occurred = TimeRange {
            start: body.valid_from.unwrap_or(learned_at),
            end: body.valid_to.unwrap_or(u64::MAX),
        };
        if occurred.start > occurred.end {
            return Err(Error::InvalidProvenanceBody(
                "derived occurred envelope start exceeds end (valid_to before valid_from/learned_at)",
            ));
        }

        let mut claim_body = ClaimBody::new(
            PREDICATE_EDGE_PROVENANCE,
            ClaimSubject::from(*subject),
            value,
            body.confidence,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        claim_body.valid_from = body.valid_from;
        claim_body.valid_to = body.valid_to;
        // The write-time validated actor_class is persisted as the record's
        // BODY key (set above, ONE-1138); the wrapper's `evid` stays empty —
        // evidence purity, no legacy `{"actor_class": u8}` map.
        let data = encode_claim_body(&claim_body)?;
        validate_claim_body_bytes(&data, true)?;

        let mut wtxn = self.store.env.write_txn()?;

        // WRITE-ONCE ids: a `claim_id` that already names ANY stored entity
        // is rejected before a single byte moves. Re-putting an existing id
        // would overwrite the stored Claim in place — resurrecting a
        // retracted/superseded wrapper as a fresh `active` body and
        // bypassing [`Error::ProvenanceClaimAlreadyClosed`] (ARCH-0003:
        // "claims are never silently deleted"). The lifecycle operations
        // (retract / supersede) are the ONLY mutators of an existing
        // provenance Claim.
        if self
            .store
            .entities
            .get(&wtxn, claim_id.as_bytes())?
            .is_some()
        {
            return Err(Error::ProvenanceClaimIdInUse);
        }

        // Subject edge must exist — no upsert.
        let edge_key = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
        if self.store.edges_out.get(&wtxn, &edge_key)?.is_none() {
            return Err(Error::EdgeNotFound);
        }

        // Actor entity must exist; the caller-supplied class is validated
        // against its kind (D13) — never defaulted.
        let actor_raw = self
            .store
            .entities
            .get(&wtxn, body.actor_entity_ref.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let actor_header = EntityMetadataHeader::parse(&actor_raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        validate_actor_class(actor_header.entity_type, actor_class)?;

        // Substrate gate (ONE-1138): a present substrate_ref must name a
        // stored MODEL (type byte 121) entity — actor = WHO, substrate =
        // WITH-WHAT; any other kind is never a substrate. Absent =
        // unrecorded-and-valid, no gate.
        if let Some(substrate_ref) = record.substrate_ref {
            let substrate_raw = self
                .store
                .entities
                .get(&wtxn, substrate_ref.as_bytes())?
                .ok_or(Error::InvalidModelSubstrate(
                    "substrate_ref does not name a stored entity",
                ))?;
            let substrate_header = EntityMetadataHeader::parse(&substrate_raw)
                .ok_or(Error::CorruptedIndex("entity header"))?;
            if substrate_header.entity_type != ENTITY_TYPE_MODEL {
                return Err(Error::InvalidModelSubstrate(
                    "substrate_ref must name a MODEL (type byte 121) entity",
                ));
            }
            // A present, type-correct (type-121) substrate row whose body
            // fails the engine MODEL shape ({name, version} ≤256B) is
            // ambiguous on-disk corruption — e.g. a remote-replay-deposited
            // malformed type-121 row — and is rejected fail-closed as
            // CorruptedIndex("model entity body") BEFORE the provenance Claim
            // is staged, mirroring the get-or-create GET scan's own strict
            // decode (single decoder, one source of truth). Never downgraded
            // to a silent skip; InvalidModelSubstrate stays reserved for the
            // clean referential rejections above (wrong kind, dangling ref).
            decode_model_entity_body(&substrate_raw[ENTITY_METADATA_HEADER_LEN..])?;
        }

        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        crate::gate::check_edge_provenance_claim_policy(
            &self.store,
            &wtxn,
            &claim_body,
            &record,
            actor_class,
            &policy,
        )?;

        // Explicit-prior gates (supersede path): the named Claim must be a
        // live edge.provenance Claim addressing the SAME EdgeRef.
        let prior_id = explicit_prior
            .map(|prior_id| -> Result<EntityId> {
                let prior = self.load_provenance_claim_in_txn(&wtxn, prior_id)?;
                if prior.subject != *subject {
                    return Err(Error::ProvenanceSubjectMismatch);
                }
                if prior.wrapper.lifecycle != ClaimLifecycleStatus::Active {
                    return Err(Error::ProvenanceClaimAlreadyClosed {
                        lifecycle: prior.wrapper.lifecycle.as_str(),
                    });
                }
                Ok(prior.id)
            })
            .transpose()?;

        // D14 precedence: the incoming Claim may never be OLDER than the
        // live frontier — it could never take precedence.
        let live = self.live_edge_provenance_claims_in_txn(&wtxn, subject, Some(claim_id))?;
        if let Some(frontier) = live.iter().map(|claim| claim.learned_at).max()
            && learned_at < frontier
        {
            return Err(Error::ProvenancePrecedenceViolation {
                incoming_learned_at: learned_at,
                frontier_learned_at: frontier,
            });
        }
        if let Some(prior_id) = prior_id
            && !live.iter().any(|claim| claim.id == prior_id)
        {
            // The prior passed the live + same-subject gates, so its
            // claim_of edge must surface it in the live scan.
            return Err(Error::CorruptedIndex("provenance claim_of edge"));
        }

        // Closures: every live Claim strictly older than the incoming one,
        // plus the explicitly named prior (closed even on a learned_at tie).
        let close_at = learned_at;
        let (closures, survivors): (Vec<&StoredProvenanceClaim>, Vec<&StoredProvenanceClaim>) =
            live.iter()
                .partition(|claim| claim.learned_at < learned_at || Some(claim.id) == prior_id);

        // Deterministic winner among the post-write live cohort (D14).
        let mut precedence: Vec<ProvenancePrecedence> =
            survivors.iter().map(|claim| claim.precedence()).collect();
        precedence.push(ProvenancePrecedence {
            learned_at,
            confidence: body.confidence,
            claim_id: *claim_id,
        });
        let winner = winner_index(&precedence)
            .ok_or(Error::InvariantViolation("provenance winner set is empty"))?;
        let flags = if winner == precedence.len() - 1 {
            EdgeProvenanceFlags {
                confirmation_status: derive_confirmation_status(body.supersession_status),
                actor_class,
            }
        } else {
            survivors[winner].flags()
        };

        let mut closure_payloads = Vec::with_capacity(closures.len());
        for closure in &closures {
            let closed_record = close_record_for_supersession(&closure.record, close_at)?;
            let (closed_occurred, closed_learned_at, closed_claim_body, closed_data) =
                closed_claim_put_payload(
                    closure,
                    &closed_record,
                    ClaimLifecycleStatus::Superseded,
                )?;
            crate::gate::check_edge_provenance_claim_policy(
                &self.store,
                &wtxn,
                &closed_claim_body,
                &closed_record,
                closure.actor_class,
                &policy,
            )?;
            closure_payloads.push((closure.id, closed_occurred, closed_learned_at, closed_data));
        }

        // New Claim through the reserved-namespace door + claim_of → the
        // subject edge's SOURCE entity (D12) + closure re-puts, all with
        // full Gate checks before apply and full type-0 validation at apply,
        // all in this one transaction.
        let mut builder = self
            .batch_in()
            .put_reserved_claim(claim_id, occurred, learned_at, &data)
            .edge(
                claim_id,
                EdgeKind::ClaimOf,
                &subject.source,
                CLAIM_OF_DEFAULT_WEIGHT,
            );
        for (closure_id, closed_occurred, closed_learned_at, closed_data) in closure_payloads {
            builder = builder.put_reserved_claim(
                &closure_id,
                closed_occurred,
                closed_learned_at,
                &closed_data,
            );
        }
        builder.apply(&mut wtxn)?;

        // Re-stamp the subject edge (both directions, identical bytes) and
        // invalidate the PPR caches its endpoints feed.
        restamp_edge_flags(&self.store, &mut wtxn, subject, flags)?;
        ppr::invalidate_ppr_for_edge(&self.store, &mut wtxn, &subject.source, &subject.target)?;

        wtxn.commit()?;
        Ok(())
    }

    /// Loads one `edge.provenance` Claim for a lifecycle operation, with the
    /// typed gate chain: missing → [`Error::EntityNotFound`]; not a type-0
    /// Claim or wrong predicate → [`Error::NotAProvenanceClaim`]; malformed
    /// stored body / record / persisted class → typed decode errors.
    fn load_provenance_claim_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<StoredProvenanceClaim> {
        let raw = self
            .store
            .entities
            .get(txn, claim_id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::NotAProvenanceClaim("entity is not a type-0 CLAIM"));
        }
        let wrapper = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if wrapper.predicate != PREDICATE_EDGE_PROVENANCE {
            return Err(Error::NotAProvenanceClaim(
                "claim predicate is not edge.provenance",
            ));
        }
        let ClaimSubject::Edge {
            source,
            kind,
            target,
        } = wrapper.subject
        else {
            return Err(Error::InvalidProvenanceBody(
                "edge.provenance claim subject is not a 33-byte EdgeRef",
            ));
        };
        let record = decode_edge_provenance_body(&wrapper.value)?;
        let actor_class = resolve_persisted_actor_class(&record, wrapper.evidence.as_ref())?;
        Ok(StoredProvenanceClaim {
            id: *claim_id,
            occurred_start: header.occurred_start,
            learned_at: header.learned_at,
            subject: EdgeRef::new(source, kind, target),
            wrapper,
            record,
            actor_class,
        })
    }

    /// Enumerates the LIVE (`life` = active) `edge.provenance` Claims for
    /// `subject` — the live cohort the D14 winner stamp is chosen from. Thin
    /// wrapper over [`Self::edge_provenance_claims_in_txn`].
    pub(crate) fn live_edge_provenance_claims_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: &EdgeRef,
        exclude: Option<&EntityId>,
    ) -> Result<Vec<StoredProvenanceClaim>> {
        self.edge_provenance_claims_in_txn(txn, subject, exclude, ClaimLifecycleStatus::Active)
    }

    /// Enumerates the RETRACTED `edge.provenance` Claims for `subject` — the
    /// surviving WITHDRAWN truth the edge's retracted dampening flag caches.
    /// The D16 delete-refresh consults this when NO active Claim survives, to
    /// decide whether the deleted Claim's EdgeRef still has a retracted
    /// truth-Claim to KEEP the 26 B retracted stamp for (else 24 B bare). Thin
    /// wrapper over [`Self::edge_provenance_claims_in_txn`].
    pub(crate) fn retracted_edge_provenance_claims_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: &EdgeRef,
        exclude: Option<&EntityId>,
    ) -> Result<Vec<StoredProvenanceClaim>> {
        self.edge_provenance_claims_in_txn(txn, subject, exclude, ClaimLifecycleStatus::Retracted)
    }

    /// Enumerates the `edge.provenance` Claims for `subject` whose wrapping
    /// Claim `life` equals `lifecycle`, via the inbound `claim_of` edges of
    /// the subject edge's SOURCE entity (D12). Non-claim sources, other
    /// predicates, claims of OTHER EdgeRefs, bodiless SoftErase shells, and
    /// claims of any other lifecycle are skipped; corrupt rows fail closed.
    /// `exclude` drops the claim currently being re-put or deleted.
    fn edge_provenance_claims_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: &EdgeRef,
        exclude: Option<&EntityId>,
        lifecycle: ClaimLifecycleStatus,
    ) -> Result<Vec<StoredProvenanceClaim>> {
        let prefix = edge_kind_prefix(&subject.source, EdgeKind::ClaimOf);
        let mut matched = Vec::new();
        for (scanned, entry) in self.store.edges_in.prefix_iter(txn, &prefix)?.enumerate() {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("live provenance claims"));
            }
            let (key, value) = entry?;
            let claim_id = parse_edge_record(&key, &value)?.target;
            if exclude == Some(&claim_id) {
                continue;
            }
            let Some(raw) = self.store.entities.get(txn, claim_id.as_bytes())? else {
                return Err(Error::CorruptedIndex("claim_of edge without claim entity"));
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                continue;
            }
            if raw.len() == ENTITY_METADATA_HEADER_LEN {
                // An ARCH-0038 SoftErase scrubbed this Claim's body but kept
                // its structural edges. A bodiless 25 B Claim shell is a
                // tombstone, never live — skip it. Safe because EVERY local
                // SoftErase (the user_delete branch AND the gdpr/policy
                // pre-purge step) commits the D16 edge refresh in the SAME
                // transaction that scrubs the body, so a shell can never
                // coexist with a stale subject-edge stamp.
                continue;
            }
            let wrapper =
                crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if wrapper.predicate != PREDICATE_EDGE_PROVENANCE {
                continue;
            }
            let ClaimSubject::Edge {
                source,
                kind,
                target,
            } = wrapper.subject
            else {
                continue;
            };
            if EdgeRef::new(source, kind, target) != *subject {
                continue;
            }
            if wrapper.lifecycle != lifecycle {
                continue;
            }
            let record = decode_edge_provenance_body(&wrapper.value)?;
            let actor_class = resolve_persisted_actor_class(&record, wrapper.evidence.as_ref())?;
            matched.push(StoredProvenanceClaim {
                id: claim_id,
                occurred_start: header.occurred_start,
                learned_at: header.learned_at,
                subject: *subject,
                wrapper,
                record,
                actor_class,
            });
        }
        Ok(matched)
    }
}

#[cfg(test)]
mod tests;
