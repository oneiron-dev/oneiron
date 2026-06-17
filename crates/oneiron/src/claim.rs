//! CLAIM body ABI + typed Claim API (ARCH-0003, pinned decisions D11/D17/D18).
//!
//! Type byte 0 is the single SEMANTIC entity type. Its MessagePack body is a
//! pinned storage ABI: the key set in [`CLAIM_BODY_KEYS`] (D11 short keys) is
//! the ON-DISK vocabulary. ARCH-0003's camelCase `Claim` shape is the
//! app-layer view; the engine never stores camelCase keys.
//!
//! Every type-0 write on every path (`Vault::put_entity`, `BatchBuilder`,
//! `TxnBatchBuilder`, sync replay via `apply_ops`) is structurally validated
//! here (D18). Bodies of all OTHER type bytes stay opaque at the storage
//! layer. Validation is fail-closed: a body that does not decode to a
//! MessagePack map carrying exactly the pinned vocabulary with all required
//! fields well-typed is rejected with [`Error::InvalidClaimBody`] and nothing
//! is written.
//!
//! The predicate gate (D17) is part of body validation: predicates must match
//! the pinned grammar (≥2 segments of `[a-z][a-z0-9_]*` joined by `.`, total
//! ≤128 bytes) or the write fails with [`Error::InvalidPredicate`]. The
//! `edge.*` namespace is reserved for the engine's provenance Claims: public
//! writes are rejected with [`Error::ReservedPredicate`]; the doors are the
//! `pub(crate)` reserved-namespace path used by the provenance unit
//! (`TxnBatchBuilder::put_reserved_claim`) and, under the `sync` feature,
//! the replicated-put door (`put_replicated`) used by CRDT replay so remote
//! provenance Claims rematerialize — both still run this full structural
//! validation. Well-formed UNKNOWN predicates
//! are accepted — the crate is predicate-agnostic for semantics (ARCH-0003
//! §G.1); no predicate registry, consent matrix, or conflict-set logic lives
//! here.

use std::io::Cursor;

use rmpv::Value;

use crate::error::{Error, Result};
use crate::types::{ENTITY_ID_LEN, EdgeKind, EntityId};

// Test-only MessagePack decode counter: AC 9 of the D19 unit pins "body
// decoded ONCE per result for gate + projection" — tests assert exact
// decode counts through this counter instead of round-tripping output.
#[cfg(test)]
thread_local! {
    static CLAIM_BODY_DECODE_COUNT: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_claim_body_decode_count() {
    CLAIM_BODY_DECODE_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn claim_body_decode_count() -> usize {
    CLAIM_BODY_DECODE_COUNT.with(std::cell::Cell::get)
}

/// Pinned ON-DISK MessagePack key set for type-0 (CLAIM) bodies (D11).
///
/// Order is canonical: the engine's encoder emits present fields in this
/// order, and the context-pack field profiles are prefixes of this list
/// (Minimal = first 2, Standard = first 5, Full = first 11; the lifecycle
/// keys `appr`/`life`/`stale` drive the D19 read-path status gate
/// ([`claim_surfaceable`]) and are excluded from every serialization
/// profile).
pub const CLAIM_BODY_KEYS: [&str; 14] = [
    "pred", "val", "conf", "sal", "evid", "from", "to", "src", "world", "subj", "scope", "appr",
    "life", "stale",
];

pub(crate) const KEY_PRED: &str = CLAIM_BODY_KEYS[0];
pub(crate) const KEY_VAL: &str = CLAIM_BODY_KEYS[1];
pub(crate) const KEY_CONF: &str = CLAIM_BODY_KEYS[2];
pub(crate) const KEY_SAL: &str = CLAIM_BODY_KEYS[3];
pub(crate) const KEY_EVID: &str = CLAIM_BODY_KEYS[4];
pub(crate) const KEY_FROM: &str = CLAIM_BODY_KEYS[5];
pub(crate) const KEY_TO: &str = CLAIM_BODY_KEYS[6];
pub(crate) const KEY_SRC: &str = CLAIM_BODY_KEYS[7];
pub(crate) const KEY_WORLD: &str = CLAIM_BODY_KEYS[8];
pub(crate) const KEY_SUBJ: &str = CLAIM_BODY_KEYS[9];
pub(crate) const KEY_SCOPE: &str = CLAIM_BODY_KEYS[10];
pub(crate) const KEY_APPR: &str = CLAIM_BODY_KEYS[11];
pub(crate) const KEY_LIFE: &str = CLAIM_BODY_KEYS[12];
pub(crate) const KEY_STALE: &str = CLAIM_BODY_KEYS[13];

/// Context-pack CLAIM field profiles, derived from [`CLAIM_BODY_KEYS`] so the
/// serializer cannot drift from the storage ABI.
pub(crate) const CLAIM_FIELDS_MINIMAL: &[&str] = claim_keys_prefix(2);
pub(crate) const CLAIM_FIELDS_STANDARD: &[&str] = claim_keys_prefix(5);
pub(crate) const CLAIM_FIELDS_FULL: &[&str] = claim_keys_prefix(11);

const fn claim_keys_prefix(len: usize) -> &'static [&'static str] {
    let whole: &[&str] = &CLAIM_BODY_KEYS;
    whole.split_at(len).0
}

/// Maximum predicate length in bytes (D17).
pub const MAX_PREDICATE_BYTES: usize = 128;

/// Reserved predicate namespace prefix (D17): `edge.*` predicates may only
/// be written through the `pub(crate)` provenance door.
pub const RESERVED_PREDICATE_NAMESPACE: &str = "edge";

/// Length of an EdgeRef subject encoding: source 16 ‖ kind u8 ‖ target 16.
pub(crate) const EDGE_REF_LEN: usize = 33;

/// Claim approval status (`appr`): the ARCH-0003 consent axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimApprovalStatus {
    Auto,
    Proposed,
    Approved,
    Rejected,
}

impl ClaimApprovalStatus {
    /// The pinned on-disk string for this status.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Proposed => "proposed",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "proposed" => Some(Self::Proposed),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

/// Claim lifecycle status (`life`): the ARCH-0003 currentness axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimLifecycleStatus {
    Active,
    Superseded,
    Retracted,
}

impl ClaimLifecycleStatus {
    /// The pinned on-disk string for this status.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Retracted => "retracted",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "superseded" => Some(Self::Superseded),
            "retracted" => Some(Self::Retracted),
            _ => None,
        }
    }
}

/// Claim provenance source (`src`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimSource {
    UserStated,
    Observed,
    Inferred,
    Imported,
}

impl ClaimSource {
    /// The pinned on-disk string for this source.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserStated => "user_stated",
            Self::Observed => "observed",
            Self::Inferred => "inferred",
            Self::Imported => "imported",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "user_stated" => Some(Self::UserStated),
            "observed" => Some(Self::Observed),
            "inferred" => Some(Self::Inferred),
            "imported" => Some(Self::Imported),
            _ => None,
        }
    }
}

/// A claim's subject reference (`subj`). Two pinned encodings:
///
/// * 16 bytes — an entity UUID;
/// * 33 bytes — an EdgeRef `(source_id 16 B ‖ edge_kind u8 ‖ target_id 16 B)`
///   addressing an edge (used by `edge.provenance` Claims; the kind byte must
///   parse as a registered [`EdgeKind`]).
///
/// Anything else fails validation with [`Error::InvalidClaimBody`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimSubject {
    /// Subject is an entity (16-byte UUID).
    Entity(EntityId),
    /// Subject is an edge, addressed as a 33-byte EdgeRef.
    Edge {
        source: EntityId,
        kind: EdgeKind,
        target: EntityId,
    },
}

impl ClaimSubject {
    pub(crate) fn encode(&self) -> Vec<u8> {
        match self {
            Self::Entity(id) => id.as_bytes().to_vec(),
            Self::Edge {
                source,
                kind,
                target,
            } => {
                let mut out = Vec::with_capacity(EDGE_REF_LEN);
                out.extend_from_slice(source.as_bytes());
                out.push(*kind as u8);
                out.extend_from_slice(target.as_bytes());
                out
            }
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        match bytes.len() {
            ENTITY_ID_LEN => {
                let arr: [u8; ENTITY_ID_LEN] = bytes
                    .try_into()
                    .map_err(|_| Error::InvalidClaimBody("subj entity id is malformed"))?;
                let id = EntityId::from_bytes(arr)
                    .map_err(|_| Error::InvalidClaimBody("subj entity id is reserved"))?;
                Ok(Self::Entity(id))
            }
            EDGE_REF_LEN => {
                let source = entity_id_from(&bytes[..ENTITY_ID_LEN], "subj EdgeRef source id")?;
                let kind = EdgeKind::try_from_u8(bytes[ENTITY_ID_LEN]).ok_or(
                    Error::InvalidClaimBody("subj EdgeRef kind byte is not a registered EdgeKind"),
                )?;
                let target = entity_id_from(&bytes[ENTITY_ID_LEN + 1..], "subj EdgeRef target id")?;
                Ok(Self::Edge {
                    source,
                    kind,
                    target,
                })
            }
            _ => Err(Error::InvalidClaimBody(
                "subj must be a 16-byte entity id or a 33-byte EdgeRef",
            )),
        }
    }
}

fn entity_id_from(bytes: &[u8], context: &'static str) -> Result<EntityId> {
    let arr: [u8; ENTITY_ID_LEN] = bytes
        .try_into()
        .map_err(|_| Error::InvalidClaimBody(context))?;
    EntityId::from_bytes(arr).map_err(|_| Error::InvalidClaimBody(context))
}

/// Decoded type-0 (CLAIM) body — the engine-pinned structural fields only.
///
/// Per-predicate columns (ARCH-0003 §G.1) are NOT modeled here: the typed
/// `val` payload is an opaque MessagePack value the crate never interprets.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ClaimBody {
    /// `pred` — predicate string, validated against the D17 grammar.
    pub predicate: String,
    /// `subj` — subject reference (entity UUID or EdgeRef).
    pub subject: ClaimSubject,
    /// `val` — typed claim value; opaque MessagePack at the storage layer.
    pub value: Value,
    /// `conf` — confidence, finite in `[0, 1]`.
    pub confidence: f32,
    /// `appr` — approval status.
    pub approval: ClaimApprovalStatus,
    /// `life` — lifecycle status.
    pub lifecycle: ClaimLifecycleStatus,
    /// `sal` — optional salience, finite in `[0, 1]`.
    pub salience: Option<f32>,
    /// `evid` — optional evidence payload (opaque MessagePack).
    pub evidence: Option<Value>,
    /// `from` — optional valid-time start (Unix seconds).
    pub valid_from: Option<u64>,
    /// `to` — optional valid-time end (Unix seconds).
    pub valid_to: Option<u64>,
    /// `src` — optional provenance source.
    pub source: Option<ClaimSource>,
    /// `world` — optional world scope: the 16-byte WORLD entity id this claim
    /// is scoped to (ARCH-0004 claim world filter; ARCH-0022 world model).
    /// ABSENT means base reality (the elide-the-default pattern, like
    /// `stale == false`). On disk it is exactly 16 MessagePack-binary bytes;
    /// any other shape is rejected fail-closed with [`Error::InvalidClaimBody`].
    /// The referenced WORLD entity is NOT required to exist at write time —
    /// extraction may create claims before their world; the read side groups
    /// by id regardless.
    pub world: Option<EntityId>,
    /// `scope` — optional relationship/facet scope (opaque MessagePack).
    pub scope: Option<Value>,
    /// `stale` — derived-data staleness marker; absent on disk means `false`.
    pub stale: bool,
}

impl ClaimBody {
    /// Creates a claim body from the six required fields; all optional
    /// fields start absent and `stale` starts `false`.
    #[must_use]
    pub fn new(
        predicate: impl Into<String>,
        subject: ClaimSubject,
        value: Value,
        confidence: f32,
        approval: ClaimApprovalStatus,
        lifecycle: ClaimLifecycleStatus,
    ) -> Self {
        Self {
            predicate: predicate.into(),
            subject,
            value,
            confidence,
            approval,
            lifecycle,
            salience: None,
            evidence: None,
            valid_from: None,
            valid_to: None,
            source: None,
            world: None,
            scope: None,
            stale: false,
        }
    }
}

/// Validates a predicate against the pinned D17 grammar: ≥2 segments, each
/// matching `[a-z][a-z0-9_]*`, joined by `.`, total ≤128 bytes.
///
/// When `allow_reserved` is `false` (every public write path), well-formed
/// predicates in the reserved `edge.*` namespace are rejected with
/// [`Error::ReservedPredicate`]. The provenance unit writes through the
/// `pub(crate)` door which sets `allow_reserved` to `true`, as does the
/// sync-replay door (`put_replicated`) so replicated provenance Claims
/// rematerialize; reads always allow reserved predicates so stored
/// provenance Claims stay decodable. `allow_reserved` skips ONLY this
/// reserved-namespace arm — the grammar checks above run unconditionally.
pub(crate) fn validate_predicate(predicate: &str, allow_reserved: bool) -> Result<()> {
    if predicate.len() > MAX_PREDICATE_BYTES {
        return Err(Error::InvalidPredicate {
            predicate: predicate.to_owned(),
            reason: "exceeds 128 bytes",
        });
    }

    let mut segments = 0_usize;
    for segment in predicate.split('.') {
        if !valid_predicate_segment(segment) {
            return Err(Error::InvalidPredicate {
                predicate: predicate.to_owned(),
                reason: "segments must match [a-z][a-z0-9_]*",
            });
        }
        segments += 1;
    }
    if segments < 2 {
        return Err(Error::InvalidPredicate {
            predicate: predicate.to_owned(),
            reason: "requires at least 2 dot-joined segments",
        });
    }

    if !allow_reserved && is_reserved_predicate(predicate) {
        return Err(Error::ReservedPredicate {
            predicate: predicate.to_owned(),
        });
    }

    Ok(())
}

/// Returns `true` when `predicate`'s first dot-separated segment is the
/// reserved `edge` namespace (D17). Reserved-namespace Claims are engine
/// provenance records: their lifecycle (supersede / retract / re-stamp) is
/// owned by the edge-provenance API, so the generic claim lifecycle ops
/// reject them with [`Error::ProvenanceClaimLifecycle`].
pub(crate) fn is_reserved_predicate(predicate: &str) -> bool {
    predicate.split('.').next() == Some(RESERVED_PREDICATE_NAMESPACE)
}

fn valid_predicate_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// Encodes a [`ClaimBody`] into the pinned MessagePack ABI: a map carrying
/// the present [`CLAIM_BODY_KEYS`] in canonical order. `stale == false` is
/// omitted (absent means `false` on decode). Encoding performs no
/// validation — every write path re-validates the encoded bytes through
/// [`decode_claim_body`], the single validator.
pub(crate) fn encode_claim_body(body: &ClaimBody) -> Result<Vec<u8>> {
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(CLAIM_BODY_KEYS.len());
    entries.push((Value::from(KEY_PRED), Value::from(body.predicate.as_str())));
    entries.push((Value::from(KEY_VAL), body.value.clone()));
    entries.push((Value::from(KEY_CONF), Value::F32(body.confidence)));
    if let Some(salience) = body.salience {
        entries.push((Value::from(KEY_SAL), Value::F32(salience)));
    }
    if let Some(evidence) = &body.evidence {
        entries.push((Value::from(KEY_EVID), evidence.clone()));
    }
    if let Some(valid_from) = body.valid_from {
        entries.push((Value::from(KEY_FROM), Value::from(valid_from)));
    }
    if let Some(valid_to) = body.valid_to {
        entries.push((Value::from(KEY_TO), Value::from(valid_to)));
    }
    if let Some(source) = body.source {
        entries.push((Value::from(KEY_SRC), Value::from(source.as_str())));
    }
    if let Some(world) = body.world {
        entries.push((
            Value::from(KEY_WORLD),
            Value::Binary(world.as_bytes().to_vec()),
        ));
    }
    entries.push((Value::from(KEY_SUBJ), Value::Binary(body.subject.encode())));
    if let Some(scope) = &body.scope {
        entries.push((Value::from(KEY_SCOPE), scope.clone()));
    }
    entries.push((Value::from(KEY_APPR), Value::from(body.approval.as_str())));
    entries.push((Value::from(KEY_LIFE), Value::from(body.lifecycle.as_str())));
    if body.stale {
        entries.push((Value::from(KEY_STALE), Value::Boolean(true)));
    }

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries))
        .map_err(|_| Error::InvariantViolation("claim body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and structurally validates a type-0 (CLAIM) body (D18).
///
/// This is the single validator: every write path validates through it (via
/// [`validate_claim_body_bytes`]) and `Vault::get_claim` decodes through it.
/// Fail-closed rules:
///
/// * the body must be exactly one MessagePack map (no trailing bytes);
/// * keys must be strings drawn from [`CLAIM_BODY_KEYS`], no duplicates;
/// * required: `pred`, `subj`, `val`, `conf`, `appr`, `life`;
/// * `conf` (and `sal` when present) must be finite numbers in `[0, 1]`;
/// * `from`/`to` must be non-negative integers fitting `u64`;
/// * `src`/`appr`/`life` must be the pinned enum strings;
/// * `stale` must be a boolean (absent = `false`);
/// * `subj` must be a 16-byte entity id or 33-byte EdgeRef ([`ClaimSubject`]);
/// * `pred` must satisfy the D17 grammar; reserved `edge.*` predicates are
///   rejected unless `allow_reserved_predicate` is set (provenance door /
///   read path).
pub(crate) fn decode_claim_body(data: &[u8], allow_reserved_predicate: bool) -> Result<ClaimBody> {
    #[cfg(test)]
    CLAIM_BODY_DECODE_COUNT.with(|count| count.set(count.get().saturating_add(1)));

    let mut cursor = Cursor::new(data);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidClaimBody("body is not valid MessagePack"))?;
    if cursor.position() != data.len() as u64 {
        return Err(Error::InvalidClaimBody("trailing bytes after body map"));
    }
    let Value::Map(entries) = value else {
        return Err(Error::InvalidClaimBody("body must be a MessagePack map"));
    };

    let mut predicate: Option<String> = None;
    let mut subject: Option<ClaimSubject> = None;
    let mut claim_value: Option<Value> = None;
    let mut confidence: Option<f32> = None;
    let mut approval: Option<ClaimApprovalStatus> = None;
    let mut lifecycle: Option<ClaimLifecycleStatus> = None;
    let mut salience: Option<f32> = None;
    let mut evidence: Option<Value> = None;
    let mut valid_from: Option<u64> = None;
    let mut valid_to: Option<u64> = None;
    let mut source: Option<ClaimSource> = None;
    let mut world: Option<EntityId> = None;
    let mut scope: Option<Value> = None;
    let mut stale: Option<bool> = None;

    let mut seen = [false; CLAIM_BODY_KEYS.len()];
    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidClaimBody("body keys must be strings"));
        };
        let Some(index) = CLAIM_BODY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::InvalidClaimBody(
                "body key is not in the pinned CLAIM_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidClaimBody("duplicate body key"));
        }
        seen[index] = true;

        match CLAIM_BODY_KEYS[index] {
            "pred" => {
                let Some(pred) = value.as_str() else {
                    return Err(Error::InvalidClaimBody("pred must be a string"));
                };
                predicate = Some(pred.to_owned());
            }
            "val" => claim_value = Some(value),
            "conf" => {
                confidence = Some(
                    unit_interval_f32(&value)
                        .ok_or(Error::InvalidClaimBody("conf must be finite in [0, 1]"))?,
                );
            }
            "sal" => {
                salience = Some(
                    unit_interval_f32(&value)
                        .ok_or(Error::InvalidClaimBody("sal must be finite in [0, 1]"))?,
                );
            }
            "evid" => evidence = Some(value),
            "from" => {
                valid_from = Some(value.as_u64().ok_or(Error::InvalidClaimBody(
                    "from must be a non-negative integer",
                ))?);
            }
            "to" => {
                valid_to = Some(
                    value
                        .as_u64()
                        .ok_or(Error::InvalidClaimBody("to must be a non-negative integer"))?,
                );
            }
            "src" => {
                let parsed =
                    value
                        .as_str()
                        .and_then(ClaimSource::parse)
                        .ok_or(Error::InvalidClaimBody(
                            "src must be one of user_stated|observed|inferred|imported",
                        ))?;
                source = Some(parsed);
            }
            "world" => {
                // ARCH-0004 / ARCH-0022: a present `world` key is the
                // 16-byte WORLD entity id. Anything that is not exactly 16
                // MessagePack-binary bytes (a string, a 15-byte blob, …) is
                // rejected fail-closed — the read side groups claims by this
                // id, so a malformed value can never be silently scoped.
                let Value::Binary(bytes) = &value else {
                    return Err(Error::InvalidClaimBody("world must be MessagePack binary"));
                };
                let arr: [u8; ENTITY_ID_LEN] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidClaimBody("world must be a 16-byte world id"))?;
                world = Some(
                    EntityId::from_bytes(arr)
                        .map_err(|_| Error::InvalidClaimBody("world id is reserved"))?,
                );
            }
            "subj" => {
                let Value::Binary(bytes) = &value else {
                    return Err(Error::InvalidClaimBody("subj must be MessagePack binary"));
                };
                subject = Some(ClaimSubject::decode(bytes)?);
            }
            "scope" => scope = Some(value),
            "appr" => {
                let parsed = value.as_str().and_then(ClaimApprovalStatus::parse).ok_or(
                    Error::InvalidClaimBody("appr must be one of auto|proposed|approved|rejected"),
                )?;
                approval = Some(parsed);
            }
            "life" => {
                let parsed = value.as_str().and_then(ClaimLifecycleStatus::parse).ok_or(
                    Error::InvalidClaimBody("life must be one of active|superseded|retracted"),
                )?;
                lifecycle = Some(parsed);
            }
            "stale" => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::InvalidClaimBody("stale must be a boolean"));
                };
                stale = Some(flag);
            }
            _ => unreachable!("index resolved from CLAIM_BODY_KEYS"),
        }
    }

    let predicate = predicate.ok_or(Error::InvalidClaimBody("missing required field pred"))?;
    validate_predicate(&predicate, allow_reserved_predicate)?;
    let subject = subject.ok_or(Error::InvalidClaimBody("missing required field subj"))?;
    let claim_value = claim_value.ok_or(Error::InvalidClaimBody("missing required field val"))?;
    let confidence = confidence.ok_or(Error::InvalidClaimBody("missing required field conf"))?;
    let approval = approval.ok_or(Error::InvalidClaimBody("missing required field appr"))?;
    let lifecycle = lifecycle.ok_or(Error::InvalidClaimBody("missing required field life"))?;

    Ok(ClaimBody {
        predicate,
        subject,
        value: claim_value,
        confidence,
        approval,
        lifecycle,
        salience,
        evidence,
        valid_from,
        valid_to,
        source,
        world,
        scope,
        stale: stale.unwrap_or(false),
    })
}

/// Structural validation entry point for raw type-0 body bytes (D18).
/// See [`decode_claim_body`] for the rules.
///
/// This is the WRITE-ONLY chokepoint (the read path — `Vault::get_claim` —
/// decodes via [`decode_claim_body`] directly): every type-0 write on every
/// door (`Vault::put_claim`, both batch builders' public puts, the
/// reserved-namespace `put_reserved_claim` door, the `put_replicated`
/// sync-replay doors, and the provenance lifecycle rewrites) validates
/// through it, either up front or via `apply_put`. On top of the D18 rules
/// it runs the predicate-aware structural branch for reserved
/// `edge.provenance` Claims (ONE-1159) — see
/// [`validate_edge_provenance_claim_structure`]. Reads stay untouched:
/// pre-existing stored junk keeps its current read behavior (typed failure
/// at the provenance ops that interpret it), it just can no longer be
/// (re)written.
pub(crate) fn validate_claim_body_bytes(data: &[u8], allow_reserved_predicate: bool) -> Result<()> {
    let body = decode_claim_body(data, allow_reserved_predicate)?;
    if body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE {
        validate_edge_provenance_claim_structure(&body)?;
    }
    Ok(())
}

/// ONE-1159 — full structural validation of an `edge.provenance` Claim at
/// the WRITE door.
///
/// D18 treats `val` as opaque MessagePack and `evid` as an opaque payload,
/// so the replicated door admitted D18-valid but STRUCTURALLY invalid
/// provenance Claims (junk `val`, non-record `val` maps, missing
/// actor-class evidence); later provenance ops then failed closed only at
/// read/supersede time. Sync replay is a WRITE PATH — the same fail-closed
/// checks run behind the trusted door:
///
/// * `val` must decode as the pinned `edge.provenance` value record via the
///   SHARED validator [`crate::provenance::validate_edge_provenance_value`]
///   — the pinned key vocabulary lives in exactly one place, so vocabulary
///   growth flows through here with zero edits;
/// * the write-time validated `actor_class` must be persisted in EXACTLY
///   one place: as an `actor_class` key in the value record (accepted only
///   once the shared vocabulary carries that key) or as the engine-owned
///   `{"actor_class": u8}` map on the wrapper's `evid`
///   ([`crate::provenance::decode_actor_class_evidence`]). Present in both
///   → ambiguous, rejected; present in neither → rejected. A provenance
///   Claim without a persisted class can never participate in flag refresh,
///   and the class is never defaulted (D13).
///
/// ONE-1159 fix-wave adds two WRAPPER-axis checks the door previously
/// skipped (D18 treats the wrapper's lifecycle fields as opaque):
///
/// * surfaceability — `appr ∈ {auto, approved}` (the exact set from
///   [`claim_surfaceable`]) and `stale = false`, so a non-surfaceable Claim
///   cannot enter at the write door and silently steer edge flags. Lifecycle
///   is NOT gated (`superseded` / `retracted` are legitimate provenance
///   states the live_/retracted_ scans read);
/// * wrapper↔value-record mirror — `conf == confidence`, `from == valid_from`,
///   `to == valid_to`, so the precedence/display wrapper can never lie about
///   the value record the writer mirrored it from.
///
/// Typed rejections only (the [`Error::InvalidProvenanceBody`] family) — at
/// the sync replay door the caller quarantines them (`x:` row, hash-only
/// per ONE-1124), never drops.
fn validate_edge_provenance_claim_structure(body: &ClaimBody) -> Result<()> {
    // ONE-1159 fix-wave (BLOCKER #2) — decode the value record ONCE via the
    // SHARED decoder so the typed record is held for the wrapper↔value-record
    // mirror checks below. This is exactly what
    // [`crate::provenance::validate_edge_provenance_value`] runs (it is the
    // same call with the record discarded), so the value-record structural
    // rules are unchanged and vocabulary growth (ONE-1138's 10-key shape)
    // flows through this one call with zero edits.
    let record = crate::provenance::decode_edge_provenance_body(&body.value)?;
    // Presence-only probe for the value-record `actor_class` key: VALIDITY
    // of the key's value is the shared decoder's job above (and a body
    // key outside the pinned vocabulary was already rejected there), so
    // this never duplicates shape logic.
    let value_has_actor_class = matches!(
        &body.value,
        Value::Map(entries) if entries.iter().any(|(key, _)| {
            key.as_str() == Some(crate::provenance::EVIDENCE_KEY_ACTOR_CLASS)
        })
    );
    match (value_has_actor_class, body.evidence.as_ref()) {
        (true, Some(_)) => {
            return Err(Error::InvalidProvenanceBody(
                "actor_class present in both the value record and the wrapper evid (ambiguous)",
            ));
        }
        (true, None) => {}
        (false, evidence) => {
            crate::provenance::decode_actor_class_evidence(evidence)?;
        }
    }

    // ONE-1159 fix-wave (BLOCKER #1) — surfaceability-axis guard on the
    // WRAPPER. A provenance Claim only drives edge-flag refresh while it is
    // surfaceable on the read gate; admitting a non-surfaceable wrapper at the
    // replay door would let an `appr=rejected` / `stale=true` Claim silently
    // steer flags. Reuse the EXACT approval set from [`claim_surfaceable`] so
    // the door and the read gate cite one approval rule. Lifecycle is
    // DELIBERATELY not gated here — `superseded` / `retracted` are legitimate
    // provenance lifecycle states the live_/retracted_ scans must read.
    if !matches!(
        body.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper appr must be auto|approved",
        ));
    }
    if body.stale {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper must not be stale",
        ));
    }

    // ONE-1159 fix-wave (BLOCKER #2) — the wrapper's `conf`/`from`/`to` MUST
    // mirror the value record's `confidence`/`valid_from`/`valid_to`. The
    // local writer guarantees this by construction, and precedence/display
    // read the wrapper, so a mismatched wrapper is a structural lie. `conf`
    // and `confidence` are both required and parsed through the same
    // `unit_interval_f32`/`Value::F32` path, so `==` is the exact VALUE
    // equality the contract pins; `from`/`to` are optional on both sides and
    // compared as `Option` equality (both-present-equal or both-absent).
    if record.confidence != body.confidence {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper conf does not mirror value-record confidence",
        ));
    }
    if record.valid_from != body.valid_from {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper from does not mirror value-record valid_from",
        ));
    }
    if record.valid_to != body.valid_to {
        return Err(Error::InvalidProvenanceBody(
            "edge.provenance wrapper to does not mirror value-record valid_to",
        ));
    }

    Ok(())
}

/// D19 read-path status gate predicate (ARCH-0003 retrieval rule; ARCH-0004
/// §H "Claim filtering — enumerated requirements" items 1, 2, 4): a Claim
/// may surface on the retrieval read paths (pipeline results across all five
/// channels, context-pack results, and context-pack neighbors) only when
///
/// * `appr ∈ {auto, approved}` — respect consent;
/// * `life = active` — only current beliefs;
/// * `stale = false` — only regenerated content (absent on disk means
///   `false`, [`decode_claim_body`]; absence alone never excludes).
///
/// The gate is an EXCLUSION, not an error: failing claims are silently
/// dropped and counted (`PackStats::claims_suppressed`). Targeted reads stay
/// deliberately UNGATED: [`crate::Vault::get_claim`] is the history /
/// consent-review door and the edge-provenance lifecycle readers must see
/// closed (`superseded` / `retracted`) Claims to compute winner stamps.
/// World/facet filtering (§H item 3) is a separate unit, and
/// deleted-revision contamination (§H item 5) is the M4/M5 sweep scope.
pub(crate) fn claim_surfaceable(body: &ClaimBody) -> bool {
    matches!(
        body.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) && body.lifecycle == ClaimLifecycleStatus::Active
        && !body.stale
}

/// Parses a MessagePack number as a finite `f32` in `[0, 1]`. Shared with
/// the provenance module so `conf` and `confidence` validate identically.
pub(crate) fn unit_interval_f32(value: &Value) -> Option<f32> {
    let parsed = match value {
        Value::F32(v) => f64::from(*v),
        Value::F64(v) => *v,
        Value::Integer(v) => {
            if let Some(i) = v.as_i64() {
                i as f64
            } else {
                return None;
            }
        }
        _ => return None,
    };

    if !parsed.is_finite() || !(0.0..=1.0).contains(&parsed) {
        return None;
    }
    Some(parsed as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicate_grammar_accepts_well_formed_unknown_predicates() {
        for predicate in [
            "hobby.collects",
            "profile.lives_in",
            "goal.learning_v2",
            "a.b.c",
        ] {
            validate_predicate(predicate, false).expect("well-formed predicate must pass");
        }
    }

    #[test]
    fn predicate_grammar_rejects_violations_typed() {
        // Single segment.
        assert!(matches!(
            validate_predicate("profile", false),
            Err(Error::InvalidPredicate { .. })
        ));
        // Uppercase.
        assert!(matches!(
            validate_predicate("Edge.Provenance", false),
            Err(Error::InvalidPredicate { .. })
        ));
        // Empty segment.
        assert!(matches!(
            validate_predicate("profile.", false),
            Err(Error::InvalidPredicate { .. })
        ));
        // Segment starting with digit / underscore.
        assert!(matches!(
            validate_predicate("profile.9lives", false),
            Err(Error::InvalidPredicate { .. })
        ));
        assert!(matches!(
            validate_predicate("profile._hidden", false),
            Err(Error::InvalidPredicate { .. })
        ));
        // Non-ASCII.
        assert!(matches!(
            validate_predicate("profilé.name", false),
            Err(Error::InvalidPredicate { .. })
        ));
    }

    #[test]
    fn predicate_length_gate_is_128_bytes_inclusive() {
        // 2 segments: "a." + 126 'b's = exactly 128 bytes — accepted.
        let at_limit = format!("a.{}", "b".repeat(126));
        assert_eq!(at_limit.len(), 128);
        validate_predicate(&at_limit, false).expect("128-byte predicate must pass");

        let over_limit = format!("a.{}", "b".repeat(127));
        assert_eq!(over_limit.len(), 129);
        assert!(matches!(
            validate_predicate(&over_limit, false),
            Err(Error::InvalidPredicate { .. })
        ));
    }

    #[test]
    fn claim_source_parse_accepts_inferred_and_imported_wire_values() {
        for (wire, source) in [
            ("inferred", ClaimSource::Inferred),
            ("imported", ClaimSource::Imported),
        ] {
            assert_eq!(ClaimSource::parse(wire), Some(source), "{wire}");
            assert_eq!(source.as_str(), wire, "{wire} round-trip literal");
        }
    }

    #[test]
    fn reserved_namespace_rejected_public_allowed_internal() {
        assert!(matches!(
            validate_predicate("edge.provenance", false),
            Err(Error::ReservedPredicate { .. })
        ));
        assert!(matches!(
            validate_predicate("edge.anything_else", false),
            Err(Error::ReservedPredicate { .. })
        ));
        // The internal door allows the reserved namespace…
        validate_predicate("edge.provenance", true).expect("door must allow edge.*");
        // …but grammar still applies through the door.
        assert!(matches!(
            validate_predicate("Edge.Provenance", true),
            Err(Error::InvalidPredicate { .. })
        ));
        // "edgework.x" is NOT in the reserved namespace (prefix is segment-exact).
        validate_predicate("edgework.tools", false).expect("edgework.* is not reserved");
    }

    /// ONE-1159 — the write-door chokepoint ([`validate_claim_body_bytes`],
    /// shared by `put_reserved_claim` AND both `put_replicated` builders via
    /// `apply_put`) runs FULL structural validation on `edge.provenance`
    /// Claims: pinned value-record shape + persisted actor-class evidence,
    /// typed `InvalidProvenanceBody` rejections. Forged cases are junk
    /// SHAPES (never key-count assumptions), so each stays invalid under any
    /// grown value-record vocabulary.
    #[test]
    fn write_door_validates_edge_provenance_claim_structure() {
        use crate::provenance::{
            EVIDENCE_KEY_ACTOR_CLASS, EdgeProvenanceClaimBody, SupersessionStatus,
            encode_actor_class_evidence, encode_edge_provenance_value,
        };
        use crate::types::EdgeActorClass;

        let actor = EntityId::from_bytes([0x42; 16]).expect("valid id");
        // ONE-1159 fix-wave: a surfaceable wrapper's `conf` MUST mirror the
        // value-record `confidence`. The prior control hardcoded `0.9` ≠ the
        // record's `0.75` — a self-inconsistent "valid" wrapper the new mirror
        // check correctly rejects. Mirror both to one literal (fix the
        // control, not the assertion). The negative cases below all reject on
        // an EARLIER axis (value-record decode / actor-class), so the shared
        // `conf` value never weakens them.
        let confidence = 0.75_f32;
        let valid_value = || {
            encode_edge_provenance_value(&EdgeProvenanceClaimBody::new(
                actor,
                confidence,
                SupersessionStatus::Confirmed,
            ))
        };
        let evid = encode_actor_class_evidence(EdgeActorClass::Human);
        let subject = ClaimSubject::Edge {
            source: EntityId::from_bytes([0x11; 16]).expect("valid id"),
            kind: EdgeKind::Mentions,
            target: EntityId::from_bytes([0x22; 16]).expect("valid id"),
        };
        let encode = |predicate: &str, value: Value, evidence: Option<Value>| {
            let mut body = ClaimBody::new(
                predicate,
                subject,
                value,
                confidence,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            body.evidence = evidence;
            encode_claim_body(&body).expect("encode")
        };

        // Fully-valid legacy shape (value record + engine-owned evid map):
        // accepted through the reserved door.
        validate_claim_body_bytes(
            &encode("edge.provenance", valid_value(), Some(evid.clone())),
            true,
        )
        .expect("valid edge.provenance claim must pass the write door");

        let missing_actor = {
            let Value::Map(mut entries) = valid_value() else {
                unreachable!("encoder emits a map");
            };
            entries.retain(|(key, _)| key.as_str() != Some("actor_entity_ref"));
            Value::Map(entries)
        };
        let garbage_key = {
            let Value::Map(mut entries) = valid_value() else {
                unreachable!("encoder emits a map");
            };
            entries.push((Value::from("zzz"), Value::from(1_u8)));
            Value::Map(entries)
        };
        let class_in_value_record = {
            let Value::Map(mut entries) = valid_value() else {
                unreachable!("encoder emits a map");
            };
            entries.push((Value::from(EVIDENCE_KEY_ACTOR_CLASS), Value::from(0_u8)));
            Value::Map(entries)
        };

        let rejected: [(&str, Vec<u8>); 6] = [
            (
                "non-map value record",
                encode("edge.provenance", Value::from("junk"), Some(evid.clone())),
            ),
            (
                "value record missing required actor_entity_ref",
                encode("edge.provenance", missing_actor, Some(evid.clone())),
            ),
            (
                "unknown key zzz in value record",
                encode("edge.provenance", garbage_key, Some(evid.clone())),
            ),
            (
                "missing actor_class evidence entirely",
                encode("edge.provenance", valid_value(), None),
            ),
            (
                "malformed actor_class evidence (non-map evid)",
                encode("edge.provenance", valid_value(), Some(Value::from(7_u8))),
            ),
            // Rejected under BOTH vocabularies: today `actor_class` is not a
            // value-record key (unknown-key reject); once the vocabulary
            // carries it, body-key + evid together are the ambiguous
            // two-sources-of-truth shape (both-present reject).
            (
                "actor_class in both the value record and evid",
                encode("edge.provenance", class_in_value_record, Some(evid)),
            ),
        ];
        for (name, data) in rejected {
            assert!(
                matches!(
                    validate_claim_body_bytes(&data, true),
                    Err(Error::InvalidProvenanceBody(_))
                ),
                "{name}: must reject typed (InvalidProvenanceBody) at the write door"
            );
        }

        // Predicate-scoped: the structural branch fires on the pinned
        // edge.provenance literal only. Other reserved-namespace claims and
        // public claims keep their opaque D18 `val`.
        validate_claim_body_bytes(
            &encode("edge.other_records", Value::from("opaque"), None),
            true,
        )
        .expect("non-provenance reserved claim keeps opaque val");
        validate_claim_body_bytes(
            &encode("hobby.collects", Value::from("opaque"), None),
            false,
        )
        .expect("public claim keeps opaque val");
    }

    #[test]
    fn claim_subject_decode_pins_both_encodings() {
        let id = EntityId::from_bytes([0x11; 16]).expect("valid id");
        assert_eq!(
            ClaimSubject::decode(id.as_bytes()).expect("16-byte subj"),
            ClaimSubject::Entity(id)
        );

        let source = EntityId::from_bytes([0x22; 16]).expect("valid id");
        let target = EntityId::from_bytes([0x33; 16]).expect("valid id");
        let mut edge_ref = Vec::new();
        edge_ref.extend_from_slice(source.as_bytes());
        edge_ref.push(9); // Mentions
        edge_ref.extend_from_slice(target.as_bytes());
        assert_eq!(
            ClaimSubject::decode(&edge_ref).expect("33-byte subj"),
            ClaimSubject::Edge {
                source,
                kind: EdgeKind::Mentions,
                target,
            }
        );

        // 17 bytes — neither encoding.
        assert!(matches!(
            ClaimSubject::decode(&[0x44; 17]),
            Err(Error::InvalidClaimBody(_))
        ));
        // 33 bytes with an unregistered kind byte.
        let mut bad_kind = edge_ref.clone();
        bad_kind[16] = 200;
        assert!(matches!(
            ClaimSubject::decode(&bad_kind),
            Err(Error::InvalidClaimBody(_))
        ));
        // Reserved entity-id bytes (all zero) rejected.
        assert!(matches!(
            ClaimSubject::decode(&[0x00; 16]),
            Err(Error::InvalidClaimBody(_))
        ));
    }

    /// ARCH-0004 / ARCH-0022 world write-validation, exercised on the claim
    /// body chokepoint with hand-built MessagePack so a wrong impl that stores
    /// arbitrary `world` bytes FAILS: a present `world` must be exactly 16
    /// binary bytes (→ an `EntityId`), an absent key is base reality (`None`),
    /// and a 15-byte blob or a string is a typed `InvalidClaimBody`.
    #[test]
    fn world_value_must_be_16_byte_binary() {
        let subj = EntityId::from_bytes([0x11; 16]).expect("valid subject id");
        let body_with_world = |world: Option<Value>| -> Vec<u8> {
            let mut entries = vec![
                (Value::from("pred"), Value::from("profile.name")),
                (Value::from("val"), Value::from("x")),
                (Value::from("conf"), Value::F32(1.0)),
            ];
            if let Some(world) = world {
                entries.push((Value::from("world"), world));
            }
            entries.push((Value::from("subj"), Value::Binary(subj.as_bytes().to_vec())));
            entries.push((Value::from("appr"), Value::from("auto")));
            entries.push((Value::from("life"), Value::from("active")));
            let mut out = Vec::new();
            rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("encode body");
            out
        };

        // Exactly 16 binary bytes → an EntityId.
        let world_id = EntityId::from_bytes([0x5A; 16]).expect("valid world id");
        let good = body_with_world(Some(Value::Binary(world_id.as_bytes().to_vec())));
        assert_eq!(
            decode_claim_body(&good, false)
                .expect("16-byte world passes")
                .world,
            Some(world_id)
        );

        // Absent key = base reality (None), the elide-the-default pattern.
        let base = body_with_world(None);
        assert_eq!(
            decode_claim_body(&base, false)
                .expect("absent world passes")
                .world,
            None
        );

        // 15-byte blob rejected fail-closed.
        assert!(matches!(
            decode_claim_body(&body_with_world(Some(Value::Binary(vec![0x5A; 15]))), false),
            Err(Error::InvalidClaimBody(_))
        ));

        // String rejected fail-closed (the pre-fix opaque-bytes behavior).
        assert!(matches!(
            decode_claim_body(&body_with_world(Some(Value::from("w0"))), false),
            Err(Error::InvalidClaimBody(_))
        ));
    }

    #[test]
    fn claim_field_profile_slices_are_prefixes_of_the_pinned_keys() {
        assert_eq!(CLAIM_FIELDS_MINIMAL, &CLAIM_BODY_KEYS[..2]);
        assert_eq!(CLAIM_FIELDS_STANDARD, &CLAIM_BODY_KEYS[..5]);
        assert_eq!(CLAIM_FIELDS_FULL, &CLAIM_BODY_KEYS[..11]);
    }

    /// D19 literal truth table: `appr ∈ {auto, approved}` ∧ `life = active`
    /// ∧ `stale = false` — every other combination is excluded (ARCH-0003;
    /// ARCH-0004 §H items 1/2/4).
    #[test]
    fn claim_surfaceable_pins_the_full_status_truth_table() {
        let subject = ClaimSubject::Entity(EntityId::from_bytes([0x11; 16]).expect("valid id"));
        let body = |appr: ClaimApprovalStatus, life: ClaimLifecycleStatus, stale: bool| {
            let mut body = ClaimBody::new("test.pred", subject, Value::from("v"), 0.5, appr, life);
            body.stale = stale;
            body
        };

        use ClaimApprovalStatus as A;
        use ClaimLifecycleStatus as L;

        // The ONLY surfaceable combinations.
        assert!(claim_surfaceable(&body(A::Auto, L::Active, false)));
        assert!(claim_surfaceable(&body(A::Approved, L::Active, false)));

        // Approval axis excludes independently of lifecycle (AC 3).
        assert!(!claim_surfaceable(&body(A::Proposed, L::Active, false)));
        assert!(!claim_surfaceable(&body(A::Rejected, L::Active, false)));

        // Lifecycle axis excludes independently of approval.
        assert!(!claim_surfaceable(&body(A::Auto, L::Superseded, false)));
        assert!(!claim_surfaceable(&body(A::Auto, L::Retracted, false)));
        assert!(!claim_surfaceable(&body(A::Approved, L::Superseded, false)));
        assert!(!claim_surfaceable(&body(A::Approved, L::Retracted, false)));

        // Staleness excludes even when both status axes pass (AC 1).
        assert!(!claim_surfaceable(&body(A::Auto, L::Active, true)));
        assert!(!claim_surfaceable(&body(A::Approved, L::Active, true)));

        // `ClaimBody::new` leaves `stale` at the decode default (absent =
        // false) — absence alone must not exclude (AC 4).
        assert!(claim_surfaceable(&ClaimBody::new(
            "test.pred",
            subject,
            Value::from("v"),
            0.5,
            A::Auto,
            L::Active,
        )));
    }

    /// ONE-1159 fix-wave — the WRITE door's surfaceability guard reuses the
    /// `claim_surfaceable` approval set: `Approved` is accepted (not only
    /// `Auto`), and `Proposed` is a typed reject. Pins the {auto, approved}
    /// boundary directly on the door function, independent of the read gate.
    #[test]
    fn provenance_door_accepts_approved_and_rejects_proposed_wrappers() {
        let subject = ClaimSubject::Entity(EntityId::from_bytes([0x11; 16]).expect("valid id"));
        // Valid value record (3 required keys), conf mirrors the wrapper, no
        // valid-time on either side, actor-class on the wrapper `evid`.
        let value_record = Value::Map(vec![
            (
                Value::from("actor_entity_ref"),
                Value::Binary(vec![0x42; 16]),
            ),
            (Value::from("confidence"), Value::F32(0.75)),
            (Value::from("supersession_status"), Value::from(1u8)),
        ]);
        let actor_class_evid = Value::Map(vec![(Value::from("actor_class"), Value::from(0u8))]);
        let wrapper = |appr: ClaimApprovalStatus| {
            let mut body = ClaimBody::new(
                crate::provenance::PREDICATE_EDGE_PROVENANCE,
                subject,
                value_record.clone(),
                0.75,
                appr,
                ClaimLifecycleStatus::Active,
            );
            body.evidence = Some(actor_class_evid.clone());
            body
        };

        // `Approved` is in the surfaceable set → the door passes it.
        validate_edge_provenance_claim_structure(&wrapper(ClaimApprovalStatus::Approved))
            .expect("approved provenance wrapper must pass the door");
        // `Proposed` is outside {auto, approved} → typed reject.
        assert!(matches!(
            validate_edge_provenance_claim_structure(&wrapper(ClaimApprovalStatus::Proposed)),
            Err(Error::InvalidProvenanceBody(_))
        ));
    }
}
