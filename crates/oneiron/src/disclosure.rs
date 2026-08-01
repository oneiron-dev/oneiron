//! Interlocutor-scoped disclosure clamp substrate (OF-365 ILD-2).
//!
//! Two-mode law: owner ABSENT means out-of-scope memories are ABSENT from
//! model context (absence is the boundary — prompt-side withholding is not a
//! security boundary); owner PRESENT with third parties keeps Tier A
//! absence-clamped while Tier B surfaces under a named-presence discretion
//! notice. Mode is stateless — recomputed from the presented interlocutor
//! set on every assembly.
//!
//! Enforcement lives in `context_pack.rs` (the enforcement point IS context
//! assembly); this module owns mode/tier/scope classification, storage, and
//! the agent-visible assembly block.

use std::io::Cursor;

use heed::RoTxn;
use rmpv::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::affect::Vad;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, claim_sensitivity_band,
    decode_claim_body, encode_claim_body, validate_claim_body_bytes,
};
use crate::edge::{EDGE_KEY_LEN, EdgeKind};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, ErrorKind, Result};
use crate::interlocutor::{InterlocutorSet, InterlocutorStamp};
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CHANNEL_IDENTITY,
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_FACET,
    ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
    ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_REDACTION_AUDIT,
};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::CLAIM_OF_DEFAULT_WEIGHT;

/// Current DisclosureScope body schema version.
pub const DISCLOSURE_SCOPE_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for DisclosureScope bodies.
pub const DISCLOSURE_SCOPE_BODY_KEYS: [&str; 7] = [
    "schema_version",
    "entities",
    "topics",
    "purpose",
    "status",
    "created_at",
    "updated_at",
];

const KEY_SCHEMA_VERSION: &str = DISCLOSURE_SCOPE_BODY_KEYS[0];
const KEY_ENTITIES: &str = DISCLOSURE_SCOPE_BODY_KEYS[1];
const KEY_TOPICS: &str = DISCLOSURE_SCOPE_BODY_KEYS[2];
const KEY_PURPOSE: &str = DISCLOSURE_SCOPE_BODY_KEYS[3];
const KEY_STATUS: &str = DISCLOSURE_SCOPE_BODY_KEYS[4];
const KEY_CREATED_AT: &str = DISCLOSURE_SCOPE_BODY_KEYS[5];
const KEY_UPDATED_AT: &str = DISCLOSURE_SCOPE_BODY_KEYS[6];

/// Pinned on-disk MessagePack key set for facet-exposure bodies.
pub const FACET_EXPOSURE_BODY_KEYS: [&str; 3] = ["schema_version", "exposure", "updated_at"];

const KEY_EXPOSURE: &str = FACET_EXPOSURE_BODY_KEYS[1];

/// Pinned on-disk MessagePack key set for per-contact facet-clearance bodies.
pub const FACET_CLEARANCE_BODY_KEYS: [&str; 5] = [
    "schema_version",
    "facets",
    "status",
    "created_at",
    "updated_at",
];

const KEY_FACETS: &str = FACET_CLEARANCE_BODY_KEYS[1];

/// Maximum facet ids one contact clearance may carry (mirrors the scope cap).
pub const MAX_FACET_CLEARANCE_ENTRIES: usize = 256;

/// Maximum explicit allowlist entries one scope may carry.
pub const MAX_DISCLOSURE_SCOPE_ENTITIES: usize = 256;
/// Maximum reserved topic tags one scope may carry.
pub const MAX_DISCLOSURE_SCOPE_TOPICS: usize = 32;
const MAX_DISCLOSURE_SCOPE_TOPIC_BYTES: usize = 128;
const MAX_DISCLOSURE_SCOPE_PURPOSE_BYTES: usize = 512;

/// `vault_meta` row key prefix for per-contact scope rows (enforcement truth;
/// one O(1) read per non-owner interlocutor, the off-record-fence shape).
const DISCLOSURE_SCOPE_KEY_PREFIX: &[u8] = b"disclosure.scope.v1:";
/// `vault_meta` row key prefix for owner Tier-A mark rows.
const DISCLOSURE_TIER_A_KEY_PREFIX: &[u8] = b"disclosure.tier_a.v1:";
/// `vault_meta` row key prefix for per-facet exposure rows (F2(d) public set).
/// A MISSING row means private — every facet is born private, fail-closed.
const FACET_EXPOSURE_KEY_PREFIX: &[u8] = b"facet.exposure.v1:";
/// `vault_meta` row key prefix for per-contact facet-clearance rows.
const FACET_CLEARANCE_KEY_PREFIX: &[u8] = b"contact.clearance.v1:";

/// Pinned `disclosure.*` claim predicates.
pub const DISCLOSURE_CLAIM_PREDICATES: [&str; 5] = [
    "disclosure.scope",
    "disclosure.tier",
    "disclosure.topic",
    "disclosure.facet_exposure",
    "disclosure.clearance",
];

pub const PREDICATE_DISCLOSURE_SCOPE: &str = "disclosure.scope";
pub const PREDICATE_DISCLOSURE_TIER: &str = "disclosure.tier";
pub const PREDICATE_DISCLOSURE_TOPIC: &str = "disclosure.topic";
pub const PREDICATE_DISCLOSURE_FACET_EXPOSURE: &str = "disclosure.facet_exposure";
pub const PREDICATE_DISCLOSURE_CLEARANCE: &str = "disclosure.clearance";

const DISCLOSURE_TIER_VALUE_TIER_A: &str = "tier_a";

/// Entity types that are NEVER disclosure material for third parties:
/// governance / consent / biometric / intimate-profile records — exactly the
/// records that describe OTHER people's consent state (design §7 rule 2).
/// The ILD-3 voice-print type byte joins this list when it lands (ONE-1518).
pub const DISCLOSURE_TIER_A_ENTITY_TYPES: [u8; 10] = [
    ENTITY_TYPE_REDACTION_AUDIT,
    ENTITY_TYPE_AUTHORITY_LOG,
    ENTITY_TYPE_POLICY_MANIFEST,
    ENTITY_TYPE_FEDERATION_GRANT,
    ENTITY_TYPE_ACCESS_GRANT,
    ENTITY_TYPE_PSYCH_PROFILE,
    ENTITY_TYPE_CHANNEL_IDENTITY,
    ENTITY_TYPE_COUNTERPARTY_CONTACT,
    ENTITY_TYPE_OUTBOUND_GRANT,
    ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
];

/// Claim predicate prefixes that classify Tier A regardless of band: affect
/// annotations and the meta-privacy families (scope/tier marks themselves
/// never leak — design §7 rule 4).
pub const DISCLOSURE_TIER_A_PREDICATE_PREFIXES: [&str; 5] = [
    "affect.",
    "disclosure.",
    "counterparty_contact.",
    "channel_identity.",
    "voice_print.",
];

/// The two-mode law's mode axis (design §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DisclosureMode {
    OwnerAlone,
    Supervised,
    AbsenceClamp,
}

impl DisclosureMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerAlone => "owner_alone",
            Self::Supervised => "supervised",
            Self::AbsenceClamp => "absence_clamp",
        }
    }

    /// Total mode derivation from the resolved interlocutor set: owner alone
    /// -> `OwnerAlone`; owner plus non-owners -> `Supervised`; no owner entry
    /// -> `AbsenceClamp`. Supervision keys to the session-constructed Owner
    /// entry only (I3).
    #[must_use]
    pub fn from_set(set: &InterlocutorSet) -> Self {
        match (set.supervised(), set.has_non_owner()) {
            (true, false) => Self::OwnerAlone,
            (true, true) => Self::Supervised,
            (false, _) => Self::AbsenceClamp,
        }
    }
}

/// Content tier under the two-tier hiding law (OF-355).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureTier {
    TierA,
    TierB,
}

/// Classifies one entity against the five Tier-A rules IN ORDER (design §7):
/// live off-record overlay membership (plus the legacy fence backstop),
/// governance type byte, sensitivity band (band 2+ or an
/// ambiguous band fails closed), Tier-A predicate prefix, owner mark row. A
/// type-0 record whose body is missing or undecodable is ambiguous and fails
/// closed to Tier A.
pub(crate) fn disclosure_tier(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    claim_body: Option<&ClaimBody>,
) -> Result<DisclosureTier> {
    // Rule 1 — live overlay membership, with the legacy fence retained as a
    // fail-closed backstop until ONE-1731 removes fence symbols.
    if crate::off_record::off_record_fence_active(store, rtxn, id)? {
        return Ok(DisclosureTier::TierA);
    }
    // Rule 2 — governance/consent/biometric/intimate-profile type bytes.
    if DISCLOSURE_TIER_A_ENTITY_TYPES.contains(&entity_type) {
        return Ok(DisclosureTier::TierA);
    }
    if entity_type == ENTITY_TYPE_CLAIM {
        let decoded;
        let body = match claim_body {
            Some(body) => Some(body),
            None => {
                decoded = read_stored_claim_body(store, rtxn, id)?;
                decoded.as_ref()
            }
        };
        let Some(body) = body else {
            return Ok(DisclosureTier::TierA);
        };
        // Rule 3 — sensitivity band: ambiguous (duplicate key) or >= 2
        // ("sensitive"/"restricted") fails closed to Tier A. A missing stamp
        // reads band 2 (the ONE-1645 unstamped floor), so a claim with no
        // recorded provenance is never disclosed to a non-owner party; only a
        // positive `"sensitivity": public|0` stamp reaches Tier B here.
        match claim_sensitivity_band(body) {
            None => return Ok(DisclosureTier::TierA),
            Some(band) if band >= 2 => return Ok(DisclosureTier::TierA),
            Some(_) => {}
        }
        // Rule 4 — Tier-A predicate prefixes.
        if DISCLOSURE_TIER_A_PREDICATE_PREFIXES
            .iter()
            .any(|prefix| body.predicate.starts_with(prefix))
        {
            return Ok(DisclosureTier::TierA);
        }
    }
    // Rule 5 — owner-marked-private row.
    if disclosure_tier_a_marked_in(store, rtxn, id)? {
        return Ok(DisclosureTier::TierA);
    }
    Ok(DisclosureTier::TierB)
}

fn read_stored_claim_body(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ClaimBody>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    Ok(raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .and_then(|payload| decode_claim_body(payload, true).ok()))
}

/// OF-153 grant-grammar lifecycle for a disclosure scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DisclosureScopeStatus {
    Active,
    Revoked,
}

impl DisclosureScopeStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// Per-contact disclosure scope: WHAT a known contact may hear about
/// (explicit entity allowlist; topics are schema-reserved, stored and
/// intersected but NOT a v1 admission path — design §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureScope {
    /// Explicit allowlist, sorted and deduped; at most
    /// [`MAX_DISCLOSURE_SCOPE_ENTITIES`].
    pub entities: Vec<EntityId>,
    /// Reserved topic tags (v1 stores + intersects; never admits).
    pub topics: Vec<String>,
    /// Human-readable task purpose from the introduction; 1..=512 bytes.
    pub purpose: String,
    pub status: DisclosureScopeStatus,
    pub created_at: u64,
    pub updated_at: u64,
}

impl DisclosureScope {
    /// The auto-scope constructor introductions call: sorts and dedupes the
    /// entity allowlist, starts Active with no topics.
    pub fn task_scoped(
        purpose: impl Into<String>,
        mut entities: Vec<EntityId>,
        created_at: u64,
    ) -> Result<Self> {
        entities.sort_unstable();
        entities.dedup();
        let scope = Self {
            entities,
            topics: Vec::new(),
            purpose: purpose.into(),
            status: DisclosureScopeStatus::Active,
            created_at,
            updated_at: created_at,
        };
        scope.validate()?;
        Ok(scope)
    }

    /// The pinned EMPTY scope — the fail-closed default an unknown party,
    /// revoked scope, or missing row contributes to the DEC-0005
    /// intersection. An all-empty struct literal is invalid by construction
    /// because `purpose` has a 1..=512-byte floor.
    #[must_use]
    pub fn deny_all(now: u64) -> Self {
        Self {
            entities: Vec::new(),
            topics: Vec::new(),
            purpose: "deny_all".to_owned(),
            status: DisclosureScopeStatus::Active,
            created_at: now,
            updated_at: now,
        }
    }

    /// Validates the pinned scope invariants.
    pub fn validate(&self) -> Result<()> {
        if self.entities.len() > MAX_DISCLOSURE_SCOPE_ENTITIES {
            return Err(Error::InvalidDisclosureScope(
                "scope entities exceed the 256-entry allowlist cap",
            ));
        }
        if !self
            .entities
            .windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
        {
            return Err(Error::InvalidDisclosureScope(
                "scope entities must be sorted and deduped",
            ));
        }
        if self.topics.len() > MAX_DISCLOSURE_SCOPE_TOPICS {
            return Err(Error::InvalidDisclosureScope(
                "scope topics exceed the 32-entry cap",
            ));
        }
        for topic in &self.topics {
            if topic.trim().is_empty()
                || topic.trim() != topic
                || topic.len() > MAX_DISCLOSURE_SCOPE_TOPIC_BYTES
            {
                return Err(Error::InvalidDisclosureScope(
                    "scope topic must be trimmed, non-empty, and at most 128 bytes",
                ));
            }
        }
        if self.purpose.trim().is_empty()
            || self.purpose.trim() != self.purpose
            || self.purpose.len() > MAX_DISCLOSURE_SCOPE_PURPOSE_BYTES
        {
            return Err(Error::InvalidDisclosureScope(
                "scope purpose must be trimmed, non-empty, and at most 512 bytes",
            ));
        }
        if self.updated_at < self.created_at {
            return Err(Error::InvalidDisclosureScope(
                "scope updated_at must not precede created_at",
            ));
        }
        Ok(())
    }

    /// DEC-0005 most-restrictive-wins intersection: entity/topic
    /// set-intersection, earliest `created_at`, latest `updated_at`,
    /// Revoked-propagating status. The empty scope is the absorbing element.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        let entities = self
            .entities
            .iter()
            .filter(|id| other.entities.binary_search(id).is_ok())
            .copied()
            .collect();
        let topics = self
            .topics
            .iter()
            .filter(|topic| other.topics.contains(topic))
            .cloned()
            .collect();
        let purpose = truncate_at_char_boundary(
            format!("{} ∩ {}", self.purpose, other.purpose),
            MAX_DISCLOSURE_SCOPE_PURPOSE_BYTES,
        );
        let status = if self.status == DisclosureScopeStatus::Active
            && other.status == DisclosureScopeStatus::Active
        {
            DisclosureScopeStatus::Active
        } else {
            DisclosureScopeStatus::Revoked
        };
        Self {
            entities,
            topics,
            purpose,
            status,
            created_at: self.created_at.min(other.created_at),
            updated_at: self.updated_at.max(other.updated_at),
        }
    }

    fn allows_entity(&self, id: &EntityId) -> bool {
        self.entities.binary_search(id).is_ok()
    }
}

fn truncate_at_char_boundary(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut cut = max_bytes;
    while cut > 0 && !value.is_char_boundary(cut) {
        cut -= 1;
    }
    value.truncate(cut);
    value
}

/// The room's facet-disclosure set (F2(d)): which facets may be the subject
/// of disclosure given who is present. A DISTINCT AXIS from
/// [`DisclosureScope`] (per-contact entity allowlist) — the two compose as
/// conjuncts inside [`DisclosureContext::admits`] and must not be merged.
///
/// Resolved security state: computed per assembly like the mode, never
/// persisted and never wire data (no `Serialize`/`Deserialize`, design §14.5
/// item 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisclosableSet {
    /// P1 identity element: the intersection over the EMPTY family of
    /// non-owner interlocutors is ALL facets. The owner alone is never locked
    /// out of their own private facets.
    All,
    /// `public ∪ (∩ clearances of all non-owner present)`; sorted and deduped.
    Facets(Vec<EntityId>),
}

impl DisclosableSet {
    /// Whether `facet` may be the subject of disclosure in this room.
    #[must_use]
    pub fn contains(&self, facet: &EntityId) -> bool {
        match self {
            Self::All => true,
            Self::Facets(facets) => facets.binary_search(facet).is_ok(),
        }
    }

    #[must_use]
    pub fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }
}

/// A facet's exposure class. The engine default for a facet with no stored
/// row is `Private` — born-private, fail-closed. Stock defaults (which facet
/// is "Base") are host configuration and are NEVER seeded by the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FacetExposure {
    Public,
    Private,
}

impl FacetExposure {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "public" => Some(Self::Public),
            "private" => Some(Self::Private),
            _ => None,
        }
    }
}

/// The stored per-facet exposure row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FacetExposureState {
    pub exposure: FacetExposure,
    pub updated_at: u64,
}

/// The stored per-contact facet clearance: which facets this contact has been
/// granted, under the OF-153 grant grammar ([`DisclosureScopeStatus`] is the
/// generic Active/Revoked lifecycle — revocation preserves the record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacetClearance {
    /// Cleared facet ids, sorted and deduped; at most
    /// [`MAX_FACET_CLEARANCE_ENTRIES`].
    pub facets: Vec<EntityId>,
    pub status: DisclosureScopeStatus,
    pub created_at: u64,
    pub updated_at: u64,
}

fn disclosure_scope_body_value(scope: &DisclosureScope) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DISCLOSURE_SCOPE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ENTITIES),
            entity_id_array_value(&scope.entities),
        ),
        (
            Value::from(KEY_TOPICS),
            Value::Array(
                scope
                    .topics
                    .iter()
                    .map(|topic| Value::from(topic.as_str()))
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_PURPOSE),
            Value::from(scope.purpose.as_str()),
        ),
        (Value::from(KEY_STATUS), Value::from(scope.status.as_str())),
        (Value::from(KEY_CREATED_AT), Value::from(scope.created_at)),
        (Value::from(KEY_UPDATED_AT), Value::from(scope.updated_at)),
    ])
}

/// Encodes a DisclosureScope body in canonical MessagePack key order.
pub fn encode_disclosure_scope_body(scope: &DisclosureScope) -> Result<Vec<u8>> {
    scope.validate()?;
    encode_body_value(
        &disclosure_scope_body_value(scope),
        "disclosure scope body MessagePack encode failed",
    )
}

/// Decodes and validates a DisclosureScope body (strict key set, no
/// duplicates, no trailing bytes).
pub fn decode_disclosure_scope_body(bytes: &[u8]) -> Result<DisclosureScope> {
    decode_disclosure_scope_value(&decode_body_value(bytes, invalid_scope)?)
}

fn decode_disclosure_scope_value(value: &Value) -> Result<DisclosureScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_scope());
    };
    validate_keys(entries, &DISCLOSURE_SCOPE_BODY_KEYS, invalid_scope)?;
    check_schema_version(entries, invalid_scope)?;

    let entities = decode_entity_id_array(
        required_value(entries, KEY_ENTITIES, invalid_scope)?,
        invalid_scope,
    )?;
    let Value::Array(raw_topics) = required_value(entries, KEY_TOPICS, invalid_scope)? else {
        return Err(invalid_scope());
    };
    let topics = raw_topics
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or_else(invalid_scope))
        .collect::<Result<Vec<_>>>()?;
    let purpose = required_value(entries, KEY_PURPOSE, invalid_scope)?
        .as_str()
        .ok_or_else(invalid_scope)?
        .to_owned();
    let status = required_value(entries, KEY_STATUS, invalid_scope)?
        .as_str()
        .and_then(DisclosureScopeStatus::parse)
        .ok_or_else(invalid_scope)?;
    let created_at = required_u64(entries, KEY_CREATED_AT, invalid_scope)?;
    let updated_at = required_u64(entries, KEY_UPDATED_AT, invalid_scope)?;

    let scope = DisclosureScope {
        entities,
        topics,
        purpose,
        status,
        created_at,
        updated_at,
    };
    scope.validate()?;
    Ok(scope)
}

/// Strict key-set check shared by every body codec in this module: exactly
/// the pinned keys, each present exactly once, no unknown keys. The caller
/// supplies its own error constructor so each family reports its own variant.
fn validate_keys(entries: &[(Value, Value)], keys: &[&str], invalid: fn() -> Error) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid());
        };
        if seen[index] {
            return Err(invalid());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn required_value<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
    invalid: fn() -> Error,
) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid)
}

fn required_u64(entries: &[(Value, Value)], key: &str, invalid: fn() -> Error) -> Result<u64> {
    required_value(entries, key, invalid)?
        .as_u64()
        .ok_or_else(invalid)
}

/// Pinned schema-version check shared by every body decoder in this module.
fn check_schema_version(entries: &[(Value, Value)], invalid: fn() -> Error) -> Result<()> {
    if required_u64(entries, KEY_SCHEMA_VERSION, invalid)? != DISCLOSURE_SCOPE_SCHEMA_VERSION {
        return Err(invalid());
    }
    Ok(())
}

/// MessagePack-encodes a body `Value`; `context` pins the family-specific
/// invariant-violation message.
fn encode_body_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(out)
}

/// Reads one MessagePack body value, rejecting undecodable bytes and
/// trailing garbage with the family's `invalid` error.
fn decode_body_value(bytes: &[u8], invalid: fn() -> Error) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid());
    }
    Ok(value)
}

fn invalid_scope() -> Error {
    Error::InvalidDisclosureScope("body failed validation")
}

fn invalid_exposure() -> Error {
    Error::InvalidFacetExposure("body failed validation")
}

fn invalid_clearance() -> Error {
    Error::InvalidFacetClearance("body failed validation")
}

/// Decodes the shared sorted-deduped hex entity-id array both the scope and
/// clearance bodies store.
fn decode_entity_id_array(value: &Value, invalid: fn() -> Error) -> Result<Vec<EntityId>> {
    let Value::Array(raw) = value else {
        return Err(invalid());
    };
    raw.iter()
        .map(|value| {
            value
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or_else(invalid)
        })
        .collect()
}

fn entity_id_array_value(ids: &[EntityId]) -> Value {
    Value::Array(ids.iter().map(|id| Value::from(id.to_hex())).collect())
}

impl FacetClearance {
    /// Constructs a clearance grant: sorts and dedupes the facet list, starts
    /// Active.
    pub fn granted(mut facets: Vec<EntityId>, created_at: u64) -> Result<Self> {
        facets.sort_unstable();
        facets.dedup();
        let clearance = Self {
            facets,
            status: DisclosureScopeStatus::Active,
            created_at,
            updated_at: created_at,
        };
        clearance.validate()?;
        Ok(clearance)
    }

    /// Validates the pinned clearance invariants.
    pub fn validate(&self) -> Result<()> {
        if self.facets.len() > MAX_FACET_CLEARANCE_ENTRIES {
            return Err(Error::InvalidFacetClearance(
                "clearance facets exceed the 256-entry cap",
            ));
        }
        if !self
            .facets
            .windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
        {
            return Err(Error::InvalidFacetClearance(
                "clearance facets must be sorted and deduped",
            ));
        }
        if self.updated_at < self.created_at {
            return Err(Error::InvalidFacetClearance(
                "clearance updated_at must not precede created_at",
            ));
        }
        Ok(())
    }

    /// The facets this clearance contributes to the room fold: an Active
    /// grant contributes its set, a Revoked one contributes nothing.
    fn granted_facets(&self) -> &[EntityId] {
        match self.status {
            DisclosureScopeStatus::Active => &self.facets,
            DisclosureScopeStatus::Revoked => &[],
        }
    }
}

fn facet_exposure_body_value(state: &FacetExposureState) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DISCLOSURE_SCOPE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_EXPOSURE),
            Value::from(state.exposure.as_str()),
        ),
        (Value::from(KEY_UPDATED_AT), Value::from(state.updated_at)),
    ])
}

/// Encodes a facet-exposure body in canonical MessagePack key order.
pub fn encode_facet_exposure_body(state: &FacetExposureState) -> Result<Vec<u8>> {
    encode_body_value(
        &facet_exposure_body_value(state),
        "facet exposure body MessagePack encode failed",
    )
}

/// Decodes and validates a facet-exposure body (strict key set, no
/// duplicates, no trailing bytes).
pub fn decode_facet_exposure_body(bytes: &[u8]) -> Result<FacetExposureState> {
    decode_facet_exposure_value(&decode_body_value(bytes, invalid_exposure)?)
}

fn decode_facet_exposure_value(value: &Value) -> Result<FacetExposureState> {
    let Value::Map(entries) = value else {
        return Err(invalid_exposure());
    };
    validate_keys(entries, &FACET_EXPOSURE_BODY_KEYS, invalid_exposure)?;
    check_schema_version(entries, invalid_exposure)?;
    let exposure = required_value(entries, KEY_EXPOSURE, invalid_exposure)?
        .as_str()
        .and_then(FacetExposure::parse)
        .ok_or_else(invalid_exposure)?;
    let updated_at = required_u64(entries, KEY_UPDATED_AT, invalid_exposure)?;
    Ok(FacetExposureState {
        exposure,
        updated_at,
    })
}

fn facet_clearance_body_value(clearance: &FacetClearance) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DISCLOSURE_SCOPE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_FACETS),
            entity_id_array_value(&clearance.facets),
        ),
        (
            Value::from(KEY_STATUS),
            Value::from(clearance.status.as_str()),
        ),
        (
            Value::from(KEY_CREATED_AT),
            Value::from(clearance.created_at),
        ),
        (
            Value::from(KEY_UPDATED_AT),
            Value::from(clearance.updated_at),
        ),
    ])
}

/// Encodes a facet-clearance body in canonical MessagePack key order.
pub fn encode_facet_clearance_body(clearance: &FacetClearance) -> Result<Vec<u8>> {
    clearance.validate()?;
    encode_body_value(
        &facet_clearance_body_value(clearance),
        "facet clearance body MessagePack encode failed",
    )
}

/// Decodes and validates a facet-clearance body (strict key set, no
/// duplicates, no trailing bytes).
pub fn decode_facet_clearance_body(bytes: &[u8]) -> Result<FacetClearance> {
    decode_facet_clearance_value(&decode_body_value(bytes, invalid_clearance)?)
}

fn decode_facet_clearance_value(value: &Value) -> Result<FacetClearance> {
    let Value::Map(entries) = value else {
        return Err(invalid_clearance());
    };
    validate_keys(entries, &FACET_CLEARANCE_BODY_KEYS, invalid_clearance)?;
    check_schema_version(entries, invalid_clearance)?;
    let facets = decode_entity_id_array(
        required_value(entries, KEY_FACETS, invalid_clearance)?,
        invalid_clearance,
    )?;
    let status = required_value(entries, KEY_STATUS, invalid_clearance)?
        .as_str()
        .and_then(DisclosureScopeStatus::parse)
        .ok_or_else(invalid_clearance)?;
    let created_at = required_u64(entries, KEY_CREATED_AT, invalid_clearance)?;
    let updated_at = required_u64(entries, KEY_UPDATED_AT, invalid_clearance)?;
    let clearance = FacetClearance {
        facets,
        status,
        created_at,
        updated_at,
    };
    clearance.validate()?;
    Ok(clearance)
}

/// Returns whether `predicate` belongs to the disclosure claim family.
#[must_use]
pub fn is_disclosure_claim_predicate(predicate: &str) -> bool {
    DISCLOSURE_CLAIM_PREDICATES.contains(&predicate)
}

/// Validates one `disclosure.*` claim body.
pub(crate) fn validate_disclosure_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "disclosure claim subject must be an entity",
        ));
    }
    match body.predicate.as_str() {
        PREDICATE_DISCLOSURE_SCOPE => decode_disclosure_scope_value(&body.value)
            .map(|_| ())
            .map_err(|_| Error::InvalidClaimBody("disclosure.scope value invalid")),
        PREDICATE_DISCLOSURE_TIER => {
            if body.value.as_str() == Some(DISCLOSURE_TIER_VALUE_TIER_A) {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "disclosure.tier value must be tier_a",
                ))
            }
        }
        PREDICATE_DISCLOSURE_TOPIC => {
            let Some(topic) = body.value.as_str() else {
                return Err(Error::InvalidClaimBody(
                    "disclosure.topic value must be a string",
                ));
            };
            if topic.trim().is_empty()
                || topic.trim() != topic
                || topic.len() > MAX_DISCLOSURE_SCOPE_TOPIC_BYTES
            {
                return Err(Error::InvalidClaimBody(
                    "disclosure.topic value must be trimmed, non-empty, and at most 128 bytes",
                ));
            }
            Ok(())
        }
        PREDICATE_DISCLOSURE_FACET_EXPOSURE => {
            if body.value.as_str().and_then(FacetExposure::parse).is_some() {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "disclosure.facet_exposure value must be public or private",
                ))
            }
        }
        PREDICATE_DISCLOSURE_CLEARANCE => decode_facet_clearance_value(&body.value)
            .map(|_| ())
            .map_err(|_| Error::InvalidClaimBody("disclosure.clearance value invalid")),
        _ => Err(Error::InvalidClaimBody(
            "unknown disclosure claim predicate",
        )),
    }
}

/// Builds a `vault_meta` row key: `<prefix><entity-id bytes>`.
fn meta_key(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + id.as_bytes().len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(id.as_bytes());
    key
}

fn disclosure_scope_meta_key(contact_id: &EntityId) -> Vec<u8> {
    meta_key(DISCLOSURE_SCOPE_KEY_PREFIX, contact_id)
}

fn facet_exposure_meta_key(facet_id: &EntityId) -> Vec<u8> {
    meta_key(FACET_EXPOSURE_KEY_PREFIX, facet_id)
}

fn facet_clearance_meta_key(contact_id: &EntityId) -> Vec<u8> {
    meta_key(FACET_CLEARANCE_KEY_PREFIX, contact_id)
}

fn disclosure_tier_a_meta_key(id: &EntityId) -> Vec<u8> {
    meta_key(DISCLOSURE_TIER_A_KEY_PREFIX, id)
}

pub(crate) fn disclosure_tier_a_marked_in(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(store
        .vault_meta
        .get(rtxn, &disclosure_tier_a_meta_key(id))?
        .is_some())
}

/// Snapshot-scoped read of a contact's clearance row. The owner-facing
/// `Vault::contact_facet_clearance` is this over a freshly-opened txn; the
/// resolver calls it on the ONE transaction the whole clamp resolves against.
fn contact_facet_clearance_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    contact_id: &EntityId,
) -> Result<Option<FacetClearance>> {
    let Some(bytes) = store
        .vault_meta
        .get(rtxn, &facet_clearance_meta_key(contact_id))?
    else {
        return Ok(None);
    };
    decode_facet_clearance_body(&bytes).map(Some)
}

/// Snapshot-scoped read of a contact's disclosure scope row. Same split as
/// [`contact_facet_clearance_in_txn`]: the presence-scope fold is a conjunct of
/// the same resolve and must see the same instant.
fn counterparty_disclosure_scope_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    contact_id: &EntityId,
) -> Result<Option<DisclosureScope>> {
    let Some(bytes) = store
        .vault_meta
        .get(rtxn, &disclosure_scope_meta_key(contact_id))?
    else {
        return Ok(None);
    };
    decode_disclosure_scope_body(&bytes).map(Some)
}

/// Deterministic claim-mirror id for a subject's disclosure claim: the CID-7
/// overwrite pattern — re-sets rewrite the SAME claim entity, so exactly one
/// owner-visible claim per (family, subject) exists and a rewrite supersedes
/// the prior value.
fn derive_disclosure_claim_id(prefix: &[u8], subject: &EntityId) -> Result<EntityId> {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(subject.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    EntityId::from_bytes(bytes)
}

fn disclosure_scope_claim_id(contact_id: &EntityId) -> Result<EntityId> {
    derive_disclosure_claim_id(b"disclosure.scope.claim.v1:", contact_id)
}

fn disclosure_tier_claim_id(id: &EntityId) -> Result<EntityId> {
    derive_disclosure_claim_id(b"disclosure.tier.claim.v1:", id)
}

fn facet_exposure_claim_id(facet_id: &EntityId) -> Result<EntityId> {
    derive_disclosure_claim_id(b"disclosure.facet_exposure.claim.v1:", facet_id)
}

fn facet_clearance_claim_id(contact_id: &EntityId) -> Result<EntityId> {
    derive_disclosure_claim_id(b"disclosure.clearance.claim.v1:", contact_id)
}

/// Reads the stored entity type for `id`, or `EntityNotFound` when no row
/// exists — the `set_counterparty_disclosure_scope` precedent, factored out
/// because three owner write ops now run the same existence+type check.
fn stored_entity_type_in_txn(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    id: &EntityId,
    expected: u8,
) -> Result<()> {
    let raw = store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != expected {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    Ok(())
}

impl Vault {
    /// Sets (or replaces — dial-not-wall) the disclosure scope for a CID-7
    /// contact record: dual-writes the `vault_meta` enforcement row and the
    /// owner-visible `disclosure.scope` claim in one wtxn. Widening is one
    /// owner call, but only through this owner-session write path (I6 — no
    /// HTTP exposure in this chain).
    pub fn set_counterparty_disclosure_scope(
        &self,
        contact_id: &EntityId,
        scope: &DisclosureScope,
    ) -> Result<()> {
        scope.validate()?;
        let data = encode_disclosure_scope_body(scope)?;
        let mut wtxn = self.store.env.write_txn()?;
        stored_entity_type_in_txn(
            &self.store,
            &wtxn,
            contact_id,
            ENTITY_TYPE_COUNTERPARTY_CONTACT,
        )?;
        self.store
            .vault_meta
            .put(&mut wtxn, &disclosure_scope_meta_key(contact_id), &data)?;
        let claim_id = disclosure_scope_claim_id(contact_id)?;
        let claim = ClaimBody::new(
            PREDICATE_DISCLOSURE_SCOPE,
            ClaimSubject::Entity(*contact_id),
            disclosure_scope_body_value(scope),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        self.put_disclosure_claim_in_txn(&mut wtxn, &claim_id, &claim, scope.updated_at)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Reads the enforcement-truth scope row for a contact. Missing row ->
    /// `Ok(None)`; a Revoked scope decodes fine — `DisclosureContext::resolve`
    /// maps it to deny-all.
    pub fn counterparty_disclosure_scope(
        &self,
        contact_id: &EntityId,
    ) -> Result<Option<DisclosureScope>> {
        let rtxn = self.store.env.read_txn()?;
        counterparty_disclosure_scope_in_txn(&self.store, &rtxn, contact_id)
    }

    /// Sets a facet's exposure class: dual-writes the `vault_meta`
    /// enforcement row and the owner-visible `disclosure.facet_exposure`
    /// claim in one wtxn.
    ///
    /// DIAL-NOT-WALL: the SAME door both widens (private -> public) and
    /// narrows (public -> private). Widening is P2 owner-gated by
    /// construction of the door — this is an owner-session Vault method with
    /// no HTTP path (I6), and the claim mirror is the ledger record.
    ///
    /// The engine seeds NOTHING: a facet with no row is private, so a fresh
    /// vault discloses no faceted material to any third party until the host
    /// writes exposure state.
    pub fn set_facet_exposure(
        &self,
        facet_id: &EntityId,
        exposure: FacetExposure,
        at: u64,
    ) -> Result<()> {
        let state = FacetExposureState {
            exposure,
            updated_at: at,
        };
        let data = encode_facet_exposure_body(&state)?;
        let mut wtxn = self.store.env.write_txn()?;
        stored_entity_type_in_txn(&self.store, &wtxn, facet_id, ENTITY_TYPE_FACET)?;
        self.store
            .vault_meta
            .put(&mut wtxn, &facet_exposure_meta_key(facet_id), &data)?;
        let claim_id = facet_exposure_claim_id(facet_id)?;
        let claim = ClaimBody::new(
            PREDICATE_DISCLOSURE_FACET_EXPOSURE,
            ClaimSubject::Entity(*facet_id),
            Value::from(exposure.as_str()),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        self.put_disclosure_claim_in_txn(&mut wtxn, &claim_id, &claim, at)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Reads a facet's stored exposure row. Missing row -> `Ok(None)`, which
    /// the resolver reads as PRIVATE. LOUD on corruption so a damaged row
    /// stays visible on the owner's consent surface.
    pub fn facet_exposure(&self, facet_id: &EntityId) -> Result<Option<FacetExposureState>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(bytes) = self
            .store
            .vault_meta
            .get(&rtxn, &facet_exposure_meta_key(facet_id))?
        else {
            return Ok(None);
        };
        decode_facet_exposure_body(&bytes).map(Some)
    }

    /// Sets (or replaces — CID-7 overwrite) a contact's facet clearance:
    /// dual-writes the `vault_meta` enforcement row and the owner-visible
    /// `disclosure.clearance` claim in one wtxn.
    ///
    /// Every cleared facet id must resolve to an existing FACET-typed entity:
    /// a dangling clearance is a caller bug and errors LOUDLY rather than
    /// silently granting nothing. Revocation is `status: Revoked` (the record
    /// is preserved — OF-153 grant grammar), narrowing and widening are both
    /// one owner call.
    pub fn set_contact_facet_clearance(
        &self,
        contact_id: &EntityId,
        clearance: &FacetClearance,
    ) -> Result<()> {
        let data = encode_facet_clearance_body(clearance)?;
        let mut wtxn = self.store.env.write_txn()?;
        stored_entity_type_in_txn(
            &self.store,
            &wtxn,
            contact_id,
            ENTITY_TYPE_COUNTERPARTY_CONTACT,
        )?;
        for facet_id in &clearance.facets {
            stored_entity_type_in_txn(&self.store, &wtxn, facet_id, ENTITY_TYPE_FACET)?;
        }
        self.store
            .vault_meta
            .put(&mut wtxn, &facet_clearance_meta_key(contact_id), &data)?;
        let claim_id = facet_clearance_claim_id(contact_id)?;
        let claim = ClaimBody::new(
            PREDICATE_DISCLOSURE_CLEARANCE,
            ClaimSubject::Entity(*contact_id),
            facet_clearance_body_value(clearance),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        self.put_disclosure_claim_in_txn(&mut wtxn, &claim_id, &claim, clearance.updated_at)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Reads a contact's stored facet clearance. Missing row -> `Ok(None)`,
    /// which the resolver reads as the EMPTY clearance. LOUD on corruption.
    pub fn contact_facet_clearance(&self, contact_id: &EntityId) -> Result<Option<FacetClearance>> {
        let rtxn = self.store.env.read_txn()?;
        contact_facet_clearance_in_txn(&self.store, &rtxn, contact_id)
    }

    /// Owner-marks an entity Tier A (design §7 rule 5): meta row plus the
    /// owner-visible `disclosure.tier` claim, one wtxn.
    pub fn set_disclosure_tier_a(&self, id: &EntityId, marked_at: u64) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_none() {
            return Err(Error::EntityNotFound);
        }
        self.store.vault_meta.put(
            &mut wtxn,
            &disclosure_tier_a_meta_key(id),
            &marked_at.to_le_bytes(),
        )?;
        let claim_id = disclosure_tier_claim_id(id)?;
        let claim = ClaimBody::new(
            PREDICATE_DISCLOSURE_TIER,
            ClaimSubject::Entity(*id),
            Value::from(DISCLOSURE_TIER_VALUE_TIER_A),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        self.put_disclosure_claim_in_txn(&mut wtxn, &claim_id, &claim, marked_at)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Clears an owner Tier-A mark: deletes the meta row and supersedes the
    /// `disclosure.tier` claim.
    ///
    /// The stored body at the derived mirror id is only superseded when it
    /// actually IS this family's `disclosure.tier` mirror. A foreign claim
    /// squatting that id (the id is a public sha256 derivation, so any
    /// caller can compute it and write there through the normal gated
    /// `put_claim` door) is left untouched rather than re-written through
    /// the engine-internal door below.
    pub fn clear_disclosure_tier_a(&self, id: &EntityId, cleared_at: u64) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_none() {
            return Err(Error::EntityNotFound);
        }
        self.store
            .vault_meta
            .delete(&mut wtxn, &disclosure_tier_a_meta_key(id))?;
        let claim_id = disclosure_tier_claim_id(id)?;
        if let Some(raw) = self.store.entities.get(&wtxn, claim_id.as_bytes())? {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type == ENTITY_TYPE_CLAIM
                && let Some(payload) = raw.get(ENTITY_METADATA_HEADER_LEN..)
                && let Ok(mut body) = decode_claim_body(payload, true)
                && body.predicate == PREDICATE_DISCLOSURE_TIER
                && body.lifecycle == ClaimLifecycleStatus::Active
            {
                body.lifecycle = ClaimLifecycleStatus::Superseded;
                body.valid_to = Some(cleared_at);
                self.put_disclosure_claim_in_txn(&mut wtxn, &claim_id, &body, cleared_at)?;
            }
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Returns whether an owner Tier-A mark row exists for `id`.
    pub fn disclosure_tier_a_marked(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        disclosure_tier_a_marked_in(&self.store, &rtxn, id)
    }

    /// Writes one disclosure claim mirror through the `apply_ops` claim
    /// door.
    ///
    /// The put uses the ENGINE-INTERNAL claim door
    /// (`allow_reserved_predicate: true`, the door the provenance unit
    /// uses): these mirrors are deterministic engine records of an action
    /// the owner just took through a dedicated owner-session Vault method
    /// (I6 — no HTTP path, no message-content path), so the first-party
    /// consent gate's criticality floor does not re-ask the owner.
    ///
    /// PREDICATE CONTAINMENT (load-bearing): the door refuses any predicate
    /// outside [`DISCLOSURE_CLAIM_PREDICATES`] before it writes. That makes
    /// the safety argument for skipping the write gate STRUCTURAL rather
    /// than a call-site convention — no body reaching this door can carry a
    /// caller-chosen predicate through the gate-exempt path. The strict
    /// pre-validation (`allow_reserved = false`) additionally rejects any
    /// reserved `edge.*` predicate, and the body passes the full
    /// disclosure-family structural validation either way.
    fn put_disclosure_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        claim_id: &EntityId,
        body: &ClaimBody,
        learned_at: u64,
    ) -> Result<()> {
        if !is_disclosure_claim_predicate(&body.predicate) {
            return Err(Error::InvalidClaimBody(
                "disclosure claim door refuses predicates outside the disclosure family",
            ));
        }
        validate_disclosure_claim_structure(body)?;
        let data = encode_claim_body(body)?;
        validate_claim_body_bytes(&data, false)?;
        let mut ops = vec![BatchOp::Put {
            id: *claim_id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        }];
        if let ClaimSubject::Entity(subject) = body.subject {
            ops.push(BatchOp::Edge {
                src: *claim_id,
                kind: EdgeKind::ClaimOf,
                tgt: subject,
                weight: CLAIM_OF_DEFAULT_WEIGHT,
                vad: Vad::NEUTRAL,
            });
        }
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(())
    }
}

/// What removing one entity's disclosure facet-state cost the graph, in the
/// shape [`crate::batch::deindex_entity`] already folds (the
/// `BlobArtifactLifecycleCleanup` precedent).
#[derive(Debug, Default)]
pub(crate) struct FacetStateCleanup {
    pub(crate) had_vector: bool,
    pub(crate) had_graph_mutation: bool,
    pub(crate) neighbors: Vec<EntityId>,
}

/// Registers the two facet-state families with ENTITY DELETION: a hard-deleted
/// entity's facet-state rows and their owner-visible claim mirrors go with it.
///
/// Without this, hard-deleting a contact left `contact.clearance.v1:<contact>`
/// and its `disclosure.clearance` mirror standing — rows naming a person who
/// no longer exists, holding the facet ids they were once cleared for. That is
/// an erasure-completeness hole (the record survives the erasure), and it is
/// also a resurrection hazard: entity ids are caller-chosen, so a later entity
/// minted at the same id would silently inherit the dead contact's clearance.
/// The facet half is symmetric — a deleted FACET's `facet.exposure.v1` row
/// would otherwise keep voting "public" in every future resolve for an id that
/// resolves to nothing.
///
/// The mirror is a CLAIM entity, so it is removed through the ordinary deindex
/// door rather than a raw row delete — it carries edges, indexes, and possibly
/// a vector, exactly like any other claim. Recursion terminates in one step:
/// a mirror is a CLAIM and matches neither branch below.
///
/// Only the families THIS lane minted are registered here. The older
/// `disclosure.scope.v1` / `disclosure.tier_a.v1` rows have the identical
/// orphan shape and are NOT swept — that is pre-existing and belongs to the
/// erasure chain that owns those families, not to a facet-state fix.
pub(crate) fn delete_facet_state_for_entity_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> Result<FacetStateCleanup> {
    let (meta_key, claim_id) = match entity_type {
        ENTITY_TYPE_COUNTERPARTY_CONTACT => {
            (facet_clearance_meta_key(id), facet_clearance_claim_id(id)?)
        }
        ENTITY_TYPE_FACET => (facet_exposure_meta_key(id), facet_exposure_claim_id(id)?),
        _ => return Ok(FacetStateCleanup::default()),
    };
    store.vault_meta.delete(wtxn, &meta_key)?;

    // Only OUR mirror is removed. The derived id is a public sha256, so a
    // foreign claim could be squatting it through the ordinary gated
    // `put_claim` door — the same custody check `clear_disclosure_tier_a`
    // makes before it rewrites a derived id.
    let Some(raw) = store.entities.get(wtxn, claim_id.as_bytes())? else {
        return Ok(FacetStateCleanup::default());
    };
    let is_our_mirror = EntityMetadataHeader::parse(&raw)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_CLAIM)
        && raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .and_then(|payload| decode_claim_body(payload, true).ok())
            .is_some_and(|body| is_disclosure_claim_predicate(&body.predicate));
    if !is_our_mirror {
        return Ok(FacetStateCleanup::default());
    }
    let (_existed, had_vector, had_graph_mutation, neighbors) =
        crate::batch::deindex_entity(store, wtxn, &claim_id)?;
    crate::ppr::invalidate_ppr_for_delete(store, wtxn, &claim_id, &neighbors)?;
    Ok(FacetStateCleanup {
        had_vector,
        had_graph_mutation,
        neighbors,
    })
}

/// Reads a facet's exposure ON THE ENFORCEMENT PATH: missing row, undecodable
/// row, or a row that says so all read PRIVATE. Born-private, fail-closed —
/// the same quiet-narrow stance [`resolve_disclosable_set`] takes, so a
/// corrupted row can never be the reason a gate opens.
pub(crate) fn facet_exposure_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    facet_id: &EntityId,
) -> Result<FacetExposure> {
    let Some(bytes) = store
        .vault_meta
        .get(txn, &facet_exposure_meta_key(facet_id))?
    else {
        return Ok(FacetExposure::Private);
    };
    Ok(decode_facet_exposure_body(&bytes).map_or(FacetExposure::Private, |state| state.exposure))
}

/// The ONE-1646 exposure-consent gate on `FacetOf` UNSTAMPING — the seam
/// `batch::validate_facet_of_edge` reserved ("gating `FacetOf` deletes on
/// exposure state lands at THIS call site once facet exposure state exists").
///
/// THE LAUNDERING PATH IT CLOSES: [`DisclosureContext::facet_conjunct_admits`]
/// reads a claim's outgoing `FacetOf` stamps and admits a claim with NO stamp
/// as the `{invariant}` (unfaceted/core) term of P7. Deletion therefore MOVES
/// A RECORD BETWEEN CLAMP CLASSES with no body edit and no consent transition:
/// stamp a claim into a private facet, delete the stamp, and the claim is
/// admitted to rooms that were never cleared for it. Set-side removal is the
/// same widening as a private→public restamp, and it takes the same door.
///
/// THE RULE: a `FacetOf` unstamp whose TARGET IS PRIVATE requires the facet to
/// have been transitioned Public through the ledgered owner door
/// (`Vault::set_facet_exposure`, which writes the `disclosure.facet_exposure`
/// claim mirror as the consent record) BEFORE the stamp comes off. A stamp to
/// a PUBLIC facet is inert in the conjunct — a public facet is a member of
/// every resolved disclosable set, so its presence never narrows and its
/// removal never widens — and is admitted unconditionally.
///
/// WHY EXPOSURE AND NOT CLEARANCE keys the gate: clearance is per-contact and
/// per-room, so no fixed clearance row is "the" consent for a delete that
/// affects every future room; exposure is the facet-global state the resolver
/// unions in for ALL rooms, so `Public` is exactly the predicate under which
/// no room's disclosable set can shrink by this deletion. The spec is silent
/// on the delete shape (it specs the write side); this is the seam contract's
/// "same transition as a private→public restamp" read literally, and it is
/// recorded here as the lane's choice.
///
/// The gate is TOTAL over the three removal paths, because all three converge
/// on removing a row that the conjunct reads:
///
/// * [`Vault::delete_edge`] — the direct convenience door;
/// * `BatchOp::DeleteEdge` — the staged-op arm;
/// * FACET-entity hard delete — the cascade in `batch::delete_related_edges`
///   tears every inbound stamp at once, so it is gated on the facet itself
///   (`source: None`) rather than per-edge.
///
/// Non-`FacetOf` kinds pass untouched, and a NON-EXISTENT stamp passes: a
/// delete that removes nothing widens nothing, so the gate never converts an
/// idempotent no-op into an error.
pub(crate) fn gate_facet_of_unstamp(
    store: &Store,
    txn: &RoTxn<'_>,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
) -> Result<()> {
    if kind != EdgeKind::FacetOf {
        return Ok(());
    }
    let key = Store::encode_edge_key(src, kind, tgt);
    if store.edges_out.get(txn, &key)?.is_none() {
        return Ok(());
    }
    if facet_exposure_in_txn(store, txn, tgt)? == FacetExposure::Public {
        return Ok(());
    }
    Err(Error::FacetUnstampWithoutConsent {
        facet: *tgt,
        stamped_by: Some(*src),
    })
}

/// The FACET-entity half of [`gate_facet_of_unstamp`]: hard-deleting a facet
/// cascades away every inbound `FacetOf` stamp at once, which unfacets every
/// stamped claim in one step — the laundering path at its widest. Gated on the
/// facet's own exposure, checked BEFORE any row is torn, so the refusal is
/// atomic with respect to the delete.
///
/// A facet carrying NO inbound stamps is deletable whatever its exposure:
/// nothing moves between clamp classes, so there is nothing to launder.
pub(crate) fn gate_facet_entity_delete(
    store: &Store,
    txn: &RoTxn<'_>,
    facet_id: &EntityId,
) -> Result<()> {
    if facet_exposure_in_txn(store, txn, facet_id)? == FacetExposure::Public {
        return Ok(());
    }
    let has_inbound_stamp = store
        .edges_in
        .prefix_iter(txn, facet_id.as_bytes())?
        .filter_map(std::result::Result::ok)
        .any(|(key, _)| key.get(ENTITY_ID_LEN) == Some(&(EdgeKind::FacetOf as u8)));
    if has_inbound_stamp {
        return Err(Error::FacetUnstampWithoutConsent {
            facet: *facet_id,
            stamped_by: None,
        });
    }
    Ok(())
}

/// F2(d) room rule — THE single resolver (P1). Computes
/// `public ∪ (∩ clearances of all non-owner present)`.
///
/// SNAPSHOT: reads run on the CALLER'S transaction, never one opened here.
/// The clearance fold and the exposure scan are two halves of one set
/// expression, and `DisclosureContext::resolve` folds presence scopes from the
/// same rows — evaluating them against different snapshots would let a
/// concurrent exposure or clearance write land BETWEEN conjuncts and produce a
/// clamp that never existed at any instant (TOCTOU). One `RoTxn` for the whole
/// resolve makes the resolved state a point-in-time fact.
///
/// CORRUPTION STANCE mirrors [`DisclosureContext::resolve`]: on the
/// enforcement path an undecodable clearance or exposure row contributes the
/// NARROWING default (empty clearance / not-public) and never aborts
/// assembly; storage I/O errors stay loud. The owner-facing Vault reads
/// (`facet_exposure` / `contact_facet_clearance`) error loudly instead, so
/// corruption stays visible on the consent surface.
fn resolve_disclosable_set(
    store: &Store,
    rtxn: &RoTxn<'_>,
    set: &InterlocutorSet,
) -> Result<DisclosableSet> {
    // P1 identity element, BEFORE any fold: the intersection over the empty
    // family of non-owner interlocutors is ALL facets. The owner alone is
    // never locked out of their own private facets, at zero reads.
    if !set.has_non_owner() {
        return Ok(DisclosableSet::All);
    }

    // Clearance fold. EVERY non-owner entry contributes a term, unidentified
    // parties included (V3: present-unidentified is an ∅-clearance MEMBER of
    // the intersection, never an absence from it). The `has_non_owner` guard
    // above guarantees at least one term, so the accumulator never starts at
    // ∅ by accident.
    let mut cleared: Option<Vec<EntityId>> = None;
    for entry in set.non_owner() {
        let entry_facets = match entry.contact_ref() {
            Some(hex) => {
                let contact_id = EntityId::from_hex(hex)?;
                match contact_facet_clearance_in_txn(store, rtxn, &contact_id) {
                    Ok(Some(clearance)) => clearance.granted_facets().to_vec(),
                    Ok(None) => Vec::new(),
                    Err(error) if error.kind() == ErrorKind::InvalidFacetClearance => Vec::new(),
                    Err(error) => return Err(error),
                }
            }
            None => Vec::new(),
        };
        cleared = Some(match cleared {
            None => entry_facets,
            Some(accumulated) => accumulated
                .into_iter()
                .filter(|id| entry_facets.binary_search(id).is_ok())
                .collect(),
        });
    }

    // Public union: one prefix scan over the exposure rows. Row count is the
    // number of facets carrying explicit exposure state — small by
    // construction. An undecodable row is skipped (= not public).
    let mut facets = cleared.unwrap_or_default();
    for row in store
        .vault_meta
        .prefix_iter(rtxn, FACET_EXPOSURE_KEY_PREFIX)?
    {
        let (key, value) = row?;
        let Some(id_bytes) = key.get(FACET_EXPOSURE_KEY_PREFIX.len()..) else {
            continue;
        };
        let Ok(id_bytes) = <[u8; ENTITY_ID_LEN]>::try_from(id_bytes) else {
            continue;
        };
        let Ok(facet_id) = EntityId::from_bytes(id_bytes) else {
            continue;
        };
        let Ok(state) = decode_facet_exposure_body(&value) else {
            continue;
        };
        if state.exposure == FacetExposure::Public {
            facets.push(facet_id);
        }
    }
    facets.sort_unstable();
    facets.dedup();
    Ok(DisclosableSet::Facets(facets))
}

/// The resolved disclosure state one context assembly is clamped against:
/// mode, interlocutor set, the (owner-absent only) DEC-0005-intersected
/// scope, and the F2(d) disclosable set. One value feeds builder, board, and
/// response so the response can never describe a different clamp than the one
/// applied (design §11 rule 6).
#[derive(Debug, Clone)]
pub struct DisclosureContext {
    mode: DisclosureMode,
    interlocutors: InterlocutorSet,
    scope: Option<DisclosureScope>,
    disclosable: DisclosableSet,
}

impl DisclosureContext {
    /// Derives the mode and, under `AbsenceClamp`, loads and intersects every
    /// non-owner interlocutor's scope. Fail-closed: an unknown party, a
    /// revoked scope, a missing row, or a row that FAILS TO DECODE
    /// contributes the EMPTY scope, so the intersection denies everything.
    /// Corruption never propagates as an error from this path (§14.5: the
    /// clamp only ever narrows — an abort here could surface partial state
    /// or be swallowed by a caller into a wider-than-intended pack); only
    /// storage I/O failures stay loud. The owner-facing read
    /// (`Vault::counterparty_disclosure_scope`) keeps erroring loudly so
    /// corruption stays visible on the consent surface.
    ///
    /// ONE SNAPSHOT FOR THE WHOLE RESOLVE. Every conjunct this builds — the
    /// per-contact presence scopes, the clearance fold, the facet-exposure
    /// scan — reads from the single `RoTxn` opened here. Opening a txn per
    /// lookup would let a concurrent exposure flip or clearance revoke land
    /// BETWEEN two conjuncts, yielding a mixed clamp that was never the vault's
    /// state at any instant: a facet could be counted public by the exposure
    /// scan while the clearance fold already reflected its revocation, or the
    /// reverse. The resolved `DisclosureContext` is the value the builder,
    /// board, and response all quote (design §11 rule 6), so it must name ONE
    /// point in time. LMDB readers are snapshot-isolated, so a writer racing
    /// this resolve is simply not visible to it — the assembly is clamped
    /// against the state that held when it began.
    pub fn resolve(vault: &Vault, set: InterlocutorSet) -> Result<Self> {
        let rtxn = vault.store.env.read_txn()?;
        let mode = DisclosureMode::from_set(&set);
        let scope = if mode == DisclosureMode::AbsenceClamp && set.has_non_owner() {
            let now = crate::unix_seconds_now();
            let mut folded: Option<DisclosureScope> = None;
            for entry in set.non_owner() {
                let entry_scope = match entry.contact_ref() {
                    Some(hex) => {
                        let contact_id = EntityId::from_hex(hex)?;
                        match counterparty_disclosure_scope_in_txn(&vault.store, &rtxn, &contact_id)
                        {
                            Ok(Some(scope)) if scope.status == DisclosureScopeStatus::Active => {
                                scope
                            }
                            Ok(_) => DisclosureScope::deny_all(now),
                            Err(error) if error.kind() == ErrorKind::InvalidDisclosureScope => {
                                DisclosureScope::deny_all(now)
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    None => DisclosureScope::deny_all(now),
                };
                folded = Some(match folded {
                    None => entry_scope,
                    Some(accumulated) => accumulated.intersect(&entry_scope),
                });
            }
            folded
        } else {
            None
        };
        let disclosable = resolve_disclosable_set(&vault.store, &rtxn, &set)?;
        drop(rtxn);
        Ok(Self {
            mode,
            interlocutors: set,
            scope,
            disclosable,
        })
    }

    #[must_use]
    pub fn mode(&self) -> DisclosureMode {
        self.mode
    }

    #[must_use]
    pub fn interlocutors(&self) -> &InterlocutorSet {
        &self.interlocutors
    }

    /// The F2(d) disclosable set this clamp resolved.
    #[must_use]
    pub fn disclosable(&self) -> &DisclosableSet {
        &self.disclosable
    }

    /// The clamp's admission predicate — THREE conjuncts, in this order:
    ///
    /// | mode / rule | outcome |
    /// |---|---|
    /// | `OwnerAlone` | admit (consistent with `DisclosableSet::All`) |
    /// | Tier A | reject (checked FIRST — never-widen, I2) |
    /// | facet conjunct fails | reject (BOTH `Supervised` and `AbsenceClamp`) |
    /// | `Supervised` | admit |
    /// | `AbsenceClamp` | presence-scope allowlist / about-subject |
    ///
    /// The facet conjunct (P7) is UNCONDITIONAL and set-valued: relevance can
    /// never bypass it, because `admits` is the only admission door at all
    /// four OF-365 enforcement points. Tier stays first so a cleared facet can
    /// never resurface Tier-A material.
    pub(crate) fn admits(
        &self,
        store: &Store,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
        entity_type: u8,
        claim_body: Option<&ClaimBody>,
    ) -> Result<bool> {
        if self.mode == DisclosureMode::OwnerAlone {
            return Ok(true);
        }
        let decoded;
        let body = if entity_type == ENTITY_TYPE_CLAIM {
            match claim_body {
                Some(body) => Some(body),
                None => {
                    decoded = read_stored_claim_body(store, rtxn, id)?;
                    decoded.as_ref()
                }
            }
        } else {
            None
        };
        if disclosure_tier(store, rtxn, id, entity_type, body)? == DisclosureTier::TierA {
            return Ok(false);
        }
        if !self.facet_conjunct_admits(store, rtxn, id, entity_type)? {
            return Ok(false);
        }
        if self.mode == DisclosureMode::Supervised {
            return Ok(true);
        }
        let Some(scope) = self.scope.as_ref() else {
            return Ok(false);
        };
        if scope.allows_entity(id) {
            return Ok(true);
        }
        if let Some(body) = body
            && let ClaimSubject::Entity(subject) = body.subject
        {
            return Ok(scope.allows_entity(&subject));
        }
        Ok(false)
    }

    /// The F2(d) facet conjunct: may this record's facet scope be the subject
    /// of disclosure in this room?
    ///
    /// * `DisclosableSet::All` — total pass (unreachable past the
    ///   `OwnerAlone` return above; kept so the conjunct is sound on its own).
    /// * a FACET entity — admitted iff the facet itself is disclosable. A
    ///   private facet's very EXISTENCE (its name, its description) is
    ///   non-disclosable, so the entity only surfaces where it is public or
    ///   cleared.
    /// * a CLAIM — its outgoing `FacetOf` stamps decide. NO stamp -> admit:
    ///   the unfaceted/core class IS the `{invariant}` term of P7's
    ///   `facet ∈ disclosable_set ∪ {invariant}`. That is sound only because
    ///   the ONE-1645 inheritance floor holds — material derived from private
    ///   provenance either carries its stamp or floors to band >= 2, which the
    ///   Tier-A conjunct above already rejected, so laundered unfaceted
    ///   material never reaches this line. One or more stamps -> admit iff
    ///   EVERY target is disclosable: a claim stamped into `{A, B}` belongs to
    ///   both masks, and admitting it to a room cleared only for `A` would
    ///   disclose `B`-linked material. Most-restrictive-of-stamps is the P3
    ///   spirit applied to the read side.
    /// * any other type -> admit. This is the v1 conjunct boundary: TURN
    ///   bodies carry a `facet_ref`, but transcript filtering is P5
    ///   barrier-event machinery (roster-widening abort/redact, per-turn stamp
    ///   filtering) and NOT this ticket. Turns and events stay governed by
    ///   Tier plus presence-scope exactly as before.
    fn facet_conjunct_admits(
        &self,
        store: &Store,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
        entity_type: u8,
    ) -> Result<bool> {
        if self.disclosable.is_all() {
            return Ok(true);
        }
        if entity_type == ENTITY_TYPE_FACET {
            return Ok(self.disclosable.contains(id));
        }
        if entity_type != ENTITY_TYPE_CLAIM {
            return Ok(true);
        }
        let mut prefix = [0_u8; ENTITY_ID_LEN + 1];
        prefix[..ENTITY_ID_LEN].copy_from_slice(id.as_bytes());
        prefix[ENTITY_ID_LEN] = EdgeKind::FacetOf as u8;
        for row in store.edges_out.prefix_iter(rtxn, prefix.as_slice())? {
            let (key, _value) = row?;
            if key.len() != EDGE_KEY_LEN {
                return Err(Error::CorruptedIndex("edge record"));
            }
            let target = EntityId::from_bytes(
                <[u8; ENTITY_ID_LEN]>::try_from(&key[ENTITY_ID_LEN + 1..])
                    .map_err(|_| Error::CorruptedIndex("edge record"))?,
            )
            .map_err(|_| Error::CorruptedIndex("edge record"))?;
            if !self.disclosable.contains(&target) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Builds the agent-visible assembly block for this clamp.
    #[must_use]
    pub fn assembly(&self, clamped_out: u64) -> DisclosureAssembly {
        DisclosureAssembly {
            mode: self.mode.as_str().to_owned(),
            notice: (self.mode == DisclosureMode::Supervised)
                .then(|| presence_discretion_notice(&self.interlocutors)),
            interlocutors: self.interlocutors.stamps(),
            clamped_out,
        }
    }

    /// The OF-369 receipt stamp for this clamp (design §10):
    /// `"mode=<mode>;interlocutors=<class>:<label>[,...]"`.
    ///
    /// AUDIT INTEGRITY: labels are caller-supplied display data, and J3
    /// pinned this stamp as the security-relevant record of the assembly.
    /// Every structural character (`%`, `=`, `;`, `,`, `:`) and every
    /// control byte in a label is percent-encoded before it enters the
    /// stamp, so no label can ambiguate the delimiter grammar or forge an
    /// entry; a parser recovers the exact label by percent-decoding. Mode
    /// and class strings are engine-fixed vocabulary and never escaped.
    #[must_use]
    pub fn receipt_stamp(&self) -> String {
        let interlocutors = self
            .interlocutors
            .entries()
            .iter()
            .map(|entry| {
                format!(
                    "{}:{}",
                    entry.class().as_str(),
                    escape_receipt_stamp_label(entry.label())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!("mode={};interlocutors={interlocutors}", self.mode.as_str())
    }
}

/// Percent-encodes the stamp's structural characters plus `%` itself and
/// control bytes, leaving every other byte verbatim. Total and reversible:
/// every label encodes safely, so stamping can never fail on a hostile
/// label — the label is display data and must not block resolution.
fn escape_receipt_stamp_label(label: &str) -> String {
    let mut escaped = String::with_capacity(label.len());
    for ch in label.chars() {
        match ch {
            '%' | '=' | ';' | ',' | ':' => {
                escaped.push('%');
                escaped.push_str(&format!("{:02X}", ch as u32));
            }
            ch if ch.is_control() => {
                for byte in ch.to_string().as_bytes() {
                    escaped.push('%');
                    escaped.push_str(&format!("{byte:02X}"));
                }
            }
            ch => escaped.push(ch),
        }
    }
    escaped
}

/// Agent-visible disclosure block riding the context-pack response and the
/// Eiri memory board. `clamped_out` counts scored candidates dropped by the
/// clamp's CANDIDATE SWEEP this assembly (the walk/edge/final enforcement
/// points drop without counting — design §9); it is diagnostic and is NOT
/// persisted on receipts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisclosureAssembly {
    pub mode: String,
    /// The presence-discretion notice; `Some` iff Supervised.
    pub notice: Option<String>,
    pub interlocutors: Vec<InterlocutorStamp>,
    pub clamped_out: u64,
}

/// The pinned named-presence discretion notice (design §10). Enumerates
/// NON-OWNER entries only, in set order — the Owner entry never appears
/// under "Others present".
#[must_use]
pub fn presence_discretion_notice(set: &InterlocutorSet) -> String {
    let others = set
        .non_owner()
        .map(|entry| {
            let mut part = format!("{} ({}", entry.label(), entry.class().as_str());
            if let Some(relationship) = entry.relationship() {
                part.push_str(", ");
                part.push_str(relationship);
            }
            if let Some(first_touch) = entry.first_touch() {
                part.push_str(", first contact: ");
                part.push_str(first_touch.as_str());
            }
            part.push(')');
            part
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "Others present: {others}. Don't volunteer personal or sensitive information; \
         if asked about private matters, defer to the owner."
    )
}

#[cfg(test)]
mod tests;
