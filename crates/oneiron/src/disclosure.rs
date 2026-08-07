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
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::interlocutor::{InterlocutorSet, InterlocutorStamp};
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CHANNEL_IDENTITY,
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_FEDERATION_GRANT,
    ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT, ENTITY_TYPE_POLICY_MANIFEST,
    ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_REDACTION_AUDIT,
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

/// Pinned `disclosure.*` claim predicates.
pub const DISCLOSURE_CLAIM_PREDICATES: [&str; 3] =
    ["disclosure.scope", "disclosure.tier", "disclosure.topic"];

pub const PREDICATE_DISCLOSURE_SCOPE: &str = "disclosure.scope";
pub const PREDICATE_DISCLOSURE_TIER: &str = "disclosure.tier";
pub const PREDICATE_DISCLOSURE_TOPIC: &str = "disclosure.topic";

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
/// live off-record overlay membership, governance type byte, sensitivity band (band 2+ or an
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
    // Rule 1 — live session-overlay membership. ONE-1731 removed the durable
    // fence half; membership in a live room is the whole rule now.
    if store.off_record_sessions.contains_entity(id)? {
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

fn disclosure_scope_body_value(scope: &DisclosureScope) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DISCLOSURE_SCOPE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ENTITIES),
            Value::Array(
                scope
                    .entities
                    .iter()
                    .map(|id| Value::from(id.to_hex()))
                    .collect(),
            ),
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
    let value = disclosure_scope_body_value(scope);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).map_err(|_| {
        Error::InvariantViolation("disclosure scope body MessagePack encode failed")
    })?;
    Ok(out)
}

/// Decodes and validates a DisclosureScope body (strict key set, no
/// duplicates, no trailing bytes).
pub fn decode_disclosure_scope_body(bytes: &[u8]) -> Result<DisclosureScope> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_scope())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_scope());
    }
    decode_disclosure_scope_value(&value)
}

fn decode_disclosure_scope_value(value: &Value) -> Result<DisclosureScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_scope());
    };
    validate_keys(entries, &DISCLOSURE_SCOPE_BODY_KEYS)?;

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64()
        != Some(DISCLOSURE_SCOPE_SCHEMA_VERSION)
    {
        return Err(invalid_scope());
    }
    let Value::Array(raw_entities) = required_value(entries, KEY_ENTITIES)? else {
        return Err(invalid_scope());
    };
    let entities = raw_entities
        .iter()
        .map(|value| {
            value
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or_else(invalid_scope)
        })
        .collect::<Result<Vec<_>>>()?;
    let Value::Array(raw_topics) = required_value(entries, KEY_TOPICS)? else {
        return Err(invalid_scope());
    };
    let topics = raw_topics
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or_else(invalid_scope))
        .collect::<Result<Vec<_>>>()?;
    let purpose = required_value(entries, KEY_PURPOSE)?
        .as_str()
        .ok_or_else(invalid_scope)?
        .to_owned();
    let status = required_value(entries, KEY_STATUS)?
        .as_str()
        .and_then(DisclosureScopeStatus::parse)
        .ok_or_else(invalid_scope)?;
    let created_at = required_value(entries, KEY_CREATED_AT)?
        .as_u64()
        .ok_or_else(invalid_scope)?;
    let updated_at = required_value(entries, KEY_UPDATED_AT)?
        .as_u64()
        .ok_or_else(invalid_scope)?;

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

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_scope)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_scope());
        };
        if seen[index] {
            return Err(invalid_scope());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_scope())
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_scope)
}

fn invalid_scope() -> Error {
    Error::InvalidDisclosureScope("body failed validation")
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
        _ => Err(Error::InvalidClaimBody(
            "unknown disclosure claim predicate",
        )),
    }
}

fn disclosure_scope_meta_key(contact_id: &EntityId) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(DISCLOSURE_SCOPE_KEY_PREFIX.len() + contact_id.as_bytes().len());
    key.extend_from_slice(DISCLOSURE_SCOPE_KEY_PREFIX);
    key.extend_from_slice(contact_id.as_bytes());
    key
}

fn disclosure_tier_a_meta_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DISCLOSURE_TIER_A_KEY_PREFIX.len() + id.as_bytes().len());
    key.extend_from_slice(DISCLOSURE_TIER_A_KEY_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
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
        let raw = self
            .store
            .entities
            .get(&wtxn, contact_id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
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
        let Some(bytes) = self
            .store
            .vault_meta
            .get(&rtxn, &disclosure_scope_meta_key(contact_id))?
        else {
            return Ok(None);
        };
        decode_disclosure_scope_body(&bytes).map(Some)
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

/// The resolved disclosure state one context assembly is clamped against:
/// mode, interlocutor set, and (owner-absent only) the DEC-0005-intersected
/// scope. One value feeds builder, board, and response so the response can
/// never describe a different clamp than the one applied (design §11 rule 6).
#[derive(Debug, Clone)]
pub struct DisclosureContext {
    mode: DisclosureMode,
    interlocutors: InterlocutorSet,
    scope: Option<DisclosureScope>,
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
    pub fn resolve(vault: &Vault, set: InterlocutorSet) -> Result<Self> {
        let mode = DisclosureMode::from_set(&set);
        let scope = if mode == DisclosureMode::AbsenceClamp && set.has_non_owner() {
            let now = crate::unix_seconds_now();
            let mut folded: Option<DisclosureScope> = None;
            for entry in set.non_owner() {
                let entry_scope = match entry.contact_ref() {
                    Some(hex) => {
                        let contact_id = EntityId::from_hex(hex)?;
                        match vault.counterparty_disclosure_scope(&contact_id) {
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
        Ok(Self {
            mode,
            interlocutors: set,
            scope,
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

    /// The clamp's admission predicate: `OwnerAlone` admits everything;
    /// `Supervised` admits everything not Tier A; `AbsenceClamp` admits only
    /// non-Tier-A entities on the intersected allowlist, or claims ABOUT an
    /// allowlisted entity. Tier is checked FIRST so scope can never override
    /// tier (never-widen, I2).
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
