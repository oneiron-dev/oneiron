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

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
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

/// Pinned on-disk MessagePack key set for reclassification-consent bodies.
pub const FACET_RECLASSIFICATION_BODY_KEYS: [&str; 5] = [
    "schema_version",
    "record",
    "facet",
    "sequence",
    "consented_at",
];

const KEY_RECORD: &str = FACET_RECLASSIFICATION_BODY_KEYS[1];
const KEY_FACET: &str = FACET_RECLASSIFICATION_BODY_KEYS[2];
const KEY_SEQUENCE: &str = FACET_RECLASSIFICATION_BODY_KEYS[3];
const KEY_CONSENTED_AT: &str = FACET_RECLASSIFICATION_BODY_KEYS[4];

/// Width of the per-pair reclassification sequence suffix, big-endian so the
/// row key order IS the event order.
const RECLASSIFICATION_SEQUENCE_LEN: usize = 8;

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
/// `vault_meta` row key prefix for the append-only reclassification LEDGER:
/// one row per `FacetOf` unstamp EVENT. Audit history, not authorization —
/// nothing reads these rows to decide whether an unstamp may proceed.
const FACET_RECLASSIFICATION_KEY_PREFIX: &[u8] = b"facet.reclassification.v1:";
/// `vault_meta` row key prefix for PENDING-UNSTAMP recovery markers: one row
/// per `(record, facet)` pair whose consent + LMDB tear have COMMITTED but
/// whose CRDT carrier removal is not yet proven durable.
///
/// The unstamp is two independent commits — the LMDB txn, then the doc
/// removal — and a crash between them left consent + the LMDB deletion
/// durable while the CRDT stamp survived. Retry was no help: the LMDB row is
/// already absent, so [`Vault::unstamp_facet_of`] answers `false` and does
/// nothing, and the next forward rematerialization walked the surviving doc
/// stamp straight back into LMDB. A CONSENTED unstamp restoring itself is the
/// worst failure direction this lane has.
///
/// So the marker is written IN THE SAME TXN as the consent event and the edge
/// deletion, and cleared only once the removal is durable in every doc that
/// can carry it. `forward_rematerialize` drains it before it can restore
/// anything ([`drain_pending_facet_unstamps`]), so the resurrection window is
/// closed by the same pass that used to open it. It is NOT authorization:
/// nothing reads it to decide whether an unstamp may proceed, and a surviving
/// marker can only cause the removal to be RE-applied.
#[cfg(feature = "sync")]
const FACET_UNSTAMP_PENDING_KEY_PREFIX: &[u8] = b"facet.unstamp_pending.v1:";

/// Pinned `disclosure.*` claim predicates.
pub const DISCLOSURE_CLAIM_PREDICATES: [&str; 6] = [
    "disclosure.scope",
    "disclosure.tier",
    "disclosure.topic",
    "disclosure.facet_exposure",
    "disclosure.clearance",
    "disclosure.facet_reclassification",
];

pub const PREDICATE_DISCLOSURE_SCOPE: &str = "disclosure.scope";
pub const PREDICATE_DISCLOSURE_TIER: &str = "disclosure.tier";
pub const PREDICATE_DISCLOSURE_TOPIC: &str = "disclosure.topic";
pub const PREDICATE_DISCLOSURE_FACET_EXPOSURE: &str = "disclosure.facet_exposure";
pub const PREDICATE_DISCLOSURE_CLEARANCE: &str = "disclosure.clearance";
pub const PREDICATE_DISCLOSURE_FACET_RECLASSIFICATION: &str = "disclosure.facet_reclassification";

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

/// One LEDGER EVENT: a `FacetOf` unstamp that [`Vault::unstamp_facet_of`]
/// performed, appended in the same commit as the removal it describes.
///
/// A LEDGER, NOT A KEY. Authorization for a disclosure-effective unstamp is
/// STRUCTURAL — the dedicated door is the only door that can remove a `FacetOf`
/// edge at all (every generic delete refuses, see [`gate_facet_of_unstamp`]),
/// and it consents and acts in one commit. This record therefore authorizes
/// NOTHING by existing; it is the owner-visible history of what was
/// reclassified and when.
///
/// WHY THE RECORD MUST NOT AUTHORIZE. Stamps are re-creatable, so anything
/// keyed to a `(record, facet)` PAIR outlives the incarnation it was minted
/// for: consent-unstamp `(C, F)`, re-stamp `C → F`, and a pair-keyed
/// authorization is still standing for a stamp the owner never consented to
/// losing. A state-shaped gate is worse still — fix-2 replaced facet exposure
/// for exactly that reason (reversible state cannot authorize an irreversible
/// act; the widen/unstamp/narrow window launders it). Both failures are the
/// same one: authorization held APART from the act can be spent on a later act.
/// Fusing them removes the class.
///
/// APPEND-ONLY, ONE ROW PER EVENT. Each unstamp appends its own row under a
/// per-pair `sequence`, so a re-stamped-then-re-unstamped pair keeps BOTH
/// events with their own timestamps rather than collapsing into one. Nothing
/// rewrites or removes a row except erasing one of the two named entities.
///
/// Each event is stored as its own `vault_meta` row plus a Tier-A
/// `disclosure.facet_reclassification` claim mirror — the owner-visible ledger
/// entry, the same dual-write every other family in this module uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FacetReclassificationConsent {
    /// The record whose stamp was removed (the claim, turn, or event).
    pub record: EntityId,
    /// The facet the stamp pointed at.
    pub facet: EntityId,
    /// When the owner performed THIS unstamp.
    pub consented_at: u64,
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

/// The consent record shares the clearance error family: both are the same
/// per-contact/per-facet grant grammar, and a third variant carrying no
/// distinct caller response would be an unused error.
fn invalid_reclassification() -> Error {
    Error::InvalidFacetClearance("reclassification consent body failed validation")
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

fn facet_reclassification_body_value(
    consent: &FacetReclassificationConsent,
    sequence: u64,
) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DISCLOSURE_SCOPE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_RECORD),
            Value::from(consent.record.to_hex()),
        ),
        (Value::from(KEY_FACET), Value::from(consent.facet.to_hex())),
        (Value::from(KEY_SEQUENCE), Value::from(sequence)),
        (
            Value::from(KEY_CONSENTED_AT),
            Value::from(consent.consented_at),
        ),
    ])
}

/// Encodes a reclassification-ledger body in canonical MessagePack key order.
/// `sequence` is the event's position in the pair's append-only ledger.
pub fn encode_facet_reclassification_body(
    consent: &FacetReclassificationConsent,
    sequence: u64,
) -> Result<Vec<u8>> {
    encode_body_value(
        &facet_reclassification_body_value(consent, sequence),
        "facet reclassification body MessagePack encode failed",
    )
}

/// Decodes and validates a reclassification-ledger body (strict key set, no
/// duplicates, no trailing bytes). Returns the event and its `sequence`.
pub fn decode_facet_reclassification_body(
    bytes: &[u8],
) -> Result<(FacetReclassificationConsent, u64)> {
    decode_facet_reclassification_value(&decode_body_value(bytes, invalid_reclassification)?)
}

fn decode_facet_reclassification_value(
    value: &Value,
) -> Result<(FacetReclassificationConsent, u64)> {
    let Value::Map(entries) = value else {
        return Err(invalid_reclassification());
    };
    validate_keys(
        entries,
        &FACET_RECLASSIFICATION_BODY_KEYS,
        invalid_reclassification,
    )?;
    check_schema_version(entries, invalid_reclassification)?;
    let record = required_entity_id(entries, KEY_RECORD, invalid_reclassification)?;
    let facet = required_entity_id(entries, KEY_FACET, invalid_reclassification)?;
    let sequence = required_u64(entries, KEY_SEQUENCE, invalid_reclassification)?;
    let consented_at = required_u64(entries, KEY_CONSENTED_AT, invalid_reclassification)?;
    Ok((
        FacetReclassificationConsent {
            record,
            facet,
            consented_at,
        },
        sequence,
    ))
}

fn required_entity_id(
    entries: &[(Value, Value)],
    key: &str,
    invalid: fn() -> Error,
) -> Result<EntityId> {
    required_value(entries, key, invalid)?
        .as_str()
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .ok_or_else(invalid)
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
        PREDICATE_DISCLOSURE_FACET_RECLASSIFICATION => {
            let (consent, _sequence) =
                decode_facet_reclassification_value(&body.value).map_err(|_| {
                    Error::InvalidClaimBody("disclosure.facet_reclassification value invalid")
                })?;
            // The mirror's SUBJECT is the reclassified record, so a body naming
            // a different record would make the ledger entry describe something
            // other than what it is filed under.
            if body.subject != ClaimSubject::Entity(consent.record) {
                return Err(Error::InvalidClaimBody(
                    "disclosure.facet_reclassification subject must be the reclassified record",
                ));
            }
            Ok(())
        }
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

/// `facet.reclassification.v1:<record><facet><sequence>` — one row per unstamp
/// EVENT, not per pair. Record first so the whole of one record's history is a
/// prefix scan (the shape erasure needs when the record itself is deleted), and
/// the big-endian sequence last so `(record, facet)` is itself a prefix and the
/// key order within it IS the event order.
fn facet_reclassification_meta_key(record: &EntityId, facet: &EntityId, sequence: u64) -> Vec<u8> {
    let mut key = facet_reclassification_pair_prefix(record, facet);
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}

/// `facet.unstamp_pending.v1:<record><facet>` — the pair-bound recovery marker
/// key. PAIR-bound, not sequence-bound: the marker names the act to finish
/// (remove this pair's CRDT carrier), and a re-stamped-then-re-unstamped pair
/// wants exactly one outstanding removal, not one per ledger event.
#[cfg(feature = "sync")]
fn facet_unstamp_pending_key(record: &EntityId, facet: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(FACET_UNSTAMP_PENDING_KEY_PREFIX.len() + ENTITY_ID_LEN * 2);
    key.extend_from_slice(FACET_UNSTAMP_PENDING_KEY_PREFIX);
    key.extend_from_slice(record.as_bytes());
    key.extend_from_slice(facet.as_bytes());
    key
}

/// Splits a pending-unstamp marker key back into its `(record, facet)` pair.
///
/// EXACT LENGTH, like [`sequence_of_reclassification_key`]: a key of any other
/// width is corruption, and reading a prefix of it would address a DIFFERENT
/// pair — i.e. remove some other record's stamp. LOUD, never a silent skip.
#[cfg(feature = "sync")]
fn facet_unstamp_pending_pair(key: &[u8]) -> Result<(EntityId, EntityId)> {
    const ERR: &str = "facet unstamp pending row key";
    let offset = FACET_UNSTAMP_PENDING_KEY_PREFIX.len();
    if key.len() != offset + ENTITY_ID_LEN * 2 {
        return Err(Error::CorruptedIndex(ERR));
    }
    let id_at = |at: usize| -> Result<EntityId> {
        key.get(at..at + ENTITY_ID_LEN)
            .and_then(|bytes| <[u8; ENTITY_ID_LEN]>::try_from(bytes).ok())
            .and_then(|bytes| EntityId::from_bytes(bytes).ok())
            .ok_or(Error::CorruptedIndex(ERR))
    };
    Ok((id_at(offset)?, id_at(offset + ENTITY_ID_LEN)?))
}

/// The `(record, facet)` prefix every event for one pair sorts under.
fn facet_reclassification_pair_prefix(record: &EntityId, facet: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        FACET_RECLASSIFICATION_KEY_PREFIX.len() + ENTITY_ID_LEN * 2 + RECLASSIFICATION_SEQUENCE_LEN,
    );
    key.extend_from_slice(FACET_RECLASSIFICATION_KEY_PREFIX);
    key.extend_from_slice(record.as_bytes());
    key.extend_from_slice(facet.as_bytes());
    key
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

/// EVENT-keyed mirror id: one ledger entry per `(record, facet, sequence)`, so
/// no reclassification's mirror ever overwrites another's — neither a different
/// facet's, nor an EARLIER unstamp of the same pair. Every component is
/// fixed-width, so the concatenation is unambiguous without a separator.
fn facet_reclassification_claim_id(
    record: &EntityId,
    facet: &EntityId,
    sequence: u64,
) -> Result<EntityId> {
    let mut hasher = Sha256::new();
    hasher.update(b"disclosure.facet_reclassification.claim.v1:");
    hasher.update(record.as_bytes());
    hasher.update(facet.as_bytes());
    hasher.update(sequence.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    EntityId::from_bytes(bytes)
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

    /// THE ONLY door that can remove a `FacetOf` stamp: it performs the removal
    /// and appends the owner's consent to that reclassification IN ONE wtxn.
    ///
    /// Removing a stamp reclassifies a SURVIVING record — at the limit into the
    /// unfaceted class the P7 conjunct admits as invariant — so it is a
    /// consent-bearing act, not a graph edit. Every generic edge-delete door
    /// refuses `FacetOf` outright ([`gate_facet_of_unstamp`]) and refers here.
    ///
    /// CONSENT-THEN-ACT IS ONE OPERATION, EVERY TIME. The consent event, its
    /// Tier-A ledger mirror, and the edge removal commit together or not at
    /// all, and each unstamp appends its OWN event. Nothing this writes is an
    /// authorization a later call can spend: the authorization is the call.
    /// That closes both laundering shapes at once — a reversible state gate
    /// (widen the facet, unstamp, narrow back) and a durable per-pair key
    /// (consent-unstamp, RE-STAMP, then let a generic delete ride the stale
    /// record into a fresh incarnation of the same stamp). Authorization held
    /// apart from the act, in any form, can be spent on a different act.
    ///
    /// THE DOC REMOVAL RIDES THE SAME ACT. Tearing only the LMDB rows left the
    /// CRDT stamp standing, and a stamp alive in the doc is not an inert
    /// leftover: restart's forward rematerialization walks the edges map and
    /// writes every surviving stamp BACK into LMDB, so an unstamp the owner
    /// consented to silently UNDID itself on the next open — and propagated
    /// the survivor to every peer. `remove_facet_of_edge_from_docs` therefore
    /// removes the `edges`-map key as part of this operation, under the
    /// internal `FACET_UNSTAMP_ORIGIN` provenance so Observer B does not
    /// re-materialize (and re-gate) the removal it just performed. Propagation
    /// is then the ordinary echo, which every peer's replicated door applies.
    ///
    /// THE TWO COMMITS ARE BRIDGED BY A RECOVERY MARKER (fix-14 defect 1). The
    /// LMDB txn and the CRDT removal cannot be one commit — Loro and LMDB are
    /// separate durability domains — so a crash lands BETWEEN them, and the
    /// state it leaves is exactly the resurrection above with no retry path:
    /// the LMDB row is already gone, so a re-issued call answers `false` and
    /// does nothing. A `facet.unstamp_pending.v1` marker is therefore written
    /// in the SAME txn as the consent event and the edge deletion, and cleared
    /// only once the doc removal is durably persisted. Recovery drains it
    /// ([`drain_pending_facet_unstamps`], called from `forward_rematerialize`
    /// BEFORE any restoration can run), so an interrupted unstamp resumes
    /// instead of reversing.
    ///
    /// Returns `false` when no such stamp existed. Nothing is written in that
    /// case — there was no reclassification, so the ledger records none.
    pub fn unstamp_facet_of(
        &self,
        record: &EntityId,
        facet_id: &EntityId,
        consented_at: u64,
    ) -> Result<bool> {
        let key_out = Store::encode_edge_key(record, EdgeKind::FacetOf, facet_id);
        let key_in = Store::encode_edge_key(facet_id, EdgeKind::FacetOf, record);
        let unstamped = self.with_write_txn(|wtxn| {
            if self.store.edges_out.get(&*wtxn, &key_out)?.is_none() {
                return Ok(false);
            }
            append_facet_reclassification_event_in_txn(self, wtxn, record, facet_id, consented_at)?;
            self.store.edges_out.delete(wtxn, &key_out)?;
            self.store.edges_in.delete(wtxn, &key_in)?;
            #[cfg(feature = "sync")]
            self.store
                .vault_meta
                .put(wtxn, &facet_unstamp_pending_key(record, facet_id), &[])?;
            crate::ppr::invalidate_ppr_for_edge(&self.store, wtxn, record, facet_id)?;
            crate::ppr::increment_graph_version(&self.store, wtxn)?;
            Ok(true)
        })?;
        if unstamped {
            #[cfg(all(test, feature = "sync"))]
            if take_injected_unstamp_doc_removal_skip() {
                // Models the CRASH: the txn above is durable (consent, torn
                // rows, pending marker) and the process dies before the doc
                // removal. Recovery must finish it, not reverse it.
                return Ok(true);
            }
            self.remove_facet_of_edge_from_docs(record, facet_id)?;
        }
        Ok(unstamped)
    }

    /// Removes the `record -FacetOf-> facet` key from every window doc that
    /// can carry it, so a consented unstamp does not survive in the CRDT and
    /// get re-materialized by restart recovery.
    ///
    /// THE SOURCE WINDOW IS COMPUTED FIRST AND ALWAYS HANDLED (fix-14 defect
    /// 2). The CRDT edge key lives in the SOURCE entity's `learned_at` month —
    /// that is where reverse remat packs it — so that window is the one
    /// carrier that MUST be reached. The earlier shape asked the live windows
    /// first and returned as soon as ANY of them held a matching key, which is
    /// wrong twice over: a duplicate key in some other open month satisfied
    /// the check while the cold source window kept its stamp, and a source
    /// window with no `d:w:` snapshot answered `WindowNotFound` and was read as
    /// "no carrier" even though its `u:w:` rows carried the stamp in plain
    /// sight. Either way a surviving stamp forward-remats straight back into
    /// LMDB. So: every live window is swept unconditionally (duplicates in
    /// other months are real carriers too and must go), and the source window
    /// is reached transiently unless a LIVE doc for THAT EXACT KEY already
    /// handled it. A snapshotless source window is REBUILT from its pending
    /// updates rather than skipped, and the removal is persisted — this never
    /// returns success having removed nothing.
    ///
    /// A `learned_at` we cannot read (headerless residue) addresses no window,
    /// and a source window with neither a snapshot nor pending rows has no
    /// carrier to remove: both are `Ok(())` after the live sweep, not errors.
    ///
    /// Commits carry `FACET_UNSTAMP_ORIGIN`, which Observer B skips — the LMDB
    /// rows are already gone in the same act, so a re-materialization would be
    /// a redundant second tear (the `DELETION_TOMBSTONE_ORIGIN` precedent).
    /// Observer A is NOT suppressed: this removal MUST become a `u:w:` row and
    /// an outbound update, or it would never reach the other devices.
    ///
    /// The pending-unstamp marker is cleared LAST, in its own txn, once every
    /// carrier above is durable — a failure anywhere leaves it set and the
    /// next recovery drain finishes the job (fix-14 defect 1).
    #[cfg(feature = "sync")]
    fn remove_facet_of_edge_from_docs(&self, record: &EntityId, facet_id: &EntityId) -> Result<()> {
        use crate::sync::bridge::format_edge_key;

        let edge_key = format_edge_key(record, EdgeKind::FacetOf, facet_id);
        let source_window = match self.get_learned_at(record) {
            Ok(learned_at) => Some(crate::sync::WindowKey::from_timestamp(learned_at)),
            Err(crate::Error::EntityNotFound) => None,
            Err(err) => return Err(err),
        };

        // Live sweep: EVERY open month, not just the first match. A duplicate
        // key in another month is its own carrier, and leaving it standing
        // resurrects the stamp on that window's next forward remat.
        let mut source_handled_live = false;
        for window in self.live_windows() {
            if !remove_edge_key_from_doc(&window.doc, &edge_key)? {
                continue;
            }
            source_handled_live |= source_window.as_ref() == Some(&window.key);
        }

        if let Some(window_key) = source_window
            && !source_handled_live
        {
            self.remove_facet_of_edge_from_closed_window(&window_key, &edge_key)?;
        }

        self.with_write_txn(|wtxn| {
            self.store
                .vault_meta
                .delete(wtxn, &facet_unstamp_pending_key(record, facet_id))?;
            Ok(())
        })?;
        Ok(())
    }

    /// The source window's carrier when no LIVE doc for that window handled it:
    /// load it transiently, remove the key, and persist the result.
    ///
    /// `WindowNotFound` (no `d:w:` snapshot) is NOT "no carrier" — a window
    /// carries pending `u:w:` rows with no snapshot whenever updates persisted
    /// before it was ever unloaded, which is precisely why production's own
    /// open path and the `rm:` drain both have a rebuild fallback. Rebuilding
    /// from those rows is the same fallback, so a stamp living only in the
    /// pending family is removed instead of silently surviving.
    #[cfg(feature = "sync")]
    fn remove_facet_of_edge_from_closed_window(
        &self,
        window_key: &crate::sync::WindowKey,
        edge_key: &str,
    ) -> Result<()> {
        use crate::sync::window::{load_window_from_state, rebuild_window_from_updates};

        let doc = match load_window_from_state(self, "local", window_key) {
            Ok(doc) => doc,
            Err(crate::Error::WindowNotFound { .. }) => {
                rebuild_window_from_updates(self, "local", window_key)?
            }
            Err(err) => return Err(err),
        };
        if !remove_edge_key_from_doc(&doc, edge_key)? {
            return Ok(());
        }
        // Transient doc — no observers, so the durable record is written here.
        // The snapshot subsumes the `u:w:` rows the load/rebuild just merged,
        // so those rows are deliberately left in place (re-importing a
        // subsumed add-op into a doc that already holds the later removal is a
        // VV-dominated no-op) and `svf:` is recomputed LAST from the surviving
        // set (ONE-1151) — it reads STALE, which makes the fast-reconnect
        // reader full-open rather than trust a partial VV. Propagation for a
        // CLOSED month is the ordinary next-open VV exchange, whose delta now
        // carries the removal.
        let snapshot =
            crate::sync::window::export_scrubbed_window_snapshot(self, window_key, &doc)?;
        let vv = crate::sync::loro_support::doc_version_vector(&doc);
        self.with_write_txn(|wtxn| {
            crate::sync::window::persist_window_doc_in_txn(self, wtxn, window_key, &snapshot, &vv)?;
            crate::sync::window::write_window_svf_in_txn(self, wtxn, window_key)
        })
    }

    #[cfg(not(feature = "sync"))]
    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    fn remove_facet_of_edge_from_docs(
        &self,
        _record: &EntityId,
        _facet_id: &EntityId,
    ) -> Result<()> {
        // No CRDT in this build: the LMDB tear IS the whole act, and a
        // sync-enabled boot rebuilds the doc from LMDB (reverse remat), which
        // inserts MISSING records only — it never re-adds a row that is gone.
        Ok(())
    }

    /// Reads the append-only reclassification LEDGER for one `(record, facet)`
    /// pair, oldest event first. Empty when the pair was never unstamped.
    ///
    /// This is audit history, not a capability: nothing in the engine consults
    /// it to decide whether an unstamp may proceed. LOUD on corruption, like
    /// every other owner-facing read in this module.
    ///
    /// BODY-TO-KEY BINDING (fix-6 item 5). The row KEY is the authority on
    /// which `(record, facet, sequence)` an event belongs to — it is what the
    /// prefix scan selected on and what
    /// [`next_facet_reclassification_sequence_in_txn`] derives from. The body
    /// repeats all three, so a body disagreeing with its key is a corrupt row,
    /// and returning it anyway would MIS-ATTRIBUTE one pair's consent to
    /// another: an owner auditing "what did I consent to reclassify for facet
    /// F" would be shown an event that names a different facet. This is
    /// exactly the class of silent substitution an audit trail cannot have, so
    /// it ERRORS ([`Error::CorruptedIndex`]) rather than skipping — consistent
    /// with the LOUD stance every owner-facing read in this module takes, and
    /// with the undecodable-body case one line below, which already errors. A
    /// silent skip would let a damaged ledger read as a SHORTER, plausible
    /// history, which is the more dangerous failure of the two.
    pub fn facet_reclassification_ledger(
        &self,
        record: &EntityId,
        facet_id: &EntityId,
    ) -> Result<Vec<FacetReclassificationConsent>> {
        let rtxn = self.store.env.read_txn()?;
        let mut events = Vec::new();
        for row in self
            .store
            .vault_meta
            .prefix_iter(&rtxn, &facet_reclassification_pair_prefix(record, facet_id))?
        {
            let (key, value) = row?;
            let (consent, sequence) = decode_facet_reclassification_body(&value)?;
            if consent.record != record_of_reclassification_key(&key)?
                || consent.facet != facet_of_reclassification_key(&key)?
                || sequence != sequence_of_reclassification_key(&key)?
            {
                return Err(Error::CorruptedIndex(
                    "facet reclassification body disagrees with its row key",
                ));
            }
            events.push(consent);
        }
        Ok(events)
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
    /// caller-chosen predicate through the gate-exempt path. The allow-list is
    /// STRICTLY NARROWER than the reserved-namespace check it stands in front
    /// of: every `edge.*` / `skill.*` predicate, and every unlisted
    /// `disclosure.*` one, is already gone before the body is encoded.
    ///
    /// THIS IS THE ONLY WRITER OF THE `disclosure.*` NAMESPACE (fix-6 item 3).
    /// The namespace is D17-reserved alongside `edge.*` and `skill.*`, so the
    /// public `put_claim` / `put_entity` doors reject these predicates with
    /// [`Error::ReservedPredicate`] and the mirrors cannot be forged at their
    /// (publicly derivable) ids. The reserved door is therefore opened on BOTH
    /// validation legs here — the pre-validation and the `apply_ops` write —
    /// because the family allow-list above, not the namespace check, is what
    /// bounds what this door may author.
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
        require_mirror_write_custody(&self.store, wtxn, claim_id, body)?;
        let data = encode_claim_body(body)?;
        validate_claim_body_bytes(&data, true)?;
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

// Test-only CRASH injection for the fix-14 defect-1 recovery regressions:
// when armed, `unstamp_facet_of` returns after its LMDB txn commits and
// BEFORE the doc removal — the exact durable state a crash between the two
// commits leaves (consent + torn rows + pending marker on disk, CRDT stamp
// alive). One-shot, thread-local.
#[cfg(all(test, feature = "sync"))]
thread_local! {
    pub(crate) static INJECT_UNSTAMP_DOC_REMOVAL_SKIP: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(all(test, feature = "sync"))]
fn take_injected_unstamp_doc_removal_skip() -> bool {
    INJECT_UNSTAMP_DOC_REMOVAL_SKIP.with(|cell| cell.replace(false))
}

/// Re-arms a discharged pending-unstamp marker: the durable signature of "the
/// doc removal landed, the marker clear did not". Test-only.
#[cfg(all(test, feature = "sync"))]
pub(crate) fn rearm_pending_unstamp(
    vault: &Vault,
    record: &EntityId,
    facet: &EntityId,
) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, &facet_unstamp_pending_key(record, facet), &[])?;
        Ok(())
    })
}

/// How many pending-unstamp markers are outstanding. Test-only.
#[cfg(all(test, feature = "sync"))]
pub(crate) fn pending_unstamp_count(vault: &Vault) -> Result<usize> {
    let rtxn = vault.store.env.read_txn()?;
    let mut count = 0;
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, FACET_UNSTAMP_PENDING_KEY_PREFIX)?
    {
        row?;
        count += 1;
    }
    Ok(count)
}

/// Removes one `edges`-map key from `doc` under the unstamp origin, returning
/// whether a carrier was actually there. The ONE place the removal commit is
/// authored, so the live and closed-window arms can never drift on origin.
///
/// `FACET_UNSTAMP_ORIGIN` makes Observer B skip the commit (the LMDB rows are
/// already gone in the same act — the `DELETION_TOMBSTONE_ORIGIN` precedent);
/// Observer A is deliberately NOT suppressed, so on a live doc the removal
/// becomes a `u:w:` carrier row and an outbound update. That IS the
/// propagation.
#[cfg(feature = "sync")]
fn remove_edge_key_from_doc(doc: &loro::LoroDoc, edge_key: &str) -> Result<bool> {
    use crate::sync::bridge::FACET_UNSTAMP_ORIGIN;
    use crate::sync::loro_support::{map_contains_key, map_delete};
    use loro::CommitOptions;

    let edges = doc.get_map("edges");
    if !map_contains_key(&edges, edge_key) {
        return Ok(false);
    }
    map_delete(&edges, edge_key)?;
    doc.commit_with(CommitOptions::new().origin(FACET_UNSTAMP_ORIGIN));
    Ok(true)
}

/// Finishes every unstamp whose consent + LMDB tear committed but whose CRDT
/// removal was not proven durable — the recovery half of fix-14 defect 1.
///
/// Called from `window::forward_rematerialize` BEFORE its entity/edge passes,
/// because that pass is exactly what turns a surviving doc stamp back into an
/// LMDB row. Draining first means an interrupted unstamp RESUMES instead of
/// reversing. (Reverse remat needs no such guard: it mirrors MISSING records
/// only, and the LMDB row the crash left behind is already absent.)
///
/// Each marked pair gets three passes, and the marker clears only after all
/// three:
///
/// * the DOC IN HAND is scrubbed — it is the one this pass is about to walk,
///   so a stamp left in it is the resurrection itself;
/// * `window_key`'s DURABLE state is scrubbed through the transient path, so
///   the doc-in-hand scrub does not depend on this open reaching an unload;
/// * the SOURCE window is scrubbed the same way, because that is where the
///   CRDT key lives by construction and it need not be the window being
///   opened. Deduped when they coincide.
///
/// Deliberately NOT [`Vault::remove_facet_of_edge_from_docs`], even though
/// that is the live path's sweep: it enumerates LIVE windows through the
/// window manager, and this runs inside `open_window`, which holds the
/// (non-reentrant) registry lock — and the doc being recovered is not
/// registered yet anyway. Every window drains on its own open, which is what
/// covers a duplicate carrier in some third month.
///
/// Idempotent: removing an absent key is a no-op, so a marker whose removal
/// already landed just discharges. A malformed marker key is LOUD
/// (`CorruptedIndex`) rather than skipped — a key we cannot parse names an
/// unstamp we cannot finish, and continuing past it would let the very
/// resurrection this drain exists to stop proceed silently.
#[cfg(feature = "sync")]
pub(crate) fn drain_pending_facet_unstamps(
    vault: &Vault,
    doc: &loro::LoroDoc,
    window_key: &crate::sync::WindowKey,
) -> Result<u32> {
    let mut pairs: Vec<(EntityId, EntityId)> = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for row in vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, FACET_UNSTAMP_PENDING_KEY_PREFIX)?
        {
            let (key, _value) = row?;
            pairs.push(facet_unstamp_pending_pair(&key)?);
        }
    }
    let mut drained = 0u32;
    for (record, facet) in pairs {
        let edge_key = crate::sync::bridge::format_edge_key(&record, EdgeKind::FacetOf, &facet);
        remove_edge_key_from_doc(doc, &edge_key)?;
        let source_window = match vault.get_learned_at(&record) {
            Ok(learned_at) => Some(crate::sync::WindowKey::from_timestamp(learned_at)),
            // A headerless record addresses no window of its own; the two
            // scrubs above still stand.
            Err(crate::Error::EntityNotFound) => None,
            Err(err) => return Err(err),
        };
        vault.remove_facet_of_edge_from_closed_window(window_key, &edge_key)?;
        if let Some(source) = source_window.filter(|source| source != window_key) {
            vault.remove_facet_of_edge_from_closed_window(&source, &edge_key)?;
        }
        // Cleared LAST and only once every carrier above is durably gone: a
        // failure anywhere leaves the marker set for the next open.
        vault.with_write_txn(|wtxn| {
            vault
                .store
                .vault_meta
                .delete(wtxn, &facet_unstamp_pending_key(&record, &facet))?;
            Ok(())
        })?;
        drained = drained.saturating_add(1);
    }
    Ok(drained)
}

/// Appends ONE reclassification event plus its Tier-A ledger mirror on the
/// CALLER'S transaction, so it commits with the unstamp it describes.
///
/// APPEND-ONLY, NEVER COLLAPSING. The event lands at the pair's next free
/// `sequence`, so a re-stamped-then-re-unstamped pair keeps both events with
/// their own timestamps. No existing row is read for permission and none is
/// rewritten: the sequence is derived from the last key under the pair prefix
/// purely so the new row does not overwrite the previous one.
fn append_facet_reclassification_event_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &EntityId,
    facet_id: &EntityId,
    consented_at: u64,
) -> Result<()> {
    let sequence =
        next_facet_reclassification_sequence_in_txn(&vault.store, wtxn, record, facet_id)?;
    let consent = FacetReclassificationConsent {
        record: *record,
        facet: *facet_id,
        consented_at,
    };
    let data = encode_facet_reclassification_body(&consent, sequence)?;
    let key = facet_reclassification_meta_key(record, facet_id, sequence);
    vault.store.vault_meta.put(wtxn, &key, &data)?;
    let claim_id = facet_reclassification_claim_id(record, facet_id, sequence)?;
    let claim = ClaimBody::new(
        PREDICATE_DISCLOSURE_FACET_RECLASSIFICATION,
        ClaimSubject::Entity(*record),
        facet_reclassification_body_value(&consent, sequence),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_disclosure_claim_in_txn(wtxn, &claim_id, &claim, consented_at)
}

/// The next free `sequence` for a pair: one past the highest existing one.
///
/// Derived from the ROW KEY, never from a body — the big-endian suffix makes
/// the last row under the pair prefix the highest sequence, so a corrupt body
/// cannot make a new event land on top of an old row. An unreadable key length
/// is `CorruptedIndex`, matching every other key parse in this module.
fn next_facet_reclassification_sequence_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    record: &EntityId,
    facet_id: &EntityId,
) -> Result<u64> {
    let prefix = facet_reclassification_pair_prefix(record, facet_id);
    let mut next = 0_u64;
    for row in store.vault_meta.prefix_iter(txn, &prefix)? {
        let (key, _value) = row?;
        next = sequence_of_reclassification_key(&key)?
            .saturating_add(1)
            .max(next);
    }
    Ok(next)
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
/// a vector, exactly like any other claim. That re-entry is bounded by the
/// worklist [`delete_disclosure_mirror_in_txn`] owns, not by the stack.
///
/// Only the families THIS lane minted are registered here. The older
/// `disclosure.scope.v1` / `disclosure.tier_a.v1` rows have the identical
/// orphan shape and are NOT swept — that is pre-existing and belongs to the
/// erasure chain that owns those families, not to a facet-state fix.
///
/// TYPE-OPTIONAL, and the `None` case is REAL (fix-10 item 3). `deindex_entity`
/// returns early for a HEADERLESS id — no entity row, so no type byte — and
/// used to skip this sweep entirely on that path. Facet state is keyed by ID
/// ALONE, so it outlives a headerless delete: a `facet.exposure.v1` row keeps
/// voting "public" in every future resolve for an id whose entity row is gone,
/// and a `contact.clearance.v1` row keeps naming facet ids for a contact that
/// no longer exists. Both are the residue this function exists to prevent,
/// reached by deleting the one thing whose type nobody can vouch for — the
/// same headerless hole [`gate_hard_delete_facet_state_for_stored_type`] closed
/// on the GATE side, closed here on the CLEANUP side.
///
/// With no type to dispatch on, BOTH families are swept: every derived key and
/// mirror id is a pure function of the id, and each tear is already custody-
/// checked (the meta row is family-prefixed; the mirror must decode as the
/// expected family and name this id back). So sweeping the family a headerless
/// id never belonged to removes nothing — there is no row at that key — and
/// the cost is two `vault_meta` point lookups plus, for a genuinely absent
/// mirror, one `entities` miss.
pub(crate) fn delete_facet_state_for_entity_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: Option<u8>,
) -> Result<FacetStateCleanup> {
    let mut cleanup = delete_facet_reclassification_consents_in_txn(store, wtxn, id, entity_type)?;
    if matches!(entity_type, None | Some(ENTITY_TYPE_COUNTERPARTY_CONTACT)) {
        sweep_facet_state_family_in_txn(
            store,
            wtxn,
            &facet_clearance_meta_key(id),
            &facet_clearance_claim_id(id)?,
            DisclosureMirrorIdentity::Clearance { contact: *id },
            &mut cleanup,
        )?;
    }
    if matches!(entity_type, None | Some(ENTITY_TYPE_FACET)) {
        sweep_facet_state_family_in_txn(
            store,
            wtxn,
            &facet_exposure_meta_key(id),
            &facet_exposure_claim_id(id)?,
            DisclosureMirrorIdentity::FacetExposure { facet: *id },
            &mut cleanup,
        )?;
    }
    Ok(cleanup)
}

/// One facet-state family's tear: the `vault_meta` enforcement row, then its
/// claim mirror through the custody-checked door. Deleting an absent row is a
/// no-op, which is what makes the headerless both-families sweep above safe.
fn sweep_facet_state_family_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    meta_key: &[u8],
    claim_id: &EntityId,
    identity: DisclosureMirrorIdentity,
    cleanup: &mut FacetStateCleanup,
) -> Result<()> {
    store.vault_meta.delete(wtxn, meta_key)?;
    delete_disclosure_mirror_in_txn(store, wtxn, claim_id, identity, cleanup)
}

/// WHICH mirror a derived id is supposed to hold — the expectation
/// [`delete_disclosure_mirror_in_txn`] checks the stored body against before it
/// tears anything.
///
/// Every variant carries the SUBJECT the caller derived the id from, so the
/// check is a round-trip: the id was computed from these fields, and the body
/// must name them back. The reclassification variant additionally pins the
/// `(record, facet, sequence)` triple its VALUE carries, which is the only part
/// of a ledger mirror that distinguishes one event of a pair from another.
#[derive(Debug, Clone, Copy)]
enum DisclosureMirrorIdentity {
    FacetExposure {
        facet: EntityId,
    },
    Clearance {
        contact: EntityId,
    },
    Reclassification {
        record: EntityId,
        facet: EntityId,
        sequence: u64,
    },
}

impl DisclosureMirrorIdentity {
    /// The predicate this mirror family writes, for the refusal log line.
    fn predicate(self) -> &'static str {
        match self {
            Self::FacetExposure { .. } => PREDICATE_DISCLOSURE_FACET_EXPOSURE,
            Self::Clearance { .. } => PREDICATE_DISCLOSURE_CLEARANCE,
            Self::Reclassification { .. } => PREDICATE_DISCLOSURE_FACET_RECLASSIFICATION,
        }
    }

    fn matches(self, body: &ClaimBody) -> bool {
        if body.predicate != self.predicate() {
            return false;
        }
        match self {
            Self::FacetExposure { facet } => body.subject == ClaimSubject::Entity(facet),
            Self::Clearance { contact } => body.subject == ClaimSubject::Entity(contact),
            Self::Reclassification {
                record,
                facet,
                sequence,
            } => {
                body.subject == ClaimSubject::Entity(record)
                    && decode_facet_reclassification_value(&body.value).is_ok_and(
                        |(consent, stored_sequence)| {
                            consent.record == record
                                && consent.facet == facet
                                && stored_sequence == sequence
                        },
                    )
            }
        }
    }
}

/// CUSTODY CHECK, WRITE SIDE (fix-10 item 2) — is the row this Put is about to
/// OVERWRITE actually this family's mirror?
///
/// Same rule as the cleanup-side check one function down, at the other end of
/// the same hazard. Mirror ids are public sha256 derivations, so a foreign
/// CLAIM can already be sitting at the derived id when a set/clear runs. The
/// write side had NO precheck: it overwrote whatever was there. That is the
/// harm the cleanup side already refuses in reverse — an unrelated record
/// destroyed as a side effect of a disclosure op the owner did not frame as
/// touching it — except overwriting is worse than tearing, because it leaves a
/// plausible disclosure record standing where another family's record used to
/// be, and the tear at least leaves the id EMPTY and re-derivable.
///
/// An ABSENT row is the ordinary first write and passes. A row that decodes as
/// THIS family's mirror for THIS subject is the ordinary re-set (the CID-7
/// overwrite pattern) and passes. Anything else REFUSES, loudly and typed: the
/// mirror is the owner's consent surface, so silently writing it over a
/// foreign record would corrupt the surface the owner audits.
///
/// REFUSE, where the cleanup side LEAVES-AND-LOGS — the asymmetry is
/// deliberate, and it is the same reasoning inverted. The cleanup side is
/// establishing erasure completeness, so refusing there would let a squatter
/// wall off an erasure (the worse harm, so it proceeds and logs). Here the
/// caller is establishing a CONSENT RECORD; proceeding over a foreign row
/// destroys data to publish a record the owner cannot trust, and refusing
/// costs the owner nothing but a typed error naming the collision. Fail
/// closed.
fn require_mirror_write_custody(
    store: &Store,
    txn: &RoTxn<'_>,
    claim_id: &EntityId,
    body: &ClaimBody,
) -> Result<()> {
    let Some(raw) = store.entities.get(txn, claim_id.as_bytes())? else {
        return Ok(());
    };
    let stored = EntityMetadataHeader::parse(&raw)
        .filter(|header| header.entity_type == ENTITY_TYPE_CLAIM)
        .and_then(|_| raw.get(ENTITY_METADATA_HEADER_LEN..))
        .and_then(|payload| decode_claim_body(payload, true).ok());
    // The expectation is the INCOMING body's own family and subject: the
    // caller derived this id from them, so the row already there must name
    // them back. A stored ledger row additionally has to be the same EVENT —
    // `(record, facet, sequence)` — which `matches` pins for that variant.
    let entitled = stored.is_some_and(|stored| {
        stored.predicate == body.predicate
            && stored.subject == body.subject
            && (stored.predicate != PREDICATE_DISCLOSURE_FACET_RECLASSIFICATION
                || decode_facet_reclassification_value(&stored.value).ok()
                    == decode_facet_reclassification_value(&body.value).ok())
    });
    if entitled {
        return Ok(());
    }
    tracing::warn!(
        mirror = %claim_id.to_hex(),
        predicate = %body.predicate,
        "disclosure mirror write refused: a foreign claim occupies the derived id"
    );
    Err(Error::InvalidClaimBody(
        "disclosure mirror id is occupied by a foreign claim",
    ))
}

/// CUSTODY CHECK (fix-6 item 2) — is the claim stored at `claim_id` actually
/// the mirror this cleanup is entitled to remove?
///
/// Mirror ids are PUBLIC sha256 derivations over ids the caller already knows,
/// so any party who can write a CLAIM can compute one. "It is a CLAIM and its
/// predicate is somewhere in the disclosure family" was not custody: it
/// admitted every OTHER disclosure record too, so deleting contact C could
/// deindex the ledger mirror of an unrelated reclassification that happened to
/// sit at C's clearance-mirror id. This checks the id's own round trip instead
/// — the exact predicate the derivation belongs to, and the subject (plus, for
/// ledger rows, the `(record, facet, sequence)` triple) the id was derived
/// from.
///
/// A mismatch LEAVES the row and logs. Refusing the whole delete would let a
/// foreign write at a derived id wall off an unrelated erasure — the reverse
/// harm, and a strictly worse one, since erasure completeness is the property
/// the caller is trying to establish. Leaving is also what
/// [`Vault::clear_disclosure_tier_a`] already does at the same hazard.
fn disclosure_mirror_matches(
    store: &Store,
    txn: &RoTxn<'_>,
    claim_id: &EntityId,
    identity: DisclosureMirrorIdentity,
) -> Result<bool> {
    let Some(raw) = store.entities.get(txn, claim_id.as_bytes())? else {
        return Ok(false);
    };
    let stored = EntityMetadataHeader::parse(&raw)
        .filter(|header| header.entity_type == ENTITY_TYPE_CLAIM)
        .and_then(|_| raw.get(ENTITY_METADATA_HEADER_LEN..))
        .and_then(|payload| decode_claim_body(payload, true).ok());
    if stored.is_some_and(|body| identity.matches(&body)) {
        return Ok(true);
    }
    tracing::warn!(
        mirror = %claim_id.to_hex(),
        expected_predicate = identity.predicate(),
        "disclosure mirror cleanup left a foreign claim at a derived id untouched"
    );
    Ok(false)
}

// The mirror-cleanup WORKLIST for the current thread (fix-6 item 4).
//
// LMDB gives one writer per environment and a write txn is neither `Send` nor
// `Sync`, so a run is exactly scoped to the transaction that opened it and a
// thread-local is the right home for it.
thread_local! {
    static MIRROR_CLEANUP_RUN: RefCell<Option<MirrorCleanupRun>> = const { RefCell::new(None) };
}

#[derive(Default)]
struct MirrorCleanupRun {
    /// Every mirror already claimed by this run. Makes a CYCLE terminate: a
    /// mirror reachable from its own cleanup is skipped rather than re-torn.
    visited: HashSet<EntityId>,
    /// Mirrors discovered by a nested frame, waiting for the outermost frame
    /// to tear them. This is what keeps the traversal off the stack.
    queue: VecDeque<EntityId>,
}

/// Opens a run when none is active. `Some` means THIS frame owns the drain;
/// `None` means an ancestor frame does and this one must only enqueue.
fn begin_mirror_cleanup_run() -> Option<MirrorCleanupRunGuard> {
    MIRROR_CLEANUP_RUN.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_some() {
            return None;
        }
        *slot = Some(MirrorCleanupRun::default());
        Some(MirrorCleanupRunGuard)
    })
}

/// Closes the run on EVERY exit, the error paths included: a run left open
/// would make the next cleanup on this thread enqueue into a worklist nobody
/// drains. The transaction is rolled back on those paths anyway, so the
/// abandoned queue describes work that never needed doing.
struct MirrorCleanupRunGuard;

impl Drop for MirrorCleanupRunGuard {
    fn drop(&mut self) {
        MIRROR_CLEANUP_RUN.with(|cell| *cell.borrow_mut() = None);
    }
}

/// Claims `claim_id` for this run. `false` when it was already claimed.
fn claim_mirror_for_cleanup(claim_id: &EntityId) -> bool {
    MIRROR_CLEANUP_RUN.with(|cell| {
        cell.borrow_mut()
            .as_mut()
            .is_some_and(|run| run.visited.insert(*claim_id))
    })
}

fn enqueue_mirror_for_cleanup(claim_id: EntityId) {
    MIRROR_CLEANUP_RUN.with(|cell| {
        if let Some(run) = cell.borrow_mut().as_mut() {
            run.queue.push_back(claim_id);
        }
    });
}

fn next_queued_mirror() -> Option<EntityId> {
    MIRROR_CLEANUP_RUN.with(|cell| {
        cell.borrow_mut()
            .as_mut()
            .and_then(|run| run.queue.pop_front())
    })
}

/// Removes ONE derived claim mirror, folding its cost into `cleanup`.
///
/// Only OUR mirror is removed — see [`disclosure_mirror_matches`] for the
/// custody rule and why a mismatch leaves rather than refuses.
///
/// The mirror is a CLAIM entity, so it goes through the ordinary deindex door
/// rather than a raw row delete — it carries edges, indexes, and possibly a
/// vector, exactly like any other claim.
///
/// ITERATIVE, CYCLE-SAFE, NO DEPTH CAP (fix-6 item 4). Deindexing a mirror
/// re-enters [`delete_facet_state_for_entity_in_txn`] with the mirror's OWN id,
/// and a mirror is itself a stampable CLAIM: stamp a mirror into a facet,
/// unstamp it through the consent door, and the ledger row that act mints has
/// the MIRROR as its `record` — so the mirror's own deletion sweeps a further
/// mirror. The predecessor's "recursion terminates in one step, a mirror is
/// never the `record` half of any consent" was exactly this mistake. Chains of
/// that shape are caller-constructible to ANY length from ordinary public ops,
/// so the old recursion was a stack-overflow abort (an unrecoverable process
/// failure, not a refusal) at attacker-chosen depth.
///
/// A DEPTH CAP IS NOT AVAILABLE HERE, which is why the traversal is iterative
/// instead: at the cap the only choices are aborting an otherwise-legitimate
/// erasure or leaving mirror rows standing, and both break the
/// erasure-completeness property this sweep exists to establish. The outermost
/// frame therefore owns a worklist; nested frames only ENQUEUE. Depth becomes
/// one heap entry per reachable mirror and the stack stays flat, so there is
/// nothing left to bound.
///
/// The visited set is the CYCLE guard. A cycle needs two mirrors that derive
/// each other, and the ids are sha256 over `(record, facet, sequence)` — so one
/// is not constructible today, and this does not rely on that staying true. It
/// also makes the sweep idempotent against a mirror reached twice by any future
/// caller. Every mirror in the run is torn inside the CALLER'S single
/// transaction, so the erasure stays atomic and the whole run rolls back
/// together on any error.
fn delete_disclosure_mirror_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    identity: DisclosureMirrorIdentity,
    cleanup: &mut FacetStateCleanup,
) -> Result<()> {
    if !disclosure_mirror_matches(store, &*wtxn, claim_id, identity)? {
        return Ok(());
    }
    let Some(_run) = begin_mirror_cleanup_run() else {
        // An ancestor frame owns the drain. Hand it the mirror and return:
        // tearing it here is exactly the unbounded recursion being removed.
        enqueue_mirror_for_cleanup(*claim_id);
        return Ok(());
    };
    let mut pending = Some(*claim_id);
    while let Some(next) = pending.take().or_else(next_queued_mirror) {
        if !claim_mirror_for_cleanup(&next) {
            continue;
        }
        let (_existed, had_vector, had_graph_mutation, neighbors) =
            crate::batch::deindex_entity(store, wtxn, &next)?;
        crate::ppr::invalidate_ppr_for_delete(store, wtxn, &next, &neighbors)?;
        cleanup.had_vector |= had_vector;
        cleanup.had_graph_mutation |= had_graph_mutation;
        cleanup.neighbors.extend(neighbors);
    }
    Ok(())
}

/// Registers the RECLASSIFICATION-LEDGER family with entity deletion, on BOTH
/// of the pair's sides.
///
/// A ledger row NAMES both the record it reclassified and the facet that record
/// left, so it must not survive either one's erasure — that is the
/// erasure-completeness rule, and it is the whole reason both sides are swept.
/// It is NOT a capability sweep: no gate reads these rows, so a survivor grants
/// nothing (fix-3 removed the authorizing read that made stale rows spendable).
///
/// Scan shapes follow the key layout (`prefix ‖ record ‖ facet ‖ sequence`):
/// the record side is an exact prefix scan, so it costs O(that record's events)
/// for any deleted entity. The facet side has no such prefix and needs a
/// filtered scan over the family, so it runs only for a delete that COULD be a
/// facet — a FACET-typed one, or (fix-10 item 3) a HEADERLESS one, whose type
/// is unknowable and therefore not proof that it was not a facet.
fn delete_facet_reclassification_consents_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: Option<u8>,
) -> Result<FacetStateCleanup> {
    let mut doomed: Vec<(Vec<u8>, EntityId, EntityId, u64)> = Vec::new();
    {
        let mut record_prefix = FACET_RECLASSIFICATION_KEY_PREFIX.to_vec();
        record_prefix.extend_from_slice(id.as_bytes());
        for row in store.vault_meta.prefix_iter(&*wtxn, &record_prefix)? {
            let (key, _value) = row?;
            let facet = facet_of_reclassification_key(&key)?;
            let sequence = sequence_of_reclassification_key(&key)?;
            doomed.push((key.to_vec(), *id, facet, sequence));
        }
    }
    if matches!(entity_type, None | Some(ENTITY_TYPE_FACET)) {
        for row in store
            .vault_meta
            .prefix_iter(&*wtxn, FACET_RECLASSIFICATION_KEY_PREFIX)?
        {
            let (key, _value) = row?;
            if facet_of_reclassification_key(&key)? != *id {
                continue;
            }
            let record = record_of_reclassification_key(&key)?;
            // A self-referential row (record == facet) is impossible to write
            // through `unstamp_facet_of` (a FacetOf edge to itself is off the
            // ONE-1645 endpoint table), but deduping keeps the double delete
            // out of the fold regardless.
            if record == *id {
                continue;
            }
            doomed.push((
                key.to_vec(),
                record,
                *id,
                sequence_of_reclassification_key(&key)?,
            ));
        }
    }

    let mut cleanup = FacetStateCleanup::default();
    for (key, record, facet, sequence) in doomed {
        store.vault_meta.delete(wtxn, &key)?;
        let claim_id = facet_reclassification_claim_id(&record, &facet, sequence)?;
        delete_disclosure_mirror_in_txn(
            store,
            wtxn,
            &claim_id,
            DisclosureMirrorIdentity::Reclassification {
                record,
                facet,
                sequence,
            },
            &mut cleanup,
        )?;
    }
    Ok(cleanup)
}

fn record_of_reclassification_key(key: &[u8]) -> Result<EntityId> {
    reclassification_key_id(key, FACET_RECLASSIFICATION_KEY_PREFIX.len())
}

fn facet_of_reclassification_key(key: &[u8]) -> Result<EntityId> {
    reclassification_key_id(key, FACET_RECLASSIFICATION_KEY_PREFIX.len() + ENTITY_ID_LEN)
}

/// The sequence suffix, read from a key that must be EXACTLY canonical.
///
/// EXACT LENGTH, not a lower bound (fix-7 item 2). The sequence is the LAST
/// field, so a `key.get(offset..offset + 8)` that ignores what follows accepts
/// `canonical_key || anything` as the canonical key's own row. Every reader in
/// this module then treats the overlong row as that `(record, facet, sequence)`
/// event: [`Vault::facet_reclassification_ledger`] returns it as a real consent
/// event once its body matches (fix-6's body-to-key binding compares against
/// these same extractors, so a body honest about the CANONICAL triple satisfies
/// all three), and
/// [`next_facet_reclassification_sequence_in_txn`] counts it when picking the
/// next free slot. A corrupt key is thereby laundered into ledger truth — the
/// exact substitution fix-6 item 5 closed on the body side, reached from the key
/// side instead.
///
/// Nothing legitimate writes a longer key: [`facet_reclassification_meta_key`]
/// emits prefix + record + facet + 8 and nothing else, so anything longer is
/// corruption or a forgery, and this module's stance on both is LOUD.
/// Length-checking HERE covers every reader, because all three field extractors
/// are called together on any key that is read as an event.
fn sequence_of_reclassification_key(key: &[u8]) -> Result<u64> {
    let offset = FACET_RECLASSIFICATION_KEY_PREFIX.len() + ENTITY_ID_LEN * 2;
    if key.len() != offset + RECLASSIFICATION_SEQUENCE_LEN {
        return Err(Error::CorruptedIndex("facet reclassification row key"));
    }
    key.get(offset..offset + RECLASSIFICATION_SEQUENCE_LEN)
        .and_then(|bytes| <[u8; RECLASSIFICATION_SEQUENCE_LEN]>::try_from(bytes).ok())
        .map(u64::from_be_bytes)
        .ok_or(Error::CorruptedIndex("facet reclassification row key"))
}

fn reclassification_key_id(key: &[u8], offset: usize) -> Result<EntityId> {
    key.get(offset..offset + ENTITY_ID_LEN)
        .and_then(|bytes| <[u8; ENTITY_ID_LEN]>::try_from(bytes).ok())
        .and_then(|bytes| EntityId::from_bytes(bytes).ok())
        .ok_or(Error::CorruptedIndex("facet reclassification row key"))
}

/// The ONE-1646 consent gate on `FacetOf` UNSTAMPING — the seam
/// `batch::validate_facet_of_edge` reserved ("gating `FacetOf` deletes on
/// exposure state lands at THIS call site once facet exposure state exists").
///
/// THE LAUNDERING PATH IT CLOSES: [`DisclosureContext::facet_conjunct_admits`]
/// reads a claim's outgoing `FacetOf` stamps and admits a claim with NO stamp
/// as the `{invariant}` (unfaceted/core) term of P7. Deletion therefore MOVES
/// A SURVIVING RECORD BETWEEN CLAMP CLASSES with no body edit: stamp a claim
/// into a private facet, delete the stamp, and the claim is admitted to rooms
/// that were never cleared for it.
///
/// THE RULE: NO generic door may remove a `FacetOf` stamp, ever. The only
/// removal is [`Vault::unstamp_facet_of`], which consents and acts in one
/// commit. "Authorized" and "done" are therefore the same event, and there is
/// no artifact anywhere that means "an unstamp of this pair is permitted".
///
/// WHY NOTHING STORED MAY AUTHORIZE, in the order this gate learned it:
///
/// * NOT FACET EXPOSURE (fix-1's shape). Exposure is REVERSIBLE state and an
///   unstamp is irreversible: `set_facet_exposure(Public)`, unstamp,
///   `set_facet_exposure(Private)` leaves the claim unfaceted, admitted as
///   invariant under the FINAL private policy, with nothing on disk saying a
///   reclassification happened. No reversible state may authorize an
///   irreversible act.
/// * NOT A DURABLE PER-PAIR CONSENT RECORD (fix-2's shape). A record keyed to
///   `(record, facet)` outlives the STAMP INCARNATION it was minted for, and
///   stamps are freely re-creatable: consent-unstamp `(C, F)`, re-stamp
///   `C → F`, and a generic delete rides the stale record into a second,
///   unconsented reclassification. Authorization that OUTLIVES its act is
///   replayable by construction.
///
/// Both are the same failure — authorization held APART from the act — so the
/// fix is to hold none at all. The `facet.reclassification.v1` rows this module
/// writes are an append-only LEDGER for the owner's consent surface; no gate
/// reads them, and adding one back would restore the replay.
///
/// The gate is TOTAL over the three LOCAL removal paths, because all three
/// converge on removing a row that the conjunct reads:
///
/// * [`Vault::delete_edge`] — the direct convenience door;
/// * `BatchOp::DeleteEdge` — the staged-op arm;
/// * FACET-entity hard delete — the cascade in `batch::delete_related_edges`
///   tears every inbound stamp at once, so it is gated on the facet itself
///   rather than per-edge.
///
/// LOCAL is the whole scope, and deliberately so. The REPLICATED-removal door
/// — the sync bridge's reverse-remat arm, where another of the owner's devices
/// echoes an unstamp it already consented to — APPLIES the removal instead
/// (see the plane-trust note on that arm in
/// [`crate::sync::bridge::materialize_edges_from_delta`]). Consent is enforced
/// ONCE, at the origin device's local gate; refusing the echo would not add a
/// second consent, it would only make a consented unstamp unpropagatable and
/// leave the devices permanently disagreeing about a surviving record's clamp
/// class.
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
    Err(Error::FacetUnstampWithoutConsent {
        facet: *tgt,
        stamped_by: Some(*src),
    })
}

/// THE hard-delete facet-state gate, type-dispatched — the ONE predicate every
/// hard-delete door evaluates, so no door can drift from another.
///
/// Two doors call it at two DIFFERENT moments, on purpose:
///
/// * `batch::deindex_entity` calls it inside the erasing txn, before the first
///   row comes off. That is the chokepoint: both hard-delete paths funnel
///   through it, so nothing can route around the gate, and a refusal there is
///   atomic with respect to LOCAL state.
/// * `deletion`'s reason-aware delete calls it BEFORE it publishes the CRDT
///   tombstone. Local atomicity alone was not enough there: the tombstone is
///   written first by locked ARCH-0038 ordering (it must precede the purge to
///   prevent sync resurrection), so a gate that only spoke inside the purge txn
///   refused AFTER hard-delete truth was already published — the entity stayed
///   whole locally while every other device was told it was erased. That
///   divergence is an erasure-completeness failure in its own right, and it is
///   not repairable from the refusing device. Deciding before TXN1 makes a
///   refused delete a total no-op: no tombstone, no marker, no receipt, no
///   state change.
///
/// Non-FACET types pass: only a FACET's deletion cascades stamps or is named by
/// clearances.
///
/// The type-KNOWN door. Callers holding only a stored-type lookup — which can
/// come back `None` — must use [`gate_hard_delete_facet_state_for_stored_type`]
/// so the unknown case fails closed instead of skipping.
pub(crate) fn gate_hard_delete_facet_state(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> Result<()> {
    gate_hard_delete_facet_state_for_stored_type(store, txn, id, Some(entity_type))
}

/// FAIL-CLOSED ON UNKNOWN TYPE (fix-6 item 1) — the gate as the row-tearing
/// site must evaluate it, where the entity type is whatever
/// [`crate::batch::stored_entity_type`] could prove and `None` is a real
/// answer.
///
/// `None` means HEADERLESS RESIDUE: no entity row under the id, but the id can
/// still be the target of live `FacetOf` stamps — a facet whose entity row was
/// removed out from under its edges, or edges written ahead of the row. The
/// gate used to be reached through `if let Some(entity_type)`, so that case
/// SKIPPED it entirely while `delete_related_edges` went on to tear every
/// inbound stamp. The stamped records SURVIVE that tear and are silently
/// reclassified into the unfaceted class the P7 conjunct admits as invariant —
/// unstamp-via-delete with no consent event anywhere, which is the exact
/// laundering shape this gate exists to close, reached by deleting the one
/// thing whose type nobody can vouch for.
///
/// So the unknown type is treated as POSSIBLY-FACET and both arms run. Only the
/// type-DISPATCH is unavailable without a type; neither arm needs one — the
/// stamp arm scans `edges_in` under the id and the clearance arm scans for
/// rows naming it, both keyed by id alone. A headerless id with no incident
/// stamp and no clearance naming it still deletes as the no-op it always was,
/// so the fail-closed default costs an `edges_in` prefix probe (bounded by that
/// id's inbound edges) plus, only when the id has no entity row, one pass over
/// the clearance family.
///
/// The remedy is unchanged and mechanical: [`Vault::unstamp_facet_of`] is the
/// consent-authorized op, and once the stamps are off through it the delete
/// proceeds.
pub(crate) fn gate_hard_delete_facet_state_for_stored_type(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: Option<u8>,
) -> Result<()> {
    if matches!(entity_type, Some(known) if known != ENTITY_TYPE_FACET) {
        return Ok(());
    }
    gate_facet_entity_delete(store, txn, id)
}

/// The FACET-entity half of [`gate_facet_of_unstamp`]: hard-deleting a facet
/// cascades away every inbound `FacetOf` stamp at once, which reclassifies
/// every stamped record in one step — the laundering path at its widest. The
/// cascade is a GENERIC removal, so it refuses exactly like the other two,
/// naming the first stamp in the way; the owner unstamps each one through the
/// dedicated door first. Checked BEFORE any row is torn, so the refusal is
/// atomic with respect to the delete.
///
/// A facet carrying NO inbound stamps is freely deletable: nothing moves
/// between clamp classes, so there is nothing to consent to.
fn gate_facet_entity_delete(store: &Store, txn: &RoTxn<'_>, facet_id: &EntityId) -> Result<()> {
    for row in store.edges_in.prefix_iter(txn, facet_id.as_bytes())? {
        let (key, _value) = row?;
        if key.get(ENTITY_ID_LEN) != Some(&(EdgeKind::FacetOf as u8)) {
            continue;
        }
        let stamped_by = EntityId::from_bytes(
            <[u8; ENTITY_ID_LEN]>::try_from(
                key.get(ENTITY_ID_LEN + 1..)
                    .ok_or(Error::CorruptedIndex("edge record"))?,
            )
            .map_err(|_| Error::CorruptedIndex("edge record"))?,
        )
        .map_err(|_| Error::CorruptedIndex("edge record"))?;
        return Err(Error::FacetUnstampWithoutConsent {
            facet: *facet_id,
            stamped_by: Some(stamped_by),
        });
    }
    gate_facet_delete_against_live_clearances(store, txn, facet_id)
}

/// P2 — the FACET-ID REUSE gate: a facet may not be hard-deleted while any
/// contact clearance still names it.
///
/// Entity ids are CALLER-CHOSEN, so a facet id is reusable. Deleting a facet
/// removes only its own `facet.exposure.v1` row and mirror; every
/// `contact.clearance.v1` row CONTAINING that id survives, because clearances
/// are keyed by CONTACT. The attack is then trivial: delete facet F, mint a
/// brand-new, unrelated FACET at the same id F, stamp a claim into it — and
/// every contact who was ever cleared for the OLD F silently inherits the new
/// one. The grant outlives the thing it was a grant FOR.
///
/// BLOCK, NOT STRIP, and the reason is custody. Silently editing live consent
/// records as a side effect of an unrelated delete is precisely the shape this
/// module refuses everywhere else: clearance rows are OF-153 grant-grammar
/// records with a `disclosure.clearance` ledger mirror, and every narrowing of
/// one is supposed to be an owner act through
/// [`Vault::set_contact_facet_clearance`] with its own mirror rewrite. A strip
/// would have to forge that owner act, from inside a delete the owner did not
/// frame as a consent change, for an unbounded number of contacts at once. The
/// block keeps ONE door for clearance narrowing and costs the owner one
/// explicit call per affected contact — which is also the call that makes the
/// revocation visible on the consent surface. It fails CLOSED and names the
/// contact standing in the way, so the remedy is mechanical.
fn gate_facet_delete_against_live_clearances(
    store: &Store,
    txn: &RoTxn<'_>,
    facet_id: &EntityId,
) -> Result<()> {
    for row in store
        .vault_meta
        .prefix_iter(txn, FACET_CLEARANCE_KEY_PREFIX)?
    {
        let (key, value) = row?;
        // A row whose body will not decode cannot be proven to EXCLUDE the
        // facet, and it is exactly as resurrectable as a valid one: the
        // resolver's quiet-narrow makes it contribute nothing TODAY, but the
        // bytes still name the id for whatever repairs it later. Fail closed.
        let names_facet = decode_facet_clearance_body(&value)
            .map_or(true, |clearance| clearance.facets.contains(facet_id));
        if !names_facet {
            continue;
        }
        let contact = key
            .get(FACET_CLEARANCE_KEY_PREFIX.len()..)
            .and_then(|bytes| <[u8; ENTITY_ID_LEN]>::try_from(bytes).ok())
            .and_then(|bytes| EntityId::from_bytes(bytes).ok())
            .ok_or(Error::CorruptedIndex("facet clearance row key"))?;
        return Err(Error::FacetDeleteWithLiveClearance {
            facet: *facet_id,
            contact,
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
