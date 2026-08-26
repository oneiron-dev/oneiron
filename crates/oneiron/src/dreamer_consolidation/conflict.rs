use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use super::provenance::{PromotionCandidate, source_meet};
use super::support::{
    DREAMER_BUCKET_HASH_DOMAIN, DREAMER_CLAIM_ID_HASH_DOMAIN, DREAMER_EVIDENCE_HASH_DOMAIN,
    TURN_BODY_FACET_REF_KEY, encode_value, hash_optional_entity, invalid_consolidation,
};
use super::watermark::entity_ref_from_value;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, claim_consolidatable,
    claim_evidence_admissible, predicate_root,
};
use crate::dreamer_runner::{DreamerTurnRole, dreamer_extraction_role_admissible};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

// ---------------------------------------------------------------------------
// Phase 2 — candidate buckets (post-extraction, semantic)
// ---------------------------------------------------------------------------

/// Phase-2 semantic bucket key. Facet stays in the key BY CANON (ARCH-0022:
/// same Person + different Facets must NOT merge behavioral profiles).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsolidationBucketKey {
    pub subject: EntityId,
    pub predicate_root: String,
    pub world: Option<EntityId>,
    pub facet: Option<EntityId>,
}

impl ConsolidationBucketKey {
    /// Domain-separated BLAKE3 over the bucket key (pinned domain
    /// `oneiron:dreamer-bucket:v1`, design D6).
    #[must_use]
    pub fn bucket_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DREAMER_BUCKET_HASH_DOMAIN);
        hasher.update(b"bucket");
        hasher.update(self.subject.as_bytes());
        hasher.update(&(self.predicate_root.len() as u64).to_be_bytes());
        hasher.update(self.predicate_root.as_bytes());
        hash_optional_entity(&mut hasher, self.world.as_ref());
        hash_optional_entity(&mut hasher, self.facet.as_ref());
        *hasher.finalize().as_bytes()
    }
}

/// One phase-2 bucket over candidate indexes into the caller's slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsolidationBucketPlan {
    pub key: ConsolidationBucketKey,
    pub candidate_indexes: Vec<usize>,
}

/// Semantic identity facts of one candidate, derived through the envelope
/// stamping path (`ClaimCandidate` keeps its fields private by design).
pub(super) struct CandidateFacts {
    pub(super) subject: EntityId,
    pub(super) predicate: String,
    pub(super) value: Value,
    pub(super) world: Option<EntityId>,
    pub(super) facet: Option<EntityId>,
}

pub(super) fn candidate_facts(candidate: &ClaimCandidate) -> Result<CandidateFacts> {
    // A throwaway envelope: into_claim_body only stamps envelope-owned
    // metadata; the identity fields we read are candidate-owned.
    let envelope = WriteEnvelope::new(
        WriteActor::new(candidate_probe_actor(), crate::edge::EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::from("dreamer-consolidation-probe"))?,
        ClaimApprovalStatus::Proposed,
    );
    let body = candidate.clone().into_claim_body(&envelope);
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(invalid_consolidation(
            "consolidation candidates must have entity subjects",
        ));
    };
    Ok(CandidateFacts {
        subject,
        predicate: body.predicate,
        value: body.value,
        world: body.world,
        facet: facet_from_scope(body.scope.as_ref()),
    })
}

fn candidate_probe_actor() -> EntityId {
    EntityId::from_bytes([0x11; 16]).unwrap_or_else(|_| unreachable!("constant id is valid"))
}

/// Reads the facet scope entry (engine-owned scope-map pattern; the same
/// idiom as `federated_original_source`).
fn facet_from_scope(scope: Option<&Value>) -> Option<EntityId> {
    let Some(Value::Map(entries)) = scope else {
        return None;
    };
    entries.iter().find_map(|(key, value)| {
        (key.as_str() == Some(TURN_BODY_FACET_REF_KEY))
            .then(|| entity_ref_from_value(value))
            .flatten()
    })
}

/// Groups candidates into semantic buckets on
/// `(subject, predicate_root, world, facet)`.
pub fn plan_candidate_buckets(
    candidates: &[PromotionCandidate],
) -> Result<Vec<ConsolidationBucketPlan>> {
    let mut buckets: BTreeMap<ConsolidationBucketKey, Vec<usize>> = BTreeMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let facts = candidate_facts(&candidate.candidate)?;
        let key = ConsolidationBucketKey {
            subject: facts.subject,
            predicate_root: predicate_root(&facts.predicate).to_owned(),
            world: facts.world,
            facet: facts.facet,
        };
        buckets.entry(key).or_default().push(index);
    }
    Ok(buckets
        .into_iter()
        .map(|(key, candidate_indexes)| ConsolidationBucketPlan {
            key,
            candidate_indexes,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Phase 3 — mechanical evidence collapse + deterministic conflict trigger
// ---------------------------------------------------------------------------

/// Swarm evidence reference — the HASH-ONLY boundary (GATE-05): a child
/// return structurally cannot carry source bytes; identity is
/// `(source_id, content_hash)` and comparisons use exactly those two
/// fields (trust ties resolve to the most restrictive at collapse time).
#[derive(Debug, Clone, Copy)]
pub struct SwarmEvidenceRef {
    pub source_id: EntityId,
    pub content_hash: [u8; 32],
    pub trust_class: ClaimSource,
}

impl SwarmEvidenceRef {
    const fn identity(&self) -> (EntityId, [u8; 32]) {
        (self.source_id, self.content_hash)
    }
}

impl PartialEq for SwarmEvidenceRef {
    fn eq(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

impl Eq for SwarmEvidenceRef {}

impl PartialOrd for SwarmEvidenceRef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SwarmEvidenceRef {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.identity().cmp(&other.identity())
    }
}

/// One swarm child's return: evidence hashes ONLY (raw content never
/// crosses the boundary — no field can carry it), candidate claims AS
/// DATA, and the weave's read pin.
#[derive(Debug, Clone, PartialEq)]
pub struct SwarmChildReturn {
    /// Evidence hashes as a `Vec`, deliberately NOT a set keyed on
    /// identity: two refs sharing one `(source_id, content_hash)` but
    /// differing in `trust_class` must BOTH reach
    /// `collapse_sibling_evidence`, the single authority that melts a
    /// same-identity tie to the most-restrictive class. A set would drop
    /// the stricter tie at insertion (identity-only `Ord`), silently
    /// inflating trust before the meet ever runs.
    pub evidence: Vec<SwarmEvidenceRef>,
    pub candidates: Vec<PromotionCandidate>,
    /// The max `learned_at` watermark captured ONCE at weave start and
    /// stamped into every child payload.
    pub read_pin: u64,
}

/// Mechanically collapsed evidence: N siblings citing one
/// `(source_id, content_hash)` are ONE independent signal.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CollapsedEvidence {
    pub independent: Vec<SwarmEvidenceRef>,
    pub duplicates_collapsed: u32,
}

/// Content hash over the entity's stored body bytes AFTER the metadata
/// header (`raw[ENTITY_METADATA_HEADER_LEN..]`) — byte-identical across
/// devices by storage construction. Domain-separated BLAKE3.
#[must_use]
pub fn swarm_evidence_content_hash(entity_body_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DREAMER_EVIDENCE_HASH_DOMAIN);
    hasher.update(entity_body_bytes);
    *hasher.finalize().as_bytes()
}

/// BLAKE3 identity collapse across sibling children (GATE-05): dedupe by
/// `(source_id, content_hash)`; trust ties on one identity resolve to the
/// MOST restrictive class.
pub fn collapse_sibling_evidence(children: &[SwarmChildReturn]) -> Result<CollapsedEvidence> {
    let mut independent: BTreeMap<(EntityId, [u8; 32]), SwarmEvidenceRef> = BTreeMap::new();
    let mut duplicates_collapsed = 0_u32;
    for child in children {
        for entry in &child.evidence {
            match independent.entry(entry.identity()) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(*entry);
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    duplicates_collapsed += 1;
                    let kept = slot.get_mut();
                    kept.trust_class = source_meet(kept.trust_class, entry.trust_class);
                }
            }
        }
    }
    Ok(CollapsedEvidence {
        independent: independent.into_values().collect(),
        duplicates_collapsed,
    })
}

/// Most-restrictive trust meet over every source read (GATE-05). Lattice
/// order, high→low: `UserStated > Observed > Inferred = Generated >
/// ToolOutput > Imported`. Empty input = `Generated`, the Dreamer's own
/// floor. Feeds `PromotionCandidate::evidence_meet` (ONE-1290 consumes:
/// meet at/below ToolOutput forces Proposed + `scope.evidence_taint`).
#[allow(single_use_lifetimes)] // pinned public signature (brief ONE-1385); anonymous impl-Trait lifetimes are unstable on this toolchain
pub fn evidence_trust_meet<'a>(refs: impl Iterator<Item = &'a SwarmEvidenceRef>) -> ClaimSource {
    refs.fold(ClaimSource::Generated, |meet, entry| {
        source_meet(meet, entry.trust_class)
    })
}

/// Rejects a child return whose `read_pin` differs from the weave's pin —
/// the result is discarded and counted by the caller, never merged.
pub fn validate_child_read_pin(expected: u64, child: &SwarmChildReturn) -> Result<()> {
    if child.read_pin != expected {
        return Err(invalid_consolidation(
            "dreamer swarm child read pin mismatch",
        ));
    }
    Ok(())
}

/// Turn → trust_class derivation (DESIGN-PIN Part B1, ratified R4):
/// native User → `UserStated`; native Assistant → `Generated` (never
/// Observed — two assistant turns must not corroborate each other above
/// the Proposed-forcing floor); imported-transcript turns → `Imported`
/// regardless of role; every other role is never classified (GATE-10
/// excludes it). The reachable working-set meet space is therefore
/// {UserStated, Generated, Imported}.
#[must_use]
pub const fn turn_trust_class(
    role: DreamerTurnRole,
    imported_transcript: bool,
) -> Option<ClaimSource> {
    if !dreamer_extraction_role_admissible(role) {
        return None;
    }
    if imported_transcript {
        return Some(ClaimSource::Imported);
    }
    match role {
        DreamerTurnRole::User => Some(ClaimSource::UserStated),
        DreamerTurnRole::Assistant => Some(ClaimSource::Generated),
        _ => None,
    }
}

/// A prior head consulted as merge context. Admission REQUIRES
/// `claim_consolidatable`; corroboration additionally requires
/// `claim_evidence_admissible` (GATE-11 — Generated-origin priors are
/// merge-eligible but contribute ZERO corroboration).
#[derive(Debug, Clone, PartialEq)]
pub struct PriorHead {
    pub claim_id: EntityId,
    pub body: ClaimBody,
}

/// Full-identity conflict key (A4): the FULL predicate — not the root —
/// refines identity WITHIN a bucket.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConflictIdentity {
    pub subject: EntityId,
    pub predicate: String,
    pub world: Option<EntityId>,
    pub facet: Option<EntityId>,
}

/// One conflicting set: same full identity, non-equal canonical values.
#[derive(Debug, Clone, PartialEq)]
pub struct ConflictSet {
    pub identity: ConflictIdentity,
    pub candidate_indexes: Vec<usize>,
    /// The consolidatable prior head with the same identity, when present.
    pub prior_head: Option<EntityId>,
}

/// Deterministic conflict trigger (DESIGN-PIN A4):
/// `CONFLICT(a,b) ⇔ same (subject, FULL predicate, world, facet) AND
/// canonical_value(a) != canonical_value(b)`. `b` ranges over sibling
/// candidates AND the prior head admitted via `claim_consolidatable`.
/// By key construction: facet-local, null-shadow, world-local.
pub fn detect_conflicts(
    candidates: &[PromotionCandidate],
    prior_heads: &[PriorHead],
) -> Result<Vec<ConflictSet>> {
    let mut groups: BTreeMap<ConflictIdentity, Vec<(usize, Vec<u8>)>> = BTreeMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let facts = candidate_facts(&candidate.candidate)?;
        let identity = ConflictIdentity {
            subject: facts.subject,
            predicate: facts.predicate,
            world: facts.world,
            facet: facts.facet,
        };
        groups
            .entry(identity)
            .or_default()
            .push((index, canonical_value_bytes(&facts.value)?));
    }

    let mut conflicts = Vec::new();
    for (identity, members) in groups {
        let prior = prior_heads.iter().find(|prior| {
            claim_consolidatable(&prior.body) && prior_matches_identity(&prior.body, &identity)
        });
        let mut values: BTreeSet<&[u8]> =
            members.iter().map(|(_, bytes)| bytes.as_slice()).collect();
        let mut prior_value = None;
        if let Some(prior) = prior {
            let bytes = canonical_value_bytes(&prior.body.value)?;
            prior_value = Some(bytes);
        }
        if let Some(bytes) = &prior_value {
            values.insert(bytes.as_slice());
        }
        if values.len() > 1 {
            conflicts.push(ConflictSet {
                identity,
                candidate_indexes: members.into_iter().map(|(index, _)| index).collect(),
                prior_head: prior.map(|prior| prior.claim_id),
            });
        }
    }
    Ok(conflicts)
}

/// The deterministic `core.conflict.open` marker id for one unresolved
/// contradiction (ONE-1710 §6).
///
/// Wrong-note protection is supersession + an open conflict + read-time
/// confidence — NOT a review state — so a contradiction needs a stable
/// identity to surface under, not a queue row. The id is minted from the
/// SAME `deterministic_claim_id` law every consolidation claim uses, so an
/// at-least-once re-run re-mints the same marker instead of a second one.
#[must_use]
pub fn conflict_open_marker_id(
    conflict: &ConflictSet,
    attempt_id: crate::attempt_queue::AttemptId,
) -> EntityId {
    deterministic_claim_id(
        attempt_id,
        conflict.identity.subject,
        crate::claim::PREDICATE_CONFLICT_OPEN,
        &Value::from(conflict.identity.predicate.as_str()),
        conflict.identity.world,
        conflict.identity.facet,
    )
}

fn prior_matches_identity(body: &ClaimBody, identity: &ConflictIdentity) -> bool {
    let ClaimSubject::Entity(subject) = body.subject else {
        return false;
    };
    subject == identity.subject
        && body.predicate == identity.predicate
        && body.world == identity.world
        && facet_from_scope(body.scope.as_ref()) == identity.facet
}

fn canonical_value_bytes(value: &Value) -> Result<Vec<u8>> {
    encode_value(&canonicalize_value(value))
}

/// Derives a [`PromotionCandidate`]'s write-once claim id DETERMINISTICALLY
/// from its identity (owning attempt, subject, predicate, canonical value, world,
/// facet).
///
/// `EntityId::now()` mints a fresh id on every call, so under the wake
/// driver's at-least-once re-execution (a crash after `sink.accept` but before
/// the attempt completes) a memoized step re-run would hand the promotion writer
/// NEW ids for the same beliefs — DUPLICATE claims. A content-addressed id is
/// stable across re-runs (and independent of `now`), so promotion stays
/// idempotent (#485-3).
pub(super) fn deterministic_claim_id(
    attempt_id: crate::attempt_queue::AttemptId,
    subject: EntityId,
    predicate: &str,
    value: &Value,
    world: Option<EntityId>,
    facet: Option<EntityId>,
) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DREAMER_CLAIM_ID_HASH_DOMAIN);
    hasher.update(attempt_id.as_bytes());
    hasher.update(subject.as_bytes());
    hasher.update(&(predicate.len() as u64).to_le_bytes());
    hasher.update(predicate.as_bytes());
    let value_bytes = canonical_value_bytes(value).unwrap_or_default();
    hasher.update(&(value_bytes.len() as u64).to_le_bytes());
    hasher.update(&value_bytes);
    hasher.update(&[u8::from(world.is_some())]);
    if let Some(world) = world {
        hasher.update(world.as_bytes());
    }
    hasher.update(&[u8::from(facet.is_some())]);
    if let Some(facet) = facet {
        hasher.update(facet.as_bytes());
    }
    let digest = hasher.finalize();
    let mut raw = [0_u8; 16];
    raw.copy_from_slice(&digest.as_bytes()[..16]);
    // A blake3 prefix colliding with a reserved id is ~2^-120; perturb
    // deterministically rather than fall back to a non-deterministic id.
    EntityId::from_bytes(raw).unwrap_or_else(|_| {
        raw[0] ^= 0x01;
        raw[15] ^= 0x01;
        EntityId::from_bytes(raw).expect("perturbed derived claim id is non-reserved")
    })
}

/// Recursively sorts every `Value::Map`'s entries by their MessagePack-encoded
/// key so canonical bytes are independent of map key order.
///
/// `json_to_rmpv` preserves serde_json object order and the workspace enables
/// serde_json `preserve_order`, so the LLM's key order flows verbatim into the
/// candidate value. Without this, two semantically identical objects that
/// differ only in key order encode differently and `detect_conflicts` sees a
/// FALSE conflict — spurious merge LLM calls, escalations, and gap writes
/// (#485-4).
fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_value).collect()),
        Value::Map(entries) => {
            let mut canon: Vec<(Vec<u8>, Value, Value)> = entries
                .iter()
                .map(|(key, val)| {
                    let key = canonicalize_value(key);
                    let val = canonicalize_value(val);
                    // Encoding a Value into a Vec never fails; a deterministic
                    // total order over encoded keys is all that is required.
                    let mut sort_key = Vec::new();
                    let _ = rmpv::encode::write_value(&mut sort_key, &key);
                    (sort_key, key, val)
                })
                .collect();
            canon.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Map(canon.into_iter().map(|(_, key, val)| (key, val)).collect())
        }
        other => other.clone(),
    }
}

/// Independent corroboration for one candidate: collapsed turn evidence
/// counts once per source; prior CLAIM refs count ONLY when
/// `claim_evidence_admissible` (GATE-11: Generated-origin priors add zero).
#[must_use]
pub fn corroboration_count(collapsed: &CollapsedEvidence, prior_heads: &[PriorHead]) -> usize {
    let prior_signals = prior_heads
        .iter()
        .filter(|prior| claim_evidence_admissible(&prior.body))
        .count();
    collapsed.independent.len() + prior_signals
}
