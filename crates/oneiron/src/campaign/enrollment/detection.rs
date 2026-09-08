//! Persisted membership-transition events, detection pass, cause routing, and per-query baseline.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::storage::{
    CAMPAIGN_ENROLLMENT_SCHEMA_VERSION, ENROLLMENT_EVENT_PREFIX, baseline_key, from_row,
    hash_from_hex, id_from_hex, keyed, pin_schema, put_meta, read_meta, to_row,
};
use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::saved_query::{
    EVIDENCE_HASH_LEN, EvaluationRequest, MatchVerdict, MembershipCause, MembershipEvent,
    MembershipTransition, QueryScope, SavedQueryEvaluator, membership_events,
    next_membership_epoch, read_saved_query,
};

// ---------------------------------------------------------------------------
// The persisted enrollment (membership) event
// ---------------------------------------------------------------------------

/// One detected, PERSISTED membership transition awaiting its consequence.
///
/// This is the row an attempt payload points at. Everything authority-bearing
/// about the transition lives here, written by the engine at detection time, so
/// no caller and no queue replay can present a different cause, epoch, or
/// evidence hash to the write path.
///
/// `definition_version` and `scope_digest` are the derivation state this
/// detection ran under. They are what makes "the definition moved" and "the
/// owner's reach moved" decidable without re-deriving ONE-1773's evidence
/// machinery here, and they are what an owner ruling on this event promotes to
/// the query's new baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignEnrollmentEvent {
    /// Durable identity of this row; the attempt payload's only membership ref.
    pub event_ref: EntityId,
    /// Query that derived the transition.
    pub query_ref: EntityId,
    /// Campaign the consequence is scoped to.
    pub campaign_ref: EntityId,
    /// Entity whose membership moved.
    pub entity_ref: EntityId,
    /// Owner actor the re-derivation must run under.
    pub owner_actor: EntityId,
    /// Monotonic per-`(query, entity)` epoch minted at detection.
    pub epoch: u64,
    /// When the transition became true.
    pub valid_at: u64,
    /// When the engine detected it.
    pub detected_at: u64,
    /// Direction.
    pub transition: MembershipTransition,
    /// Engine-derived cause. The routing dial reads THIS, never a payload field.
    pub cause: MembershipCause,
    /// Evidence the detection verdict was derived from.
    pub evidence_hash: [u8; EVIDENCE_HASH_LEN],
    /// Definition version the detection ran against.
    pub definition_version: u64,
    /// Digest of the effective (declared ∩ granted) scope at detection.
    pub scope_digest: [u8; 32],
}

impl CampaignEnrollmentEvent {
    /// Projection onto ONE-1773's event type. The commit boundary owns the
    /// event shape; this module owns only the durable row that carries it.
    #[must_use]
    pub fn membership_event(&self) -> MembershipEvent {
        MembershipEvent {
            query_ref: self.query_ref,
            campaign_ref: self.campaign_ref,
            entity_ref: self.entity_ref,
            epoch: self.epoch,
            valid_at: self.valid_at,
            detected_at: self.detected_at,
            transition: self.transition,
            cause: self.cause,
            evidence_hash: self.evidence_hash,
        }
    }
}

/// Reads one persisted enrollment event.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is [`Error::CorruptedIndex`].
pub fn campaign_enrollment_event(
    vault: &Vault,
    event_ref: EntityId,
) -> Result<Option<CampaignEnrollmentEvent>> {
    read_meta(
        vault,
        &keyed(ENROLLMENT_EVENT_PREFIX, &[event_ref.as_bytes()]),
    )?
    .map(|raw| decode_event(event_ref, &raw))
    .transpose()
}

/// What a detection pass concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentDetection {
    /// A transition was recorded and is ready to be enqueued.
    Recorded(Box<CampaignEnrollmentEvent>),
    /// Nothing to do: the entity does not match, or already holds the cohort
    /// row this evidence would write.
    NoTransition,
}

/// Detection-door input. Refs and a clock — no cause, epoch, evidence hash,
/// enrolled flag, or outbound request, because none of those is a caller's to
/// assert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectEnrollment {
    /// The saved query.
    pub query_ref: EntityId,
    /// The campaign the consequence is scoped to.
    pub campaign_ref: EntityId,
    /// The entity being considered.
    pub entity_ref: EntityId,
    /// Detection instant.
    pub now: u64,
}

/// Runs one detection pass and, on a real transition, PERSISTS the event.
///
/// The epoch is minted here, once, and pinned to the row — not re-minted at
/// execution. That is what makes a retry of the same attempt land on the same
/// epoch and content, and therefore report `AlreadyApplied` instead of writing
/// a second cohort row one epoch later.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the query is absent or `owner_actor` does not
/// own it; evaluation and storage errors propagate.
pub async fn detect_enrollment(
    evaluator: &SavedQueryEvaluator<'_>,
    owner_actor: EntityId,
    input: &DetectEnrollment,
) -> Result<EnrollmentDetection> {
    let vault = evaluator.vault;
    let record =
        read_saved_query(vault, owner_actor, input.query_ref)?.ok_or(Error::EntityNotFound)?;
    let scope_digest = effective_scope_digest(&record.definition.scope, evaluator.owner_grants);
    let definition_version = record.definition.definition_version;
    let cause = derive_cause(vault, input.query_ref, definition_version, &scope_digest)?;
    let outcome = evaluator
        .evaluate_entity(&EvaluationRequest {
            query_ref: input.query_ref,
            campaign_ref: input.campaign_ref,
            entity_ref: input.entity_ref,
            definition: &record.definition,
            cause,
            valid_at: input.now,
            detected_at: input.now,
        })
        .await?;
    if outcome.decision.verdict != MatchVerdict::Match {
        return Ok(EnrollmentDetection::NoTransition);
    }
    // A transition is a CHANGE. An entity already entered on exactly this
    // evidence has nothing to transition into, and minting an epoch for it
    // would churn the cohort head on every wake.
    if membership_events(vault, input.query_ref, input.entity_ref)?
        .last()
        .is_some_and(|last| {
            last.transition == MembershipTransition::Entered
                && last.evidence_hash == outcome.evidence_hash
        })
    {
        return Ok(EnrollmentDetection::NoTransition);
    }
    let event = CampaignEnrollmentEvent {
        event_ref: EntityId::now(),
        query_ref: input.query_ref,
        campaign_ref: input.campaign_ref,
        entity_ref: input.entity_ref,
        owner_actor,
        epoch: next_membership_epoch(vault, input.query_ref, input.entity_ref)?,
        valid_at: input.now,
        detected_at: input.now,
        transition: MembershipTransition::Entered,
        cause,
        evidence_hash: outcome.evidence_hash,
        definition_version,
        scope_digest,
    };
    put_event(vault, &event)?;
    Ok(EnrollmentDetection::Recorded(Box::new(event)))
}

/// Routes the transition onto ONE of the three closed causes.
///
/// Precedence is definition > scope > data, because a definition move can also
/// move the effective scope and the more specific explanation is the honest
/// one.
///
/// The comparison is against the query's ACCEPTED baseline, and two things
/// about that are the whole point of the routing dial:
///
/// * it is what the owner last accepted, not what the last detection ran
///   under. A baseline that advanced at detection would let a definition move
///   launder itself — the first detection reports `DefinitionChange`, and every
///   later one under the same unreviewed definition reports `DataChange` and
///   auto-enrolls the very change that was routed for review;
/// * it is held per QUERY, not per entity. A per-entity row is absent for
///   exactly the entities a widened definition swept in, and an absent row can
///   only mean `DataChange` — so the population review exists for would be the
///   population that skips it.
///
/// A query with no baseline yet has no prior definition or scope that could
/// have moved, so the first detection pins one and reads as data movement.
fn derive_cause(
    vault: &Vault,
    query_ref: EntityId,
    definition_version: u64,
    scope_digest: &[u8; 32],
) -> Result<MembershipCause> {
    let Some(baseline) = read_baseline(vault, query_ref)? else {
        put_baseline(vault, query_ref, definition_version, scope_digest)?;
        return Ok(MembershipCause::DataChange);
    };
    Ok(if baseline.definition_version != definition_version {
        MembershipCause::DefinitionChange
    } else if &baseline.scope_digest != scope_digest {
        MembershipCause::ScopeChange
    } else {
        MembershipCause::DataChange
    })
}

/// Records the owner's ruling on a reviewed bulk move: the derivation state
/// `event` was detected under becomes the query's baseline, so detections under
/// it route as ordinary data movement again.
///
/// This is the engine half of [`EnrollmentExecution::ReviewRequired`]. Without
/// it the routing rule would be a wall rather than a dial — every detection
/// under a moved definition would report the move forever and the owner's
/// ruling would have nowhere to land. Presenting the review is later surface
/// work; the durable effect of ruling on it is here.
///
/// # Errors
///
/// Storage errors propagate.
pub fn accept_enrollment_baseline(vault: &Vault, event: &CampaignEnrollmentEvent) -> Result<()> {
    put_baseline(
        vault,
        event.query_ref,
        event.definition_version,
        &event.scope_digest,
    )
}

/// Digest of the scope the query will ACTUALLY run under: declared ∩ granted.
/// A closed intersection gets its own tag so "the owner lost all reach" is
/// distinguishable from "the owner's reach is unrestricted".
fn effective_scope_digest(declared: &QueryScope, grants: &QueryScope) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.campaign.enrollment.scope.v1");
    match declared.intersect(grants) {
        None => hasher.update([0u8]),
        Some(scope) => {
            hasher.update([1u8]);
            let mut worlds: Vec<[u8; 16]> =
                scope.worlds.iter().map(|world| *world.as_bytes()).collect();
            worlds.sort_unstable();
            hasher.update((worlds.len() as u64).to_be_bytes());
            for world in &worlds {
                hasher.update(world);
            }
            let mut facets = scope.facets;
            facets.sort_unstable();
            hasher.update((facets.len() as u64).to_be_bytes());
            for facet in &facets {
                hasher.update((facet.len() as u64).to_be_bytes());
                hasher.update(facet.as_bytes());
            }
        }
    }
    hasher.finalize().into()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventRow {
    schema_version: u32,
    query_ref: String,
    campaign_ref: String,
    entity_ref: String,
    owner_actor: String,
    epoch: u64,
    valid_at: u64,
    detected_at: u64,
    transition: String,
    cause: String,
    evidence_hash: String,
    definition_version: u64,
    scope_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineRow {
    schema_version: u32,
    definition_version: u64,
    scope_digest: String,
}

struct EnrollmentBaseline {
    definition_version: u64,
    scope_digest: [u8; 32],
}

pub(super) fn put_event(vault: &Vault, event: &CampaignEnrollmentEvent) -> Result<()> {
    let bytes = to_row(&EventRow {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        query_ref: event.query_ref.to_hex(),
        campaign_ref: event.campaign_ref.to_hex(),
        entity_ref: event.entity_ref.to_hex(),
        owner_actor: event.owner_actor.to_hex(),
        epoch: event.epoch,
        valid_at: event.valid_at,
        detected_at: event.detected_at,
        transition: event.transition.as_str().to_owned(),
        cause: event.cause.as_str().to_owned(),
        evidence_hash: bytes_to_hex_lower(&event.evidence_hash),
        definition_version: event.definition_version,
        scope_digest: bytes_to_hex_lower(&event.scope_digest),
    })?;
    put_meta(
        vault,
        &keyed(ENROLLMENT_EVENT_PREFIX, &[event.event_ref.as_bytes()]),
        &bytes,
    )
}

fn decode_event(event_ref: EntityId, raw: &[u8]) -> Result<CampaignEnrollmentEvent> {
    const CONTEXT: &str = "campaign enrollment event";
    let row: EventRow = from_row(raw, CONTEXT)?;
    pin_schema(row.schema_version, CONTEXT)?;
    Ok(CampaignEnrollmentEvent {
        event_ref,
        query_ref: id_from_hex(&row.query_ref, CONTEXT)?,
        campaign_ref: id_from_hex(&row.campaign_ref, CONTEXT)?,
        entity_ref: id_from_hex(&row.entity_ref, CONTEXT)?,
        owner_actor: id_from_hex(&row.owner_actor, CONTEXT)?,
        epoch: row.epoch,
        valid_at: row.valid_at,
        detected_at: row.detected_at,
        transition: MembershipTransition::parse(&row.transition)
            .ok_or(Error::CorruptedIndex(CONTEXT))?,
        cause: MembershipCause::parse(&row.cause).ok_or(Error::CorruptedIndex(CONTEXT))?,
        evidence_hash: hash_from_hex(&row.evidence_hash, CONTEXT)?,
        definition_version: row.definition_version,
        scope_digest: hash_from_hex(&row.scope_digest, CONTEXT)?,
    })
}

fn read_baseline(vault: &Vault, query_ref: EntityId) -> Result<Option<EnrollmentBaseline>> {
    const CONTEXT: &str = "campaign enrollment baseline";
    let Some(raw) = read_meta(vault, &baseline_key(query_ref))? else {
        return Ok(None);
    };
    let row: BaselineRow = from_row(&raw, CONTEXT)?;
    pin_schema(row.schema_version, CONTEXT)?;
    Ok(Some(EnrollmentBaseline {
        definition_version: row.definition_version,
        scope_digest: hash_from_hex(&row.scope_digest, CONTEXT)?,
    }))
}

fn put_baseline(
    vault: &Vault,
    query_ref: EntityId,
    definition_version: u64,
    scope_digest: &[u8; 32],
) -> Result<()> {
    let bytes = to_row(&BaselineRow {
        schema_version: CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
        definition_version,
        scope_digest: bytes_to_hex_lower(scope_digest),
    })?;
    put_meta(vault, &baseline_key(query_ref), &bytes)
}
