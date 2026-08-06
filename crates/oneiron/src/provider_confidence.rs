//! Provider confidence priors and read-time confidence composition (ES-09).

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{BatchOp, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    unit_interval_f32,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;

/// Provider reliability belief, stored as a superseding claim on the provider actor.
pub const PREDICATE_ACTOR_CONFIDENCE_PRIOR: &str = "actor.confidence_prior";

const PROVIDER_ACTOR_INDEX_PREFIX: &[u8] = b"provider_confidence/actor/v1\0";
pub(crate) const PREDICATE_PROVIDER_ENRICHMENT: &str = "provider.enrichment";
const PROVIDER_VALUE_KEY: &str = "provider";
const MAX_PROVIDER_KEY_BYTES: usize = 512;

/// Returns whether `predicate` is the provider confidence-prior predicate.
#[must_use]
pub fn is_actor_confidence_prior_claim_predicate(predicate: &str) -> bool {
    predicate == PREDICATE_ACTOR_CONFIDENCE_PRIOR
}

/// Validates an `actor.confidence_prior` claim body.
///
/// Provider attribution on enrichment claims follows the `skill.scan_verdict`
/// precedent: the provider is a string under the `provider` key in the claim
/// body's value map, never a new [`ClaimBody`] field. [`effective_confidence`]
/// validates and reads that key to resolve this prior's actor subject.
pub(crate) fn validate_actor_confidence_prior_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "actor confidence prior subject must be an entity",
        ));
    }
    if !is_actor_confidence_prior_claim_predicate(&body.predicate) {
        return Err(Error::InvalidClaimBody(
            "unknown actor confidence prior predicate",
        ));
    }
    if unit_interval_f32(&body.value).is_none() {
        return Err(Error::InvalidClaimBody(
            "actor confidence prior value must be confidence 0..1",
        ));
    }
    if body.confidence != 1.0 {
        return Err(Error::InvalidClaimBody(
            "actor confidence prior claim confidence must be 1.0",
        ));
    }
    if body.approval != ClaimApprovalStatus::Auto {
        return Err(Error::InvalidClaimBody(
            "actor confidence prior approval must be auto",
        ));
    }
    // Local-only trust boundary (ES-09): priors are same-owner beliefs. Same-owner
    // multi-device sync preserves source=Observed, so a user's own priors replicate
    // and materialize. The cross-vault federation door restamps foreign claims
    // source->Imported; this pin then rejects them at materialization — the intended
    // injection defense (a peer's conf=1.0/Auto prior must never set this vault's
    // provider trust multiplier). Do NOT relax this to accept Imported; that opens
    // the hole. (Foreign-prior terminal quarantine is the audit trail, not a break.)
    if body.source != Some(ClaimSource::Observed) {
        return Err(Error::InvalidClaimBody(
            "actor confidence prior source must be observed",
        ));
    }
    if body
        .evidence
        .as_ref()
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(Error::InvalidClaimBody(
            "actor confidence prior must carry string evidence",
        ));
    }
    Ok(())
}

/// Resolves or mints the provider actor, then writes a new active prior and
/// supersedes every prior active head for that actor in the same transaction.
///
/// Writes through the engine-owned reserved door: `actor.*` is a reserved
/// namespace (ONE-1739), so this — the ONE prior-writing path — carries the
/// same exemption the skill-hub doors carry, and the generic public Claim API
/// can no longer plant a head here.
pub fn write_provider_prior(
    vault: &Vault,
    provider: &str,
    prior: f32,
    evidence: &str,
) -> Result<EntityId> {
    validate_provider_key(provider)?;
    if !prior.is_finite() || !(0.0..=1.0).contains(&prior) {
        return Err(Error::InvalidClaimBody(
            "provider confidence prior must be in 0..1",
        ));
    }
    if evidence.is_empty() {
        return Err(Error::InvalidClaimBody(
            "provider confidence prior evidence must be non-empty",
        ));
    }

    let now = crate::unix_seconds_now();
    vault.with_write_txn(|wtxn| {
        let actor = resolve_or_create_provider_actor_in_txn(vault, wtxn, provider)?;
        let active_priors = prior_claims_for_actor_in_txn(vault, &*wtxn, &actor)?
            .into_iter()
            .filter(|(_, body)| body.lifecycle == ClaimLifecycleStatus::Active)
            .map(|(id, _)| id)
            .collect::<Vec<_>>();

        let claim_id = EntityId::now();
        let mut body = ClaimBody::new(
            PREDICATE_ACTOR_CONFIDENCE_PRIOR,
            ClaimSubject::Entity(actor),
            Value::F32(prior),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.evidence = Some(Value::from(evidence));
        body.valid_from = Some(now);
        body.source = Some(ClaimSource::Observed);
        vault.put_reserved_claim_in_txn(
            wtxn,
            &claim_id,
            &body,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
        for prior_id in active_priors {
            vault.supersede_reserved_claim_in_txn(wtxn, &claim_id, &prior_id, now)?;
        }
        Ok(claim_id)
    })
}

/// Mints a fresh stand-in enriched entity for the [`write_enrichment_claim`]
/// oracle seam. Not indexed — the claim references it by subject only.
#[cfg(feature = "test-support")]
fn mint_enriched_entity_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>) -> Result<EntityId> {
    let id = EntityId::now();
    let body = encode_value(&Value::Map(vec![(
        Value::from("enriched"),
        Value::Boolean(true),
    )]))?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_PERSON,
            occurred: TimeRange { start: 0, end: 0 },
            learned_at: crate::unix_seconds_now(),
            data: body,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )?;
    Ok(id)
}

/// Oracle/reference seam: writes a minimal provider-attributed enrichment claim
/// with an unmodified stored confidence and returns its durable claim id.
///
/// The claim is subject-ed to a freshly-minted stand-in ENRICHED entity, never
/// to the provider actor — the provider actor holds only `actor.confidence_prior`
/// beliefs, so prior lookups never scan enrichment volume. Provider attribution
/// lives in the value map (`provider` key) per the CID-5 template.
///
/// Production enrichment writes do NOT call this: they subject the claim to the
/// real enriched entity they are enriching (via the generic claim API) and never
/// mint per event. This seam is `test-support`-gated so it cannot become a
/// production entity-spam path.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn write_enrichment_claim(vault: &Vault, provider: &str, confidence: f32) -> Result<EntityId> {
    validate_provider_key(provider)?;
    let now = crate::unix_seconds_now();
    vault.with_write_txn(|wtxn| {
        let enriched = mint_enriched_entity_in_txn(vault, wtxn)?;
        let claim_id = EntityId::now();
        let mut body = ClaimBody::new(
            PREDICATE_PROVIDER_ENRICHMENT,
            ClaimSubject::Entity(enriched),
            Value::Map(vec![(
                Value::from(PROVIDER_VALUE_KEY),
                Value::from(provider),
            )]),
            confidence,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.valid_from = Some(now);
        body.source = Some(ClaimSource::Observed);
        vault.put_claim_in_txn(
            wtxn,
            &claim_id,
            &body,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
        Ok(claim_id)
    })
}

/// Composition form is an engine default chosen under ratified-doc latitude (doc 13 §7 leaves f abstract): read-time confidence = stored claim confidence × the claim provider's active actor.confidence_prior. Read-time only — never mutates the stored confidence. The product form is closed on [0,1] and swappable to another monotone-both-axes composition without any storage migration.
///
/// A provider with no active prior uses the neutral prior `1.0`, so the
/// effective confidence is identical to the stored confidence.
pub fn effective_confidence(vault: &Vault, claim_ref: &EntityId) -> Result<f32> {
    let body = claim_body(vault, claim_ref)?;
    let provider = provider_from_claim_body(&body)?;
    let prior = match resolve_provider_actor(vault, provider)? {
        Some(actor) => active_provider_prior(vault, &actor)?.unwrap_or(1.0),
        None => 1.0,
    };
    Ok(body.confidence * prior)
}

/// Reads the claim's stored confidence without applying or writing a provider prior.
pub fn stored_confidence(vault: &Vault, claim_ref: &EntityId) -> Result<f32> {
    claim_body(vault, claim_ref).map(|body| body.confidence)
}

/// Counts active `actor.confidence_prior` claims for `provider`.
pub fn count_active_prior_claims(vault: &Vault, provider: &str) -> Result<usize> {
    count_prior_claims(vault, provider, ClaimLifecycleStatus::Active)
}

/// Counts superseded `actor.confidence_prior` claims for `provider`.
pub fn count_superseded_prior_claims(vault: &Vault, provider: &str) -> Result<usize> {
    count_prior_claims(vault, provider, ClaimLifecycleStatus::Superseded)
}

/// Counts active provider priors carrying exactly `evidence`.
pub fn count_active_prior_claims_with_evidence(
    vault: &Vault,
    provider: &str,
    evidence: &str,
) -> Result<usize> {
    validate_provider_key(provider)?;
    let Some(actor) = resolve_provider_actor(vault, provider)? else {
        return Ok(0);
    };
    Ok(prior_claim_bodies(vault, &actor)?
        .into_iter()
        .filter(|body| {
            body.lifecycle == ClaimLifecycleStatus::Active
                && body.evidence.as_ref().and_then(Value::as_str) == Some(evidence)
        })
        .count())
}

fn count_prior_claims(
    vault: &Vault,
    provider: &str,
    lifecycle: ClaimLifecycleStatus,
) -> Result<usize> {
    validate_provider_key(provider)?;
    let Some(actor) = resolve_provider_actor(vault, provider)? else {
        return Ok(0);
    };
    Ok(prior_claim_bodies(vault, &actor)?
        .into_iter()
        .filter(|body| body.lifecycle == lifecycle)
        .count())
}

/// The active prior for `actor`, or `None` (neutral) if it has none.
///
/// Tolerance vs authorization — two devices can concurrently write a prior for
/// the same provider; under CRDT replay both land ACTIVE until the next
/// `write_provider_prior` supersedes. That is a legitimate convergence state,
/// not corruption, so we pick the newest head deterministically (by
/// `valid_from`, then claim id) rather than bricking every read with an error.
///
/// The authorization boundary that makes "newest head wins" safe is predicate
/// reservation: `actor.confidence_prior` is trust-bearing, and `actor.*` joined
/// the reserved-predicate namespace alongside `{edge, skill}` in ONE-1739. A
/// generic `put_claim` can no longer plant a head here whatever the policy
/// says — [`write_provider_prior`] is the only local writer, so every head this
/// read honors came through it.
fn active_provider_prior(vault: &Vault, actor: &EntityId) -> Result<Option<f32>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut best: Option<(u64, EntityId, f32)> = None;
    for claim_id in vault.claims_for_subject_in_txn(&rtxn, actor)? {
        let Some(body) = vault.get_claim_in_txn(&rtxn, &claim_id)? else {
            continue;
        };
        if !is_actor_confidence_prior_claim_predicate(&body.predicate)
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let value = unit_interval_f32(&body.value).ok_or(Error::InvalidClaimBody(
            "active provider confidence prior must be in 0..1",
        ))?;
        let valid_from = body.valid_from.unwrap_or(0);
        let newer = match &best {
            None => true,
            Some((best_vf, best_id, _)) => {
                valid_from > *best_vf || (valid_from == *best_vf && claim_id > *best_id)
            }
        };
        if newer {
            best = Some((valid_from, claim_id, value));
        }
    }
    Ok(best.map(|(_, _, value)| value))
}

fn claim_body(vault: &Vault, claim_ref: &EntityId) -> Result<ClaimBody> {
    vault.get_claim(claim_ref)?.ok_or(Error::EntityNotFound)
}

fn provider_from_claim_body(body: &ClaimBody) -> Result<&str> {
    let Value::Map(entries) = &body.value else {
        return Err(Error::InvalidClaimBody(
            "provider-attributed claim value must be a map",
        ));
    };
    let mut provider = None;
    for (key, value) in entries {
        if key.as_str() != Some(PROVIDER_VALUE_KEY) {
            continue;
        }
        if provider.is_some() {
            return Err(Error::InvalidClaimBody(
                "provider-attributed claim value has duplicate provider keys",
            ));
        }
        provider = Some(value.as_str().ok_or(Error::InvalidClaimBody(
            "provider-attributed claim provider must be a string",
        ))?);
    }
    let provider = provider.ok_or(Error::InvalidClaimBody(
        "provider-attributed claim value is missing provider",
    ))?;
    validate_provider_key(provider)?;
    Ok(provider)
}

fn prior_claim_bodies(vault: &Vault, actor: &EntityId) -> Result<Vec<ClaimBody>> {
    vault.claim_bodies_for_subjects_matching(&[*actor], |body, _| {
        is_actor_confidence_prior_claim_predicate(&body.predicate)
    })
}

fn prior_claims_for_actor_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Vec<(EntityId, ClaimBody)>> {
    let mut priors = Vec::new();
    for claim_id in vault.claims_for_subject_in_txn(rtxn, actor)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &claim_id)? else {
            continue;
        };
        if is_actor_confidence_prior_claim_predicate(&body.predicate) {
            priors.push((claim_id, body));
        }
    }
    Ok(priors)
}

fn resolve_or_create_provider_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    provider: &str,
) -> Result<EntityId> {
    validate_provider_key(provider)?;
    let index_key = provider_actor_index_key(provider);
    if let Some(raw) = vault.store.vault_meta.get(&*wtxn, &index_key)? {
        let id = decode_provider_actor_id(&raw)?;
        let cached_is_person = vault
            .store
            .entities
            .get(&*wtxn, id.as_bytes())?
            .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type))
            == Some(ENTITY_TYPE_PERSON);
        if cached_is_person {
            return Ok(id);
        }
    }

    let id = EntityId::now();
    let body = encode_value(&Value::Map(vec![(
        Value::from("provider_key"),
        Value::from(provider),
    )]))?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_PERSON,
            occurred: TimeRange { start: 0, end: 0 },
            learned_at: crate::unix_seconds_now(),
            data: body,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )?;
    vault
        .store
        .vault_meta
        .put(wtxn, &index_key, id.as_bytes())?;
    Ok(id)
}

fn resolve_provider_actor(vault: &Vault, provider: &str) -> Result<Option<EntityId>> {
    validate_provider_key(provider)?;
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &provider_actor_index_key(provider))?
    else {
        return Ok(None);
    };
    let id = decode_provider_actor_id(&raw)?;
    let is_person = vault
        .store
        .entities
        .get(&rtxn, id.as_bytes())?
        .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type))
        == Some(ENTITY_TYPE_PERSON);
    Ok(is_person.then_some(id))
}

fn provider_actor_index_key(provider: &str) -> Vec<u8> {
    let digest = Sha256::digest(provider.as_bytes());
    let mut key = Vec::with_capacity(PROVIDER_ACTOR_INDEX_PREFIX.len() + digest.len());
    key.extend_from_slice(PROVIDER_ACTOR_INDEX_PREFIX);
    key.extend_from_slice(&digest);
    key
}

fn validate_provider_key(provider: &str) -> Result<()> {
    if provider.trim() != provider || provider.is_empty() || provider.len() > MAX_PROVIDER_KEY_BYTES
    {
        return Err(Error::InvalidClaimBody(
            "provider key must be trimmed, non-empty, and at most 512 bytes",
        ));
    }
    Ok(())
}

fn decode_provider_actor_id(raw: &[u8]) -> Result<EntityId> {
    let bytes: [u8; ENTITY_ID_LEN] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("provider actor reference"))?;
    EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex("provider actor reference"))
}

fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| Error::InvariantViolation("provider actor MessagePack encode failed"))?;
    Ok(bytes)
}
