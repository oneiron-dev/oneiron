//! Provider confidence priors and read-time confidence composition (ES-09).
//!
//! # Index model: two DISPOSABLE shortcuts over one truth
//!
//! The provider actor row and the provider prior-head row in `vault_meta` are
//! CACHES, never authority. Truth is the stored graph: an active PERSON entity
//! whose MessagePack body carries an exact `provider_key`, plus the
//! `actor.confidence_prior` CLAIMs subject-ed to it. Every read validates a
//! shortcut against that truth before honouring it and falls back to a full
//! scan on any mismatch, so deleting both rows — or filling them with garbage —
//! can only cost work, never change an answer. That is what makes an
//! upgraded vault correct with no migration, no startup pass, and no bulk
//! rebuild: the first read that misses repairs what it needed and nothing else.
//!
//! # Cross-actor staleness bound
//!
//! The prior head is stored per PROVIDER, not per actor, and may name a CLAIM
//! owned by any actor carrying that provider key. While a cached head still
//! validates, a NEWER prior synced onto a DIFFERENT actor for the same provider
//! is not observed — the read is authorized to trust its validated shortcut.
//! That newer head is discovered on the next stale/miss (any invalidation of
//! the cached head, an index clear, or an upgraded vault's first read), and the
//! duplicate actors themselves reconcile by merge under ARCH-0035 law rather
//! than by this module inventing a reconciliation of its own. The bound is
//! therefore "one stale/miss", and it is a latency bound, not a correctness
//! one: no state is written from the stale view.
//!
//! # Transaction norm: NO NESTING
//!
//! `Vault::with_write_txn` / `try_with_write_txn` (vault.rs:1533-1556) take the
//! LMDB writer mutex before running the closure. Every public entry point here
//! opens exactly ONE of them and does all of its work through the `_in_txn`
//! form; the public forms must NEVER be called from inside a held transaction.

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    unit_interval_f32,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::identity_topology::EntityLifecycleState;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;

/// Provider reliability belief, stored as a superseding claim on the provider actor.
pub const PREDICATE_ACTOR_CONFIDENCE_PRIOR: &str = "actor.confidence_prior";

const PROVIDER_ACTOR_INDEX_PREFIX: &[u8] = b"provider_confidence/actor/v1\0";

/// Disposable per-provider shortcut to the CLAIM id of the newest active
/// `actor.confidence_prior` head, whichever actor owns it.
///
/// Deliberately a SECOND prefix rather than a wider value under the actor
/// prefix: the actor row answers "which entity is this provider" and the head
/// row answers "which claim is its current belief". They invalidate for
/// different reasons and are repaired independently, and keeping the actor
/// prefix byte-stable means an existing vault's actor rows keep working
/// untouched while the head row simply starts absent.
const PROVIDER_PRIOR_HEAD_INDEX_PREFIX: &[u8] = b"provider_confidence/prior_head/v1\0";

/// Provider-attributed enrichment output, the production read the ES-09
/// composition scores. Attribution lives in the value map's `provider` key.
pub const PREDICATE_PROVIDER_ENRICHMENT: &str = "provider.enrichment";
const PROVIDER_VALUE_KEY: &str = "provider";
const PROVIDER_ACTOR_BODY_KEY: &str = "provider_key";
const MAX_PROVIDER_KEY_BYTES: usize = 512;

/// Returns whether `predicate` is the provider confidence-prior predicate.
#[must_use]
pub fn is_actor_confidence_prior_claim_predicate(predicate: &str) -> bool {
    predicate == PREDICATE_ACTOR_CONFIDENCE_PRIOR
}

/// Returns whether `predicate` is the provider-enrichment predicate.
///
/// EXACT match, deliberately not a `provider.` prefix: adopting every future
/// `provider.*` predicate into this validator would decide the shape of
/// families that do not exist yet, and the write chokepoint still accepts
/// unknown well-formed predicates on their own terms.
#[must_use]
pub fn is_provider_enrichment_claim_predicate(predicate: &str) -> bool {
    predicate == PREDICATE_PROVIDER_ENRICHMENT
}

/// Validates a `provider.enrichment` claim body.
///
/// The one structural contract every enrichment write must satisfy for the
/// ES-09 composition to be able to score it: an entity subject and a value MAP
/// carrying the `provider` key EXACTLY once, whose value is a trimmed,
/// non-empty, at-most-512-byte string. Sibling payload keys are allowed and
/// ignored — the map is the provider's own output and this validator claims
/// only the attribution slot in it, exactly as the `skill.scan_verdict`
/// precedent does.
///
/// Deliberately WEAKER than the prior validator beside it: enrichment claims
/// are ordinary third-party observations, so `source`/`approval` stay the
/// caller's business and the local-only trust pin belongs to the prior alone.
/// The prior validator above is unchanged by this door.
pub(crate) fn validate_provider_enrichment_claim_structure(body: &ClaimBody) -> Result<()> {
    if !is_provider_enrichment_claim_predicate(&body.predicate) {
        return Err(Error::InvalidClaimBody(
            "unknown provider enrichment predicate",
        ));
    }
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "provider enrichment subject must be an entity",
        ));
    }
    provider_from_claim_body(body).map(|_| ())
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
        // The shortcut moves in the SAME transaction that mints the head it
        // names. A separate write would leave a window in which the row points
        // at a claim this transaction is about to supersede — survivable (the
        // read revalidates and falls back) but pointless churn, and a rollback
        // would strand it pointing at a claim that never landed.
        vault.store.vault_meta.put(
            wtxn,
            &provider_prior_head_index_key(provider),
            claim_id.as_bytes(),
        )?;
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

/// Composition form is an engine default chosen under ratified-doc latitude (doc 13 §7 leaves f abstract): read-time confidence = stored claim confidence × the claim provider's active actor.confidence_prior. Read-time only — never mutates the stored confidence. The product form is closed on `[0,1]` and swappable to another monotone-both-axes composition without any storage migration.
///
/// A provider with no active prior uses the neutral prior `1.0`, so the
/// effective confidence is identical to the stored confidence.
///
/// Opens ONE write transaction because a read may REPAIR a stale shortcut (see
/// the module docs' index model). NO NESTING: `with_write_txn` takes the LMDB
/// writer mutex first, so callers already holding a transaction must reach
/// [`effective_confidence_in_txn`] instead of this door.
pub fn effective_confidence(vault: &Vault, claim_ref: &EntityId) -> Result<f32> {
    vault.with_write_txn(|wtxn| effective_confidence_in_txn(vault, wtxn, claim_ref))
}

/// Transaction-composable [`effective_confidence`]: the whole composition —
/// claim read, provider extraction, prior resolution, and any shortcut repair
/// the resolution needed — inside the caller's transaction.
///
/// The product stays closed on `[0,1]` (both factors are), and NOTHING is
/// materialized: the stored `confidence` column is never rewritten.
pub(crate) fn effective_confidence_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim_ref: &EntityId,
) -> Result<f32> {
    let body = vault
        .get_claim_in_txn(&*wtxn, claim_ref)?
        .ok_or(Error::EntityNotFound)?;
    let provider = provider_from_claim_body(&body)?;
    let prior = active_provider_prior_in_txn(vault, wtxn, provider)?.unwrap_or(1.0);
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
///
/// Same truth-fallback resolver as every other read here, so the count is
/// already correct on a vault whose shortcut rows were never written (or were
/// just cleared) — no rebuild read has to run first.
pub fn count_active_prior_claims_with_evidence(
    vault: &Vault,
    provider: &str,
    evidence: &str,
) -> Result<usize> {
    validate_provider_key(provider)?;
    // One write transaction: resolving may repair the actor shortcut. NO
    // NESTING — see the module docs.
    vault.with_write_txn(|wtxn| {
        let Some(actor) = resolve_provider_actor_in_txn(vault, wtxn, provider)? else {
            return Ok(0);
        };
        Ok(prior_claims_for_actor_in_txn(vault, &*wtxn, &actor)?
            .into_iter()
            .filter(|(_, body)| {
                body.lifecycle == ClaimLifecycleStatus::Active
                    && body.evidence.as_ref().and_then(Value::as_str) == Some(evidence)
            })
            .count())
    })
}

fn count_prior_claims(
    vault: &Vault,
    provider: &str,
    lifecycle: ClaimLifecycleStatus,
) -> Result<usize> {
    validate_provider_key(provider)?;
    vault.with_write_txn(|wtxn| {
        let Some(actor) = resolve_provider_actor_in_txn(vault, wtxn, provider)? else {
            return Ok(0);
        };
        Ok(prior_claims_for_actor_in_txn(vault, &*wtxn, &actor)?
            .into_iter()
            .filter(|(_, body)| body.lifecycle == lifecycle)
            .count())
    })
}

/// The active prior for `provider`, or `None` (neutral) if it has none.
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
///
/// TWO SCOPES:
///
/// * **Cache-valid.** The cached head id must still resolve to an active
///   `actor.confidence_prior` CLAIM that passes the prior-structure validator
///   and carries a unit-interval value, subject-ed to an entity whose LIVE
///   PERSON body carries this exact `provider_key`. The head is then re-selected
///   as the newest prior WITHIN THAT ACTOR on every read, so a same-actor
///   supersession is observed immediately and a cached row naming an older but
///   still-valid head cannot pin the answer.
/// * **Stale or missing.** The shortcut teaches nothing, so truth decides:
///   every active actor carrying the key is enumerated, the actor shortcut is
///   repaired to the lexicographically smallest of them, and the newest prior
///   across ALL of them wins. The winning CLAIM id is cached regardless of which
///   actor owns it. Finding none DELETES a stale positive row and returns
///   `None`; no negative/absence sentinel is ever stored, because a sentinel is
///   a second thing that can go stale and it would have to be invalidated by
///   the very writes it exists to avoid reading.
///
/// A structurally invalid CLAIM under the exact prior predicate is a TYPED
/// ERROR, never a silent neutral: `1.0` is a load-bearing trust multiplier, so
/// "this vault holds a prior we cannot read" must not be reported as "this
/// provider is fully trusted".
fn active_provider_prior_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    provider: &str,
) -> Result<Option<f32>> {
    validate_provider_key(provider)?;
    let head_key = provider_prior_head_index_key(provider);
    let cached_head = vault.store.vault_meta.get(&*wtxn, &head_key)?;
    let cached_head_present = cached_head.is_some();

    // ---- scope 1: the shortcut, honoured only after it re-earns trust ----
    if let Some(actor) = cached_head
        .as_deref()
        // A malformed-length row is STALE, not corruption: these bytes are a
        // cache the engine may overwrite at will, so a decode failure routes to
        // the rebuild below instead of failing the caller's read.
        .and_then(decode_index_entity_id)
        .map(|head| validated_prior_head_owner_in_txn(vault, &*wtxn, &head, provider))
        .transpose()?
        .flatten()
        && let Some((claim_id, value)) =
            newest_active_prior_for_actor_in_txn(vault, &*wtxn, &actor)?
    {
        if cached_head.as_deref() != Some(claim_id.as_bytes()) {
            vault
                .store
                .vault_meta
                .put(wtxn, &head_key, claim_id.as_bytes())?;
        }
        return Ok(Some(value));
    }

    // ---- scope 2: stale or missing — truth decides and repairs ----
    let actors = provider_actors_for_key_in_txn(vault, &*wtxn, provider)?;
    if let Some(smallest) = actors.first() {
        vault.store.vault_meta.put(
            wtxn,
            &provider_actor_index_key(provider),
            smallest.as_bytes(),
        )?;
    }
    let mut best: Option<(u64, EntityId, f32)> = None;
    for actor in &actors {
        for (valid_from, claim_id, value) in active_priors_for_actor_in_txn(vault, &*wtxn, actor)? {
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
    }
    match best {
        Some((_, claim_id, value)) => {
            vault
                .store
                .vault_meta
                .put(wtxn, &head_key, claim_id.as_bytes())?;
            Ok(Some(value))
        }
        None => {
            if cached_head_present {
                vault.store.vault_meta.delete(wtxn, &head_key)?;
            }
            Ok(None)
        }
    }
}

/// Confirms a cached prior-head id still names a live head for `provider` and
/// returns the ACTOR that owns it.
///
/// Every link in the chain is re-checked because every link can rot
/// independently: the claim can be superseded or retracted, its subject can be
/// merged away into a redirect shell, and the subject's body can be rewritten
/// to a different provider key. `None` means "stale" — the caller rebuilds.
///
/// The entity read is spelled out rather than delegated to
/// [`Vault::get_claim_in_txn`] because that door RAISES on an id naming a
/// non-CLAIM entity — the right answer for a caller that meant a claim, the
/// wrong one for a DISPOSABLE cache row, which must degrade to "stale" for
/// every shape of wrongness alike. A stray row may cost a full scan; it may
/// never deny a read that truth can answer. Storage errors still propagate.
fn validated_prior_head_owner_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    head: &EntityId,
    provider: &str,
) -> Result<Option<EntityId>> {
    let Some(raw) = vault.store.entities.get(rtxn, head.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let Ok(body) =
        crate::claim::decode_claim_body(raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or(&[]), true)
    else {
        return Ok(None);
    };
    if !is_actor_confidence_prior_claim_predicate(&body.predicate)
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
        || validate_actor_confidence_prior_claim_structure(&body).is_err()
        || unit_interval_f32(&body.value).is_none()
    {
        return Ok(None);
    }
    let ClaimSubject::Entity(actor) = body.subject else {
        return Ok(None);
    };
    if active_actor_provider_key_matches_in_txn(vault, rtxn, &actor, provider)? {
        Ok(Some(actor))
    } else {
        Ok(None)
    }
}

/// Whether `id` is CURRENTLY an active PERSON entity whose body names exactly
/// `provider`. Redirect shells (`Merged` / `Split`) are not active actors.
fn active_actor_provider_key_matches_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    provider: &str,
) -> Result<bool> {
    let Some(raw) = vault.store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(false);
    };
    if header.entity_type != ENTITY_TYPE_PERSON {
        return Ok(false);
    }
    if vault.entity_lifecycle_state_in_txn(rtxn, id)? != EntityLifecycleState::Active {
        return Ok(false);
    }
    Ok(
        provider_key_from_actor_body(raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or(&[]))
            .as_deref()
            == Some(provider),
    )
}

/// Every ACTIVE PERSON entity whose body carries exactly `provider_key ==
/// provider`, sorted and deduplicated.
///
/// The full-scan truth source, run only on a stale shortcut or a miss.
/// Malformed and unrelated bodies are IGNORED rather than fatal: the PERSON
/// type index is shared with every other person in the vault, and one
/// undecodable neighbour must not deny a provider its prior.
fn provider_actors_for_key_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    provider: &str,
) -> Result<Vec<EntityId>> {
    let mut actors = Vec::new();
    for entry in vault
        .store
        .type_index
        .prefix_iter(rtxn, &[ENTITY_TYPE_PERSON])?
    {
        let (key, _) = entry?;
        let id = crate::vault::entity_id_from_type_index_key(&key)?;
        if active_actor_provider_key_matches_in_txn(vault, rtxn, &id, provider)? {
            actors.push(id);
        }
    }
    actors.sort_unstable();
    actors.dedup();
    Ok(actors)
}

/// The active `actor.confidence_prior` heads on `actor` as
/// `(valid_from, claim_id, value)`.
///
/// Structurally invalid matching CLAIMs raise instead of being skipped — see
/// [`active_provider_prior_in_txn`] on why a broken prior may not read neutral.
fn active_priors_for_actor_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Vec<(u64, EntityId, f32)>> {
    let mut priors = Vec::new();
    for claim_id in vault.claims_for_subject_in_txn(rtxn, actor)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &claim_id)? else {
            continue;
        };
        if !is_actor_confidence_prior_claim_predicate(&body.predicate)
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.stale
        {
            continue;
        }
        validate_actor_confidence_prior_claim_structure(&body)?;
        let value = unit_interval_f32(&body.value).ok_or(Error::InvalidClaimBody(
            "active provider confidence prior must be in 0..1",
        ))?;
        priors.push((body.valid_from.unwrap_or(0), claim_id, value));
    }
    Ok(priors)
}

/// The newest active prior on `actor` by `(valid_from, claim_id)`.
fn newest_active_prior_for_actor_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Option<(EntityId, f32)>> {
    Ok(active_priors_for_actor_in_txn(vault, rtxn, actor)?
        .into_iter()
        .max_by(|(left_vf, left_id, _), (right_vf, right_id, _)| {
            (left_vf, left_id).cmp(&(right_vf, right_id))
        })
        .map(|(_, claim_id, value)| (claim_id, value)))
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

/// Resolves the provider actor, minting one only when TRUTH — not the
/// shortcut — says none exists.
///
/// The mint is behind the resolver on purpose: an upgraded vault whose actor
/// row was never written already HAS its actor in the graph, and minting a
/// second one there would fork the provider's belief history across two PERSON
/// entities that only a merge could ever rejoin.
fn resolve_or_create_provider_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    provider: &str,
) -> Result<EntityId> {
    if let Some(actor) = resolve_provider_actor_in_txn(vault, wtxn, provider)? {
        return Ok(actor);
    }

    let index_key = provider_actor_index_key(provider);
    let id = EntityId::now();
    let body = encode_value(&Value::Map(vec![(
        Value::from(PROVIDER_ACTOR_BODY_KEY),
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

/// The provider's actor, validated against live truth and repaired on miss.
///
/// A cached id is honoured only while it still names an ACTIVE PERSON carrying
/// this exact `provider_key`; anything else (absent row, malformed bytes, wrong
/// entity type, redirect shell, rewritten body) routes to the full scan, which
/// picks the lexicographically SMALLEST active actor and rewrites the shortcut
/// to it. Smallest — rather than newest — because the choice must be a pure
/// function of the set: two devices scanning the same vault have to land on the
/// same actor without consulting a clock either of them owns.
///
/// `None` is returned ONLY after the truth scan has run and found nothing, so
/// a cold or cleared index can never report a provider as unknown.
fn resolve_provider_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    provider: &str,
) -> Result<Option<EntityId>> {
    validate_provider_key(provider)?;
    let index_key = provider_actor_index_key(provider);
    if let Some(cached) = vault
        .store
        .vault_meta
        .get(&*wtxn, &index_key)?
        .as_deref()
        .and_then(decode_index_entity_id)
        && active_actor_provider_key_matches_in_txn(vault, &*wtxn, &cached, provider)?
    {
        return Ok(Some(cached));
    }

    let Some(actor) = provider_actors_for_key_in_txn(vault, &*wtxn, provider)?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    vault
        .store
        .vault_meta
        .put(wtxn, &index_key, actor.as_bytes())?;
    Ok(Some(actor))
}

fn provider_actor_index_key(provider: &str) -> Vec<u8> {
    provider_index_key(PROVIDER_ACTOR_INDEX_PREFIX, provider)
}

fn provider_prior_head_index_key(provider: &str) -> Vec<u8> {
    provider_index_key(PROVIDER_PRIOR_HEAD_INDEX_PREFIX, provider)
}

/// `prefix || sha256(provider)` — a fixed-width suffix so an arbitrary
/// 512-byte provider key cannot shape the key space.
fn provider_index_key(prefix: &'static [u8], provider: &str) -> Vec<u8> {
    let digest = Sha256::digest(provider.as_bytes());
    let mut key = Vec::with_capacity(prefix.len() + digest.len());
    key.extend_from_slice(prefix);
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

/// Tolerant decode of a shortcut row. `None` = "this row teaches nothing",
/// which is the only verdict a DISPOSABLE index is allowed to produce: raising
/// here would let a stray byte deny a read that truth can answer perfectly.
fn decode_index_entity_id(raw: &[u8]) -> Option<EntityId> {
    let bytes: [u8; ENTITY_ID_LEN] = raw.try_into().ok()?;
    EntityId::from_bytes(bytes).ok()
}

/// The `provider_key` string in a PERSON actor's MessagePack body, if any.
fn provider_key_from_actor_body(body: &[u8]) -> Option<String> {
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut std::io::Cursor::new(body)) else {
        return None;
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(PROVIDER_ACTOR_BODY_KEY))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned)
}

fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| Error::InvariantViolation("provider actor MessagePack encode failed"))?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Test-support seams
//
// The shortcut rows live in `vault_meta`, which is `pub(crate)`. These three
// doors exist so the ES-09 oracle can build the stale/cleared states a reader
// must survive WITHOUT exporting the metadata database itself. They touch the
// two provider rows and nothing else — never a PERSON, CLAIM, supersession,
// subject-edge, temporal, or sync row — so nothing they do can fabricate the
// truth the reader is being tested against. There is deliberately NO production
// cache-control surface: in production these rows are only ever written by the
// reads and the prior writer above.
// ---------------------------------------------------------------------------

/// Deletes both shortcut rows for `provider`, simulating an upgraded vault
/// that never had them (or an operator clearing the cache).
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn clear_provider_confidence_indexes(vault: &Vault, provider: &str) -> Result<()> {
    validate_provider_key(provider)?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .delete(wtxn, &provider_actor_index_key(provider))?;
        vault
            .store
            .vault_meta
            .delete(wtxn, &provider_prior_head_index_key(provider))?;
        Ok(())
    })
}

/// `(actor row present, prior-head row present)` for `provider`.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn provider_confidence_index_presence(vault: &Vault, provider: &str) -> Result<(bool, bool)> {
    validate_provider_key(provider)?;
    let rtxn = vault.store.env.read_txn()?;
    Ok((
        vault
            .store
            .vault_meta
            .get(&rtxn, &provider_actor_index_key(provider))?
            .is_some(),
        vault
            .store
            .vault_meta
            .get(&rtxn, &provider_prior_head_index_key(provider))?
            .is_some(),
    ))
}

/// Overwrites both shortcut rows for `provider` with raw bytes; `None` deletes.
///
/// Total in both slots on purpose — a partial setter would need to READ the
/// row it is leaving alone, which is the one thing a raw seam must not teach
/// its caller.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn set_provider_confidence_index_raw(
    vault: &Vault,
    provider: &str,
    actor_row: Option<&[u8]>,
    prior_head_row: Option<&[u8]>,
) -> Result<()> {
    validate_provider_key(provider)?;
    vault.with_write_txn(|wtxn| {
        for (key, value) in [
            (provider_actor_index_key(provider), actor_row),
            (provider_prior_head_index_key(provider), prior_head_row),
        ] {
            match value {
                Some(bytes) => vault.store.vault_meta.put(wtxn, &key, bytes)?,
                None => {
                    vault.store.vault_meta.delete(wtxn, &key)?;
                }
            }
        }
        Ok(())
    })
}
