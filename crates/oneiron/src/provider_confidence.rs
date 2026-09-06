//! Provider confidence priors and read-time confidence composition (ES-09).
//!
//! # Index model: two DISPOSABLE shortcuts over one truth
//!
//! The provider actor row and the provider prior-head row in `vault_meta` are
//! CACHES, never authority. Truth is the stored graph: an active PERSON entity
//! whose MessagePack body carries an exact `provider_key`, plus the
//! `actor.confidence_prior` CLAIMs subject-ed to it or to matching merged shells
//! that resolve to it. A prior stranded outside active matching actors is a
//! typed error, never neutral. Every read validates a
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
//! one: no state is written from the stale view. A newer prior on a shell other
//! than the cached head's subject, or a newly stranded shell, is discovered on
//! the next stale/miss event.
//!
//! # Transaction norm: NO NESTING
//!
//! `Vault::with_write_txn` / `try_with_write_txn` (vault.rs:1533-1556) take the
//! LMDB writer mutex before running the closure. Every public entry point here
//! opens exactly ONE of them and does all of its work through the `_in_txn`
//! form; the public forms must NEVER be called from inside a held transaction.
//!
//! A waterfall scoring pass also keeps an in-memory prior memo for that one
//! transaction. It reuses successful resolutions, including neutral absence,
//! while graph truth cannot change. The memo is discarded before commit; it
//! never writes a negative shortcut or survives into a later evaluation.

mod indexes;
mod transaction_memo;

use rmpv::Value;

use crate::Vault;
#[cfg(feature = "test-support")]
use crate::batch::{BatchOp, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    unit_interval_f32,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
#[cfg(feature = "test-support")]
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;

use indexes::{
    active_provider_prior_in_txn, prior_claims_for_actor_in_txn, provider_prior_head_index_key,
    resolve_or_create_provider_actor_in_txn, resolve_provider_actor_in_txn,
};
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use indexes::{
    clear_provider_confidence_indexes, provider_confidence_index_presence,
    set_provider_confidence_index_raw,
};
pub(crate) use transaction_memo::ProviderPriorMemo;

/// Provider reliability belief, stored as a superseding claim on the provider actor.
pub const PREDICATE_ACTOR_CONFIDENCE_PRIOR: &str = "actor.confidence_prior";

/// Provider-attributed enrichment output, the production read the ES-09
/// composition scores. Attribution lives in the value map's `provider` key.
pub const PREDICATE_PROVIDER_ENRICHMENT: &str = "provider.enrichment";
const PROVIDER_VALUE_KEY: &str = "provider";
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
    vault.with_write_txn(|wtxn| {
        let mut prior_memo = ProviderPriorMemo::default();
        effective_confidence_in_txn(vault, wtxn, claim_ref, &mut prior_memo)
    })
}

/// Transaction-composable [`effective_confidence`]: the whole composition —
/// claim read, provider extraction, prior resolution, and any shortcut repair
/// the resolution needed — inside the caller's transaction.
///
/// The product stays closed on `[0,1]` (both factors are), and NOTHING is
/// materialized: the stored `confidence` column is never rewritten.
///
/// The caller owns one memo for this scoring transaction only. Repeated
/// providers reuse their resolved prior, including neutral absence, while
/// each claim still supplies its own stored confidence. No actor or prior
/// truth may change while this memo is in use.
pub(crate) fn effective_confidence_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim_ref: &EntityId,
    prior_memo: &mut ProviderPriorMemo,
) -> Result<f32> {
    let body = vault
        .get_claim_in_txn(&*wtxn, claim_ref)?
        .ok_or(Error::EntityNotFound)?;
    let provider = provider_from_claim_body(&body)?;
    let prior = prior_memo
        .resolve(provider, || {
            active_provider_prior_in_txn(vault, wtxn, provider)
        })?
        .unwrap_or(1.0);
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

fn validate_provider_key(provider: &str) -> Result<()> {
    if provider.trim() != provider || provider.is_empty() || provider.len() > MAX_PROVIDER_KEY_BYTES
    {
        return Err(Error::InvalidClaimBody(
            "provider key must be trimmed, non-empty, and at most 512 bytes",
        ));
    }
    Ok(())
}

fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| Error::InvariantViolation("provider actor MessagePack encode failed"))?;
    Ok(bytes)
}
