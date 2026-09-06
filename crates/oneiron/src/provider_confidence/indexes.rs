//! Disposable provider actor and prior-head indexes over stored graph truth.
//!
//! The parent module documents cache validation and the cross-actor staleness bound.

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject, unit_interval_f32};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::identity_topology::EntityLifecycleState;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;

use super::{
    encode_value, is_actor_confidence_prior_claim_predicate,
    validate_actor_confidence_prior_claim_structure, validate_provider_key,
};

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

const PROVIDER_ACTOR_BODY_KEY: &str = "provider_key";

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
/// says — [`super::write_provider_prior`] is the only local writer, so every head this
/// read honors came through it.
///
/// TWO SCOPES:
///
/// * **Cache-valid.** The cached head id must still resolve to an active
///   `actor.confidence_prior` CLAIM that passes the prior-structure validator
///   and carries a unit-interval value. Its subject projects to an active PERSON
///   carrying this exact `provider_key`. The head is re-selected over that actor's
///   direct priors plus the cached claim's own subject shell on every read, so
///   a same-owner supersession is observed immediately and a cached row naming
///   an older but still-valid head cannot pin the answer.
/// * **Stale or missing.** The shortcut teaches nothing, so truth decides:
///   every active actor carrying the key is enumerated, the actor shortcut is
///   repaired to the lexicographically smallest of them, and the newest prior
///   across ALL of them and their matching merged shells wins. A matching shell
///   with active priors but no active matching head raises instead of reading
///   neutral. The winning CLAIM id is cached regardless of which actor owns it.
///   Finding none DELETES a stale positive row and returns `None`; no negative/absence sentinel is ever stored, because a sentinel is
///   a second thing that can go stale and it would have to be invalidated by
///   the very writes it exists to avoid reading.
///
/// A structurally invalid CLAIM under the exact prior predicate is a TYPED
/// ERROR, never a silent neutral: `1.0` is a load-bearing trust multiplier, so
/// "this vault holds a prior we cannot read" must not be reported as "this
/// provider is fully trusted".
pub(super) fn active_provider_prior_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    provider: &str,
) -> Result<Option<f32>> {
    validate_provider_key(provider)?;
    let head_key = provider_prior_head_index_key(provider);
    let cached_head = vault.store.vault_meta.get(&*wtxn, &head_key)?;
    let cached_head_present = cached_head.is_some();

    // ---- scope 1: the shortcut, honoured only after it re-earns trust ----
    if let Some((actor, subject)) = cached_head
        .as_deref()
        // A malformed-length row is STALE, not corruption: these bytes are a
        // cache the engine may overwrite at will, so a decode failure routes to
        // the rebuild below instead of failing the caller's read.
        .and_then(decode_index_entity_id)
        .map(|head| validated_prior_head_owner_in_txn(vault, &*wtxn, &head, provider))
        .transpose()?
        .flatten()
        && let Some((claim_id, value)) =
            newest_active_prior_for_actor_in_txn(vault, &*wtxn, &actor, &subject)?
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
    let ProviderActors {
        actors,
        shell_priors,
    } = provider_actors_for_key_in_txn(vault, &*wtxn, provider)?;
    if let Some(smallest) = actors.first() {
        vault.store.vault_meta.put(
            wtxn,
            &provider_actor_index_key(provider),
            smallest.as_bytes(),
        )?;
    }
    let mut best = shell_priors
        .into_iter()
        .max_by_key(|(valid_from, claim_id, _)| (*valid_from, *claim_id));
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
/// returns its canonical ACTOR owner and its original subject for re-selection.
///
/// Every link in the chain is re-checked because every link can rot
/// independently: the claim can be superseded or retracted, its subject can be
/// merged away into a redirect shell, and the subject's body can be rewritten
/// to a different provider key. `None` means "stale" — the caller rebuilds.
/// A matching merged shell projects read-only; a stranded prior raises.
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
) -> Result<Option<(EntityId, EntityId)>> {
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
    Ok(projected_prior_owner_in_txn(vault, rtxn, &actor, provider)?.map(|owner| (owner, actor)))
}

/// Projects a matching prior subject without moving its claim or its edges.
/// A matching shell with an active prior must not read as neutral or mint anew.
fn projected_prior_owner_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    subject: &EntityId,
    provider: &str,
) -> Result<Option<EntityId>> {
    if !actor_provider_key_matches_in_txn(vault, rtxn, subject, provider)? {
        return Ok(None);
    }
    let state = vault.entity_lifecycle_state_in_txn(rtxn, subject)?;
    if state == EntityLifecycleState::Active {
        return Ok(Some(*subject));
    }
    if state == EntityLifecycleState::Merged {
        let heads = vault.resolve_entity_in_txn(rtxn, subject)?;
        if let [head] = heads.as_slice()
            && active_actor_provider_key_matches_in_txn(vault, rtxn, head, provider)?
        {
            return Ok(Some(*head));
        }
    }
    Err(Error::InvalidClaimBody(
        "provider confidence prior stranded by merge",
    ))
}

/// Whether `id` is CURRENTLY an active PERSON entity whose body names exactly
/// `provider`. Redirect shells (`Merged` / `Split`) are not active actors.
fn active_actor_provider_key_matches_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    provider: &str,
) -> Result<bool> {
    Ok(
        actor_provider_key_matches_in_txn(vault, rtxn, id, provider)?
            && vault.entity_lifecycle_state_in_txn(rtxn, id)? == EntityLifecycleState::Active,
    )
}

fn actor_provider_key_matches_in_txn(
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
    Ok(
        provider_key_from_actor_body(raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or(&[]))
            .as_deref()
            == Some(provider),
    )
}

struct ProviderActors {
    actors: Vec<EntityId>,
    shell_priors: Vec<(u64, EntityId, f32)>,
}

/// Every ACTIVE PERSON entity whose body carries exactly `provider_key ==
/// provider`, sorted and deduplicated.
///
/// Matching shells contribute priors only through an active matching head.
/// The full-scan truth source, run on a stale shortcut, a miss, or before a write.
/// Malformed and unrelated bodies are IGNORED rather than fatal: the PERSON
/// type index is shared with every other person in the vault, and one
/// undecodable neighbour must not deny a provider its prior.
fn provider_actors_for_key_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    provider: &str,
) -> Result<ProviderActors> {
    let mut actors = Vec::new();
    let mut shells = Vec::new();
    for entry in vault
        .store
        .type_index
        .prefix_iter(rtxn, &[ENTITY_TYPE_PERSON])?
    {
        let (key, _) = entry?;
        let id = crate::vault::entity_id_from_type_index_key(&key)?;
        if !actor_provider_key_matches_in_txn(vault, rtxn, &id, provider)? {
            continue;
        }
        if vault.entity_lifecycle_state_in_txn(rtxn, &id)? == EntityLifecycleState::Active {
            actors.push(id);
        } else {
            shells.push(id);
        }
    }
    actors.sort_unstable();
    actors.dedup();
    let mut shell_priors = Vec::new();
    for shell in shells {
        let priors = active_priors_for_actor_in_txn(vault, rtxn, &shell)?;
        if priors.is_empty() {
            continue;
        }
        let owner = projected_prior_owner_in_txn(vault, rtxn, &shell, provider)?;
        if owner.is_none_or(|head| actors.binary_search(&head).is_err()) {
            return Err(Error::InvalidClaimBody(
                "provider confidence prior stranded by merge",
            ));
        }
        shell_priors.extend(priors);
    }
    Ok(ProviderActors {
        actors,
        shell_priors,
    })
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

/// The newest active prior on `actor` and the cached head's original subject
/// by `(valid_from, claim_id)`. Other shells wait for the next stale/miss scan.
fn newest_active_prior_for_actor_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    actor: &EntityId,
    subject: &EntityId,
) -> Result<Option<(EntityId, f32)>> {
    let mut priors = active_priors_for_actor_in_txn(vault, rtxn, actor)?;
    if subject != actor {
        priors.extend(active_priors_for_actor_in_txn(vault, rtxn, subject)?);
    }
    Ok(priors
        .into_iter()
        .max_by(|(left_vf, left_id, _), (right_vf, right_id, _)| {
            (left_vf, left_id).cmp(&(right_vf, right_id))
        })
        .map(|(_, claim_id, value)| (claim_id, value)))
}

pub(super) fn prior_claims_for_actor_in_txn(
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
pub(super) fn resolve_or_create_provider_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    provider: &str,
) -> Result<EntityId> {
    // Writes cannot use the read-side staleness bound. Even a valid cached
    // actor must not hide a stranded prior on another matching shell. Check
    // provider-wide truth before resolving, repairing indexes, or minting.
    provider_actors_for_key_in_txn(vault, &*wtxn, provider)?;
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
pub(super) fn resolve_provider_actor_in_txn(
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
        .actors
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

pub(super) fn provider_prior_head_index_key(provider: &str) -> Vec<u8> {
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
// reads and the prior writer in the parent module.
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

#[cfg(test)]
#[path = "prior_projection_tests.rs"]
mod tests;
