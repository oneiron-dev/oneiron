//! Disposable provider actor and prior-head indexes over stored graph truth.
//!
//! The parent module documents cache validation and the cross-actor staleness bound.

use crate::ports::EntityStoreRead;
use rmpv::Value;
use sha2::Digest;
use sha2::Sha256;

use crate::Vault;
use crate::batch::{BatchOp, apply_ops};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject, unit_interval_f32};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SideTableRowProblem, StoreError};
use crate::identity_topology::EntityLifecycleState;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::side_table::{self, Raw, SideTable};
use crate::temporal::TimeRange;

use super::{
    encode_value, is_actor_confidence_prior_claim_predicate,
    validate_actor_confidence_prior_claim_structure, validate_provider_key,
};

/// Disposable per-provider shortcut to the entity id of the actor PERSON
/// carrying a given `provider_key`. Key: `sha256(provider)`.
pub(super) const PROVIDER_ACTOR_INDEX: SideTable<[u8; 32], EntityId, Raw> =
    SideTable::new(&side_table::PROVIDER_ACTOR_INDEX);

/// Disposable per-provider shortcut to the CLAIM id of the newest active
/// `actor.confidence_prior` head, whichever actor owns it. Key:
/// `sha256(provider)`.
///
/// Deliberately a SECOND table rather than a wider value under the actor
/// table: the actor row answers "which entity is this provider" and the head
/// row answers "which claim is its current belief". They invalidate for
/// different reasons and are repaired independently, and keeping the actor
/// row byte-stable means an existing vault's actor rows keep working
/// untouched while the head row simply starts absent.
pub(super) const PROVIDER_PRIOR_HEAD_INDEX: SideTable<[u8; 32], EntityId, Raw> =
    SideTable::new(&side_table::PROVIDER_PRIOR_HEAD_INDEX);

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
    let digest = provider_key_hash(provider);
    // A malformed-length row is STALE, not corruption: these bytes are a
    // cache the engine may overwrite at will, so a decode failure routes to
    // the rebuild below instead of failing the caller's read.
    let cached_head =
        tolerate_undecodable(PROVIDER_PRIOR_HEAD_INDEX.get(&vault.store, &*wtxn, &digest))?;
    let cached_head_present = cached_head.is_some();

    // ---- scope 1: the shortcut, honoured only after it re-earns trust ----
    if let Some((actor, subject)) = cached_head
        .map(|head| validated_prior_head_owner_in_txn(vault, &*wtxn, &head, provider))
        .transpose()?
        .flatten()
        && let Some((claim_id, value)) =
            newest_active_prior_for_actor_in_txn(vault, &*wtxn, &actor, &subject)?
    {
        if cached_head != Some(claim_id) {
            PROVIDER_PRIOR_HEAD_INDEX.put(&vault.store, wtxn, &digest, &claim_id)?;
        }
        return Ok(Some(value));
    }

    // ---- scope 2: stale or missing — truth decides and repairs ----
    let ProviderActors {
        actors,
        shell_priors,
    } = provider_actors_for_key_in_txn(vault, &*wtxn, provider)?;
    if let Some(smallest) = actors.first() {
        PROVIDER_ACTOR_INDEX.put(&vault.store, wtxn, &digest, smallest)?;
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
            PROVIDER_PRIOR_HEAD_INDEX.put(&vault.store, wtxn, &digest, &claim_id)?;
            Ok(Some(value))
        }
        None => {
            if cached_head_present {
                PROVIDER_PRIOR_HEAD_INDEX.delete(&vault.store, wtxn, &digest)?;
            }
            Ok(None)
        }
    }
}

/// Treats a malformed-length shortcut row as absent rather than a fatal
/// decode error: these rows are DISPOSABLE caches the engine may overwrite at
/// will, so a stray byte must route to the truth-scan rebuild, never deny a
/// read that truth can answer.
fn tolerate_undecodable<T>(result: Result<Option<T>>) -> Result<Option<T>> {
    match result {
        Err(Error::Store(StoreError::SideTableRow {
            problem: SideTableRowProblem::Undecodable,
            ..
        })) => Ok(None),
        other => other,
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
    let Some(raw) = vault.store.port_entity_record(rtxn, head)? else {
        return Ok(None);
    };

    if raw.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let Ok(body) = crate::claim::decode_claim_body(raw.body.get(0..).unwrap_or(&[]), true) else {
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
    let Some(raw) = vault.store.port_entity_record(rtxn, id)? else {
        return Ok(false);
    };

    if raw.entity_type != ENTITY_TYPE_PERSON {
        return Ok(false);
    }
    Ok(provider_key_from_actor_body(raw.body.get(0..).unwrap_or(&[])).as_deref() == Some(provider))
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
        .port_entity_ids_by_type(rtxn, ENTITY_TYPE_PERSON, None)?
    {
        let id = entry?;
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
    let mutation_recorded_at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    // Writes cannot use the read-side staleness bound. Even a valid cached
    // actor must not hide a stranded prior on another matching shell. Check
    // provider-wide truth before resolving, repairing indexes, or minting.
    provider_actors_for_key_in_txn(vault, &*wtxn, provider)?;
    if let Some(actor) = resolve_provider_actor_in_txn(vault, wtxn, provider)? {
        return Ok(actor);
    }

    let digest = provider_key_hash(provider);
    let id = vault.store.clock.entity_id()?;
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
            learned_at: mutation_recorded_at,
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
    PROVIDER_ACTOR_INDEX.put(&vault.store, wtxn, &digest, &id)?;
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
    let digest = provider_key_hash(provider);
    if let Some(cached) =
        tolerate_undecodable(PROVIDER_ACTOR_INDEX.get(&vault.store, &*wtxn, &digest))?
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
    PROVIDER_ACTOR_INDEX.put(&vault.store, wtxn, &digest, &actor)?;
    Ok(Some(actor))
}

/// `sha256(provider)` — a fixed-width key so an arbitrary 512-byte provider
/// key cannot shape the key space. Shared by both provider-confidence
/// shortcut tables: a provider's digest is the same row-address suffix under
/// either table's own prefix.
pub(super) fn provider_key_hash(provider: &str) -> [u8; 32] {
    Sha256::digest(provider.as_bytes()).into()
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
        let digest = provider_key_hash(provider);
        PROVIDER_ACTOR_INDEX.delete(&vault.store, wtxn, &digest)?;
        PROVIDER_PRIOR_HEAD_INDEX.delete(&vault.store, wtxn, &digest)?;
        Ok(())
    })
}

/// `(actor row present, prior-head row present)` for `provider`.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn provider_confidence_index_presence(vault: &Vault, provider: &str) -> Result<(bool, bool)> {
    validate_provider_key(provider)?;
    let rtxn = vault.store.env.read_txn()?;
    let digest = provider_key_hash(provider);
    Ok((
        PROVIDER_ACTOR_INDEX.contains(&vault.store, &rtxn, &digest)?,
        PROVIDER_PRIOR_HEAD_INDEX.contains(&vault.store, &rtxn, &digest)?,
    ))
}

/// Overwrites both shortcut rows for `provider` with raw bytes; `None` deletes.
///
/// Total in both slots on purpose — a partial setter would need to READ the
/// row it is leaving alone, which is the one thing a raw seam must not teach
/// its caller.
///
/// Plants the row's VALUE bytes through `put_undecodable` rather than the
/// typed tables' `put`: the whole point of this seam is to plant bytes a real
/// write could never produce (wrong length, foreign entity ids) so a reader
/// can be proven tolerant of them.
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
        let digest = provider_key_hash(provider);
        for (table, value) in [
            (PROVIDER_ACTOR_INDEX, actor_row),
            (PROVIDER_PRIOR_HEAD_INDEX, prior_head_row),
        ] {
            match value {
                Some(bytes) => table.put_undecodable(&vault.store, wtxn, &digest, bytes)?,
                None => {
                    table.delete(&vault.store, wtxn, &digest)?;
                }
            }
        }
        Ok(())
    })
}

#[cfg(test)]
#[path = "prior_projection_tests.rs"]
mod tests;
