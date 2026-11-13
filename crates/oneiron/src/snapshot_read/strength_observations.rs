//! Bounded pages of the Dreamer's strength observations, with the effective
//! strength policy and scoring config from the same read transaction.
//!
//! The owner reads under its proof. A live Steward reader reads only claims
//! and sources its grant and scoped read both reach. A withheld source carries
//! no id, position or detail, so the page never reveals whether an unread
//! source moved. An unread claim is absent: it changes no page, whatever the
//! cursor.

use std::collections::BTreeSet;
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use crate::claim::{ClaimReadStatus, ScopedRead, ScopedReadResult};
use crate::dreamer_consolidation::selection::{SelectionConfig, selection_config_pin_in_txn};
use crate::dreamer_consolidation::strength::{
    ConsolidationStrengthPolicy, OBSERVATIONS, StrengthObservations, observation_pin_in_txn,
    policy_in_txn, strength_policy_pin_in_txn,
};
use crate::dreamer_runner::DreamerAttemptBinding;
use crate::federation::{Scope, grant_scope, holds_system_agent_grant, steward_reach_in};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EntityId, Result, Vault};

/// The next observation page, bounded by the effective snapshot page settings.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StrengthObservationsPageRequest {
    /// The preceding page's opaque cursor; absent on the first page.
    pub cursor: Option<String>,
    /// The most claims served, capped at the effective page row bound.
    pub limit: Option<u32>,
}

/// One observation page and the policy and config it was read under.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrengthObservationsPage {
    pub policy: ConsolidationStrengthPolicy,
    pub policy_pin: String,
    pub config: SelectionConfig,
    pub config_pin: String,
    pub claims: Vec<ObservedClaim>,
    pub next: Option<String>,
}

/// Whether all observed sources still read at their observed revisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedClaimStatus {
    Current,
    Moved,
    Withheld,
}

/// An observed claim whose own row reads for this caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedClaim {
    pub claim: String,
    pub predicate: String,
    pub last_activity_ms: u64,
    pub status: ObservedClaimStatus,
    /// The readable sources in id order, then one bare entry per withheld one.
    pub sources: Vec<ObservedSource>,
    /// The full source list exceeds an otherwise empty page's byte bound.
    pub sources_omitted: bool,
    pub signals: Option<ObservedSignals>,
    pub pin: Option<String>,
}

/// A source's coarse status; withheld sources disclose nothing else, and are
/// served after every readable one so their place in the id order stays unread.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ObservedSource {
    Current { source: String },
    Moved { source: String },
    Withheld,
}

/// The native strength scorer's evidence inputs, without per-source detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedSignals {
    pub source_count: usize,
    pub latest_learned_at_ms: u64,
    pub distinct_diversity: usize,
}

/// Reads observations through the caller's live reach and scoped read.
///
/// As with snapshot pages, the byte bound counts encoded rows, not the
/// envelope. Unread claims are skipped and counted nowhere; the cursor names
/// the last served claim, and a full page sets it only when a later claim
/// reads, so no unread row changes the answer. Source lists too large for an
/// empty page are omitted only after their complete status and signals are
/// judged.
///
/// # Errors
///
/// No owner proof or live Steward read grant, an invalid cursor, a byte bound
/// too small even for a claim with its sources omitted, and storage failures.
pub fn strength_observations_page(
    memory: &Memory<'_>,
    input: &StrengthObservationsPageRequest,
) -> MemoryResult<ScopedReadResult<StrengthObservationsPage>> {
    observations_page(memory, input, None)
}

/// [`strength_observations_page`] for a strength attempt's bound client
/// (untangle 6.9c PR 3): `binding` is proved in the page's own read, before
/// any row of it is read.
///
/// # Errors
///
/// As [`strength_observations_page`], and the binding's refusals.
pub(crate) fn strength_observations_page_bound(
    memory: &Memory<'_>,
    input: &StrengthObservationsPageRequest,
    binding: &DreamerAttemptBinding,
) -> MemoryResult<ScopedReadResult<StrengthObservationsPage>> {
    observations_page(memory, input, Some(binding))
}

/// The one page body, with the binding of a bound call to prove in its read.
fn observations_page(
    memory: &Memory<'_>,
    input: &StrengthObservationsPageRequest,
    binding: Option<&DreamerAttemptBinding>,
) -> MemoryResult<ScopedReadResult<StrengthObservationsPage>> {
    let vault = memory.vault();
    let owner = memory
        .embedded_owner("vault.consolidation.strength.observations.page")
        .ok();
    let bounds = vault.snapshot_read_settings()?;
    let limit = input
        .limit
        .unwrap_or(bounds.page_rows)
        .min(bounds.page_rows)
        .max(1);
    let after = observation_cursor_key(input.cursor.as_deref())?;
    let read = memory.read_lane(ClaimReadStatus::Recorded)?;
    let _pins = read.prepare_point_read::<MemoryError>()?;
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    memory.prove_read_authority_in_txn(&txn)?;
    if let Some(binding) = binding {
        binding.check_in_txn(&txn)?;
    }
    let scope = observation_reader_scope_in_txn(memory, &txn, owner.as_ref())?;
    read.read_projected_in_txn(&txn, &[], None, |txn, _| {
        let mut page = StrengthObservationsPage {
            policy: policy_in_txn(vault, txn)?,
            policy_pin: strength_policy_pin_in_txn(vault, txn)?,
            config: vault.consolidation_selection_in_txn(txn)?,
            config_pin: selection_config_pin_in_txn(vault, txn)?,
            claims: Vec::new(),
            next: None,
        };
        let start = after.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
        let mut rows = OBSERVATIONS.iter_range(&vault.store, txn, start, Bound::Unbounded)?;
        let mut bytes = 0u64;
        let mut shown = after;
        while let Some(entry) = rows.next() {
            let (id, observations) = entry?;
            let Some(mut claim) =
                observed_claim_in_txn(vault, txn, &read, scope.as_ref(), id, observations)?
            else {
                continue;
            };
            let mut size = serde_json::to_vec(&claim)
                .map_err(|error| MemoryError::bad_request(error.to_string()))?
                .len() as u64;
            if page.claims.is_empty() && size > bounds.page_bytes {
                claim.sources.clear();
                claim.sources_omitted = true;
                size = serde_json::to_vec(&claim)
                    .map_err(|error| MemoryError::bad_request(error.to_string()))?
                    .len() as u64;
                if size > bounds.page_bytes {
                    return Err(MemoryError::bad_request(
                        "the snapshot page byte bound cannot hold the observed claim without its sources",
                    ));
                }
            }
            if bytes.saturating_add(size) > bounds.page_bytes {
                page.next = shown.map(|key| format!("strength-observations:{}", key.to_hex()));
                break;
            }
            bytes = bytes.saturating_add(size);
            page.claims.push(claim);
            shown = Some(id);
            if page.claims.len() as u64 >= u64::from(limit) {
                let mut later = false;
                for entry in rows.by_ref() {
                    let (later_id, _) = entry?;
                    if observed_claim_reads_in_txn(vault, txn, &read, scope.as_ref(), later_id)? {
                        later = true;
                        break;
                    }
                }
                page.next = later.then(|| format!("strength-observations:{}", id.to_hex()));
                break;
            }
        }
        Ok(page)
    })
}

/// The live grant's record scope, or the whole vault for the proven owner
/// and a base agent whose manifest rows still stand in place of a grant.
fn observation_reader_scope_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    owner: Option<&crate::consent::AuthenticatedOwner>,
) -> MemoryResult<Option<Scope>> {
    let vault = memory.vault();
    if let Some(owner) = owner {
        owner.revalidate_as_vault_owner_in_txn(vault, txn)?;
        return Ok(None);
    }
    match observation_reader_scope_for_actor_in_txn(vault, txn, memory.actor())? {
        Some(scope) => Ok(scope),
        None => Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "strength observations read for the owner under its proof or a live Steward reader",
            &[],
        )),
    }
}

/// A non-owner actor's record scope in `txn`: the standing reach's scope
/// with `read` and, for a base agent, a live MACHINE binding; the whole
/// vault for a base agent with no row; else no read reach. `None` is no
/// read, `Some(None)` the whole vault, `Some(Some)` the grant's scope.
pub(crate) fn observation_reader_scope_for_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<Option<Option<Scope>>> {
    let base = holds_system_agent_grant(actor);
    match steward_reach_in(&vault.store, txn, actor)? {
        Some(reach)
            if reach.verbs.contains(grant_scope::STEWARD_READ_VERB)
                && (!base || vault.system_agent_binding_live_in(txn, actor)?) =>
        {
            Ok(Some(Some(reach.scope)))
        }
        None if base => Ok(Some(None)),
        _ => Ok(None),
    }
}

fn observation_record_reached_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: Option<&Scope>,
    id: EntityId,
) -> Result<bool> {
    match scope {
        Some(scope) => crate::gate::reaches_target(
            &vault.store,
            txn,
            scope,
            grant_scope::STEWARD_READ_VERB,
            id,
        ),
        None => Ok(true),
    }
}

/// Whether the observed claim's own row reads for this caller: the scope
/// reaches its record and the scoped read finds it live.
fn observed_claim_reads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    scope: Option<&Scope>,
    id: EntityId,
) -> Result<bool> {
    Ok(observation_record_reached_in_txn(vault, txn, scope, id)?
        && read.entity_raw_live_in(txn, &id)?.is_some())
}

fn observed_claim_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    scope: Option<&Scope>,
    id: EntityId,
    observations: StrengthObservations,
) -> Result<Option<ObservedClaim>> {
    if !observed_claim_reads_in_txn(vault, txn, read, scope, id)? {
        return Ok(None);
    }
    let (status, sources) =
        classify_observation_sources_in_txn(vault, txn, read, scope, &observations)?;
    let current = status == ObservedClaimStatus::Current;
    let signals = current.then(|| {
        let diversity: BTreeSet<_> = observations
            .sources
            .iter()
            .filter_map(|source| source.diversity.as_ref())
            .collect();
        ObservedSignals {
            source_count: observations.sources.len(),
            latest_learned_at_ms: observations
                .sources
                .iter()
                .map(|source| source.learned_at_ms)
                .max()
                .unwrap_or_default(),
            distinct_diversity: diversity.len(),
        }
    });
    let pin = if current {
        observation_pin_in_txn(vault, txn, &id)?
    } else {
        None
    };
    Ok(Some(ObservedClaim {
        claim: id.to_hex(),
        predicate: observations.predicate,
        last_activity_ms: observations.last_activity_ms,
        status,
        sources,
        sources_omitted: false,
        signals,
        pin,
    }))
}

/// Each stored source as the caller reads it now: current at its observed
/// revision, moved, or withheld with no id, position or detail (the
/// readable sources in id order, then the withheld ones). Withheld dominates
/// moved. The page and the archive item judge by this one helper.
pub(crate) fn classify_observation_sources_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    scope: Option<&Scope>,
    observations: &StrengthObservations,
) -> Result<(ObservedClaimStatus, Vec<ObservedSource>)> {
    let mut sources = Vec::with_capacity(observations.sources.len());
    let mut withheld = 0usize;
    let mut status = ObservedClaimStatus::Current;
    for source in &observations.sources {
        let raw = if observation_record_reached_in_txn(vault, txn, scope, source.source)? {
            read.entity_raw_live_in(txn, &source.source)?
        } else {
            None
        };
        let served = match raw {
            None => {
                status = ObservedClaimStatus::Withheld;
                withheld = withheld.saturating_add(1);
                continue;
            }
            Some(raw) if *blake3::hash(&raw).as_bytes() == source.revision => {
                ObservedSource::Current {
                    source: source.source.to_hex(),
                }
            }
            Some(_) => {
                if status != ObservedClaimStatus::Withheld {
                    status = ObservedClaimStatus::Moved;
                }
                ObservedSource::Moved {
                    source: source.source.to_hex(),
                }
            }
        };
        sources.push(served);
    }
    sources.extend(std::iter::repeat_n(ObservedSource::Withheld, withheld));
    Ok((status, sources))
}

fn observation_cursor_key(cursor: Option<&str>) -> MemoryResult<Option<EntityId>> {
    cursor
        .map(|cursor| {
            let hex = cursor
                .strip_prefix("strength-observations:")
                .ok_or_else(|| MemoryError::bad_request("invalid strength observation cursor"))?;
            EntityId::from_hex(hex)
                .map_err(|_| MemoryError::bad_request("invalid strength observation cursor"))
        })
        .transpose()
}
