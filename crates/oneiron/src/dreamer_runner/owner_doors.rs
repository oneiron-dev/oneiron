//! The owner's reads of the private Dreamer runner (DOOR-101): which node
//! this runner holds as the elected MACRO home, and one consolidation job's
//! retry chain with a page of its committed steps. Each read revalidates the
//! owner in its one read transaction and reads everything in that snapshot.
//! Nothing is elected, minted, leased, resumed or handed off: these observe
//! this node's runner rows and do not claim that a peer holds the same.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::store::{DreamerRunnerStore, PARKED, decode_dreamer_attempt_status};
use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptRecord, AttemptResultRef, AttemptResumePoint, AttemptState,
};
use crate::consent::AuthenticatedOwner;
use crate::engine_executor::checkpoint_read::{
    CHECKPOINT_READ_DEFAULT_LIMIT, CHECKPOINT_READ_MAX_LIMIT,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::memory::{DreamerParkedAttemptView, MemoryError, MemoryResult};

/// The elected MACRO home as this node's private runner row records it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationHomeNode {
    /// The home's stable sync client id.
    pub node_id: u64,
    /// The election class that placed it: `cloud_attached`,
    /// `always_on_local` or `primary_device`.
    pub class: String,
    /// Unix seconds; a re-election of the same winner keeps its first time.
    pub elected_at: u64,
}

/// What this node's runner knows of the single MACRO home (ARCH-0026).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationHomeView {
    /// `None` while no election has placed a home in this node's runner.
    pub home: Option<ConsolidationHomeNode>,
    /// This install's stable sync client id, read without minting one:
    /// `None` before this install has an id.
    pub this_node: Option<u64>,
    /// Whether the candidate set the election ranked can be read. `false`
    /// today: the candidates live only in the sync topology's in-memory
    /// watch and are never persisted, so none is reported, and none is
    /// inferred from the winner.
    pub candidates_available: bool,
}

/// One consolidation job's lineage, with a page of its committed steps.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationLineageRequest {
    /// 32-hex attempt id (`job:` prefix allowed), as
    /// `vault.consolidation.status` names it.
    pub job_ref: String,
    /// 64-hex step hash the page starts at, inclusive.
    #[serde(default)]
    pub from_step: Option<String>,
    /// Steps in this page: `vault.runs.checkpoint`'s default when absent,
    /// at most its ceiling. Must be positive.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One job's retry chain and a page of the requested try's committed steps.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationLineageView {
    /// 32-hex attempt id of the requested try.
    pub job_ref: String,
    /// The requested try, then each try it retries, back to the root.
    pub tries: Vec<ConsolidationTryView>,
    /// False when the walk stopped before a try that retries none: a
    /// predecessor this node no longer holds, or a link back into the chain.
    pub chain_complete: bool,
    /// The requested try's committed steps, in step-hash order.
    pub steps: Vec<ConsolidationStepRef>,
    /// Where the next page starts; none past the last step.
    pub next_step: Option<String>,
}

/// One try of a consolidation job, as its queue row and park row hold it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationTryView {
    /// 32-hex attempt id.
    pub job_ref: String,
    /// Queue attempt kind.
    pub kind: String,
    pub state: AttemptState,
    /// Run correlation id, if any.
    pub run_id: Option<String>,
    /// 32-hex id of the attempt that spawned this one, if any.
    pub parent_attempt: Option<String>,
    /// 32-hex id of the try this one retries, if any.
    pub retry_of: Option<String>,
    /// Tries of this lineage a compaction deleted between this one and
    /// `retry_of`, or before it when it retries none.
    pub folded_retries: u32,
    /// The lease fence within this one try, not a retry count: each retry
    /// is its own try in `tries`.
    pub attempt_count: u32,
    /// The runner's worker label holding the lease, never a node id.
    pub lease_owner: Option<String>,
    /// The artifact version this try's durable output lives in.
    pub result_ref: Option<String>,
    /// The point a successor resumes from, once recorded.
    pub resume_point: Option<AttemptResumePoint>,
    /// The try's park, when the runner parked it.
    pub parked: Option<DreamerParkedAttemptView>,
}

/// One committed step, by refs; `vault.runs.step` reads its response.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationStepRef {
    /// 64-hex canonical request hash.
    pub step_hash: String,
    /// The terminal `dreamer.step` claim that settled it.
    pub claim_ref: EntityId,
}

/// Reads, as the vault owner, this node's MACRO home designation and this
/// install's sync client id in one read transaction. It elects, mints and
/// wakes nothing.
///
/// # Errors
///
/// A stale owner proof; storage errors.
pub fn consolidation_home_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> MemoryResult<ConsolidationHomeView> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    owner.revalidate_in_txn(vault, &txn)?;
    let home = DreamerRunnerStore::new(vault)
        .home_node_designation_in_txn(&txn)?
        .map(|home| ConsolidationHomeNode {
            node_id: home.node_id,
            class: home.class.as_str().to_owned(),
            elected_at: home.elected_at,
        });
    Ok(ConsolidationHomeView {
        home,
        this_node: crate::identity::read_client_id_in_txn(vault, &txn)?,
        candidates_available: false,
    })
}

/// Reads, as the vault owner, one consolidation job's retry chain and a page
/// of its committed steps in one read transaction. An unknown job reads as
/// absent, as `vault.consolidation.status` does.
///
/// # Errors
///
/// `BAD_REQUEST` for a malformed job ref or step cursor, or a zero limit; a
/// stale owner proof; a try that is not a Dreamer attempt; storage errors.
pub fn consolidation_lineage_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ConsolidationLineageRequest,
) -> MemoryResult<Option<ConsolidationLineageView>> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    owner.revalidate_in_txn(vault, &txn)?;
    let job = crate::memory::parse_job_ref(&input.job_ref)?;
    let limit = owner_read_page_limit(input.limit)
        .ok_or_else(|| MemoryError::bad_request("limit must be positive"))?;
    let store = DreamerRunnerStore::new(vault);
    let Some(record) = store.attempts.get_in_txn(&txn, job)? else {
        return Ok(None);
    };
    let (tries, chain_complete) = retry_chain(&store, &txn, record)?;
    let (steps, next_step) =
        crate::llm::committed_steps_in_txn(vault, &txn, job, input.from_step.as_deref(), limit)?;
    Ok(Some(ConsolidationLineageView {
        job_ref: job_hex(job),
        tries,
        chain_complete,
        steps: steps
            .into_iter()
            .map(|(step_hash, claim_ref)| ConsolidationStepRef {
                step_hash,
                claim_ref,
            })
            .collect(),
        next_step,
    }))
}

/// A page's row count under `vault.runs.checkpoint`'s convention: its
/// default when absent, at most its ceiling; `None` for zero, which refuses.
pub(crate) fn owner_read_page_limit(limit: Option<u32>) -> Option<usize> {
    let limit = match limit {
        Some(0) => return None,
        Some(limit) => limit.min(CHECKPOINT_READ_MAX_LIMIT),
        None => CHECKPOINT_READ_DEFAULT_LIMIT,
    };
    usize::try_from(limit).ok()
}

/// `record`, then each try it retries, and whether the walk reached a try
/// that retries none. A predecessor this node no longer holds, or a link
/// back into the chain, ends the walk.
fn retry_chain(
    store: &DreamerRunnerStore<'_>,
    txn: &heed::RoTxn<'_>,
    record: AttemptRecord,
) -> MemoryResult<(Vec<ConsolidationTryView>, bool)> {
    let mut seen = HashSet::from([record.id]);
    let mut tries = Vec::new();
    let mut current = record;
    loop {
        let retry_of = current.retry_of;
        tries.push(try_view(store, txn, current)?);
        let Some(predecessor) = retry_of else {
            return Ok((tries, true));
        };
        if !seen.insert(predecessor) {
            return Ok((tries, false));
        }
        let Some(row) = store.attempts.get_in_txn(txn, predecessor)? else {
            return Ok((tries, false));
        };
        current = row;
    }
}

fn try_view(
    store: &DreamerRunnerStore<'_>,
    txn: &heed::RoTxn<'_>,
    record: AttemptRecord,
) -> MemoryResult<ConsolidationTryView> {
    let parked = PARKED.get(&store.vault.store, txn, &record.id)?;
    let status = decode_dreamer_attempt_status(record)?;
    let attempt = status.attempt;
    let resume_point = attempt.resume_point().cloned();
    Ok(ConsolidationTryView {
        job_ref: job_hex(attempt.id),
        kind: attempt.kind,
        state: attempt.state,
        run_id: attempt.run_id,
        parent_attempt: status.payload.parent_attempt.map(job_hex),
        retry_of: attempt.retry_of.map(job_hex),
        folded_retries: attempt.folded_retries,
        attempt_count: attempt.attempt_count,
        lease_owner: attempt.lease_owner,
        result_ref: attempt.result_ref.map(AttemptResultRef::into_string),
        resume_point,
        parked: parked.map(|park| DreamerParkedAttemptView {
            job_ref: job_hex(park.attempt_id),
            cause: park.cause.into(),
            parked_at: park.parked_at,
        }),
    })
}

fn job_hex(id: AttemptId) -> String {
    bytes_to_hex_lower(id.as_bytes())
}
