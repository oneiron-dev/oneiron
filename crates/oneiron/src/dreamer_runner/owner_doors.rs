//! The owner's doors over the private Dreamer runner (DOOR-101): which node
//! this runner holds as the elected MACRO home, the candidates its election
//! ranks (the vault's authorized home candidacies and its host's own, FIX
//! 4898), the owner's home pick as every linked machine folds it, and one
//! consolidation job's retry chain
//! with a page of its committed steps; and the owner's pick of the home node
//! (PR2a), a signed act on the vault's main authority log. Each read
//! revalidates the owner in its one read transaction and reads everything in
//! that snapshot; the reads elect, mint, lease, resume and hand off nothing,
//! and do not claim that a peer holds the same. A pick re-elects this node's
//! home where it lands, and moves no job, lease or budget.
//!
//! Node ids are decimal strings on the wire: a `u64` past 2^53 does not
//! survive a JavaScript number.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::store::{DreamerRunnerStore, PARKED, decode_dreamer_attempt_status};
use super::types::{DreamerHomeNodeCandidate, DreamerHomeNodeDesignation};
use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptRecord, AttemptResultRef, AttemptResumePoint, AttemptState,
};
use crate::authority::{ActAuthority, ActSurface, HomePickState};
use crate::consent::AuthenticatedOwner;
use crate::engine_executor::checkpoint_read::{
    CHECKPOINT_READ_DEFAULT_LIMIT, CHECKPOINT_READ_MAX_LIMIT,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::memory::{DreamerParkedAttemptView, MemoryError, MemoryResult};

#[doc(hidden)]
use oneiron_verb_wire::dreamer_runner::owner_doors::hex32;
#[doc(hidden)]
pub use oneiron_verb_wire::dreamer_runner::owner_doors::{
    ConsolidationHomeCandidate, ConsolidationHomeNode, ConsolidationHomePickHead,
    ConsolidationHomePickReceipt, ConsolidationHomePickRequest, ConsolidationHomeView,
    ConsolidationLineageRequest, ConsolidationLineageView, ConsolidationStepRef,
    ConsolidationTryView,
};

/// Reads, as the vault owner, this node's MACRO home designation, the
/// candidates its election ranks (the one source the election reads) and
/// this install's sync client id in one read transaction. It elects, mints,
/// signs and wakes nothing.
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
    let runner = DreamerRunnerStore::new(vault);
    let home = runner.home_node_designation_in_txn(&txn)?.map(home_node);
    let local = runner.home_candidates_in_txn(&txn)?;
    let declared = crate::authority::home_candidacies_in_txn(vault, &txn)?;
    let candidates =
        super::home::HomeCandidates::of(&declared, local.as_deref().unwrap_or_default()).candidates;
    let picks = PickView::of(&crate::authority::home_pick_in_txn(vault, &txn)?);
    Ok(ConsolidationHomeView {
        home,
        this_node: crate::identity::read_client_id_in_txn(vault, &txn)?.map(|id| id.to_string()),
        candidates_available: local.is_some() || !candidates.is_empty(),
        candidates: candidates.into_iter().map(home_candidate).collect(),
        pick: picks.pick,
        revision: picks.revision,
        heads: picks.heads,
        conflict: picks.conflict,
    })
}

/// Picks, as the vault owner, the node that runs his vault's MACRO
/// consolidation, or clears the pick: a signed owner act on the vault's main
/// authority log, which every linked machine folds and re-elects over its
/// own candidates. `surface` is where he said so, for audit only. The
/// pick is recorded whether or not this machine knows the node; its landing
/// re-elects this machine's home in the same transaction. No admitted call,
/// lease or budget moves. A `seen` revision makes the pick land only over
/// the live picks the owner was shown.
///
/// # Errors
///
/// `BAD_REQUEST` for a node id that is not a nonzero decimal string of ASCII
/// digits within `u64`, or a `seen` that is not 64 hex; a concurrent-write
/// refusal when `seen` is no longer the live picks' revision (read
/// `vault.consolidation.home.get` again); a stale owner proof; an install
/// that cannot carry the act; storage errors.
pub fn consolidation_home_pick_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: ConsolidationHomePickRequest,
) -> MemoryResult<ConsolidationHomePickReceipt> {
    let node_id = input.node_id.as_deref().map(parse_node_id).transpose()?;
    let seen = input.seen.as_deref().map(parse_revision).transpose()?;
    let authority = ActAuthority::Owner(owner.clone(), surface);
    let landed = vault.set_home_pick_as(&authority, node_id, seen)?;
    let picks = PickView::of(&landed.state);
    Ok(ConsolidationHomePickReceipt {
        pick: picks.pick,
        act_ref: bytes_to_hex_lower(&landed.act),
        revision: picks.revision,
        heads: picks.heads,
        conflict: picks.conflict,
        home: landed.home.map(home_node),
    })
}

/// A node id as the wire carries it: ASCII digits only (no sign, space,
/// leading zero or number form), within `u64`, never zero.
fn parse_node_id(text: &str) -> MemoryResult<u64> {
    let refused = || {
        MemoryError::bad_request(
            "node_id is a nonzero decimal string of ASCII digits, at most 18446744073709551615",
        )
    };
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(refused());
    }
    text.parse().map_err(|_| refused())
}

/// A pick revision as the home doors show it: 64 hex digits.
fn parse_revision(text: &str) -> MemoryResult<[u8; 32]> {
    hex32(text).ok_or_else(|| MemoryError::bad_request("seen is a 64-hex home pick revision"))
}

fn home_candidate(candidate: DreamerHomeNodeCandidate) -> ConsolidationHomeCandidate {
    ConsolidationHomeCandidate {
        node_id: candidate.node_id.to_string(),
        class: candidate
            .designation_class()
            .map(|class| class.as_str().to_owned()),
        cloud: candidate.cloud,
        attached: candidate.attached,
        always_on_local: candidate.always_on_local,
        primary_device: candidate.primary_device,
    }
}

fn home_node(home: DreamerHomeNodeDesignation) -> ConsolidationHomeNode {
    ConsolidationHomeNode {
        node_id: home.node_id.to_string(),
        class: home.class.as_str().to_owned(),
        elected_at: home.elected_at,
    }
}

/// The owner's pick state as both home doors show it.
struct PickView {
    pick: Option<String>,
    revision: String,
    heads: Vec<ConsolidationHomePickHead>,
    conflict: Vec<ConsolidationHomePickHead>,
}

impl PickView {
    fn of(state: &HomePickState) -> Self {
        let head = |head: &crate::authority::HomePickHead| ConsolidationHomePickHead {
            act_ref: bytes_to_hex_lower(&head.act),
            machine: head.machine,
            node_id: head.choice.map(|node| node.to_string()),
            at: head.at,
        };
        Self {
            pick: state.pick().map(|node| node.to_string()),
            revision: bytes_to_hex_lower(&state.revision),
            heads: state.heads.iter().map(head).collect(),
            conflict: state.conflict.iter().map(head).collect(),
        }
    }
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
    // An answer the read adds: a queue that does not read leaves it unknown
    // and fails nothing the read answered before (FIX 4906).
    let latest_job_ref = store
        .attempts
        .newest_retry_in_txn(&txn, job)
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "the consolidation lineage's newest try did not read");
            None
        })
        .map(job_hex);
    let (steps, next_step) =
        crate::llm::committed_steps_in_txn(vault, &txn, job, input.from_step.as_deref(), limit)?;
    Ok(Some(ConsolidationLineageView {
        job_ref: job_hex(job),
        tries,
        chain_complete,
        latest_job_ref,
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
