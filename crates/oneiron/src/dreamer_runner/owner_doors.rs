//! The owner's doors over the private Dreamer runner (DOOR-101): which node
//! this runner holds as the elected MACRO home, the host's last candidate
//! set it elected over, the owner's home pick as every linked machine folds
//! it, and one consolidation job's retry chain
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

/// The elected MACRO home as this node's private runner row records it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationHomeNode {
    /// The home's stable sync client id, as a decimal string.
    pub node_id: String,
    /// The election class that placed it: `cloud_attached`,
    /// `always_on_local` or `primary_device`.
    pub class: String,
    /// Unix seconds; a re-election of the same winner keeps its first time.
    pub elected_at: u64,
}

/// What this node's runner knows of the single MACRO home (ARCH-0026), and
/// the owner's home pick as this node folds it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationHomeView {
    /// `None` while no election has placed a home in this node's runner.
    pub home: Option<ConsolidationHomeNode>,
    /// This install's stable sync client id as a decimal string, read
    /// without minting one: `None` before this install has an id.
    pub this_node: Option<String>,
    /// Whether this node keeps a candidate set: the host's last one, which
    /// its last election ranked. `false`: no election has run here, and
    /// `candidates` is empty; none is inferred from the winner or the pick.
    pub candidates_available: bool,
    /// The host's last candidates, in the order it supplied them. A pick
    /// of a node outside them is recorded all the same; only this node's
    /// election passes over it.
    pub candidates: Vec<ConsolidationHomeCandidate>,
    /// The owner's pick (a decimal node id) the last unconflicted pick
    /// names: what he recorded, not the node elected. `None` for no pick or
    /// a clear.
    pub pick: Option<String>,
    /// 64-hex digest of the live picks, all zeros when none.
    pub revision: String,
    /// Every live pick.
    pub heads: Vec<ConsolidationHomePickHead>,
    /// The live picks in conflict, empty when none: while any conflict, the
    /// election passes over the pick, which stays recorded.
    pub conflict: Vec<ConsolidationHomePickHead>,
}

/// One node the host offered this node's election.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationHomeCandidate {
    /// The node's stable sync client id, as a decimal string.
    pub node_id: String,
    /// The election class it is eligible for now (`cloud_attached`,
    /// `always_on_local` or `primary_device`); `None` when it is not
    /// eligible (a detached cloud, or a device neither always-on nor
    /// primary), so the election passes over it even when picked.
    pub class: Option<String>,
    pub cloud: bool,
    pub attached: bool,
    pub always_on_local: bool,
    pub primary_device: bool,
}

/// One signed home pick as the owner's surface shows it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationHomePickHead {
    /// 64-hex authority entry hash of the signed pick.
    pub act_ref: String,
    /// The machine whose install key carried it.
    pub machine: EntityId,
    /// The picked node as a decimal string; `None` for a clear.
    pub node_id: Option<String>,
    /// Unix seconds the carrier stamped: advisory, for display only.
    pub at: u64,
}

/// The owner's pick of the node that runs his vault's MACRO consolidation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationHomePickRequest {
    /// The node's sync client id as a decimal string of ASCII digits, never
    /// zero; `null` clears the pick, so the default election order holds
    /// again. A node this machine does not know is recorded all the same.
    pub node_id: Option<String>,
    /// The 64-hex `revision` the owner's surface showed him, as
    /// `vault.consolidation.home.get` reads it: the pick refuses when the
    /// live picks moved since. Absent: the pick takes the current ones.
    #[serde(default)]
    pub seen: Option<String>,
}

/// One landed home pick, and this machine's home after its own re-election.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsolidationHomePickReceipt {
    /// The owner's pick (a decimal node id) the last unconflicted pick
    /// names: what he recorded, not the node elected. `None` for a clear.
    pub pick: Option<String>,
    /// 64-hex authority entry hash of the signed pick.
    pub act_ref: String,
    /// 64-hex digest of the live picks, all zeros when none.
    pub revision: String,
    /// Every live pick.
    pub heads: Vec<ConsolidationHomePickHead>,
    /// The live picks in conflict, empty when none.
    pub conflict: Vec<ConsolidationHomePickHead>,
    /// This machine's MACRO home after its own re-election over its host's
    /// last candidates; `None` while no election places one here.
    pub home: Option<ConsolidationHomeNode>,
}

impl ConsolidationHomePickReceipt {
    /// The AUTHORITY_LOG row the pick landed as, which its listing names.
    #[must_use]
    pub fn act_row(&self) -> Option<EntityId> {
        crate::authority::authority_log_entity_id_from_hash(&hex32(&self.act_ref)?).ok()
    }
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

/// Reads, as the vault owner, this node's MACRO home designation, the
/// host's last candidate set and this install's sync client id in one read
/// transaction. It elects, mints and wakes nothing.
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
    let candidates = runner.home_candidates_in_txn(&txn)?;
    let picks = PickView::of(&crate::authority::home_pick_in_txn(vault, &txn)?);
    Ok(ConsolidationHomeView {
        home,
        this_node: crate::identity::read_client_id_in_txn(vault, &txn)?.map(|id| id.to_string()),
        candidates_available: candidates.is_some(),
        candidates: candidates
            .unwrap_or_default()
            .into_iter()
            .map(home_candidate)
            .collect(),
        pick: picks.pick,
        revision: picks.revision,
        heads: picks.heads,
        conflict: picks.conflict,
    })
}

/// Picks, as the vault owner, the node that runs his vault's MACRO
/// consolidation, or clears the pick: a signed owner act on the vault's main
/// authority log, which every linked machine folds and re-elects over its
/// own host's candidates. `surface` is where he said so, for audit only. The
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

/// 32 bytes from 64 ASCII hex digits of either case.
fn hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0; 32];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
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
