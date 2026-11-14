//! Moved from `crates/oneiron/src/dreamer_runner/owner_doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::dreamer::DreamerParkedAttemptView;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_state::AttemptState;
use oneiron_wake_contract::store::attempt_cancel::AttemptResumePoint;
use serde::Deserialize;
use serde::Serialize;

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
    /// Whether this node has candidates to show: an authorized home
    /// candidacy, or a candidacy its host kept for itself. `false`: neither,
    /// and `candidates` is empty; none is inferred from the winner or the
    /// pick.
    pub candidates_available: bool,
    /// The candidates this node's election ranks, as its fold reads them
    /// now: each live owner machine's declaration that says it can run
    /// MACRO, then the host's own candidacy in the order it supplied it. A
    /// pick of a node outside them is recorded all the same; only the
    /// election passes over it until a matching declaration lands.
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

/// One node this node's election ranks.
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
    /// This machine's MACRO home after its own re-election over its
    /// candidates; `None` while no election places one here.
    pub home: Option<ConsolidationHomeNode>,
}

impl ConsolidationHomePickReceipt {
    /// The AUTHORITY_LOG row the pick landed as, which its listing names.
    #[must_use]
    pub fn act_row(&self) -> Option<EntityId> {
        oneiron_authority::authority::authority_log_entity_id_from_hash(&hex32(&self.act_ref)?).ok()
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
    /// 32-hex attempt id of the job's newest try, found by following each
    /// try's one retry forward from the requested one: the requested try
    /// itself when nothing retries it. Ask for this ref to read the newest
    /// try's chain and steps. `None` when a try has two retries, the walk
    /// meets a try twice, or the queue did not read.
    pub latest_job_ref: Option<String>,
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

/// 32 bytes from 64 ASCII hex digits of either case.
pub fn hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0; 32];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}
