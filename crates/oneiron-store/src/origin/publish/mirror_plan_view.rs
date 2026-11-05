//! The read of one automatic mirror push plan (FIX 7175;
//! `vault.code.origin.mirror.plan`): what a `schedule` or `full_auto` run
//! froze, where each of its refs and batches stands, and one page of its
//! review, as `ORIGIN_MIRROR_WORK` keeps them. The mirror row's automation
//! status names only the newest plan; this names any plan the mirror keeps.

use serde::{Deserialize, Serialize};

use crate::origin::mirror_auto::OriginMirrorPendingCheck;
use crate::origin::mirror_strategy::OriginMirrorSyncStrategy;
use crate::origin::publish::mirror_plan_types::MirrorBatchClaim;
use crate::origin::publish::mirror_plan_types::MirrorObservedTip;
use crate::origin::publish::mirror_plan_types::MirrorRefOutcome;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// Reads one automatic plan of a served repository's mirror.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginMirrorPlanRequest {
    pub repo: String,
    /// The plan; absent: the mirror's open plan, else the one it settled
    /// last.
    #[serde(default)]
    pub plan_id: Option<EntityId>,
    /// The review page, from 0.
    #[serde(default)]
    pub page: u64,
}

/// One batch of a plan.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorPlanBatchView {
    pub claim: MirrorBatchClaim,
    /// Its refs, as indexes into the plan's refs.
    pub refs: Vec<u32>,
    /// The redacted cause of its last child that did not succeed.
    pub detail: Option<String>,
}
