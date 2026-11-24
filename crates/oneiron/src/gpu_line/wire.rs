//! The `vault.gpu.lines.*` verbs' inputs and answers (design pass 32,
//! section 5). Ids travel as lower hex, as every entity reference does.
use serde::{Deserialize, Serialize};

use super::defaults;
use super::fold::{BudgetPolicy, GpuLine, GpuLinePeriod, Track};
use crate::EntityId;
use crate::federation::WalletRef;

fn default_period_secs() -> u64 {
    defaults::PERIOD_SECS
}

/// The owner's policy for one lane's GPU time: every field of a line but its
/// seats, which `vault.gpu.lines.families.admit` writes. A field left out
/// takes its default (`gpu_line::defaults`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GpuLinePolicy {
    /// The host wallet the line's allocation funds.
    pub wallet: WalletRef,
    /// The offers the line manages. A line that names none spends nothing.
    #[serde(default)]
    pub offers: Vec<String>,
    /// The machines the line may run on.
    #[serde(default)]
    pub machines: Vec<EntityId>,
    /// Grants that hold the lead role on this line.
    #[serde(default)]
    pub leads: Vec<EntityId>,
    /// Grants that hold the reviewer role on this line.
    #[serde(default)]
    pub reviewers: Vec<EntityId>,
    /// Grants that may seat a new idea and read the line.
    #[serde(default)]
    pub planners: Vec<EntityId>,
    /// Fixed once a period is minted.
    #[serde(default = "default_period_secs")]
    pub period_secs: u64,
    /// The start of period 0, in milliseconds of the vault's clock; fixed
    /// once a period is minted.
    pub period_anchor_ms: u64,
    /// Applies from the next mint.
    #[serde(default)]
    pub budget: BudgetPolicy,
}

/// `vault.gpu.lines.set`: the owner sets the policy of one lane project's
/// GPU line. The budget applies from the next mint; the offers, machines and
/// role lists at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GpuLineSetRequest {
    /// Names this ask: the same key with the same ask answers again with
    /// `replayed: true`; with a different ask it is refused.
    pub intent_key: String,
    /// The lane project.
    pub project: EntityId,
    pub policy: GpuLinePolicy,
}

/// `vault.gpu.lines.get`: one lane project's GPU line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GpuLineRef {
    /// The lane project.
    pub project: EntityId,
}

/// `vault.gpu.lines.families.admit`: seat one child project of the lane as a
/// family on its GPU line. A seat carries no seed: the mint reads only the
/// line's own rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GpuLineFamilyAdmitRequest {
    /// As in [`GpuLineSetRequest::intent_key`].
    pub intent_key: String,
    /// The lane project.
    pub project: EntityId,
    /// The family: a child project of the lane.
    pub family: EntityId,
    pub track: Track,
}

/// A GPU line as its doors answer it: the line, and the record of the period
/// that holds now. Before the first write of a period touches it, the record
/// is the mint's preview (`preview: true`); the next write door mints that
/// same record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GpuLineView {
    pub line: GpuLine,
    /// `None` before period 0 starts. Its cohort seed is withheld until the
    /// period ends.
    pub period: Option<GpuLinePeriod>,
    pub preview: bool,
    /// The answer of an earlier call with the same intent key and ask, or
    /// of an earlier call that made the same seat.
    pub replayed: bool,
}
