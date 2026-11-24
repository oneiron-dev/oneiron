//! The `vault.gpu.lines.*` verbs' inputs and answers (design pass 32,
//! section 5). Ids travel as lower hex, as every entity reference does.
use serde::{Deserialize, Serialize};

use super::fold::{GpuLine, GpuLinePeriod, InvalidCost, PayoffSeed, PinnedMode, RuleRef, Track};
use crate::EntityId;
use crate::federation::WalletRef;

/// The owner's policy for one lane's GPU time: every field of a line but its
/// seats, which `vault.gpu.lines.families.admit` writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GpuLinePolicy {
    /// The host wallet the line's allocation funds.
    pub wallet: WalletRef,
    /// The fleet's `--who` for this line.
    pub fleet_who: String,
    pub period_secs: u64,
    /// The start of period 0, in milliseconds of the vault's clock.
    pub period_anchor_ms: u64,
    /// GPU-seconds a period.
    pub allowance_units: u64,
    pub pinned_track: Track,
    /// The pinned share as [numerator, denominator].
    pub pinned_parts: [u32; 2],
    #[serde(default)]
    pub pinned_mode: PinnedMode,
    pub floor_arms: u32,
    /// The cap of each rung in seconds, rung 1 first.
    pub rung_caps_secs: Vec<u64>,
    pub forecast_required: bool,
    pub rules: Vec<RuleRef>,
    #[serde(default)]
    pub invalid_cost: InvalidCost,
    pub window_periods: u32,
    pub hosts: Vec<String>,
}

/// `vault.gpu.lines.set`: the owner sets the policy of one lane project's
/// GPU line. It takes effect at the next mint, except `hosts`, at once.
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
/// family on its GPU line.
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
    /// The family's history from the lane's own lab ledger, as a prior.
    #[serde(default)]
    pub seed: Option<PayoffSeed>,
}

/// A GPU line as its doors answer it: the line, and the record of the period
/// that holds now. Before the first write of a period touches it, the
/// record is the mint's preview (`period_minted: false`); the next write
/// door mints that same record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GpuLineView {
    pub line: GpuLine,
    /// `None` before period 0 starts.
    pub period: Option<GpuLinePeriod>,
    pub period_minted: bool,
    /// The answer of an earlier call with the same intent key and ask.
    pub replayed: bool,
}
