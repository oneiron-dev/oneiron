//! The `vault.gpu.lines.*` verbs' inputs and answers (design pass 32,
//! section 5). Ids travel as lower hex, as every entity reference does.
use serde::{Deserialize, Serialize};

use super::fold::{BudgetPolicy, GpuLine, GpuLinePeriod, Track};
use super::preset::LinePresetRef;
use super::store::gpu_seconds;
use crate::EntityId;
use crate::federation::WalletRef;
use crate::llm::run_admission::LeaseUnit;

/// The owner's policy for one lane's GPU time: every field of a line but its
/// seats, which `vault.gpu.lines.families.admit` writes. A budget field left
/// out takes the engine's neutral default (`gpu_line::defaults`); the period,
/// the allowance and the rung caps have none. A lane's numbers come in its
/// preset document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GpuLinePolicy {
    /// The unit the line counts in; each managed offer's `cost_unit` equals
    /// it. `gpu_seconds` when left out.
    #[serde(default = "gpu_seconds")]
    pub unit: LeaseUnit,
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
    pub period_secs: u64,
    /// The start of period 0, in milliseconds of the vault's clock; fixed
    /// once a period is minted.
    pub period_anchor_ms: u64,
    /// Applies from the next mint.
    pub budget: BudgetPolicy,
}

/// The fields of a [`GpuLinePolicy`] the owner states to `vault.gpu.lines.set`,
/// as one JSON object. With no preset they are the whole policy, read as it
/// always was; with a preset, each field he states replaces the preset's
/// (inside `budget`, field by field), so he states the wallet, the anchor, the
/// lists and only the budget fields that differ (pass 34, 3.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GpuLinePolicyFields(pub serde_json::Map<String, serde_json::Value>);

impl From<&GpuLinePolicy> for GpuLinePolicyFields {
    /// Every field of `policy`: the whole policy, as an owner with no preset
    /// states it.
    fn from(policy: &GpuLinePolicy) -> Self {
        match serde_json::to_value(policy) {
            Ok(serde_json::Value::Object(fields)) => Self(fields),
            _ => Self::default(),
        }
    }
}

/// [`GpuLinePolicy`]'s schema with no field required: a preset may give any of
/// them, and the door checks the whole.
impl schemars::JsonSchema for GpuLinePolicyFields {
    fn schema_name() -> String {
        "GpuLinePolicyFields".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        let mut schema = <GpuLinePolicy as schemars::JsonSchema>::json_schema(generator);
        if let schemars::schema::Schema::Object(object) = &mut schema
            && let Some(validation) = object.object.as_mut()
        {
            validation.required.clear();
        }
        schema
    }
}

/// `vault.gpu.lines.set` with the policy stated whole: the owner sets the
/// policy of one lane project's GPU line. The budget applies from the next
/// mint; the offers, machines and role lists at once. The verb takes
/// [`GpuLineSetWire`], which may also name a preset.
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

/// `vault.gpu.lines.set` as the verb takes it: the owner sets the policy of
/// one lane project's GPU line, stated whole or laid over a lane's preset
/// (pass 34, 3.2). The budget applies from the next mint; the offers,
/// machines and role lists at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GpuLineSetWire {
    /// As in [`GpuLineSetRequest::intent_key`].
    pub intent_key: String,
    /// The lane project.
    pub project: EntityId,
    /// The lane preset the policy starts from: a line policy document of an
    /// installed pack, named by its digest. The line keeps the reference
    /// beside the full values; a later version of the pack changes no value
    /// in force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<LinePresetRef>,
    pub policy: GpuLinePolicyFields,
}

impl From<&GpuLineSetRequest> for GpuLineSetWire {
    /// The whole policy, with no preset.
    fn from(request: &GpuLineSetRequest) -> Self {
        Self {
            intent_key: request.intent_key.clone(),
            project: request.project,
            preset: None,
            policy: GpuLinePolicyFields::from(&request.policy),
        }
    }
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
