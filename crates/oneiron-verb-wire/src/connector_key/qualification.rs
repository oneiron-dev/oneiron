//! Moved from `crates/oneiron/src/connector_key/qualification.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::connector_key::qualification::receipt::BUILTIN_PROBE_QUALIFICATION_SUITE;
pub use crate::connector_key::qualification::receipt::CONNECTOR_QUALIFICATION_SUITE;
pub use crate::connector_key::qualification::receipt::OWNER_ATTESTED_QUALIFICATION_SUITE;
pub use crate::connector_key::qualification::receipt::PROXY_ADMISSION_QUALIFICATION_SUITE;
pub use crate::connector_key::qualification::receipt::SETUP_CHECK_QUALIFICATION_SUITE;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProbeRequest {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QualificationLimits {
    pub tokens: u64,
    pub latency_ms: u64,
    pub budget_units: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QualificationCase {
    pub call: ProbeRequest,
    /// Out-of-scope cases must refuse or honestly report no record, never answer.
    pub in_scope: bool,
    pub allowed_predicates: BTreeSet<String>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub enum QualificationInjectionSurface {
    FetchedContent,
    ToolResult,
    ForeignAsk,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QualificationInjection {
    pub surface: QualificationInjectionSurface,
    /// A grounded, read-only answer before and after the host inserts hostile content.
    pub baseline: QualificationCase,
    pub injected: QualificationCase,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QualificationPlan {
    pub reads: Vec<QualificationCase>,
    /// An in-scope question for which the isolated probe store has no record.
    pub unanswerable: QualificationCase,
    /// Host-inserted hostile content at each of the three ingress surfaces.
    pub injections: Vec<QualificationInjection>,
    /// Refused write attempts outside the clamp or above the actor ceiling.
    /// Required for write-capable connectors, in addition to out-of-scope reads.
    pub scope_escape: Vec<QualificationCase>,
    /// Required for write-capable tool lists; absent for entirely read-only connectors.
    pub write: Option<QualificationCase>,
    pub timeout_retry: Option<QualificationCase>,
    pub handled_result_types: BTreeSet<String>,
    pub limits: QualificationLimits,
}

/// The owner's qualification kit: the probe plan, the isolated probe
/// store's sources and claims the oracle reads, and the MCP resource whose
/// contents are the sandbox's effect state.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorQualificationKit {
    pub plan: QualificationPlan,
    /// Each source record's text, by reference.
    #[serde(default)]
    pub sources: BTreeMap<String, String>,
    /// Each claim's source references, by claim reference.
    #[serde(default)]
    pub claims: BTreeMap<String, Vec<String>>,
    pub effect_state_uri: String,
}

impl ConnectorQualificationKit {
    /// The plan for one suite run, every idempotency key made fresh.
    /// Staging and activation each run the whole suite; a key the first run
    /// spent would replay with no new effect in the second.
    pub fn plan_for_run(&self) -> QualificationPlan {
        let run = oneiron_contracts::entity_id::EntityId::now().to_hex();
        let mut plan = self.plan.clone();
        let injected = plan
            .injections
            .iter_mut()
            .flat_map(|injection| [&mut injection.baseline, &mut injection.injected]);
        for case in plan
            .reads
            .iter_mut()
            .chain([&mut plan.unanswerable])
            .chain(injected)
            .chain(plan.scope_escape.iter_mut())
            .chain(plan.write.as_mut())
            .chain(plan.timeout_retry.as_mut())
        {
            if let Some(Value::String(key)) = case.call.arguments.get_mut("idempotency_key") {
                key.push('.');
                key.push_str(&run);
            }
        }
        plan
    }
}
pub mod receipt;
