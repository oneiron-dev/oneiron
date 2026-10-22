//! Connector qualification probes. The host supplies independent transport
//! connections and a store-backed grounding oracle, never a connector self-grade.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

mod receipt;
mod runner;
use receipt::QualificationEvidence;
pub use receipt::{
    CONNECTOR_QUALIFICATION_SUITE, ConnectorQualificationReceipt,
    PROXY_ADMISSION_QUALIFICATION_SUITE, SETUP_CHECK_QUALIFICATION_SUITE,
};
pub(crate) use runner::qualify_connector_with_schemas;
pub use runner::{qualify_connector, validate_headers};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeTool {
    pub name: String,
    pub input_schema: Value,
    pub trigger: Option<String>,
    pub result_types: BTreeSet<String>,
    pub writes: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProbeRequest {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeCitation {
    pub source_ref: String,
    pub start: usize,
    pub end: usize,
    pub quote: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeWrite {
    pub reference: String,
    pub predicate: String,
    pub citations: Vec<ProbeCitation>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeDisposition {
    Answer,
    NoRecord,
    Refused,
    Timeout,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeTraceKind {
    Start,
    Retrieval,
    FetchedContent,
    ToolResult,
    Write,
    ForeignAsk,
    Quarantine,
    End,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeTraceEvent {
    pub sequence: u64,
    pub request_id: String,
    pub kind: ProbeTraceKind,
    pub reference: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReply {
    /// Captured by the transport adapter; not a field copied from tool output.
    pub request_body: Value,
    pub request_headers: BTreeMap<String, String>,
    pub disposition: ProbeDisposition,
    pub result_type: String,
    pub result: Value,
    pub writes: Vec<ProbeWrite>,
    pub answer_claim_refs: Vec<String>,
    pub retrieval_refs: Vec<String>,
    pub trace: Vec<ProbeTraceEvent>,
    pub tokens: u64,
    pub budget_units: u64,
}

pub trait QualificationConnection {
    fn tools_list(&mut self) -> Result<Vec<ProbeTool>, QualificationFailure>;
    fn call(&mut self, request: &ProbeRequest) -> Result<ProbeReply, QualificationFailure>;
}
pub trait QualificationConnector {
    /// Must establish a fresh connection, not borrow the first connection.
    fn connect(&self) -> Result<Box<dyn QualificationConnection + '_>, QualificationFailure>;
    /// Canonical observable state, including external effect receipts. A replay
    /// must leave the same state; this is read independently from call replies.
    fn effect_state(&self) -> Result<Vec<u8>, QualificationFailure>;
}
pub trait GroundingOracle {
    fn source_bytes(&self, reference: &str) -> Option<Vec<u8>>;
    fn claim_sources(&self, reference: &str) -> Option<Vec<String>>;
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
        let run = crate::EntityId::now().to_hex();
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

/// The kit's probe store, never the connector's word.
impl GroundingOracle for ConnectorQualificationKit {
    fn source_bytes(&self, reference: &str) -> Option<Vec<u8>> {
        self.sources
            .get(reference)
            .map(|text| text.as_bytes().to_vec())
    }

    fn claim_sources(&self, reference: &str) -> Option<Vec<String>> {
        self.claims.get(reference).cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QualificationFailure {
    #[error("connector transport unavailable")]
    Transport,
    #[error("independent connections disagree")]
    StatelessMismatch,
    #[error("unhandled or undeclared result type")]
    ResultType,
    #[error("MCP method/name headers do not match request body")]
    HeaderMismatch,
    #[error("idempotency key is not an explicit tool argument")]
    IdempotencyArgument,
    #[error("connector write exceeds predicate ceiling")]
    Scope,
    #[error("connector answer or write is not grounded")]
    Grounding,
    #[error("connector trace is malformed")]
    Trace,
    #[error("foreign request was not quarantined")]
    ForeignAsk,
    #[error("connector replay changed committed effects")]
    Replay,
    #[error("connector exceeded its envelope")]
    Envelope,
    #[error("connector followed injected instructions")]
    Injection,
    #[error("connector confabulated an unanswerable question")]
    Unanswerable,
    #[error("qualification plan omits required probes")]
    IncompletePlan,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualificationReport {
    pub tools: Vec<ProbeTool>,
    pub exercised_result_types: BTreeSet<String>,
    pub calls: usize,
    /// Digest of the plan, observed tools, captured calls and resulting effect state.
    pub report_hash: String,
}

#[cfg(test)]
pub(crate) mod tests;
