//! Moved from `crates/oneiron/src/connector_key/qualification.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::connector_key::qualification::ConnectorQualificationKit;
pub use oneiron_verb_wire::connector_key::qualification::ProbeRequest;
pub use oneiron_verb_wire::connector_key::qualification::QualificationCase;
pub use oneiron_verb_wire::connector_key::qualification::QualificationInjection;
pub use oneiron_verb_wire::connector_key::qualification::QualificationInjectionSurface;
pub use oneiron_verb_wire::connector_key::qualification::QualificationLimits;
pub use oneiron_verb_wire::connector_key::qualification::QualificationPlan;
pub use oneiron_verb_wire::connector_key::qualification::receipt::BUILTIN_PROBE_QUALIFICATION_SUITE;
pub use oneiron_verb_wire::connector_key::qualification::receipt::CONNECTOR_QUALIFICATION_SUITE;
pub use oneiron_verb_wire::connector_key::qualification::receipt::OWNER_ATTESTED_QUALIFICATION_SUITE;
pub use oneiron_verb_wire::connector_key::qualification::receipt::PROXY_ADMISSION_QUALIFICATION_SUITE;
pub use oneiron_verb_wire::connector_key::qualification::receipt::SETUP_CHECK_QUALIFICATION_SUITE;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeTool {
    pub name: String,
    pub input_schema: Value,
    pub trigger: Option<String>,
    pub result_types: BTreeSet<String>,
    pub writes: bool,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualificationReport {
    pub tools: Vec<ProbeTool>,
    pub exercised_result_types: BTreeSet<String>,
    pub calls: usize,
    /// Digest of the plan, observed tools, captured calls and resulting effect state.
    pub report_hash: String,
}
