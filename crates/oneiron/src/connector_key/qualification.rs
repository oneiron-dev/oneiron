//! Connector qualification probes. The host supplies independent transport
//! connections and a store-backed grounding oracle, never a connector self-grade.
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

mod receipt;
mod runner;
use receipt::QualificationEvidence;
pub use receipt::{
    BUILTIN_PROBE_QUALIFICATION_SUITE, CONNECTOR_QUALIFICATION_SUITE,
    ConnectorQualificationReceipt, OWNER_ATTESTED_QUALIFICATION_SUITE,
    PROXY_ADMISSION_QUALIFICATION_SUITE, SETUP_CHECK_QUALIFICATION_SUITE,
};
pub(crate) use runner::qualify_connector_with_schemas;
pub use runner::{qualify_connector, validate_headers};

#[doc(hidden)]
pub use oneiron_records::connector_key::qualification::{
    ProbeCitation, ProbeDisposition, ProbeReply, ProbeTool, ProbeTraceEvent, ProbeTraceKind,
    ProbeWrite, QualificationReport,
};

#[doc(hidden)]
pub use oneiron_verb_wire::connector_key::qualification::{
    ConnectorQualificationKit, ProbeRequest, QualificationCase, QualificationInjection,
    QualificationInjectionSurface, QualificationLimits, QualificationPlan,
};

/// A discovery request captured by its transport, with credentials excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCapturedRequest {
    pub request_body: Value,
    pub request_headers: BTreeMap<String, String>,
}

/// Declarations and the actual page requests that discovered them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeToolsList {
    pub tools: Vec<ProbeTool>,
    /// One entry per HTTP page, in send order; no entries for an in-process list.
    pub requests: Vec<ProbeCapturedRequest>,
}

pub trait QualificationConnection {
    fn tools_list(&mut self) -> Result<ProbeToolsList, QualificationFailure>;
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
#[cfg(test)]
pub(crate) mod tests;
