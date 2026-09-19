//! Connector qualification probes. The host supplies independent transport
//! connections and a store-backed grounding oracle, never a connector self-grade.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeTool {
    pub name: String,
    pub input_schema: Value,
    pub result_types: BTreeSet<String>,
    pub writes: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRequest {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCitation {
    pub source_ref: String,
    pub start: usize,
    pub end: usize,
    pub quote: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeWrite {
    pub predicate: String,
    pub citations: Vec<ProbeCitation>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeDisposition {
    Answer,
    NoRecord,
    Refused,
    Timeout,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeTraceKind {
    Start,
    Retrieval,
    Write,
    ForeignAsk,
    Quarantine,
    End,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTraceEvent {
    pub sequence: u64,
    pub request_id: String,
    pub kind: ProbeTraceKind,
    pub reference: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone)]
pub struct QualificationLimits {
    pub tokens: u64,
    pub latency_ms: u64,
    pub budget_units: u64,
}
#[derive(Debug, Clone)]
pub struct QualificationCase {
    pub call: ProbeRequest,
    /// Out-of-scope cases must refuse or honestly report no record, never answer.
    pub in_scope: bool,
    pub allowed_predicates: BTreeSet<String>,
}
#[derive(Debug, Clone)]
pub struct QualificationPlan {
    pub reads: Vec<QualificationCase>,
    pub write: QualificationCase,
    pub timeout_retry: QualificationCase,
    pub handled_result_types: BTreeSet<String>,
    pub limits: QualificationLimits,
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
    #[error("qualification plan omits required probes")]
    IncompletePlan,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualificationReport {
    pub tools: Vec<ProbeTool>,
    pub exercised_result_types: BTreeSet<String>,
    pub calls: usize,
}

pub fn qualify_connector(
    connector: &dyn QualificationConnector,
    plan: &QualificationPlan,
    oracle: &dyn GroundingOracle,
) -> Result<QualificationReport, QualificationFailure> {
    if plan.reads.is_empty() {
        return Err(QualificationFailure::IncompletePlan);
    }
    let mut first = connector.connect()?;
    let mut second = connector.connect()?;
    let tools = first.tools_list()?;
    if tools != second.tools_list()? {
        return Err(QualificationFailure::StatelessMismatch);
    }
    if tools
        .iter()
        .any(|t| t.result_types.is_empty() || !t.result_types.is_subset(&plan.handled_result_types))
    {
        return Err(QualificationFailure::ResultType);
    }
    let mut exercised = BTreeSet::new();
    let mut calls = 0;
    for case in &plan.reads {
        let state_before = connector.effect_state()?;
        let a = probe(&mut *first, case, &tools, &plan.limits, oracle)?;
        let b = probe(&mut *second, case, &tools, &plan.limits, oracle)?;
        calls += 2;
        if a.disposition != b.disposition || a.result_type != b.result_type || a.result != b.result
        {
            return Err(QualificationFailure::StatelessMismatch);
        }
        if state_before != connector.effect_state()? || !a.writes.is_empty() || !b.writes.is_empty()
        {
            return Err(QualificationFailure::Replay);
        }
        exercised.insert(a.result_type);
    }
    for (case, allow_timeout) in [(&plan.write, false), (&plan.timeout_retry, true)] {
        let key = case
            .call
            .arguments
            .get("idempotency_key")
            .and_then(Value::as_str)
            .filter(|key| !key.is_empty())
            .ok_or(QualificationFailure::IdempotencyArgument)?;
        if key == case.call.id {
            return Err(QualificationFailure::IdempotencyArgument);
        }
        let original_state = connector.effect_state()?;
        let initial = probe(&mut *first, case, &tools, &plan.limits, oracle)?;
        calls += 1;
        if initial.disposition == ProbeDisposition::Timeout && !allow_timeout {
            return Err(QualificationFailure::Replay);
        }
        if allow_timeout && initial.disposition != ProbeDisposition::Timeout {
            return Err(QualificationFailure::IncompletePlan);
        }
        let before = connector.effect_state()?;
        let mut retry = case.clone();
        retry.call.id = format!("{}-retry", case.call.id);
        let replay = probe(&mut *second, &retry, &tools, &plan.limits, oracle)?;
        calls += 1;
        if replay.disposition == ProbeDisposition::Timeout {
            return Err(QualificationFailure::Replay);
        }
        let after = connector.effect_state()?;
        if original_state == after {
            return Err(QualificationFailure::Replay);
        }
        // Timeout-before-effect may commit on retry. A second settled retry must
        // still converge; timeout-after-effect already has one final state.
        if !allow_timeout && before != after {
            return Err(QualificationFailure::Replay);
        }
        retry.call.id.push_str("-settled");
        let settled = probe(&mut *first, &retry, &tools, &plan.limits, oracle)?;
        calls += 1;
        if connector.effect_state()? != after
            || settled.result != replay.result
            || settled.disposition != replay.disposition
        {
            return Err(QualificationFailure::Replay);
        }
        exercised.insert(replay.result_type);
    }
    let declared: BTreeSet<_> = tools
        .iter()
        .flat_map(|tool| tool.result_types.iter().cloned())
        .collect();
    if !declared.is_subset(&exercised) {
        return Err(QualificationFailure::ResultType);
    }
    Ok(QualificationReport {
        tools,
        exercised_result_types: exercised,
        calls,
    })
}

fn probe(
    connection: &mut dyn QualificationConnection,
    case: &QualificationCase,
    tools: &[ProbeTool],
    limits: &QualificationLimits,
    oracle: &dyn GroundingOracle,
) -> Result<ProbeReply, QualificationFailure> {
    let tool = tools
        .iter()
        .find(|t| t.name == case.call.name)
        .ok_or(QualificationFailure::IncompletePlan)?;
    if tool.writes
        && (case
            .call
            .arguments
            .get("idempotency_key")
            .and_then(Value::as_str)
            .is_none()
            || tool
                .input_schema
                .pointer("/properties/idempotency_key")
                .is_none())
    {
        return Err(QualificationFailure::IdempotencyArgument);
    }
    let started = Instant::now();
    let reply = connection.call(&case.call)?;
    if started.elapsed().as_millis() > u128::from(limits.latency_ms)
        || reply.tokens > limits.tokens
        || reply.budget_units > limits.budget_units
    {
        return Err(QualificationFailure::Envelope);
    }
    validate_headers(&reply.request_headers, &reply.request_body)?;
    if reply.request_body
        != json!({"jsonrpc":"2.0","id":case.call.id,"method":"tools/call","params":{"name":case.call.name,"arguments":case.call.arguments}})
    {
        return Err(QualificationFailure::HeaderMismatch);
    }
    if !tool.result_types.contains(&reply.result_type) {
        return Err(QualificationFailure::ResultType);
    }
    validate_grounding(&reply, case, oracle)?;
    validate_trace(&reply, &case.call.id)?;
    Ok(reply)
}

pub fn validate_headers(
    headers: &BTreeMap<String, String>,
    body: &Value,
) -> Result<(), QualificationFailure> {
    let get = |name: &str| {
        let values: Vec<_> = headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect();
        (values.len() == 1).then(|| values[0])
    };
    if get("Mcp-Method") != body.get("method").and_then(Value::as_str)
        || get("Mcp-Name") != body.pointer("/params/name").and_then(Value::as_str)
        || get("Mcp-Method").is_none()
        || get("Mcp-Name").is_none()
    {
        return Err(QualificationFailure::HeaderMismatch);
    }
    Ok(())
}
fn validate_grounding(
    reply: &ProbeReply,
    case: &QualificationCase,
    oracle: &dyn GroundingOracle,
) -> Result<(), QualificationFailure> {
    if !case.in_scope
        && (!reply.writes.is_empty()
            || !matches!(
                reply.disposition,
                ProbeDisposition::Refused | ProbeDisposition::NoRecord
            ))
    {
        return Err(QualificationFailure::Scope);
    }
    if reply.disposition == ProbeDisposition::NoRecord
        && (!reply.result.is_null()
            || !reply.writes.is_empty()
            || !reply.answer_claim_refs.is_empty()
            || !reply.retrieval_refs.is_empty())
    {
        return Err(QualificationFailure::Grounding);
    }
    for write in &reply.writes {
        if !case.allowed_predicates.contains(&write.predicate) {
            return Err(QualificationFailure::Scope);
        }
        if write.citations.is_empty() {
            return Err(QualificationFailure::Grounding);
        }
        for citation in &write.citations {
            let bytes = oracle
                .source_bytes(&citation.source_ref)
                .ok_or(QualificationFailure::Grounding)?;
            if citation.start >= citation.end
                || bytes.get(citation.start..citation.end) != Some(citation.quote.as_slice())
            {
                return Err(QualificationFailure::Grounding);
            }
        }
    }
    if matches!(reply.disposition, ProbeDisposition::Answer)
        && (reply.retrieval_refs.is_empty()
            || reply.answer_claim_refs.is_empty()
            || reply.answer_claim_refs.iter().any(|reference| {
                oracle.claim_sources(reference).is_none_or(|sources| {
                    sources.is_empty()
                        || sources
                            .iter()
                            .any(|source| !reply.retrieval_refs.contains(source))
                })
            }))
    {
        return Err(QualificationFailure::Grounding);
    }
    if reply
        .retrieval_refs
        .iter()
        .any(|reference| oracle.source_bytes(reference).is_none())
    {
        return Err(QualificationFailure::Grounding);
    }
    Ok(())
}
fn validate_trace(reply: &ProbeReply, request_id: &str) -> Result<(), QualificationFailure> {
    if reply.trace.first().map(|e| &e.kind) != Some(&ProbeTraceKind::Start)
        || reply.trace.last().map(|e| &e.kind) != Some(&ProbeTraceKind::End)
    {
        return Err(QualificationFailure::Trace);
    }
    let mut foreign = BTreeSet::new();
    let mut quarantined = BTreeSet::new();
    let mut executed = BTreeSet::new();
    let mut retrieved = BTreeSet::new();
    for (i, event) in reply.trace.iter().enumerate() {
        if event.sequence != i as u64 || event.request_id != request_id {
            return Err(QualificationFailure::Trace);
        }
        if event.kind == ProbeTraceKind::Write {
            executed.insert(event.reference.clone().ok_or(QualificationFailure::Trace)?);
        }
        if event.kind == ProbeTraceKind::Retrieval {
            retrieved.insert(event.reference.clone().ok_or(QualificationFailure::Trace)?);
        }
        match event.kind {
            ProbeTraceKind::ForeignAsk => {
                foreign.insert(event.reference.clone().ok_or(QualificationFailure::Trace)?);
            }
            ProbeTraceKind::Quarantine => {
                quarantined.insert(event.reference.clone().ok_or(QualificationFailure::Trace)?);
            }
            ProbeTraceKind::Write
                if event
                    .reference
                    .as_ref()
                    .is_some_and(|r| foreign.contains(r)) =>
            {
                return Err(QualificationFailure::ForeignAsk);
            }
            _ => {}
        }
    }
    if foreign != quarantined || !foreign.is_disjoint(&executed) {
        return Err(QualificationFailure::ForeignAsk);
    }
    if reply.retrieval_refs.iter().any(|r| !retrieved.contains(r)) {
        return Err(QualificationFailure::Trace);
    }
    if !reply.retrieval_refs.is_empty()
        && !reply
            .trace
            .iter()
            .any(|e| e.kind == ProbeTraceKind::Retrieval)
    {
        return Err(QualificationFailure::Trace);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
