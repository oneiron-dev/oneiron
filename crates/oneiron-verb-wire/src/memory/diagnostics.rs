//! Moved from `crates/oneiron/src/memory/diagnostics.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `vault.diagnostics.list` input: the caller's diagnostic band, newest
/// stored order first as the lane serves it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsListRequest {
    /// Restrict to this closed event class, by wire spelling
    /// (`agent_blocked`, `consent_denied`, ...).
    #[serde(default)]
    pub event_class: Option<String>,
    /// Restrict to diagnostics naming this actor, 32-hex id.
    #[serde(default)]
    pub actor_ref: Option<String>,
    /// Restrict to diagnostics evidenced by this entity, 32-hex id.
    #[serde(default)]
    pub evidence_ref: Option<String>,
    /// Maximum results (required; no unbounded scans).
    pub limit: usize,
}

/// `vault.diagnostics.get` input: one diagnostic by ref.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsGetRequest {
    /// Diagnostic short ref or 32-hex id.
    pub diagnostic_ref: String,
}

/// One typed diagnostic finding, as the lane serves it. Every field is
/// engine-authored; `expected`, `actual` and `delta` carry only nil,
/// bool, number, or arrays of those, and `untrusted_detail` is always
/// nil: foreign text appears in no diagnostic value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DiagnosticEventView {
    /// 32-hex DIAGNOSTIC id.
    pub diagnostic_ref: String,
    /// Stable detector token that authored the finding.
    pub detector_id: String,
    /// Closed event class, wire spelling.
    pub event_class: String,
    /// Agent-health signal, present exactly for `agent_health`.
    pub signal: Option<String>,
    /// Actor class that owns the failure: `agent`, `human` or `system`.
    pub actor_class: String,
    /// Concrete actor, 32-hex id, when the finding names one.
    pub actor_ref: Option<String>,
    /// Read-only substrate: `receipt`, `retrieval_telemetry`,
    /// `dreamer_event_dag` or `self_report`.
    pub source: String,
    /// `normal` or `critical`.
    pub criticality: String,
    /// What should have been true (nil, bool, number, or arrays).
    pub expected: serde_json::Value,
    /// What was true instead.
    pub actual: serde_json::Value,
    /// How the two differ.
    pub delta: serde_json::Value,
    /// Content address of the bytes the verdict was computed over, hex.
    pub replay_content_hash: String,
    /// Optional run coordinate of the replay.
    pub replay_run_ref: Option<String>,
    /// Optional checkpoint coordinate inside the run.
    pub replay_checkpoint_ref: Option<String>,
    /// Entities this finding is evidenced by, 32-hex ids ascending.
    pub evidence_refs: Vec<String>,
    /// Always nil: diagnostics carry no world text, escaped or not.
    pub untrusted_detail: Option<String>,
    /// Bitemporal validity start, unix seconds.
    pub valid_from: u64,
    /// Bitemporal validity end, unix seconds, when closed.
    pub valid_to: Option<u64>,
}

/// `vault.coach.inspect` input: one blocked report, by its witnessed
/// receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoachInspectRequest {
    /// Blocked receipt short ref or 32-hex MESSAGE id, as
    /// `self.report_blocked` returned it.
    pub receipt_ref: String,
}

/// One verified blocked report, sem-trusted evidence only. The detail
/// stays the fenced, untrusted leaf of the receipt; no field here can
/// drive routing or grant anything.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BlockedReportView {
    /// The witnessed receipt's MESSAGE id, hex.
    pub receipt_ref: String,
    /// Closed blocked category: `tool`, `permission`, `context` or
    /// `environment`.
    pub category: String,
    /// The escaped, untrusted detail exactly as witnessed.
    pub untrusted_detail: String,
    /// The agent attempt the host ran the report under, hex, when bound.
    pub attempt: Option<String>,
    /// Always true: the report is the agent's own word, never a trigger.
    pub semi_trusted: bool,
}

/// The working set the Coach's Issues job reads for one report: the
/// evidence it routes on and the linked diagnostic band. Rows the
/// caller's lane withholds are absent, never summarized.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoachWorkingSetView {
    /// The evidence of the route question: the receipt, then its
    /// diagnostic when one is linked.
    pub evidence_refs: Vec<String>,
    /// The linked diagnostic band: every diagnostic the lane serves
    /// that evidences this receipt or shares evidence with its
    /// diagnostic.
    pub diagnostic_refs: Vec<String>,
    /// The actor the report was witnessed for, hex, while pending.
    pub reporter: Option<String>,
    /// The durable run that reported, hex, when it had one.
    pub run_ref: Option<String>,
    /// When the report was witnessed, unix seconds, while pending.
    pub reported_at: Option<u64>,
    /// Issues runs whose decision already failed on this report.
    pub retries: Option<u8>,
}
