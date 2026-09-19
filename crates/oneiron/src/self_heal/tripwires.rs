//! Closed-form T1 projections. Invalid source records produce no observations.
use super::{
    DeterministicDetector, DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass,
    DiagnosticObservation, DiagnosticReplayCoordinate, DiagnosticSourceKind, DiagnosticWorkingSet,
    MAX_EVENTS_PER_RUN, run_deterministic_detectors,
};
use crate::{
    EntityId, Result, Vault,
    receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord},
    store::RetrievalRunRecord,
};
use rmpv::Value;
use serde::{Deserialize, Serialize};

fn draft(
    id: &str,
    class: DiagnosticEventClass,
    source: DiagnosticSourceKind,
    input: &DiagnosticWorkingSet<'_>,
    observation: &DiagnosticObservation,
) -> DiagnosticEvent {
    DiagnosticEvent {
        detector_id: id.into(),
        event_class: class,
        actor_class: "system".into(),
        actor_ref: None,
        source,
        criticality: DiagnosticCriticality::Normal,
        expected: Value::from(1),
        actual: Value::from(0),
        delta: Value::from(-1),
        replay: DiagnosticReplayCoordinate {
            content_hash: observation.payload_digest,
            run_ref: Some(input.scope_ref.into()),
            checkpoint_ref: None,
        },
        evidence_refs: vec![observation.source_ref],
        untrusted_detail: None,
        valid_from: observation.observed_at,
        valid_to: None,
    }
}
macro_rules! point_detector {
    ($name:ident,$id:literal,$kind:literal,$class:ident,$source:ident) => {
        pub struct $name;
        impl DeterministicDetector for $name {
            fn detector_id(&self) -> &'static str {
                $id
            }
            fn detect(&self, input: &DiagnosticWorkingSet<'_>) -> Vec<DiagnosticEvent> {
                input
                    .observations
                    .iter()
                    .filter(|o| o.kind == $kind)
                    .map(|o| {
                        draft(
                            $id,
                            DiagnosticEventClass::$class,
                            DiagnosticSourceKind::$source,
                            input,
                            o,
                        )
                    })
                    .collect()
            }
        }
    };
}
point_detector!(
    RetrievalMissDetector,
    "retrieval.miss.v1",
    "retrieval_miss",
    RetrievalMiss,
    RetrievalTelemetry
);
point_detector!(
    ConsolidationErrorDetector,
    "consolidation.error.v1",
    "consolidation_error",
    ConsolidationError,
    Receipt
);
point_detector!(
    DreamerDegenerateDetector,
    "dreamer.degenerate.v1",
    "dreamer_degenerate",
    DreamerRunDegenerate,
    DreamerEventDag
);
point_detector!(
    SilentConversationDetector,
    "conversation.silent.v1",
    "conversation_silent",
    SilentConversationDegradation,
    DreamerEventDag
);

/// One fixed-window bound resolved from the vault's POLICY_MANIFEST rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TripwireBounds {
    pub window_secs: u64,
    pub consent_depth: u64,
    pub actor_writes: u64,
}
impl Default for TripwireBounds {
    fn default() -> Self {
        Self {
            window_secs: 600,
            consent_depth: 1_000,
            actor_writes: 100,
        }
    }
}
impl TripwireBounds {
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let entries = value.as_map()?;
        if entries.len() != 3 {
            return None;
        }
        let field = |name| {
            let matches: Vec<_> = entries
                .iter()
                .filter(|(key, _)| key.as_str() == Some(name))
                .collect();
            if matches.len() != 1 {
                return None;
            }
            matches[0].1.as_u64()
        };
        let bounds = Self {
            window_secs: field("window_secs")?,
            consent_depth: field("consent_depth")?,
            actor_writes: field("actor_writes")?,
        };
        bounds.valid().then_some(bounds)
    }

    fn valid(self) -> bool {
        self.window_secs > 0
            && (1..=MAX_EVENTS_PER_RUN as u64).contains(&self.consent_depth)
            && (1..=MAX_EVENTS_PER_RUN as u64).contains(&self.actor_writes)
    }
}
pub struct ConsentStormDetector {
    pub bounds: TripwireBounds,
    pub window_end: u64,
}
pub struct PredicateDriftDetector {
    pub bounds: TripwireBounds,
    pub window_end: u64,
    pub actor: EntityId,
}
struct WindowRule {
    id: &'static str,
    kind: &'static str,
    class: DiagnosticEventClass,
}
fn window_event(
    rule: WindowRule,
    input: &DiagnosticWorkingSet<'_>,
    bounds: TripwireBounds,
    end: u64,
    threshold: u64,
    actor: Option<EntityId>,
) -> Vec<DiagnosticEvent> {
    if !bounds.valid() {
        return vec![];
    }
    let observations: Vec<_> = input
        .observations
        .iter()
        .filter(|o| {
            o.kind == rule.kind
                && o.observed_at > end.saturating_sub(bounds.window_secs)
                && o.observed_at <= end
        })
        .collect();
    if (observations.len() as u64) < threshold {
        return vec![];
    }
    let Some(last) = observations.last() else {
        return vec![];
    };
    let mut event = draft(
        rule.id,
        rule.class,
        DiagnosticSourceKind::Receipt,
        input,
        last,
    );
    event.actor_ref = actor;
    event.expected = Value::from(threshold);
    event.actual = Value::from(observations.len() as u64);
    event.delta = Value::from(observations.len() as u64 - threshold);
    let mut hash = blake3::Hasher::new();
    for o in &observations {
        hash.update(&o.payload_digest);
    }
    hash.update(&end.to_be_bytes());
    hash.update(&threshold.to_be_bytes());
    event.replay.content_hash = *hash.finalize().as_bytes();
    vec![event]
}
impl DeterministicDetector for ConsentStormDetector {
    fn detector_id(&self) -> &'static str {
        "consent.storm.v1"
    }
    fn detect(&self, input: &DiagnosticWorkingSet<'_>) -> Vec<DiagnosticEvent> {
        window_event(
            WindowRule {
                id: self.detector_id(),
                kind: "consent_pending",
                class: DiagnosticEventClass::ConsentDenied,
            },
            input,
            self.bounds,
            self.window_end,
            self.bounds.consent_depth,
            None,
        )
    }
}
impl DeterministicDetector for PredicateDriftDetector {
    fn detector_id(&self) -> &'static str {
        "predicate.drift.v1"
    }
    fn detect(&self, input: &DiagnosticWorkingSet<'_>) -> Vec<DiagnosticEvent> {
        window_event(
            WindowRule {
                id: self.detector_id(),
                kind: "predicate_drift",
                class: DiagnosticEventClass::ConsolidationError,
            },
            input,
            self.bounds,
            self.window_end,
            self.bounds.actor_writes,
            Some(self.actor),
        )
    }
}
fn observation<T: Serialize>(
    source_ref: EntityId,
    kind: &'static str,
    observed_at: u64,
    record: &T,
) -> Option<DiagnosticObservation> {
    let bytes = rmp_serde::to_vec_named(record).ok()?;
    Some(DiagnosticObservation {
        source_ref,
        kind,
        observed_at,
        payload_digest: *blake3::hash(&bytes).as_bytes(),
    })
}
impl DiagnosticObservation {
    pub fn from_retrieval_run(run: &RetrievalRunRecord) -> Option<Self> {
        if run.version != 0
            || run.claims_suppressed > run.total_in_scope
            || !run.result_ids.is_empty()
            || run.total_in_scope <= run.claims_suppressed
            || run.empty_reason.as_ref().is_none_or(String::is_empty)
        {
            return None;
        }
        observation(
            EntityId::from_bytes(run.run_id.as_bytes()).ok()?,
            "retrieval_miss",
            run.started_at,
            run,
        )
    }
    pub fn from_consolidation_receipt(receipt: &ReceiptRecord) -> Option<Self> {
        if receipt.receipt_kind != ReceiptKind::Gate
            || receipt.outcome != "denied"
            || receipt.fields.get("content_kind").map(String::as_str) != Some("claim")
            || !receipt
                .policy_trace
                .iter()
                .any(|r| r.starts_with("gate.deny.dreamer_precommit."))
        {
            return None;
        }
        observation(
            receipt_id(receipt)?,
            "consolidation_error",
            receipt.occurred_at,
            receipt,
        )
    }
}
fn receipt_id(receipt: &ReceiptRecord) -> Option<EntityId> {
    EntityId::from_hex(receipt.receipt_id.strip_prefix("gate:")?).ok()
}
/// A terminal run's structured output facts. No model grades enter this shape.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamerRunFacts {
    #[serde(with = "super::receipt_serde::id")]
    pub run_ref: EntityId,
    pub completed_at: u64,
    pub completed: bool,
    pub output_expected: bool,
    pub output: String,
    pub error_count: u64,
    pub conversation: bool,
}
impl DreamerRunFacts {
    fn observation(&self) -> Option<DiagnosticObservation> {
        if !self.completed || !self.output_expected || !self.output.trim().is_empty() {
            return None;
        }
        let kind = if self.conversation && self.error_count == 0 {
            "conversation_silent"
        } else {
            "dreamer_degenerate"
        };
        observation(self.run_ref, kind, self.completed_at, self)
    }
}
impl Vault {
    pub fn tripwire_bounds(&self) -> Result<Option<TripwireBounds>> {
        let txn = self.store.env.read_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed() {
            return Ok(None);
        }
        Ok(Some(policy.diagnostic_bounds.unwrap_or_default()))
    }
    /// Read the stored ARCH-0037 records, never caller-authored telemetry labels.
    pub fn run_retrieval_miss_detector(&self, scope: &str, limit: usize) -> Result<Vec<EntityId>> {
        if limit == 0 || limit > MAX_EVENTS_PER_RUN {
            return Ok(vec![]);
        }
        let observations = self
            .store
            .retrieval_runs(limit)?
            .iter()
            .filter_map(DiagnosticObservation::from_retrieval_run)
            .collect();
        run(self, scope, observations, &[&RetrievalMissDetector])
    }
    pub fn run_receipt_tripwires(
        &self,
        scope: &str,
        query: ReceiptQuery,
        end: u64,
    ) -> Result<Vec<EntityId>> {
        let capacity = query.limit;
        let receipts = self.receipts(query)?;
        self.project_receipt_tripwires_with_capacity(scope, &receipts, end, Some(capacity))
    }
    /// Projects a bounded scoped receipt slice; also used by receipt adapters.
    pub fn project_receipt_tripwires(
        &self,
        scope: &str,
        receipts: &[ReceiptRecord],
        end: u64,
    ) -> Result<Vec<EntityId>> {
        self.project_receipt_tripwires_with_capacity(scope, receipts, end, None)
    }
    fn project_receipt_tripwires_with_capacity(
        &self,
        scope: &str,
        receipts: &[ReceiptRecord],
        end: u64,
        capacity: Option<usize>,
    ) -> Result<Vec<EntityId>> {
        let Some(bounds) = self.tripwire_bounds()? else {
            return Ok(vec![]);
        };
        if capacity
            .is_some_and(|limit| limit < bounds.consent_depth.max(bounds.actor_writes) as usize)
        {
            return Err(crate::Error::InvalidConfig(
                "receipt query cannot reach the configured tripwire bounds".into(),
            ));
        }
        if receipts.len() > MAX_EVENTS_PER_RUN {
            return Err(crate::Error::InvalidConfig(
                "tripwire receipt window exceeds observation capacity".into(),
            ));
        }
        let mut observations: Vec<_> = receipts
            .iter()
            .filter_map(DiagnosticObservation::from_consolidation_receipt)
            .collect();
        // Pending receipts are immutable history. Count only the current tray
        // row for that exact decision, once, even if an adapter repeats it.
        let txn = self.store.env.read_txn()?;
        let mut seen = std::collections::BTreeSet::new();
        for receipt in receipts {
            if receipt.receipt_kind != ReceiptKind::Gate || receipt.outcome != "pending" {
                continue;
            }
            let Some(claim) = receipt
                .trigger_ref
                .as_deref()
                .and_then(|r| r.strip_prefix("claim:"))
                .and_then(|r| EntityId::from_hex(r).ok())
            else {
                continue;
            };
            let Some(id) = receipt_id(receipt) else {
                continue;
            };
            let Some(pending) = self.store.pending_gate_consent_in_txn(&txn, &claim)? else {
                continue;
            };
            if pending.decision_id.as_bytes() == *id.as_bytes()
                && seen.insert(id)
                && let Some(o) = observation(id, "consent_pending", pending.created_at, &pending)
            {
                observations.push(o);
            }
        }
        drop(txn);
        let mut ids = run(
            self,
            scope,
            observations,
            &[
                &ConsolidationErrorDetector,
                &ConsentStormDetector {
                    bounds,
                    window_end: end,
                },
            ],
        )?;
        // Drift counts only writes whose manifest criticality rose from the recorded baseline.
        let txn = self.store.env.read_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        let mut actors = std::collections::BTreeMap::<EntityId, Vec<DiagnosticObservation>>::new();
        for receipt in receipts {
            let Some(actor) = receipt
                .actor
                .as_deref()
                .and_then(|a| EntityId::from_hex(a).ok())
            else {
                continue;
            };
            let Some(predicate) = receipt.fields.get("predicate") else {
                continue;
            };
            if receipt.receipt_kind != ReceiptKind::Gate
                || !matches!(
                    receipt.outcome.as_str(),
                    "allow" | "auto" | "proposed" | "pending"
                )
                || receipt.fields.get("criticality").map(String::as_str) != Some("normal")
                || policy.criticality_for_predicate(predicate)
                    != crate::gate::PolicyCriticality::Critical
            {
                continue;
            }
            if let Some(id) = receipt_id(receipt)
                && let Some(o) = observation(id, "predicate_drift", receipt.occurred_at, receipt)
            {
                actors.entry(actor).or_default().push(o);
            }
        }
        drop(txn);
        for (actor, observations) in actors {
            ids.extend(run(
                self,
                scope,
                observations,
                &[&PredicateDriftDetector {
                    bounds,
                    window_end: end,
                    actor,
                }],
            )?);
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }
    pub fn run_dreamer_output_tripwires(
        &self,
        scope: &str,
        records: &[DreamerRunFacts],
    ) -> Result<Vec<EntityId>> {
        if records.len() > MAX_EVENTS_PER_RUN {
            return Ok(vec![]);
        }
        run(
            self,
            scope,
            records
                .iter()
                .filter_map(DreamerRunFacts::observation)
                .collect(),
            &[&DreamerDegenerateDetector, &SilentConversationDetector],
        )
    }
}
fn run(
    vault: &Vault,
    scope: &str,
    mut observations: Vec<DiagnosticObservation>,
    detectors: &[&dyn DeterministicDetector],
) -> Result<Vec<EntityId>> {
    observations.sort_by_key(DiagnosticObservation::order_key);
    observations.dedup();
    let input = DiagnosticWorkingSet {
        scope_ref: scope,
        observations: &observations,
    };
    run_deterministic_detectors(vault, &input, detectors)
}

/// Gate receipts keep the original predicate, not the claim value. The fact
/// survives ordinary claim edits and is cleared by receipt redaction.
pub(crate) fn normal_baseline_token(predicate: &str) -> String {
    format!("tripwire_normal_v2:{predicate}")
}

pub(crate) fn normal_baseline_predicate(token: &str) -> Option<&str> {
    let predicate = token.strip_prefix("tripwire_normal_v2:")?;
    crate::claim::validate_predicate(predicate, true).ok()?;
    Some(predicate)
}
