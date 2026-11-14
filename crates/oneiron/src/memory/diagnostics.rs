//! Typed diagnostic reads and scoped Coach repair inspection
//! (OPERATIONS-01). Diagnostics are the engine-authored
//! [`crate::self_heal::DiagnosticEvent`] corpus read through the caller's
//! own scoped lane; the Coach inspection reads exactly what the Coach's
//! Issues job reads for one blocked report — its fenced receipt, its
//! linked diagnostic band, and the repair proposal the Coach filed —
//! and nothing else. Every row reaches the caller only through the
//! lane, so an unrelated private row is never in the working set.

use serde::{Deserialize, Serialize};

use super::read_lane::fold_receipt;
use super::support::*;
use super::*;

use crate::claim::{ClaimReadStatus, PointRead, ScopedReadResult};
use crate::entity_id::EntityId;
use crate::failure_ladder::{BlockedReportRef, ingest_report_blocked};
use crate::store::diagnostic_record::{DiagnosticEvent, DiagnosticEventClass};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::diagnostics::{
    BlockedReportView, CoachInspectRequest, CoachWorkingSetView, DiagnosticEventView,
    DiagnosticsGetRequest, DiagnosticsListRequest,
};

/// The Coach's proposed repair for one report: it repairs the AGENT,
/// never performs its task. The claim is the proposal as the lane
/// serves it — its actor, source, provenance and gate result
/// (`approval`, `lifecycle`) are the claim's own; its own route and
/// criticality govern consent, not the triggering report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoachProposalView {
    /// The proposal claim, as the record lane serves it.
    pub claim: ClaimView,
    /// The repair route: `skill_edit`, `prompt_inject`, `environment`
    /// or `person`.
    pub route: Option<String>,
    /// How the route was reached: `ladder`, `abstained` or `unanswered`.
    pub decided: Option<String>,
    /// The drafted skill repair a `skill_edit` proposal carries, when
    /// one was drafted.
    pub repair: Option<serde_json::Value>,
    /// When the Coach filed the proposal, unix seconds.
    pub settled_at: u64,
}

/// `vault.coach.inspect`'s answer for one blocked receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoachInspectionView {
    /// The receipt inspected, hex.
    pub receipt_ref: String,
    /// `pending` while the Coach has not filed, `settled` once it has,
    /// `unfiled` for a verified report no Issues row names, and
    /// `unknown` when the receipt is withheld from the caller or is
    /// no blocked report.
    pub state: String,
    /// The verified blocked report, when the lane serves its receipt.
    pub report: Option<BlockedReportView>,
    /// The diagnostic filed for the report, when linked and served.
    pub diagnostic: Option<DiagnosticEventView>,
    /// What the Coach's Issues job reads for this report.
    pub working_set: CoachWorkingSetView,
    /// The repair proposal the Coach filed, when settled and served.
    pub proposal: Option<CoachProposalView>,
}

fn invariant_json(value: &rmpv::Value) -> serde_json::Value {
    match value {
        rmpv::Value::Boolean(flag) => serde_json::Value::Bool(*flag),
        rmpv::Value::Integer(int) => int.as_u64().map_or_else(
            || {
                int.as_i64().map_or(serde_json::Value::Null, |signed| {
                    serde_json::Value::Number(serde_json::Number::from(signed))
                })
            },
            |unsigned| serde_json::Value::Number(serde_json::Number::from(unsigned)),
        ),
        rmpv::Value::F32(single) => serde_json::Number::from_f64(f64::from(*single))
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        rmpv::Value::F64(double) => serde_json::Number::from_f64(*double)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        rmpv::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(invariant_json).collect())
        }
        // Nil, and — by the diagnostic grammar's construction — never
        // text: anything else serves as nil rather than leak a string
        // into an authority field.
        _ => serde_json::Value::Null,
    }
}

fn diagnostic_view(id: &EntityId, event: &DiagnosticEvent) -> DiagnosticEventView {
    DiagnosticEventView {
        diagnostic_ref: id.to_hex(),
        detector_id: event.detector_id.clone(),
        event_class: event.event_class.as_str().to_owned(),
        signal: event.signal.map(|signal| signal.as_str().to_owned()),
        actor_class: event.actor_class.clone(),
        actor_ref: event.actor_ref.map(|actor| actor.to_hex()),
        source: event.source.as_str().to_owned(),
        criticality: event.criticality.as_str().to_owned(),
        expected: invariant_json(&event.expected),
        actual: invariant_json(&event.actual),
        delta: invariant_json(&event.delta),
        replay_content_hash: crate::entity_id::bytes_to_hex_lower(&event.replay.content_hash),
        replay_run_ref: event.replay.run_ref.clone(),
        replay_checkpoint_ref: event.replay.checkpoint_ref.clone(),
        evidence_refs: event
            .evidence_refs
            .iter()
            .map(|evidence| evidence.to_hex())
            .collect(),
        untrusted_detail: None,
        valid_from: event.valid_from,
        valid_to: event.valid_to,
    }
}

fn empty_working_set() -> CoachWorkingSetView {
    CoachWorkingSetView {
        evidence_refs: Vec::new(),
        diagnostic_refs: Vec::new(),
        reporter: None,
        run_ref: None,
        reported_at: None,
        retries: None,
    }
}

impl Memory<'_> {
    /// Lists the diagnostic events this caller may read, filtered by
    /// class, actor, or evidence. The lane's receipt states how many
    /// stored events it withheld.
    pub fn diagnostics_list(
        &self,
        request: &DiagnosticsListRequest,
    ) -> MemoryResult<ScopedReadResult<Vec<DiagnosticEventView>>> {
        if request.limit == 0 {
            return Err(MemoryError::bad_request(
                "diagnostics_list limit must be at least 1",
            ));
        }
        let event_class = match request.event_class.as_deref() {
            Some(raw) => Some(DiagnosticEventClass::from_wire(raw).ok_or_else(|| {
                MemoryError::bad_request_with(
                    format!("unknown diagnostic event class {raw:?}"),
                    &["Use a closed class spelling such as agent_blocked or consent_denied."],
                )
            })?),
            None => None,
        };
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let ScopedReadResult { value, receipt } = lane.diagnostic_events()?;
        let views = value
            .into_iter()
            .filter(|(_, event)| event_class.is_none_or(|class| event.event_class == class))
            .filter(|(_, event)| {
                request.actor_ref.as_ref().is_none_or(|actor| {
                    event
                        .actor_ref
                        .is_some_and(|named| named.to_hex() == *actor)
                })
            })
            .filter(|(_, event)| {
                request.evidence_ref.as_ref().is_none_or(|evidence| {
                    event
                        .evidence_refs
                        .iter()
                        .any(|named| named.to_hex() == *evidence)
                })
            })
            .take(request.limit)
            .map(|(id, event)| diagnostic_view(&id, &event))
            .collect();
        Ok(ScopedReadResult {
            value: views,
            receipt,
        })
    }

    /// Reads one diagnostic by ref. `None` when absent or withheld;
    /// the receipt says which axes narrowed.
    pub fn diagnostics_get(
        &self,
        request: &DiagnosticsGetRequest,
    ) -> MemoryResult<ScopedReadResult<Option<DiagnosticEventView>>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let id = self.resolve_ref_in_lane(&lane, &request.diagnostic_ref)?;
        let ScopedReadResult { value, receipt } = lane.diagnostic_events()?;
        let view = value
            .into_iter()
            .find(|(named, _)| *named == id)
            .map(|(named, event)| diagnostic_view(&named, &event));
        Ok(ScopedReadResult {
            value: view,
            receipt,
        })
    }

    /// Inspects one blocked report as the Coach reads it: the verified
    /// fenced receipt (through `ingest_report_blocked`, the failure
    /// ladder's own intake), its linked diagnostic band, and the
    /// repair proposal the Coach filed for it. The receipt row must
    /// first read through the caller's lane; a withheld or foreign
    /// receipt inspects as `unknown` and reveals nothing.
    pub fn coach_inspect(
        &self,
        request: &CoachInspectRequest,
    ) -> MemoryResult<ScopedReadResult<CoachInspectionView>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let receipt_id = self.resolve_ref_in_lane(&lane, &request.receipt_ref)?;
        let mut receipt = None;
        let ScopedReadResult {
            value: rows,
            receipt: read,
        } = lane.read(&[PointRead::id(receipt_id)], None)?;
        fold_receipt(&mut receipt, read);
        let readable = rows
            .into_iter()
            .next()
            .flatten()
            .is_some_and(|row| row.body.is_some());
        let unknown = || CoachInspectionView {
            receipt_ref: receipt_id.to_hex(),
            state: "unknown".to_owned(),
            report: None,
            diagnostic: None,
            working_set: empty_working_set(),
            proposal: None,
        };
        if !readable {
            return Ok(ScopedReadResult {
                value: unknown(),
                receipt: receipt.unwrap_or(lane.read_receipt(None, 0)?),
            });
        }
        let entry = ingest_report_blocked(
            self.vault,
            BlockedReportRef {
                receipt_ref: receipt_id.to_hex(),
            },
        )
        .ok();
        let Some(entry) = entry else {
            return Ok(ScopedReadResult {
                value: unknown(),
                receipt: receipt.unwrap_or(lane.read_receipt(None, 0)?),
            });
        };
        let issue = crate::self_heal::blocked_reports::blocked_issue(self.vault, &receipt_id)?;
        let settled = crate::self_heal::blocked_reports::settled_issue(self.vault, &receipt_id)?;
        let state = if issue.is_some() {
            "pending"
        } else if settled.is_some() {
            "settled"
        } else {
            "unfiled"
        };

        let ScopedReadResult {
            value: events,
            receipt: read,
        } = lane.diagnostic_events()?;
        fold_receipt(&mut receipt, read);
        let diagnostic = issue
            .as_ref()
            .and_then(|issue| events.iter().find(|(named, _)| *named == issue.diagnostic))
            .or_else(|| {
                events
                    .iter()
                    .find(|(_, event)| event.evidence_refs.contains(&receipt_id))
            });
        let band: Vec<String> = events
            .iter()
            .filter(|(_, event)| {
                event.evidence_refs.contains(&receipt_id)
                    || diagnostic.is_some_and(|(_, named)| {
                        event
                            .evidence_refs
                            .iter()
                            .any(|evidence| named.evidence_refs.contains(evidence))
                    })
            })
            .map(|(named, _)| named.to_hex())
            .collect();
        let mut evidence_refs = vec![receipt_id.to_hex()];
        if let Some((named, _)) = diagnostic {
            evidence_refs.push(named.to_hex());
        }
        let working_set = CoachWorkingSetView {
            evidence_refs,
            diagnostic_refs: band,
            reporter: issue.as_ref().map(|issue| issue.reporter.to_hex()),
            run_ref: issue
                .as_ref()
                .and_then(|issue| issue.run.map(|run| run.to_hex())),
            reported_at: issue.as_ref().map(|issue| issue.reported_at),
            retries: issue.as_ref().map(|issue| issue.retries),
        };

        let proposal = match settled {
            Some(settled) => {
                let ScopedReadResult {
                    value: rows,
                    receipt: read,
                } = lane.read(&[PointRead::id(settled.proposal)], None)?;
                fold_receipt(&mut receipt, read);
                match rows.into_iter().next().flatten() {
                    Some(row) => match row.body.as_deref() {
                        Some(bytes) => {
                            let body = crate::claim::decode_claim_body(bytes, true)?;
                            let claim = self.served_claim_view(&row.id, &body)?;
                            let named = match &claim.value {
                                serde_json::Value::String(text) => {
                                    serde_json::from_str::<serde_json::Value>(text).ok()
                                }
                                other => Some(other.clone()),
                            };
                            let field = |key: &str| {
                                named
                                    .as_ref()
                                    .and_then(|value| value.get(key))
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned)
                            };
                            Some(CoachProposalView {
                                route: field("route"),
                                decided: field("decided"),
                                repair: named
                                    .as_ref()
                                    .and_then(|value| value.get("repair"))
                                    .filter(|repair| !repair.is_null())
                                    .cloned(),
                                claim,
                                settled_at: settled.at,
                            })
                        }
                        None => None,
                    },
                    None => None,
                }
            }
            None => None,
        };

        Ok(ScopedReadResult {
            value: CoachInspectionView {
                receipt_ref: receipt_id.to_hex(),
                state: state.to_owned(),
                report: Some(BlockedReportView {
                    receipt_ref: entry.report.receipt_ref,
                    category: entry.receipt.category.as_str().to_owned(),
                    untrusted_detail: entry.receipt.untrusted_detail,
                    attempt: entry.receipt.attempt,
                    semi_trusted: entry.semi_trusted,
                }),
                diagnostic: diagnostic.map(|(named, event)| diagnostic_view(named, event)),
                working_set,
                proposal,
            },
            receipt: receipt.unwrap_or(lane.read_receipt(None, 0)?),
        })
    }
}
