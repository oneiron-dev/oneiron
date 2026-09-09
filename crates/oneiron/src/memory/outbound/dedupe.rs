//! Idempotent-replay receipts, retry-lineage walk, and gate-binding side index.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::super::support::{Memory, hex_string};
use super::super::{MemoryError, MemoryResult};
use super::types::OutboundIntentReceipt;
use crate::attempt_queue::{AttemptId, AttemptQueue};
/// Internal side-index record: the gate surface a scheduled outbound attempt's
/// first dispatch produced, persisted by attempt id so an idempotent replay
/// (`EnqueueOutcome::Existing`) can re-surface the original decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct OutboundGateBinding {
    gate_outcome: String,
    #[serde(default)]
    gate_decision_ref: Option<String>,
    #[serde(default)]
    gate_reason_codes: Vec<String>,
}

/// Bound on the `retry_of` climb behind an `already_scheduled` receipt, the
/// same 64 steps the run-root climb uses.
///
/// The walk is infallible by construction — the dedupe hit itself is the floor
/// — so this cap only decides how far back a receipt may recover an origin, and
/// guarantees a fabricated chain can never make a replay hang.
const RETRY_LINEAGE_WALK_LIMIT: usize = 64;

impl Memory<'_> {
    pub(super) fn already_scheduled_outbound_receipt(
        &self,
        attempt_id: AttemptId,
    ) -> OutboundIntentReceipt {
        // The live index owner may be a retry CHILD of the row that was
        // actually scheduled, and only the schedule-time row carries the intent
        // ref and Gate binding this receipt owes the caller. So resolve the
        // originating attempt first, then re-surface the ORIGINAL gate decision
        // it persisted. Ownership of the dedupe index never moves back.
        let origin_id = self.outbound_schedule_origin_id(attempt_id);
        let binding = self.outbound_gate_binding(origin_id);
        OutboundIntentReceipt {
            intent_ref: outbound_intent_ref(origin_id),
            outcome: "already_scheduled".to_owned(),
            gate_outcome: binding.as_ref().map(|binding| binding.gate_outcome.clone()),
            gate_decision_ref: binding
                .as_ref()
                .and_then(|binding| binding.gate_decision_ref.clone()),
            gate_reason_codes: binding
                .map(|binding| binding.gate_reason_codes)
                .unwrap_or_default(),
            deduped: true,
        }
    }

    /// Walks `retry_of` back from a dedupe hit to the attempt that was
    /// originally scheduled.
    ///
    /// Infallible and bounded by construction: the hit itself is the floor, a
    /// visited set refuses a cycle, and [`RETRY_LINEAGE_WALK_LIMIT`] caps the
    /// climb. A missing parent, a decode failure, or a parent that disagrees
    /// with its child on kind, dedupe key, TASK backlink, or dedupe actor scope
    /// stops the walk at the deepest ancestor already verified — a receipt
    /// never crosses from one schedule's lineage into another's.
    pub(super) fn outbound_schedule_origin_id(&self, attempt_id: AttemptId) -> AttemptId {
        let queue = AttemptQueue::new(self.vault);
        let Ok(Some(hit)) = queue.get(attempt_id) else {
            return attempt_id;
        };
        let mut origin_id = attempt_id;
        let mut child = hit;
        let mut visited = HashSet::from([attempt_id]);
        while let Some(parent_id) = child.retry_of {
            if visited.len() >= RETRY_LINEAGE_WALK_LIMIT || !visited.insert(parent_id) {
                break;
            }
            let Ok(Some(parent)) = queue.get(parent_id) else {
                break;
            };
            if parent.kind != child.kind
                || parent.dedupe_key != child.dedupe_key
                || parent.task_ref != child.task_ref
                || parent.dedupe_actor_ref != child.dedupe_actor_ref
            {
                break;
            }
            origin_id = parent_id;
            child = parent;
        }
        origin_id
    }

    /// Persists the gate surface of a scheduled outbound attempt (best-effort).
    pub(super) fn persist_outbound_gate_binding(
        &self,
        attempt_id: AttemptId,
        gate_outcome: &str,
        gate_decision_ref: Option<&str>,
        gate_reason_codes: &[String],
    ) {
        let binding = OutboundGateBinding {
            gate_outcome: gate_outcome.to_owned(),
            gate_decision_ref: gate_decision_ref.map(ToOwned::to_owned),
            gate_reason_codes: gate_reason_codes.to_vec(),
        };
        if let Ok(encoded) = serde_json::to_vec(&binding) {
            let _ = self
                .vault
                .store
                .put_outbound_gate_binding(attempt_id.as_bytes(), &encoded);
        }
    }

    /// Reads the persisted gate surface of a scheduled outbound attempt, if any.
    pub(super) fn outbound_gate_binding(
        &self,
        attempt_id: AttemptId,
    ) -> Option<OutboundGateBinding> {
        self.vault
            .store
            .outbound_gate_binding(attempt_id.as_bytes())
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
    }

    // ── calendar (CAL-09) ───────────────────────────────────────────────
}

pub(super) fn outbound_intent_ref(attempt_id: AttemptId) -> String {
    format!("intent:{}", hex_string(attempt_id.as_bytes()))
}

pub(in crate::memory) fn parse_job_ref(job_ref: &str) -> MemoryResult<AttemptId> {
    let reference = job_ref
        .trim()
        .strip_prefix("job:")
        .unwrap_or_else(|| job_ref.trim());
    if reference.len() != 32 || !reference.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(MemoryError::bad_request(format!(
            "attempt ref {job_ref:?} is not a 32-hex attempt id"
        )));
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&reference[index * 2..index * 2 + 2], 16)
            .map_err(|_| MemoryError::bad_request(format!("attempt ref {job_ref:?} is not hex")))?;
    }
    AttemptId::from_bytes(&bytes).map_err(|_| {
        MemoryError::bad_request(format!("attempt ref {job_ref:?} is not an attempt id"))
    })
}
