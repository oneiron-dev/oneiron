//! Retained citable evidence on the process memory line.

use oneiron::claim::{PointRead, ScopedRead};
use oneiron::host_memory::{MachineMemory, MemoryLease};
use oneiron::memory::ReadMode;
use oneiron::retrieval_depth::DepthSearchResult;
use serde_json::{Map, Value};

use super::MemoryReasonEvidence;
use crate::error::ApiError;
use crate::projection::{BodyBudget, PreparedOmittedBody, View};

pub(super) struct CollectedEvidence {
    // The retained rows and their strings drop before their memory charge.
    rows: Vec<MemoryReasonEvidence>,
    memory: MemoryLease,
}

impl CollectedEvidence {
    pub(super) fn with_capacity(memory: &MachineMemory, capacity: usize) -> Self {
        let rows = Vec::with_capacity(capacity);
        let mut memory = memory.empty_lease();
        memory.materialized(0, backing_bytes(rows.capacity()));
        Self { rows, memory }
    }

    pub(super) fn push(&mut self, row: MemoryReasonEvidence) {
        let strings = (row.short_id.capacity() as u64)
            .saturating_add(row.kind.capacity() as u64)
            .saturating_add(row.text.capacity() as u64);
        let previous_capacity = self.rows.capacity();
        self.rows.push(row);
        let added_backing = backing_bytes(self.rows.capacity() - previous_capacity);
        self.memory
            .materialized(0, strings.saturating_add(added_backing));
    }

    fn pin(
        &mut self,
        index: usize,
        vault: &oneiron::Vault,
        mode: ReadMode,
    ) -> Result<(), ApiError> {
        let row = &mut self.rows[index];
        let short_id = vault
            .pinned_short_ref_with_mode(&row.id, mode)
            .map_err(|_| ApiError::internal_server_error("memory citation pin failed"))?;
        // Each deferred citation fills one newly pushed row's empty short id.
        self.memory.materialized(0, short_id.capacity() as u64);
        row.short_id = short_id;
        Ok(())
    }

    pub(super) fn as_slice(&self) -> &[MemoryReasonEvidence] {
        &self.rows
    }
}

fn backing_bytes(capacity: usize) -> u64 {
    (capacity as u64).saturating_mul(std::mem::size_of::<MemoryReasonEvidence>() as u64)
}

struct EvidenceProjection {
    evidence: CollectedEvidence,
    actions: Vec<DeferredEvidenceAction>,
}

enum DeferredEvidenceAction {
    Cite { index: usize, mode: ReadMode },
    Omitted(PreparedOmittedBody),
}

enum EvidenceReadError {
    Projection,
    MissingRevision,
}

impl From<oneiron::Error> for EvidenceReadError {
    fn from(_: oneiron::Error) -> Self {
        Self::Projection
    }
}

/// Projects admitted hits in native frames, retaining evidence but not raw bodies.
/// Citation and omission lookups retain their original interleaved input order,
/// after the single scoped read and its body pin have closed.
pub(super) fn collect_evidence(
    vault: &oneiron::Vault,
    scoped_read: &ScopedRead<'_>,
    retrieved: &mut DepthSearchResult,
    bodies: &mut BodyBudget<'_>,
    memory: &MachineMemory,
) -> Result<(CollectedEvidence, Vec<Value>), ApiError> {
    let refs: Vec<_> = retrieved
        .hits
        .iter()
        .filter_map(|hit| {
            retrieved
                .revisions
                .get(&hit.id)
                .map(|revision| PointRead::id(hit.id).at(ReadMode::Pinned(*revision)))
        })
        .collect();
    let requested = retrieved
        .narrowing
        .last()
        .map(|receipt| receipt.applied.as_filter());
    let projected = scoped_read
        .read_frames(
            &refs,
            requested.as_ref(),
            EvidenceProjection {
                evidence: CollectedEvidence::with_capacity(memory, refs.len()),
                actions: Vec::new(),
            },
            |offset, rows, state| {
                for (read, row) in refs[offset..].iter().zip(rows) {
                    let Some(oneiron::claim::ReadRow {
                        id,
                        entity_type: kind,
                        learned_at,
                        body: Some(body),
                        ..
                    }) = row
                    else {
                        continue;
                    };
                    let mode = read.mode;
                    if !bodies.admits(body.len()) {
                        state.actions.push(DeferredEvidenceAction::Omitted(
                            BodyBudget::prepare_omitted(
                                &id,
                                kind,
                                learned_at,
                                &body,
                                View::Summary,
                                mode,
                            ),
                        ));
                        continue;
                    }
                    let Value::Object(fields) = crate::projection::project_entity_parts(
                        &id,
                        kind,
                        learned_at,
                        &body,
                        View::Full,
                    ) else {
                        continue;
                    };
                    let ReadMode::Pinned(revision) = mode else {
                        return Err(EvidenceReadError::MissingRevision);
                    };
                    let index = state.evidence.rows.len();
                    state.evidence.push(MemoryReasonEvidence {
                        id,
                        revision,
                        kind: string_field(&fields, "kind").unwrap_or_else(|| "UNKNOWN".to_owned()),
                        text: evidence_text(&fields),
                        confidence: evidence_confidence(&fields),
                        short_id: String::new(),
                    });
                    state
                        .actions
                        .push(DeferredEvidenceAction::Cite { index, mode });
                }
                Ok(())
            },
        )
        .map_err(|error| match error {
            EvidenceReadError::Projection => {
                ApiError::internal_server_error("memory reason projection failed")
            }
            EvidenceReadError::MissingRevision => {
                ApiError::internal_server_error("memory evidence has no revision")
            }
        })?;
    retrieved.narrowing.push(projected.receipt);
    let EvidenceProjection {
        mut evidence,
        actions,
    } = projected.value;
    let mut omitted = Vec::new();
    for action in actions {
        match action {
            DeferredEvidenceAction::Cite { index, mode } => evidence.pin(index, vault, mode)?,
            DeferredEvidenceAction::Omitted(prepared) => {
                omitted.push(bodies.finish_omitted(prepared))
            }
        }
    }
    Ok((evidence, omitted))
}

fn string_field(fields: &Map<String, Value>, key: &str) -> Option<String> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|value| !value.trim().is_empty())
}

/// The row's text, preferring the claim value, then the common content keys,
/// then the projection's own label. Non-string values are rendered as compact
/// JSON so a structured value is still shown rather than silently dropped.
pub(super) fn evidence_text(fields: &Map<String, Value>) -> String {
    for key in ["val", "content", "text", "txt", "body"] {
        match fields.get(key) {
            Some(Value::String(text)) if !text.trim().is_empty() => return text.clone(),
            Some(Value::Null) | Some(Value::String(_)) | None => {}
            Some(other) => return other.to_string(),
        }
    }
    string_field(fields, "label").unwrap_or_default()
}

/// The row's calibrated confidence.
///
/// `conf` is the claim codec's own calibrated-absolute field. A structural
/// record carries none and is `1.0`: the caller named a stored fact, and
/// nothing about it is a ranked guess.
fn evidence_confidence(fields: &Map<String, Value>) -> f32 {
    fields
        .get("conf")
        .and_then(Value::as_f64)
        .map_or(1.0, |confidence| confidence.clamp(0.0, 1.0) as f32)
}
