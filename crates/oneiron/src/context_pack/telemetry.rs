//! Finalize or discard the retrieval-run row a pack assembly registered.
//!
//! The [`super::builder::ContextPackTelemetry`] target itself is builder state;
//! only the two terminal writes live here.

use crate::context_pack::{ContextEntity, ContextPack};
use crate::error::Result;
use crate::store::{RetrievalPackOutput, RetrievalRunFinalize, RetrievalRunId};

use super::builder::ContextPackTelemetry;

#[expect(
    clippy::too_many_arguments,
    reason = "the finalize door carries one atomic run receipt and its optional exact pack output"
)]
pub(super) fn finalize_context_pack_telemetry(
    telemetry: ContextPackTelemetry<'_>,
    telemetry_run_id: Option<RetrievalRunId>,
    elapsed_us: u64,
    total_in_scope: usize,
    claims_suppressed: usize,
    surfaced_result_ids: &[[u8; 16]],
    empty_reason: Option<String>,
    pack_output: Option<RetrievalPackOutput>,
) -> Result<Option<RetrievalRunId>> {
    let Some(run_id) = telemetry_run_id else {
        return Ok(None);
    };
    match telemetry.finalize(RetrievalRunFinalize {
        run_id,
        elapsed_us,
        total_in_scope,
        claims_suppressed,
        surfaced_result_ids,
        empty_reason,
        pack_output,
    }) {
        Ok(()) => Ok(Some(run_id)),
        Err(error) => {
            discard_failed_context_pack_telemetry(telemetry, Some(run_id));
            if telemetry.is_session() {
                // A ROOM's assembly fails with its finalize. Warning past it
                // would return a successful off-record retrieval carrying a
                // provisional row and no final registration — log-and-continue
                // over both the exactly-once clause and the close-set one. The
                // discard above is the residue half of the same rule and is
                // attempted first; whether it lands or not, the retrieval is
                // the failure the caller sees.
                return Err(error);
            }
            tracing::warn!(
                ?error,
                "context-pack retrieval telemetry finalization failed; discarding provisional run id"
            );
            Ok(None)
        }
    }
}

pub(super) fn discard_failed_context_pack_telemetry(
    telemetry: ContextPackTelemetry<'_>,
    telemetry_run_id: Option<RetrievalRunId>,
) {
    let Some(run_id) = telemetry_run_id else {
        return;
    };
    if let Err(error) = telemetry.discard(run_id) {
        tracing::warn!(
            ?error,
            "failed context-pack retrieval telemetry discard failed; continuing error return"
        );
    }
}

/// A lossless snapshot of the structured return, not a profile- or budget-
/// projected presentation. Serializable terminal paths record their actual
/// wire bytes instead.
#[derive(serde::Serialize)]
struct PackSnapshot<'a> {
    capabilities: &'a [crate::context_board::CapabilityHit],
    l2_base: Option<L2Snapshot<'a>>,
    retrieval_quality: &'a crate::retrieval_quality::RetrievalQualityReport,
    results: Vec<EntitySnapshot<'a>>,
    neighbors: Vec<EntitySnapshot<'a>>,
    stats: &'a crate::context_pack::PackStats,
    empty: &'a Option<crate::context_pack::EmptyContext>,
}

#[derive(serde::Serialize)]
struct L2Snapshot<'a> {
    content_hash: [u8; 32],
    body: &'a str,
    evidence_ids: Vec<[u8; 16]>,
}

#[derive(serde::Serialize)]
struct EntitySnapshot<'a> {
    id: [u8; 16],
    short_id: &'a str,
    content_hash: u8,
    source_revision_ref: Option<[u8; 16]>,
    entity_type: u8,
    score: f32,
    critical: bool,
    fields: &'a Option<std::collections::HashMap<String, serde_json::Value>>,
    edges: Option<Vec<EdgeSnapshot<'a>>>,
    vector: &'a Option<Vec<f32>>,
}

#[derive(serde::Serialize)]
struct EdgeSnapshot<'a> {
    kind: u8,
    target: [u8; 16],
    target_short_id: &'a Option<String>,
    weight: f32,
    created_at: u64,
    vad: &'a Option<crate::affect::Vad>,
    provenance: Option<[u8; 2]>,
}

impl<'a> From<&'a ContextEntity> for EntitySnapshot<'a> {
    fn from(entity: &'a ContextEntity) -> Self {
        Self {
            id: *entity.id.as_bytes(),
            short_id: &entity.short_id,
            content_hash: entity.content_hash,
            source_revision_ref: entity.source_revision_ref,
            entity_type: entity.entity_type,
            score: entity.score,
            critical: entity.critical,
            fields: &entity.fields,
            edges: entity.edges.as_ref().map(|edges| {
                edges
                    .iter()
                    .map(|edge| EdgeSnapshot {
                        kind: edge.kind as u8,
                        target: *edge.target.as_bytes(),
                        target_short_id: &edge.target_short_id,
                        weight: edge.weight,
                        created_at: edge.created_at,
                        vad: &edge.vad,
                        provenance: edge.provenance.map(|flags| {
                            [flags.confirmation_status as u8, flags.actor_class as u8]
                        }),
                    })
                    .collect()
            }),
            vector: &entity.vector,
        }
    }
}

pub(super) fn raw_pack_output(pack: &ContextPack) -> Result<RetrievalPackOutput> {
    let snapshot = PackSnapshot {
        capabilities: &pack.capabilities,
        l2_base: pack.l2_base.as_ref().map(|summary| L2Snapshot {
            content_hash: summary.content_hash,
            body: summary.body.as_ref(),
            evidence_ids: summary
                .evidence_ids()
                .iter()
                .map(|id| *id.as_bytes())
                .collect(),
        }),
        retrieval_quality: &pack.retrieval_quality,
        results: pack.results.iter().map(EntitySnapshot::from).collect(),
        neighbors: pack.neighbors.iter().map(EntitySnapshot::from).collect(),
        stats: &pack.stats,
        empty: &pack.empty,
    };
    let bytes = rmp_serde::to_vec_named(&snapshot)
        .map_err(|_| crate::Error::InvariantViolation("retrieval pack telemetry encode failed"))?;
    Ok(RetrievalPackOutput {
        format: "msgpack.context-pack.v1".to_owned(),
        bytes,
    })
}
