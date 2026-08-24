//! Finalize or discard the retrieval-run row a pack assembly registered.
//!
//! The [`super::builder::ContextPackTelemetry`] target itself is builder state;
//! only the two terminal writes live here.

use crate::error::Result;
use crate::store::RetrievalRunId;

use super::builder::ContextPackTelemetry;

pub(super) fn finalize_context_pack_telemetry(
    telemetry: ContextPackTelemetry<'_>,
    telemetry_run_id: Option<RetrievalRunId>,
    elapsed_us: u64,
    claims_suppressed: usize,
    surfaced_result_ids: &[[u8; 16]],
    empty_reason: Option<String>,
) -> Result<Option<RetrievalRunId>> {
    let Some(run_id) = telemetry_run_id else {
        return Ok(None);
    };
    match telemetry.finalize(
        run_id,
        elapsed_us,
        claims_suppressed,
        surfaced_result_ids,
        empty_reason,
    ) {
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
