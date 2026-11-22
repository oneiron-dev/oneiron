//! Door for `tests/timeline_shell_projection_recheck.rs` (FIX
//! TIMELINE-SHELL-TWO-SNAPSHOT-CAP): the projection the core memory
//! timeline route (`GET /v1/core/memory/{id}/timeline`) and a watched
//! timeline feed run on a timeline read before it, so a test can change the
//! reader's authority between the read's snapshot and the projection's.

use serde_json::Value;

/// The answer the timeline route builds from `timeline`, read on `read`
/// earlier, as it projects it now in the summary view under the default
/// body budget; the route's error, as text, when the projection fails.
pub fn project_timeline(
    read: &oneiron::claim::ScopedRead<'_>,
    timeline: oneiron::claim::ScopedReadResult<oneiron::MemoryTimeline>,
) -> Result<Value, String> {
    let response = crate::api::core_memory_timeline_response(
        read,
        timeline,
        crate::projection::View::Summary,
        crate::config::LimitsConfig::default().projection_body_bytes,
    )
    .map_err(|error| format!("{error:?}"))?;
    serde_json::to_value(response).map_err(|error| error.to_string())
}
