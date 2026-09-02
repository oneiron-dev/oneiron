//! ONE-1579 report envelope.
//!
//! The perf harness is the SIBLING of BEAM, not a replacement for it: BEAM
//! keeps accuracy and cost, this report answers "does the engine hold up".
//! Nothing here ever collapses accuracy, latency and cost into one number —
//! there is deliberately no composite score field, and every axis is emitted
//! as its own object with its own evidence kind and sample counts.
//!
//! Beside the eight axes the envelope carries three sections a consumer needs
//! in order to use them: `provenance` (where and from what inputs),
//! `publication` (every check the publish verdict rests on) and `acceptance`
//! (the ONE-1578 knobs and the ONE-1537 relationship). All three are checked
//! for before a report is allowed to leave the process.

use serde::Serialize;

use super::acceptance::AcceptanceEvidence;
use super::axes::{GatedWriteAxis, RecallLatencyAxis, ResidentMemoryAxis, SessionsAxis, WakeAxis};
use super::cache_events::CacheAxis;
use super::cells::RunMode;
use super::nvme::NvmeFsyncAxis;
use super::precision::PrecisionAxis;
use super::provenance::Provenance;
use super::publication::PublicationDecision;

/// Report envelope schema id.
pub(crate) const PERF_REPORT_SCHEMA: &str = "oneiron.bench.perf_report.v1";

/// Every axis the report must emit, in report order.
pub(crate) const AXES: [&str; 8] = [
    "recall_latency",
    "wake",
    "sessions",
    "resident_memory",
    "gated_writes",
    "precision",
    "cache",
    "nvme_fsync",
];

/// Non-axis sections the report must also carry.
pub(crate) const REPORT_SECTIONS: [&str; 3] = ["provenance", "publication", "acceptance"];

/// Every provenance field the report must carry.
pub(crate) const PROVENANCE_FIELDS: [&str; 23] = [
    "build_revision_blake3",
    "build_revision_source",
    "build_git_sha",
    "build_git_sha_source",
    "build_tree_dirty",
    "build_tree_dirty_source",
    "build_profile",
    "source_checkout_git_sha",
    "source_checkout_git_sha_source",
    "target_triple",
    "node",
    "cpu",
    "memory",
    "os",
    "filesystem",
    "plan_hash",
    "corpus_hash",
    "corpus_marker_evidence",
    "cache_events_hash",
    "cache_source",
    "seed",
    "sample_counts",
    "evidence_kind",
];

/// The whole report. Deliberately has NO composite/overall score field.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct PerfReport {
    pub(crate) schema: &'static str,
    pub(crate) mode: RunMode,
    pub(crate) publishable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) non_publishable_reason: Option<String>,
    /// Every check the publish verdict rests on, satisfied or not.
    pub(crate) publication: PublicationDecision,
    pub(crate) scoring_policy: &'static str,
    pub(crate) beam_relationship: &'static str,
    pub(crate) plan_label: String,
    pub(crate) provenance: Provenance,
    /// ONE-1578 knob measurements and the ONE-1537 embed-latency relationship.
    pub(crate) acceptance: AcceptanceEvidence,
    pub(crate) recall_latency: RecallLatencyAxis,
    pub(crate) wake: WakeAxis,
    pub(crate) sessions: SessionsAxis,
    pub(crate) resident_memory: ResidentMemoryAxis,
    pub(crate) gated_writes: GatedWriteAxis,
    pub(crate) precision: PrecisionAxis,
    pub(crate) cache: CacheAxis,
    pub(crate) nvme_fsync: NvmeFsyncAxis,
}

/// Scoring policy pinned into every report.
pub(crate) const SCORING_POLICY: &str = "axes are reported side by side and never collapsed into one score; accuracy and cost stay \
     BEAM-owned (ONEIRON-ARCH-0042) and are not restated, re-weighted or summarized here";
/// Relationship to BEAM pinned into every report.
pub(crate) const BEAM_RELATIONSHIP: &str = "sibling harness: BEAM answers 'is the answer good and what did it cost', this answers 'does \
     the engine hold up'; results live beside BEAM, never inside its score";

/// Axis keys that are present and non-null in `value`, reported as the ones
/// that are MISSING. Used by the emit path itself, so a dropped axis fails the
/// command instead of shipping a partial report.
pub(crate) fn missing_axes(value: &serde_json::Value) -> Vec<&'static str> {
    AXES.into_iter()
        .filter(|axis| !is_present(value, axis))
        .collect()
}

/// Non-axis sections that are missing or null.
pub(crate) fn missing_sections(value: &serde_json::Value) -> Vec<&'static str> {
    REPORT_SECTIONS
        .into_iter()
        .filter(|section| !is_present(value, section))
        .collect()
}

/// Provenance keys that are missing or null under `value.provenance`.
pub(crate) fn missing_provenance_fields(value: &serde_json::Value) -> Vec<&'static str> {
    let Some(provenance) = value.get("provenance") else {
        return PROVENANCE_FIELDS.to_vec();
    };
    PROVENANCE_FIELDS
        .into_iter()
        .filter(|field| !is_present(provenance, field))
        .collect()
}

fn is_present(value: &serde_json::Value, key: &str) -> bool {
    value.get(key).is_some_and(|found| !found.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dropped_axis_or_section_is_reported_as_missing() {
        let empty = serde_json::json!({});
        assert_eq!(missing_axes(&empty).len(), AXES.len());
        assert_eq!(missing_sections(&empty).len(), REPORT_SECTIONS.len());
        assert_eq!(
            missing_provenance_fields(&empty).len(),
            PROVENANCE_FIELDS.len()
        );

        let nulled = serde_json::json!({
            "recall_latency": serde_json::Value::Null,
            "provenance": { "build_revision_blake3": serde_json::Value::Null },
        });
        assert!(missing_axes(&nulled).contains(&"recall_latency"));
        assert!(missing_sections(&nulled).contains(&"publication"));
        assert!(missing_sections(&nulled).contains(&"acceptance"));
        assert!(missing_provenance_fields(&nulled).contains(&"build_revision_blake3"));
        assert!(missing_provenance_fields(&nulled).contains(&"build_git_sha"));
        assert!(missing_provenance_fields(&nulled).contains(&"source_checkout_git_sha"));
        assert!(missing_provenance_fields(&nulled).contains(&"cache_events_hash"));
        assert!(missing_provenance_fields(&nulled).contains(&"node"));
    }
}
