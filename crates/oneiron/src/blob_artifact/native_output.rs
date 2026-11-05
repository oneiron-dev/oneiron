//! Native organ export files offered as artifact versions.

use crate::write_envelope::provenance::made_by::MadeBy;

/// One native organ result offered to an artifact as its next version: the
/// export file the organ produced, its report, and who made it from what.
#[derive(Debug, Clone, PartialEq)]
pub struct NativeOutput {
    /// The run that produced it: the consume-once key and the agent-run provenance.
    pub run_ref: String,
    /// The file name the organ gave its export.
    pub name: String,
    /// Must equal the artifact's media type: an export is a version of its kind.
    pub media_type: String,
    pub bytes: Vec<u8>,
    /// The organ's structured report (JSON), kept with the proposal.
    pub report: serde_json::Value,
    /// The kept version's envelope; `None` gives the writer's own.
    pub made_by: Option<MadeBy>,
}

impl NativeOutput {
    /// An organ's MessagePack report as the JSON report a native output keeps.
    #[must_use]
    pub fn report_from_msgpack(report: &rmpv::Value) -> serde_json::Value {
        serde_json::to_value(report).unwrap_or(serde_json::Value::Null)
    }
}
