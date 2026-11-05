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
    /// The organ's structured report as encoded JSON text, kept with the
    /// proposal verbatim (FIX 12431).
    pub report: String,
    /// The kept version's envelope; `None` gives the writer's own.
    pub made_by: Option<MadeBy>,
}

impl NativeOutput {
    /// JSON text for one finite 32-bit float, via the engine's JSON writer,
    /// for the organ landing (which holds no JSON writer). `None` when the
    /// float is not finite.
    pub fn json_f32_text(value: f32) -> Option<String> {
        if !value.is_finite() {
            return None;
        }
        serde_json::to_string(&value).ok()
    }

    /// JSON text for one finite 64-bit float, via the engine's JSON writer,
    /// for the organ landing (which holds no JSON writer). `None` when the
    /// float is not finite.
    pub fn json_f64_text(value: f64) -> Option<String> {
        if !value.is_finite() {
            return None;
        }
        serde_json::to_string(&value).ok()
    }
}
