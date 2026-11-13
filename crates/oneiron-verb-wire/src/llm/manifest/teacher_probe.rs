//! Moved from `crates/oneiron/src/llm/manifest/teacher_probe.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_model::model_binding::ModelBinding;
use oneiron_model::model_binding::invalid;
pub use oneiron_model::teacher_probe_policy::TEACHER_PROBE_ID;
pub use oneiron_model::teacher_probe_policy::TeacherProbePolicy;
pub(crate) use oneiron_model::teacher_probe_policy::valid_holder_ref;
use serde::Deserialize;
use serde::Serialize;
use std::path::Path;

pub fn binding_hash(binding: &ModelBinding) -> Result<String> {
    let bytes = serde_json::to_vec(binding)
        .map_err(|e| invalid(&format!("teacher binding serialization failed: {e}")))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}
