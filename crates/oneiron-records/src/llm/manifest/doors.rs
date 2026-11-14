//! Moved from `crates/oneiron/src/llm/manifest/doors.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::llm::manifest::doors::ModelRoleInput;
pub use oneiron_verb_wire::llm::manifest::doors::ModelRoleInvoke;
pub use oneiron_verb_wire::llm::manifest::doors::ModelRoleRead;
pub use oneiron_verb_wire::llm::manifest::doors::ModelRoleReceipt;
pub use oneiron_verb_wire::llm::manifest::doors::ModelRouteRead;
pub use oneiron_verb_wire::llm::manifest::doors::ModelRouteReplace;
pub use oneiron_verb_wire::llm::manifest::doors::ModelRouteView;
pub use oneiron_verb_wire::llm::manifest::doors::OneironerBind;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// The loaded native bundle's receipt at its bind: stack and checkpoint,
/// label count and per-artifact hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OneironerBundleReceipt {
    pub stack_sha16: String,
    pub checkpoint_sha16: String,
    pub label_count: u32,
    /// Per-artifact sha256 (`file:hash`), in manifest order; None when the
    /// bind path has no manifest read. The missing field is `artifacts`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<String>>,
}
