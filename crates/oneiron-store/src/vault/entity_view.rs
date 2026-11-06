//! Read-facing entity metadata and decoded body projection.

use serde::{Deserialize, Serialize};

/// Typed read-back view of one entity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EntityView {
    /// 32-hex entity id.
    pub id_hex: String,
    /// Short-id ref, when one is assigned.
    pub short_ref: Option<String>,
    /// Registry kind string (e.g. `MESSAGE`); `TYPE_<n>` for unregistered.
    pub kind: String,
    /// Occurred interval start (Unix seconds).
    pub occurred_start: u64,
    /// Occurred interval end (Unix seconds).
    pub occurred_end: u64,
    /// Learned-at (Unix seconds).
    pub learned_at: u64,
    /// Body decoded MessagePack→JSON; `None` when absent or not
    /// JSON-shaped (binary values are redacted per the companion codec).
    pub body: Option<serde_json::Value>,
    /// Original host-stamped Rule A provenance, with unreadable input refs withheld.
    pub made_by: Option<crate::write_envelope::provenance::made_by::MadeBy>,
}
