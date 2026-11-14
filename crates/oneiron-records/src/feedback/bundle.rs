//! Moved from `crates/oneiron/src/feedback/bundle.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::feedback::bundle::FEEDBACK_REF_MAX_BYTES;
pub use oneiron_verb_wire::feedback::bundle::FeedbackCategory;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::io::Cursor;

/// Stable encoding token for the v1 feedback bundle wire contract.
pub const FEEDBACK_BUNDLE_ENCODING: &str = "oneiron.feedback.bundle.v1";

/// Stable encoding token for a bundle that carries a proposal: the six v1
/// keys in v1 order, then `proposal`.
pub const FEEDBACK_BUNDLE_ENCODING_V2: &str = "oneiron.feedback.bundle.v2";

/// Maximum accepted `engine_version` length in bytes.
pub const FEEDBACK_ENGINE_VERSION_MAX_BYTES: usize = 64;

/// Domain separator for the bundle digest preimage.
pub const FEEDBACK_DIGEST_DOMAIN: &[u8] = b"oneiron.feedback.bundle.v1\0";

/// Domain separator for the v2 bundle digest preimage.
pub const FEEDBACK_DIGEST_DOMAIN_V2: &[u8] = b"oneiron.feedback.bundle.v2\0";

/// Graph tuning knobs, projected verbatim from the vault configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackHnswSnapshot {
    /// Maximum neighbors per node in layer 0.
    pub m_max_0: usize,
    /// Beam width used during graph construction.
    pub ef_construction: usize,
    /// Beam width used during search.
    pub ef_search: usize,
}
