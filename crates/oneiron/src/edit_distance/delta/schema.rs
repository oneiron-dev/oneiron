//! Delta schema types, the shared d_norm metric, encode/decode, and version/count helpers.

use serde::{Deserialize, Serialize};

use super::endpoint::EndpointRef;
use crate::edit_distance::myers::MOVE_DISCOUNT;
use crate::error::{Error, Result};

#[doc(hidden)]
pub use oneiron_records::edit_distance::delta::schema::{DeltaSource, OpsSummary};

/// The six ARCH-0056 §2 Δ fields, serialized into ONE-1747's reserved
/// `amendment_delta` receipt slot.
///
/// `proposed_ref` / `final_ref` are (document, version) pointers in every
/// lane: each names the retained source its end lives in, so the measurement
/// recomputes from the refs alone. A lane that hashed an end keeps the hash
/// beside the pointer as a check value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AmendmentDelta {
    /// The window's proposed end.
    pub proposed_ref: EndpointRef,
    /// The window's finalized end.
    pub final_ref: EndpointRef,
    /// Which lane measured this Δ.
    pub source: DeltaSource,
    /// [`OpsSummary::d_norm`] — the ONE pinned formula every ED producer
    /// uses, so a downstream consumer never sees mixed metrics.
    pub d_norm: f32,
    /// The edit mass behind `d_norm`.
    pub ops_summary: OpsSummary,
    /// Engine version that measured it, stamped at the encode site.
    pub engine_ver: String,
}

impl AmendmentDelta {
    /// Canonical bytes for the reserved receipt slot.
    ///
    /// # Errors
    ///
    /// Serialization failure — reachable only for a hand-built Δ whose
    /// `d_norm` is not finite (JSON has no NaN). Every constructor here
    /// clamps, so the engine's own Δs cannot hit it.
    pub fn encode(&self) -> Result<Vec<u8>> {
        crate::llm::canonical_json_bytes(self)
            .map_err(|_| Error::InvariantViolation("amendment delta encode"))
    }

    /// Reads back an encoded Δ.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] when the payload is not a Δ this engine
    /// wrote.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|_| Error::CorruptedIndex("amendment delta"))
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The measurement engine's own version (ARCH-0056 §2 `engine_ver`). It
/// moves only when a lane's counting changes, so a crate release that changes
/// no measurement does not split every version-keyed fold. 2.0.0: the
/// recorded-ops lane reads the authored op stream (FIX 7820).
pub const MEASUREMENT_ENGINE_VERSION: &str = "2.0.0";

/// The version stamped on every Δ at its measurement site.
pub(super) fn engine_ver() -> String {
    MEASUREMENT_ENGINE_VERSION.to_owned()
}

/// Shared with the reconstructed lane's line counts.
pub(in crate::edit_distance) fn u32_saturating(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
