//! Delta schema types, the shared d_norm metric, encode/decode, and version/count helpers.

use serde::{Deserialize, Serialize};

use crate::edit_distance::myers::MOVE_DISCOUNT;
use crate::error::{Error, Result};

/// How an [`AmendmentDelta`] was measured. Ordered by precedence, and the
/// token is pinned: a receipt's Δ payload carries it on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaSource {
    /// Replayed from ED-00's recorded op window.
    RecordedOps,
    /// Structured per-field diff of two canonical-MessagePack bodies.
    FieldDiff,
    /// Reconstructed after the fact by diffing the two endpoint texts.
    Reconstructed,
}

impl DeltaSource {
    /// The pinned on-disk token for this lane.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordedOps => "recorded_ops",
            Self::FieldDiff => "field_diff",
            Self::Reconstructed => "reconstructed",
        }
    }
}

/// The edit mass behind a Δ, in the unit its lane counts: CHARACTERS for
/// [`DeltaSource::RecordedOps`], LEAVES for [`DeltaSource::FieldDiff`], LINES
/// for [`DeltaSource::Reconstructed`].
///
/// `moved` is the discount channel: a producer that DETECTS a move records
/// the relocated units here and leaves them out of `ins`/`del`, so relocated
/// content is charged once and cheaply instead of twice at full price. Only
/// the reconstructed lane detects moves; the other two report `0`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsSummary {
    /// Units inserted.
    pub ins: u32,
    /// Units deleted.
    pub del: u32,
    /// Units the amendment left standing.
    pub kept: u32,
    /// Units relocated rather than rewritten (see the type docs).
    pub moved: u32,
    /// Whether the producer hit its own cost cap, leaving these counts an
    /// upper BOUND rather than an exact script.
    ///
    /// Only the reconstructed lane can set it (its Myers trace is the only
    /// capped work in the module). It rides the Δ onto disk because a
    /// consumer reading a capped diff as exact is the one way this telemetry
    /// lies.
    pub approx: bool,
}

impl OpsSummary {
    /// `clamp(edit_mass / (len_before + len_after), 0, 1)` — the ONE ratified
    /// ED metric, with `edit_mass = ins + del + 2 · MOVE_DISCOUNT · moved`.
    ///
    /// Every producer normalizes HERE so no two lanes can drift into
    /// different numbers. Two properties the callers depend on:
    ///
    /// * The denominator SUMS the two lengths rather than taking the max,
    ///   because a rewritten unit is one deletion AND one insertion: a full
    ///   replacement scores exactly `1`, where a max denominator would score
    ///   it `2`.
    /// * A zero-length window scores `0`. Nothing changed, because there was
    ///   nothing to change.
    #[must_use]
    pub fn d_norm(self, len_before: u32, len_after: u32) -> f32 {
        let window = len_before.saturating_add(len_after);
        if window == 0 {
            return 0.0;
        }
        let ratio = self.edit_mass() / f64::from(window);
        ratio.clamp(0.0, 1.0) as f32
    }

    /// The edit mass `d_norm` normalizes. A relocated unit costs
    /// `2 · MOVE_DISCOUNT` where the delete-plus-insert it stands in for
    /// would cost `2`.
    fn edit_mass(self) -> f64 {
        let relocated = f64::from(2.0 * MOVE_DISCOUNT) * f64::from(self.moved);
        f64::from(self.ins) + f64::from(self.del) + relocated
    }
}

/// The six ARCH-0056 §2 Δ fields, serialized into ONE-1747's reserved
/// `amendment_delta` receipt slot.
///
/// `proposed_ref` / `final_ref` are read THROUGH `source`: the recorded-ops
/// lane carries encoded Loro `Frontiers` (directly replayable), the
/// field-diff and reconstructed lanes carry the blake3 of each side (directly
/// verifiable). One string type, two meanings, disambiguated by a field that
/// is already in the struct.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AmendmentDelta {
    /// Handle for the window's proposed end.
    pub proposed_ref: String,
    /// Handle for the window's finalized end.
    pub final_ref: String,
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

/// House pattern (cf. `gate.rs`): the version is stamped from the manifest at
/// the measurement site, never written as a literal that outlives its bump.
pub(super) fn engine_ver() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Shared with the reconstructed lane's line counts.
pub(crate) fn u32_saturating(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
