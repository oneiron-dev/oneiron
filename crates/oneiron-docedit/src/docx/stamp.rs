//! Stable engine and version stamps for native docx revisions.
//!
//! Every tracked change this organ writes carries the engine author string,
//! and every docx manifest records the engine stamp, so a version record or
//! receipt can say which engine produced which bytes without re-parsing XML.
//! The stamp strings are pinned: changing one is a reviewed decision, never a
//! silent edit, because stored receipts compare them by value.

use serde::{Deserialize, Serialize};

/// The native docx writer engine name. Pinned.
pub const DOCX_ENGINE: &str = "oneiron-docedit-docx";
/// The native docx writer version. Pinned per release; bump with the organ.
pub const DOCX_ENGINE_VERSION: &str = "0.1.0";
/// The stemma source-fork tag this writer uses. Pinned; see
/// `vendor/stemma/PROVENANCE.md`.
pub const DOCX_STEMMA_PIN: &str = "v0.6.0 ad1e70deac0a828d5162ac3b3f2186c2bb0c075e";

/// The engine stamp recorded on every docx manifest and revision mark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocxEngineStamp {
    /// Which engine wrote the revision (`DOCX_ENGINE`).
    pub engine: String,
    /// Engine version (`DOCX_ENGINE_VERSION`).
    pub version: String,
    /// Upstream source pin (`DOCX_STEMMA_PIN`).
    pub stemma_pin: String,
}

impl DocxEngineStamp {
    /// Storage-independent version stamp for the shared handoff.
    #[must_use]
    pub fn engine_id(&self) -> crate::calc::EngineId {
        crate::calc::EngineId {
            engine: self.engine.clone(),
            version: self.version.clone(),
        }
    }
    /// The current stamp. No I/O, no clock, deterministic.
    #[must_use]
    pub fn current() -> Self {
        Self {
            engine: DOCX_ENGINE.to_owned(),
            version: DOCX_ENGINE_VERSION.to_owned(),
            stemma_pin: DOCX_STEMMA_PIN.to_owned(),
        }
    }

    /// The `w:author` value written on `w:ins`/`w:del` marks.
    /// Deterministic: `oneiron-docedit-docx/0.1.0`.
    #[must_use]
    pub fn author(&self) -> String {
        let engine = &self.engine;
        let version = &self.version;
        format!("{engine}/{version}")
    }
}

impl Default for DocxEngineStamp {
    fn default() -> Self {
        Self::current()
    }
}
