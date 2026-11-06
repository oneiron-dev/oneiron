//! Consolidation attempt-table lanes and their stored queue kinds.

use crate::dreamer_attempt_kind::{
    DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND, DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND,
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND,
};

/// Consolidation attempt-table lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DreamerConsolidationScope {
    Micro,
    Meso,
    Macro,
}

impl DreamerConsolidationScope {
    /// Stable scope string used in Dreamer payloads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Micro => "micro",
            Self::Meso => "meso",
            Self::Macro => "macro",
        }
    }

    /// Private attempt-table kind for this consolidation lane.
    #[must_use]
    pub const fn attempt_kind(self) -> &'static str {
        match self {
            Self::Micro => DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND,
            Self::Meso => DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND,
            Self::Macro => DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND,
        }
    }
}
