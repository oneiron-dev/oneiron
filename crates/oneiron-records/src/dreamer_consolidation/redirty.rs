//! Moved from `crates/oneiron/src/dreamer_consolidation/redirty.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::consolidation_scope::DreamerConsolidationScope;

pub const fn slot(scope: DreamerConsolidationScope) -> usize {
    match scope {
        DreamerConsolidationScope::Micro => 0,
        DreamerConsolidationScope::Meso => 1,
        DreamerConsolidationScope::Macro => 2,
    }
}
