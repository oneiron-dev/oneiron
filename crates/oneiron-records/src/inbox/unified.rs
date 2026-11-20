//! Moved from `crates/oneiron/src/inbox/unified.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::inbox::compilation_target::CompilationTarget;
pub use oneiron_verb_wire::inbox::unified::InboxGroupResolveTarget;

impl From<&InboxGroupResolveTarget> for CompilationTarget {
    fn from(value: &InboxGroupResolveTarget) -> Self {
        match value {
            InboxGroupResolveTarget::Fallback => Self::Fallback,
            InboxGroupResolveTarget::Ban(text) => Self::Ban(text.clone()),
            InboxGroupResolveTarget::StyleRule(text) => Self::StyleRule(text.clone()),
            InboxGroupResolveTarget::CharterLine(text) => Self::CharterLine(text.clone()),
            InboxGroupResolveTarget::BriefUpdate(text) => Self::BriefUpdate(text.clone()),
        }
    }
}
