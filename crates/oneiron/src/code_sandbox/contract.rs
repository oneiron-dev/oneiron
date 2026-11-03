//! Sandbox boundary contracts are defined in the store layer.

pub use crate::store::sandbox_contract::{
    PLAIN_JS_HOST_VERB_DTS, SANDBOX_JS_COMPONENT_NAME, SANDBOX_WIT_WORLD_NAME,
    SandboxBoundaryContract, SandboxComponentBoundary, SandboxGuestLanguage, SandboxGuestRuntime,
    SandboxGuestTier,
};

use crate::code_run::SelfEffect;
/// Executor effects of a linked sandbox import.
pub trait SandboxLinkedImportEffects {
    fn write_trap_effect(self) -> Option<SelfEffect>;
}

impl SandboxLinkedImportEffects for SandboxLinkedImport {
    #[must_use]
    fn write_trap_effect(self) -> Option<SelfEffect> {
        match (self.class, self.name) {
            (SandboxImportClass::WriteTrap, "self.report_blocked") => {
                Some(SelfEffect::ReportBlocked)
            }
            _ => None,
        }
    }
}

pub use crate::store::sandbox_import::{SandboxImportClass, SandboxLinkedImport};
