//! Core half of `store::sandbox_import`: its store-layer items live in `oneiron_store::sandbox_import` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::sandbox_import::*;

/// One host import exposed at link time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SandboxLinkedImport {
    pub(crate) name: &'static str,
    pub(crate) class: SandboxImportClass,
}

impl SandboxLinkedImport {
    #[must_use]
    pub const fn new(name: &'static str, class: SandboxImportClass) -> Self {
        Self { name, class }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    #[must_use]
    pub const fn class(self) -> SandboxImportClass {
        self.class
    }
}
