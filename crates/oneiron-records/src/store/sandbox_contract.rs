//! Moved from `crates/oneiron/src/store/sandbox_contract.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::sandbox_import::SandboxImportClass;

pub const SANDBOX_WIT_WORLD_NAME: &str = "oneiron:code-run/guest@1.0.0";
