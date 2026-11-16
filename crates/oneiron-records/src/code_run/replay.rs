//! Moved from `crates/oneiron/src/code_run/replay.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::result_manifest::CODE_RUN_REPLAY_HASH_LEN;
pub use oneiron_store::result_manifest::CodeRunOutputKind;
pub use oneiron_store::result_manifest::CodeRunOutputPreview;

pub const CODE_RUN_RNG_SEED_LEN: usize = 32;
