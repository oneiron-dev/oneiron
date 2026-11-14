//! Moved from `crates/oneiron/src/code_run/replay.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub(crate) use oneiron_store::result_manifest::CODE_RUN_OUTPUT_PREVIEW_WITHHELD;
pub use oneiron_store::result_manifest::CODE_RUN_REPLAY_HASH_LEN;
pub use oneiron_store::result_manifest::CodeRunOutputKind;
pub use oneiron_store::result_manifest::CodeRunOutputPreview;
use std::borrow::Cow;
use std::sync::Mutex;

pub const CODE_RUN_RNG_SEED_LEN: usize = 32;
