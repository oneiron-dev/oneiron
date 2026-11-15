//! Moved from `crates/oneiron/src/store/site_skill_exposure.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `(run, skill, rest)`: the run that was shown the knowledge, the skill it
/// came from, and `be64(seq)` plus the first 8 bytes of `blake3(scope)`.
pub type SiteExposureKey = ([u8; 16], [u8; 16], Vec<u8>);
