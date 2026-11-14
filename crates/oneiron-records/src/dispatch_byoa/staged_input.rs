//! Moved from `crates/oneiron/src/dispatch_byoa/staged_input.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One run's staged job: the artifact version that holds it whole, its length
/// and digest, and the file it is staged as. The artifact id and the file
/// name are both derived from the digest, so a pin cannot point a run at
/// another artifact's bytes or at another path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedInputPin {
    /// The artifact version holding the job, as `blob-artifact:<id>@<version>`.
    pub artifact: String,
    /// The job's length in bytes.
    pub len: u64,
    /// BLAKE3 of the job.
    pub blake3: [u8; 32],
    /// The file the job is staged as, relative to the checkout's root:
    /// `.oneiron/staged/<blake3 hex>.json`.
    pub name: String,
}
