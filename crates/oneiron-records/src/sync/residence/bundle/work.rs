//! Moved from `crates/oneiron/src/sync/residence/bundle/work.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::AuthorityEntryHash;
use oneiron_authority::authority::RecoveryRootId;
use oneiron_store::bundle_generations::SealedBundleGeneration;
use serde::Deserialize;
use serde::Serialize;

/// The immutable publication a caller asks the home to finish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedBundleCommitInput {
    pub generation: SealedBundleGeneration,
    pub parent: Option<SealedBundleGeneration>,
    pub root: Option<RecoveryRootId>,
    pub request: Option<AuthorityEntryHash>,
}
