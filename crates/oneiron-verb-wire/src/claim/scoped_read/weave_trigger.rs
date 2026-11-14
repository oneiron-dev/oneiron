//! Moved from `crates/oneiron/src/claim/scoped_read/weave_trigger.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::claim::ScopedReadReceipt;
use serde::Deserialize;
use serde::Serialize;

/// A completed publication. Read its sections through `vault.weave.digest`
/// with `scheduled_for`; the trigger does not run the lens's model step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WeaveDigestRendered {
    pub scheduled_for: u64,
    pub rendered_at: u64,
    pub narrowing: ScopedReadReceipt,
}
