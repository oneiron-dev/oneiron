//! Private Dreamer runner store plus atomic admission.
//!
//! Durable Dreamer milestones are ordinary vault claims. Live runner state
//! (queue leases, local run-tree rows, parked rows, and budget counters) stays
//! in private LMDB rows and is not sync materialized as vault entities.

mod admission;
mod claim_authoring;
mod codec;
mod constants;
mod milestone;
#[cfg(feature = "sync")]
mod progress;
mod store;
mod types;

#[cfg(test)]
mod tests;

// `admission` is impl-only: it re-opens `impl DreamerRunnerStore` and owns no
// name the rest of the crate reaches for, so it needs no re-export. The globs
// below keep the pre-split surface byte-identical: `pub` items stay `pub`,
// `pub(crate)` seams stay `pub(crate)`, and `pub(super)` internals become
// visible to the whole dreamer_runner tree, tests.rs included.
// ONE-1707 registration: the plugin-suggestion payload type rides the
// EXISTING generic `DREAMER_RUNNER_ATTEMPT_KIND` queue. Re-exported here so
// the runner's attempt-type vocabulary is complete in one place, exactly as
// the other payload discriminators are. No queue kind, lease, retry, budget,
// or run-tree machinery is added: the job body lives in
// `dreamer_plugin_suggest` and reaches the queue through the ordinary
// `DreamerRunnerStore::enqueue` door.
pub use crate::dreamer_plugin_suggest::DREAMER_PLUGIN_SUGGEST_ATTEMPT_TYPE;

pub use self::claim_authoring::*;
pub use self::codec::*;
pub use self::constants::*;
pub use self::milestone::*;
#[cfg(feature = "sync")]
pub use self::progress::*;
pub use self::store::*;
pub use self::types::*;

// The flat dreamer_runner.rs module used to provide these names to the test
// module through `use super::*`; after the directory split the seam re-imports
// them so the sibling `tests.rs` resolves exactly as it did inline.
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptQueue, ClaimAttempt, ClaimOutcome,
};
#[cfg(test)]
use crate::claim::ClaimSubject;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(all(feature = "sync", test))]
use crate::registry::ENTITY_TYPE_CLAIM;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::WriteEnvelope;
#[cfg(test)]
use rmpv::Value;
