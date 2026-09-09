//! ED-07 (ONE-1763, ARCH-0056 §8): the routing loop — what a judged amendment
//! says about the MODEL GENERATION that drafted the proposal.
//!
//! ED-03 ([`crate::edit_distance::attribution`]) answers *who owns this
//! amendment*. This module asks a different question of the same receipts: how
//! much editing does a given model generation cost the decider, in a given kind
//! of work. The aggregate is keyed `(model_version, task_class)` and folds
//! exactly two facts per judged amendment — the edit mass, and whether the
//! proposal was SOUND. That pair is the entire state behind every number here.
//!
//! # Relative, never absolute
//!
//! A raw mean edit cost is not a fact about a model, it is a fact about the
//! work: prose gets edited more than a calendar entry, and a generation that
//! only ever drafts prose would look terrible beside one that only ever drafts
//! calendar entries. Every exported score is therefore PGR-style RELATIVE —
//! this generation's mean against the mean of ALL generations' runs in the SAME
//! task class. `1.0` is par. A generation with no peers scores exactly par,
//! which is the honest answer to "compared to what".
//!
//! # A swap is a new generation, not a new datapoint
//!
//! [`RoutingScopeKey::model_version`] is a `ModelStack` identity, resolved from
//! a [`ModelId`] HERE (`settings::model_versioning` stays read-only prior art).
//! Swapping the serving model therefore starts a FRESH aggregate: the old row
//! is retained as history and never merged into the new one. Blending two
//! generations' edit mass would produce a number that describes neither, and it
//! would do so silently — the failure this keying exists to make impossible.
//!
//! Which generation a run belongs to is not re-derivable after the fact, so it
//! is recorded: [`record_judged_amendment`] writes a membership row binding the
//! receipt to the version that was serving. That ledger is what makes
//! [`rebuild_routing_projection`] an identity rather than a re-attribution.
//!
//! # The rollout ladder
//!
//! Per task class, owner-promoted, never automatic:
//!
//! | rung | computes | visible | feeds routing |
//! |---|---|---|---|
//! | [`RolloutRung::Shadow`] (default) | yes | no | no |
//! | [`RolloutRung::DataBar`] | yes | [`routing_data_bar`] | no |
//! | [`RolloutRung::Graduated`] | yes | yes | [`routing_weight_hint`] |
//!
//! Shadow is the default and it is not a formality: a scope nobody promoted
//! has its numbers computed and persisted and reaching nothing, so the ladder
//! can be climbed on evidence that already exists.
//!
//! # The Goodhart guard is the type, not a warning
//!
//! [`routing_weight_hint`] returns [`WeightHint`], which carries the relative
//! edit cost and the paired OUTCOME score together, and there is no accessor
//! that yields one without the other. The reason is that they come apart in
//! exactly the way that matters: a big Δ from pure preference is a sound
//! proposal that cost a lot to land, and a tiny Δ correcting a real defect is
//! an unsound one that cost almost nothing. Optimizing the cost alone would
//! select for proposals that are cheap to accept rather than right — so the
//! cost is never readable alone.
//!
//! For the same reason there is no `is_banned`, no exclusion list, and no door
//! that removes a model from consideration. The hint informs a WEIGHT. A
//! generation that should not be served is a settings decision, made by the
//! owner, somewhere else.

mod keys;
mod ladder;
mod read;
mod rebuild;
mod scope;
mod version;
mod write;

pub use self::ladder::{rollout_rung, set_rollout_rung};
pub use self::read::{routing_data_bar, routing_weight_hint};
pub use self::rebuild::rebuild_routing_projection;
pub use self::scope::{RolloutRung, RoutingScopeKey, RoutingScopeStats, WeightHint};
pub use self::version::{serving_model_version, set_serving_model};
pub use self::write::record_judged_amendment;

pub(in crate::edit_distance) use self::write::folded_model_version_in_txn;

#[cfg(test)]
mod tests;

// The flat routing.rs module used to provide these names to the sibling test
// module through `use super::*`: every routing-internal item the tests name
// bare. After the directory split the seam re-imports them so `tests.rs`
// resolves exactly as it did before.
#[cfg(test)]
use self::keys::DRAFTING_ROLE;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::llm::ModelId;
