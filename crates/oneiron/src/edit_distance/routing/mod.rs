//! ED-07 (ONE-1763, ARCH-0056 §8): the routing loop — what a judged amendment
//! says about the EXECUTOR that drafted the proposal.
//!
//! ED-03 ([`crate::edit_distance::attribution`]) answers *who owns this
//! amendment*. This module asks a different question of the same receipts: how
//! much editing does a given executor cost the decider, in a given kind of
//! work. A head is keyed by executor identity at revision, task class, task
//! type and measurement version, and folds per judged amendment the edit mass
//! and the label shares that explain it.
//!
//! # Relative, never absolute
//!
//! A raw mean edit cost is not a fact about a model, it is a fact about the
//! work: prose gets edited more than a calendar entry, and an executor that
//! only ever drafts prose would look terrible beside one that only ever drafts
//! calendar entries. The relative score is therefore PGR-style — this head's
//! mean against the observed floor and ceiling of the SAME task class and task
//! type. A head with no range to compare against (one executor, or floor equal
//! to ceiling) reads no relative score, which is the honest answer to
//! "compared to what".
//!
//! # A swap is a new head, not a new datapoint
//!
//! [`RoutingScopeKey::executor`] is the executor identity at revision — a
//! [`ModelId`](crate::ModelId), `provider/name@revision` — never a stack token
//! that would pool distinct models (FIX 7826). Swapping the executor therefore
//! starts a FRESH head: the old row is retained as the old executor's evidence
//! and never merged into the new one. Blending two executors' edit mass would
//! produce a number that describes neither, and it would do so silently — the
//! failure this keying exists to make impossible.
//!
//! The new head starts with zero own runs and reads the most recent other
//! executor's score as a weak prior of origin `carried`, with an explicit
//! weight in runs, marked UNTESTED while its own runs are below that weight
//! (`prior.rs`). The judge is unchanged by an executor swap; runs drafted on
//! the judge's own model are counted on the head.
//!
//! Which executor drafted a run is not re-derivable after the fact, so it is
//! recorded where the run begins: the attempt's executor stamp, carried onto
//! the amendment evidence and frozen on its judgment (FIX 9812).
//! [`record_judged_amendment`] and [`rebuild_routing_projection`] read that
//! stamp and nothing else — never the model serving at fold time. A receipt
//! with no stamp folds under the unknown-executor key.
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
//! [`routing_weight_hint`] returns [`WeightHint`], which carries the edit cost
//! together with the anchored outcomes of the runs behind it — how each run's
//! TASK settled, counted beside the cost and never blended into it (FIX 7828)
//! — and there is no accessor that yields the cost alone. The reason is that
//! they come apart in exactly the way that matters: low edit distance alone
//! rewards short, bland, hard-to-object-to output, a big Δ from pure
//! preference is a sound proposal that cost a lot to land, and a tiny Δ
//! correcting a real defect is an unsound one that cost almost nothing.
//! Optimizing the cost alone would select for proposals that are cheap to
//! accept rather than right — so the cost is never readable alone. The
//! attribution labels ride along as an explanation, never as the outcome.
//!
//! For the same reason there is no `is_banned`, no exclusion list, and no door
//! that removes a model from consideration. The hint informs a WEIGHT. An
//! executor that should not be served is a settings decision, made by the
//! owner, somewhere else.

mod keys;
mod ladder;
mod outcomes;
mod prior;
mod read;
mod rebuild;
mod scope;
mod version;
mod write;

pub use self::ladder::{rollout_rung, set_rollout_rung};
pub use self::read::{routing_data_bar, routing_weight_hint};
pub use self::rebuild::rebuild_routing_projection;
pub use self::scope::{CarriedPrior, RolloutRung, RoutingScopeKey, RoutingScopeStats, WeightHint};
pub use self::version::{serving_model_version, set_serving_model};
pub use self::write::record_judged_amendment;

pub(crate) use self::write::refold_task_outcomes_in_txn;

#[cfg(test)]
mod tests;

// The flat routing.rs module used to provide these names to the sibling test
// module through `use super::*`: every routing-internal item the tests name
// bare. After the directory split the seam re-imports them so `tests.rs`
// resolves exactly as it did before.
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::llm::ModelId;
