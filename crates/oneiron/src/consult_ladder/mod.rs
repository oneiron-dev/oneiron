//! Pure cross-actor consult ladder: state machine, typed verdicts, the OF-399
//! novelty guard, the Dreamer magistrate decision core, and the A2A wire
//! projection (ONE-1888).
//!
//! Nothing here reads or writes a vault. The module owns VOCABULARY and
//! DECISIONS; `crate::task_verb` owns every durable consequence — the TASK
//! body projection, the single LWW terminal register, the magistrate
//! provenance derivation, and the receipt writes. That split is the point:
//! a decision core that cannot touch storage cannot quietly grow a second
//! durable state owner beside ONE-1699's CRDT-synced TASK.
//!
//! Three laws are structural rather than conventional here:
//!
//! * **terminal is immutable** — every transition out of
//!   [`ConsultLadderState::Terminal`] is [`LadderTransitionError::TerminalImmutable`];
//!   corrections mint new lineage-bearing records instead;
//! * **rejected is not failed** — [`LadderTerminalDisposition::Rejected`] is a
//!   completed decision and [`LadderTerminalDisposition::Failed`] is
//!   infrastructure retry semantics, and they stay distinct through the TASK
//!   projection, the board tokens, and the A2A projection;
//! * **the writer never self-judges** — `decide_magistrate_from_derived_authorship`
//!   recuses on Dreamer-authored state BEFORE it weighs any evidence, and the
//!   authorship argument it takes is DERIVED from vault provenance by
//!   `task_verb`, never carried on [`MagistrateCase`].

mod a2a_projection;
mod ladder_state;
mod magistrate_decision;

pub use self::a2a_projection::*;
pub use self::ladder_state::*;
pub use self::magistrate_decision::*;

pub(crate) use self::magistrate_decision::{
    decide_magistrate_from_derived_authorship, magistrate_decision_layer,
};

#[cfg(test)]
mod tests;

// The flat consult_ladder.rs module used to provide these names to the sibling
// test module through `use super::*`: its own private crate import header.
// After the directory split the seam re-imports them so `tests.rs` resolves
// exactly as it did before.
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::task_verb::TaskAssignee;
