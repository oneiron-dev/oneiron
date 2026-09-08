//! ORF-2 / OF-361 — the BudgetMem statistical PRE-FILTER: the cheap screen
//! that decides what is worth extracting BEFORE a token is spent.
//!
//! # Where it sits
//!
//! The batch tier plans a Dreamer round as `scan_dirty_turns` → Phase-1
//! `plan_partitions`. Until now the only pre-extraction filter was GATE-10's
//! role gate ([`dreamer_extraction_role_admissible`]), which answers
//! *eligibility*: a System or Tool turn may never seed a first-party claim.
//! This module answers the second, different question — *value*: of the turns
//! that MAY be extracted, which ones are worth the extraction budget.
//!
//! The two compose in that order and never merge. The role gate runs inside
//! the scan (`enumerate_admissible_turns`); the screen runs at the top of both
//! partition planners, over what the scan already admitted. A turn the role
//! gate refused is never scored, and a turn the screen skipped was already
//! role-admissible.
//!
//! # What it is not
//!
//! * **Not a security gate.** It is a budget estimate. Every failure mode
//!   resolves toward KEEPING work: an unreadable body passes unscored, an
//!   absent config row bootstraps to the compiled default. Committing a lossy
//!   round requires complete planning input and atomic screening receipts;
//!   corrupt rows abort that commit rather than silently losing its audit.
//! * **Not a selection authority.** It NEVER touches the watermark scan, the
//!   snapshot fence, `planned_turn_ids`, or `advance_watermark_to`. Skipped
//!   turns are still consumed by the round and still advance the cursor, so a
//!   skip costs the turn its extraction, not its place in the log — the
//!   [`reopen_prefilter_rescan`] door re-sweeps them on demand.
//! * **Not an LLM caller.** The scorer is pure arithmetic over the turn body.
//!   This module imports no model surface, by design and by test.
//!
//! # The shipped default is a no-op
//!
//! [`PrefilterConfig::default`] is `enabled` with `threshold = 0.0`, and a
//! verdict passes when `score >= threshold`. Every score is in `[0, 1]`, so
//! the default screens, scores, and drops NOTHING: planning is byte-identical
//! and no receipt is written. Turning a lossy filter on is an explicit
//! operator act ([`Vault::set_prefilter_config`]), never a side effect of
//! upgrading. The scores are still computed under the default so an operator
//! can watch the distribution before choosing a cut.
//!
//! [`dreamer_extraction_role_admissible`]: crate::dreamer_runner::dreamer_extraction_role_admissible

mod config;
mod receipts;
mod score;
mod screen;
mod supersession;

pub use self::{config::*, receipts::*, score::*, screen::*};

use std::collections::{BTreeMap, BTreeSet};

use crate::Vault;
use crate::dreamer_consolidation::{WorkingSetTurn, partition_round_hash};
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

#[cfg(test)]
mod tests;

// The flat dreamer_prefilter.rs module used to provide these names to the
// sibling test module through `use super::*`: its own private crate/std
// import header, and every dreamer_prefilter-internal item the tests name
// bare. After the directory split the seam re-imports both so `tests.rs`
// resolves exactly as it did before.
#[cfg(test)]
use crate::batch::ENTITY_METADATA_HEADER_LEN;
#[cfg(test)]
use crate::dreamer_runner::{DreamerTurnRole, dreamer_turn_role};
#[cfg(test)]
use crate::receipt::{
    FIELD_PREFILTER_DECISION, FIELD_PREFILTER_FEATURE_PREFIX, FIELD_PREFILTER_PASSED,
    FIELD_PREFILTER_PHASE, FIELD_PREFILTER_ROUND, FIELD_PREFILTER_SCANNED, FIELD_PREFILTER_SCORE,
    FIELD_PREFILTER_SKIPPED, FIELD_PREFILTER_THRESHOLD, FIELD_PREFILTER_TOKENS_SAVED,
    FIELD_PREFILTER_TURN, ReceiptKind, ReceiptQuery, ReceiptRecord,
};
#[cfg(test)]
use crate::registry::ENTITY_TYPE_TURN;
