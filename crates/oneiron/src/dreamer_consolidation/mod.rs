//! Dreamer consolidation algorithm + reflection gap scan (ONE-1289,
//! DREAM-002; DESIGN-PIN-20260710 Part A).
//!
//! Phases: 0 — global `learned_at` watermark scan selects dirty TURN
//! entities (claims never enter the working set, GATE-11); 1 — work
//! partitions in turn vocabulary `(conversation, world, facet)`; 2 —
//! post-extraction semantic candidate buckets keyed on
//! `(subject, predicate_root, world, facet)`; 3 — mechanical BLAKE3
//! evidence collapse, then the deterministic conflict trigger on the FULL
//! predicate, with only conflicting sets entering scoped LLM merge steps;
//! 4 — the reflection gap scan with dedupe/decay and escalate-once.
//!
//! This module NEVER writes belief claims: surviving candidates go to the
//! promotion writer (`dreamer_promotion`, ONE-1290) through a
//! [`ConsolidationSink`]. The watermark is the selection authority; the
//! landed offset pager and every `ledger_revision` hint are efficiency
//! devices only, never authority (1184-D1).
//!
//! Temporal-key writer contract, stated here as the CONSUMER-side assumption
//! of the cursor that depends on it: the watermark is a POSITION in the
//! `learned_at` temporal index, so an entity that must be re-consolidated is
//! re-stamped with a `learned_at` AHEAD of the cursor — never backdated behind
//! it. A re-dirtied TURN takes its new position from `now`, which is how the
//! append path returns it to the working set. A caller-supplied `learned_at`
//! that lands behind the cursor is simply never selected again, exactly as it
//! is under a seconds-only watermark: the temporal-index writers (the batch
//! layer) own that contract; this module only reads the index and cannot
//! enforce it.

mod conflict;
mod executor;
mod gap;
mod partition;
mod provenance;
mod support;
mod watermark;

#[cfg(test)]
mod tests;

pub use conflict::*;
pub use executor::*;
pub use gap::*;
pub use partition::*;
pub use provenance::*;
pub use support::*;
pub use watermark::*;

// The flat dreamer_consolidation.rs module used to provide these names to the
// sibling test module through `use super::*`; after the directory split the
// seam re-imports them so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::batch::EntityMetadataHeader;
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject};
#[cfg(test)]
use crate::dreamer_runner::{
    DreamerClaimAuthoringStrategy, DreamerConsolidationScope, DreamerRunnerStore, DreamerTurnRole,
    EnqueueDreamerAttemptOutcome,
};
#[cfg(test)]
use crate::dreamer_wake::{DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext};
#[cfg(test)]
use crate::edge::EdgeKind;
#[cfg(test)]
use crate::entity_id::{EntityId, bytes_to_hex_lower};
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::llm::{LlmBackend, LlmRequest};
#[cfg(test)]
use crate::registry::ENTITY_TYPE_TURN;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope};
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::collections::BTreeSet;
