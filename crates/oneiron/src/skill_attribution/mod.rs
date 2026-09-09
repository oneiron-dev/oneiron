//! ARCH-0035 attribution projector for the ARCH-0053 §4 skills loop.
//!
//! The bottom half of the loop: an attempt's outcome plus its edit-feedback is
//! CLASSIFIED before anything lands, so a good skill is not churned because the
//! executor fumbled, and an agent is not blamed for a skill that lied.
//!
//! ```text
//! RECEIPT (outcome + pack manifest)
//!   └─ projector ──> routed verdict
//!        ├─ skill_defect    → judgment against the SKILL entity
//!        ├─ execution_lapse → judgment against the ACTOR entity
//!        └─ discovery       → a skill EDIT PROPOSAL, never a claim
//! ```
//!
//! **Layer scope (SK stack 1737 → 1738 → 1739).** This module ROUTES and
//! PERSISTS judgments; it writes no claims. `skill.reliability` materializes in
//! ONE-1738 and the `actor.*` write doors open in ONE-1739 — both consume the
//! judgment rows this projector persists. The absence of claim writes here is
//! the stack's shape, not an omission: routing is the decision, claiming is the
//! consequence, and they land in different tickets so the routing can be
//! reviewed on its own.
//!
//! House shape is [`crate::comm::run_comm_projector`]: callers RECORD evidence
//! through a door, the projector converts unprojected evidence into durable
//! output in sequence order, and a cursor makes the pass idempotent and
//! resumable. The cursor is a local u64 following the
//! [`crate::dreamer_consolidation`] `read_watermark`/`advance_watermark` shape
//! (no generic engine watermark type exists — `ConsolidationWatermark` is
//! consolidation-scoped).

mod audit;
mod codec;
mod judge;
mod projector;
mod types;

pub use self::audit::{
    AttributionAuditReport, AuditFixture, attribution_audit_reports, held_out_audit_fixtures,
    run_attribution_audit, run_attribution_audit_with_judge,
};
pub use self::judge::{
    ATTRIBUTION_CALL_PURPOSE_NAME, AttributionJudge, RuleAttributionJudge, attribution_call_purpose,
};
pub use self::projector::{
    attribution_judgments, pending_edit_proposals, read_attribution_cursor,
    record_attribution_evidence, run_attribution_projector, run_attribution_projector_with_judge,
};
pub use self::types::{
    AttemptOutcome, AttributionJudgment, AttributionVerdict, OutcomeEvidence,
    SKILL_ATTRIBUTION_SCHEMA_VERSION, SkillEditProposal,
};

#[cfg(test)]
mod tests;

// The flat skill_attribution.rs module used to provide these names to the
// sibling test module through `use super::*`: its own private crate/std
// import header. After the directory split the seam re-imports the header
// (the re-exports above travel through the same glob) so `tests.rs`
// resolves exactly as it did before.
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use rmpv::Value;
