//! SAVED_QUERY — durable standing queries with staged evaluation (CA-02).
//!
//! A saved query is a *definition* plus a *staged evaluator*. Stage 1 is a
//! typed, cheap claim/edge expression; stage 2 is a hard expression, a semantic
//! threshold against an exemplar, or a rubric-driven LLM judge. Stage 1 failure
//! prevents every stage-2 call — that ordering is the whole cost model, so it
//! is a structural property of [`SavedQueryEvaluator::evaluate_entity`] rather
//! than a convention.
//!
//! What this module deliberately is NOT:
//!
//! * **Not a projector runtime.** ARCH-0035's `ProjectionState` is design-only.
//!   Membership lives as the CA-01-owned `campaign.member` derived claim plus
//!   entered/exited event rows; verdicts live as evidence-hash-keyed memo rows.
//!   No projector DAG, no live-subscription registry, no OF-241 dependency:
//!   evaluation runs on demand and on bounded wake batches.
//! * **Not a second member model.** [`CampaignMemberValue`] and its optional
//!   `derivation` are owned by `campaign::claims`; this module populates the
//!   derivation and writes through that module's encoder.
//! * **Not a byte allocator.** The structural kind takes a caller-assigned byte
//!   from the CRM band at registration time. There is no constant here, no
//!   `registry.rs` row, and no static byte anywhere in this ticket.
//!
//! ## Where the bytes live
//!
//! `vault_meta` rows do NOT replicate — sync exports entities, edges, and
//! claims. So the split here is by AUTHORITY, not by convenience:
//!
//! * **The definition is a real entity** of the dynamically registered
//!   SAVED_QUERY kind, written through the batch put chokepoint. A dynamic
//!   registration IS writable (`Store::validate_entity_type` accepts it), so
//!   there is no reason for the authority of a saved query to be a node-local
//!   sidecar — a peer that never received the definition could not evaluate,
//!   repair, or even name the query that derived its cohort.
//! * **The membership epoch is replica-convergent.** The `vault_meta` watermark
//!   row is a local fast path; the FLOOR is recomputed from the replicated
//!   `campaign.member` claims, whose CA-01 derivation carries the epoch. A
//!   promoted peer therefore continues the epoch sequence instead of restarting
//!   at 1 (see [`next_membership_epoch`]).
//! * **Memos, event rows, repair receipts, and migration maps stay
//!   node-local.** A memo is a derivation cache, not authority. Event rows are
//!   a local audit projection of transitions whose authoritative record is the
//!   replicated claim chain; losing them on a peer loses history, never truth.
//!
//! ## Principal binding
//!
//! The owner actor stored on the definition is the ONLY evaluation principal.
//! [`create_saved_query`] sets it from the authenticated principal (the request
//! DTO has no owner field, so no caller can choose another owner), and
//! [`update_saved_query`] / [`archive_saved_query`] re-check it before writing.
//! A principal that does not own a query cannot observe that it exists: reads
//! answer `None` and writes answer [`Error::EntityNotFound`], so the lifecycle
//! API leaks nothing to a caller who was never granted the query.

mod definition;
mod evaluator;
mod evidence;
mod filter;
mod lifecycle;
mod membership;
mod pack_drift;
mod storage;
mod support;

/// Private-encoding unit tests: memo-key canonicalization, malformed-row
/// rejection, and the pure predicates the evaluator composes. Public
/// behavior lives in `tests/saved_query_oracle.rs`.
#[cfg(test)]
mod tests;

pub use self::definition::{
    CreateSavedQueryRequest, EvalMode, EvalPolicy, QueryScope, SAVED_QUERY_SCHEMA_VERSION,
    SAVED_QUERY_SHORT_ID_PREFIX, SavedQueryDefinition, SavedQueryLifecycle, SavedQueryRecord,
    UpdateSavedQueryRequest, register_saved_query_kind,
};
pub use self::evaluator::{
    EvaluationRequest, SavedQueryEvaluator, SavedQueryJudgeBinding, run_llm_judge,
};
pub use self::evidence::{
    EVIDENCE_HASH_LEN, EvaluationOutcome, MatchDecision, MatchVerdict, RelevantEvidence,
    SavedQueryDerivationEnvelope, VerdictMemoKey, VerdictMemoRow, WakeEvaluationReport,
    compute_evidence_hash, put_verdict_memo, verdict_memo,
};
pub use self::filter::{
    ClaimComparison, EvidenceDependencies, FilterAst, MatcherSpec, filter_dependencies,
    parse_filter_ast, validate_per_entity_decidable,
};
pub use self::lifecycle::{
    archive_saved_query, create_saved_query, read_saved_query, update_saved_query,
};
pub use self::membership::{
    MembershipCause, MembershipCommitOutcome, MembershipEvent, MembershipTransition,
    MembershipWritePlan, commit_membership_plan, derived_member_value, membership_events,
    next_membership_epoch,
};
pub use self::pack_drift::{
    PackDrift, PackDriftResolution, PackMigrationMap, PackPredicateRewrite, put_pack_migration_map,
    repair_pack_drift,
};

// The flat saved_query.rs module used to provide these names to the test
// module through `use super::*`; after the directory split the seam re-imports
// them so the extracted sibling `tests.rs` resolves exactly as it did inline.
#[cfg(test)]
use self::evaluator::{
    CollectedEvidence, claim_effective_at, claim_in_scope, decode_judge_decision, evidence_to_json,
    semantic_decision,
};
#[cfg(test)]
use self::lifecycle::validate_definition;
#[cfg(test)]
use self::membership::watermark_verdict;
#[cfg(test)]
use self::storage::{
    decode_memo_row, decode_watermark, definition_from_json, definition_to_json, encode_memo_row,
    encode_watermark, keys,
};
#[cfg(test)]
use self::support::{
    EVALUATOR_VERSION, MICROS_PER_UNIT, canonical_json_bytes, cosine_similarity_micros, hex_lower,
    rmpv_to_json, vector_pair_fingerprint,
};

// Referenced only by an intra-doc link in this module's header; gated so the
// name is in scope for rustdoc without being an unused import.
#[cfg(doc)]
use crate::campaign::claims::CampaignMemberValue;
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
// Named by an intra-doc link in this module's header as well as by the
// extracted sibling tests; the `doc` arm keeps the name in scope for rustdoc,
// which does not enable `cfg(test)`.
#[cfg(any(test, doc))]
use crate::error::Error;
#[cfg(test)]
use serde_json::Value;
