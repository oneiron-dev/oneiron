//! SKILL-OPT-2 (ONE-1449, ARCH-0026 dreamer-v2 / ARCH-0053 §6): the held-out
//! score gate that arms `candidate → active` for an optimizer-born proposal.
//!
//! ```text
//! ONE-1448 drafts ─▶ proposal (candidate + proposed, cycle stamped at birth)
//!        │
//!        ├─ score gate ─┬─ held-out receipts, recomputed HERE
//!        │              ├─ a standing acceptance over the same basis is
//!        │              │  RETURNED, not re-scored (retries are free)
//!        │              ├─ judged replay: score(current) vs score(proposed)
//!        │              ├─ strict  after > before  (ties reject)
//!        │              ├─ commit-time: held-out set recomputed and compared
//!        │              ├─ accept-time governance_tier recheck
//!        │              └─ per-cycle ACCEPT cap, counted in PROPOSALS
//!        │                     ├─▶ typed verdict row ─▶ Gate receipt
//!        │                     └─▶ any ANSWER closes the proposal
//!        │
//!        └─ admission ──┬─ requires an ACCEPTED verdict
//!                       ├─ requires that verdict to bind THIS body, THIS
//!                       │  predecessor and THIS reserved evidence, all
//!                       │  recomputed in the committing snapshot
//!                       ├─ requires every cited source message still live
//!                       └─▶ candidate → active  (then the caller supersedes)
//! ```
//!
//! # A verdict is about a body, not about an id
//!
//! Every acceptance records the canonical content digest of the candidate it
//! scored, of the predecessor it scored against, and the count and digest of
//! the exact reserved evidence it was judged over. Admission recomputes all
//! three in the transaction the flip commits into and refuses on any
//! difference. Without that, "proposal X passed" was a permission attached to
//! an ID: edit the body under it, or re-point it at another target, and
//! unscored content reaches canon through a gate that did pass — once, for
//! something else.
//!
//! # An answer closes the question, and a race is not an answer
//!
//! ONE-1448 skips any skill with an open `candidate + proposed` revision,
//! because an unanswered proposal is a question already put to a human. So a
//! ruling that ANSWERS a proposal — a rejection, a tie, any refusal — moves it
//! to `approval: rejected` in the same transaction as the verdict row. Exactly
//! ONE durable disposition leaves the record open, and it is the cap deferral
//! ([`SkillEditDisposition::DeferredCycleCap`]): the budget was spent, which
//! says nothing about the proposal, so a later cycle picks it up. A terminal
//! answer that left the record open would wedge that skill out of the
//! optimization loop permanently on one tie.
//!
//! When the WORLD moves under an in-flight call instead — the reserved
//! evidence changes while the scorer is thinking, or a terminal reason read
//! before the write door no longer holds inside it — there is no ruling at all.
//! The transaction returns [`Error::SkillEditGateRetry`] and rolls back, so no
//! verdict row, no closure, no cap spend and no marker change commits: the
//! proposal is left byte-identical to a call that never ran. That is a
//! RETRYABLE outcome, typed apart from every refusal, and a rerun over a
//! settled ledger rules on it deterministically. A durable "the snapshot moved"
//! row would have been a second open class the contract does not have, and one
//! that grew a duplicate row on every raced retry.
//!
//! # The gate refines the approval flow, it does not replace it
//!
//! A passing score makes a proposal ELIGIBLE. Admission
//! ([`admit_optimized_skill_revision`]) is still an explicit act, and freezing
//! the predecessor is still [`crate::Vault::supersede_skill_record`]'s — the
//! landed chain is untouched. What ONE-1449 adds is a floor UNDER the automated
//! loop: an optimizer-born candidate cannot reach canon through a bare state
//! flip at all ([`check_optimizer_admission_in_txn`], wired at the batch
//! materialization chokepoint every SKILL body converges on). The owner's
//! ordinary update door over a HUMAN-authored record is untouched, protected
//! tier included: this is a dial on the robot, not a wall on the owner.
//!
//! # The split is a correctness convention, not a security boundary
//!
//! In-crate, a same-process reader can reach any receipt; the threat here is
//! overfitting drift, not an adversary, so no capability machinery is built for
//! it. Two honest layers are enforced instead:
//!
//! 1. **Import direction.** The optimizer's evidence loader
//!    ([`super::optimize_brief`]) calls [`dev_receipts`] and nothing else, so
//!    the author never sees a held-out outcome. Stated in both modules, and
//!    checkable by reading one function.
//! 2. **Independent recomputation.** The gate derives its held-out view from
//!    the DURABLE outcome ledger at accept time — never from a list the
//!    proposal carries. A leaky proposer therefore cannot influence WHICH
//!    receipts score it, only what it says.
//!
//! The partition itself is a per-skill hash of receipt identity with about one
//! fifth reserved, so the same `(skill, receipt)` always lands on the same side
//! however often it is asked, and the two sides are complements by
//! construction — disjoint without a second ledger to keep honest.
//!
//! # The score is a judged replay, and the judge is not the author
//!
//! A posterior recomputed over held-out receipts cannot be measured offline for
//! instructions that were never run, so the honest v1 score is a REPLAY:
//! [`HeldOutReplayScorer`] is asked to judge the same held-out evidence against
//! each instruction version in turn. The seam is the [`crate::skill_attribution::AttributionJudge`]
//! posture — a host-supplied LLM tier under [`skill_edit_score_call_purpose`],
//! injectable in tests, and structurally not the optimizer grading its own
//! homework. No epsilon: strict `>` is the anti-Goodhart floor, and a tie is a
//! rejection.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use rmpv::Value;
use sha2::{Digest, Sha256};

use super::{
    PROVENANCE_OPTIMIZE_CYCLE_KEY, PROVENANCE_OPTIMIZE_OF_ENTITY_KEY, PROVENANCE_OPTIMIZE_OF_KEY,
    PROVENANCE_OPTIMIZE_OF_VERSION_KEY, SKILL_OPTIMIZE_BIRTH_PATH,
    SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE, invalid, proven_cycle, tier_verdict_in_txn,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::ClaimApprovalStatus;
use crate::entity_id::{ENTITY_ID_LEN, EntityId, bytes_to_hex_lower, parse_entity_id};
use crate::error::{Error, ErrorKind, Result};
use crate::llm::CallPurpose;
use crate::receipt::{
    FIELD_SKILL_EDIT_ACCEPTED_VERDICT, FIELD_SKILL_EDIT_CYCLE, FIELD_SKILL_EDIT_DISPOSITION,
    FIELD_SKILL_EDIT_HELD_OUT_COUNT, FIELD_SKILL_EDIT_HELD_OUT_DIGEST,
    FIELD_SKILL_EDIT_HELD_OUT_RECEIPTS, FIELD_SKILL_EDIT_HELD_OUT_TRUNCATED,
    FIELD_SKILL_EDIT_MISSING_SOURCES, FIELD_SKILL_EDIT_PROPOSAL, FIELD_SKILL_EDIT_PROPOSAL_DIGEST,
    FIELD_SKILL_EDIT_SCORE_AFTER, FIELD_SKILL_EDIT_SCORE_BEFORE, FIELD_SKILL_EDIT_SKILL,
    FIELD_SKILL_EDIT_TARGET_DIGEST, ReceiptKind, ReceiptQuery, ReceiptRecord,
    retain_newest_receipt,
};
use crate::skill::{
    SkillGovernanceTier, SkillLifecycle, SkillRecord, encode_skill_record, validate_skill_update,
};
use crate::skill_convert::{PROVENANCE_BIRTH_KEY, source_message_refs};
use crate::store::Store;
use crate::temporal::TimeRange;

mod admission;
mod basis;
mod decision;
mod ledger;
mod verdict;

pub use admission::admit_optimized_skill_revision;
pub use basis::{
    HELD_OUT_REPLAY_SCORER, HeldOutReplayCase, HeldOutReplayScorer, SkillEditCycle, dev_receipts,
    held_out_receipt_set_digest, held_out_receipts, receipt_is_held_out,
    register_held_out_replay_scorer, set_skill_edit_cycle_cap, skill_body_binding_digest,
    skill_edit_cycle_cap, skill_edit_score_call_purpose,
};
pub use decision::{
    score_gate_skill_edit, score_gate_skill_edit_in_cycle, score_gate_skill_edit_with_scorer,
};
pub use ledger::{
    is_skill_edit_verdict_receipt, skill_edit_verdict, skill_edit_verdicts,
    skill_edit_verdicts_for_proposal,
};
pub use verdict::{HeldOutVerdict, SkillEditDisposition};

pub(crate) use admission::{
    check_optimizer_admission_in_txn, optimizer_birth_marker_for_create_in_txn,
};
pub(crate) use ledger::skill_edit_verdict_receipts;

#[cfg(test)]
pub(super) use admission::optimizer_origin_marker_key;

#[cfg(test)]
pub(super) use decision::{clear_pre_score_race_hook, set_pre_score_race_hook};

// The seam between the children: a helper one child hands another is
// re-imported here, so every mover resolves it exactly as it did inline.
use admission::{
    bounded_receipts, provenance_str, require_open_optimizer_proposal, target_is_current, target_of,
};
use basis::{
    ScoredBasis, cycle_cap_in_txn, evidence_identity, held_out_receipts_in_txn, host_replay_scorer,
    validate_score,
};
use decision::{close_answered_proposal_in_txn, readable_target, standing_verdict_in_txn};
use ledger::{record_verdict_in_txn, verdict_rows_in_txn};

// ---------------------------------------------------------------------------
// Dials + pinned strings
// ---------------------------------------------------------------------------

/// `vault_meta` key holding K, the accepted edits one Dreamer cycle may admit.
///
/// The `SKILL_OPTIMIZE_MIN_OUTCOMES_KEY` house pattern — a per-feature engine
/// dial over `vault_meta`, not a `settings.rs` UI preference.
pub const SKILL_EDIT_CYCLE_CAP_KEY: &[u8] = b"settings:skill_optimize:v1:cycle_cap";

/// K when the dial has never been set.
///
/// Two. The cap is a blast-radius bound on an automated editor, not a
/// throughput target: a wake that rewrites two skills leaves a reviewer a diff
/// they can hold in their head, and the overflow is DEFERRED rather than lost.
pub const DEFAULT_SKILL_EDIT_CYCLE_CAP: u32 = 2;

/// One receipt in this many is reserved for the gate.
///
/// Five ≈ the canon's 20%. Stated as a divisor because that is what the split
/// actually computes: bucket 0 of five is held out, buckets 1..5 are dev.
pub const HELD_OUT_RESERVE_DIVISOR: u32 = 5;

/// The [`CallPurpose`] a replay scorer's LLM tier must stamp, so gate scoring
/// is budgeted and audited as its own class rather than hiding inside the
/// drafting author's totals.
pub const SKILL_EDIT_SCORE_CALL_PURPOSE_NAME: &str = "skill_edit_score_replay";

/// Upper bound on a cycle label.
pub const SKILL_EDIT_CYCLE_MAX_BYTES: usize = 128;

/// Domain separator of the split hash. Pinned: changing it repartitions every
/// skill's evidence, which is a migration, not a refactor.
const SPLIT_DOMAIN: &[u8] = b"skill_optimize:heldout:v1\0";

/// `vault_meta` key prefix of the verdict ledger. Full key is this prefix ‖ a
/// UUIDv7 row id, so key order is WRITE order and a caller-supplied `at` stays
/// data rather than ordering (the `edit_distance::escalation` posture).
pub(super) const VERDICT_PREFIX: &[u8] = b"skill_optimize/verdict/v1\0";

/// Bumped by the MATERIAL-10 repair (v1 → v2: a v1 row carries no binding
/// digests, so a reader that accepted one would be trusting an acceptance
/// nobody can check the body of) and again by the MATERIAL-6 repair (v2 → v3: a
/// v2 row binds no PROPOSAL tier, so an owner's identity mark on the proposal
/// rode an older acceptance into canon, and v2 could still spell the retired
/// `deferred_evidence_changed` disposition).
///
/// Prerelease, and the honest answer to an unbindable row is to refuse it
/// rather than to grow a second code path for it: every v1/v2 row decodes as
/// [`Error::CorruptedIndex`]. There is no shim and no migration.
const VERDICT_SCHEMA_VERSION: u64 = 3;
const KEY_SCHEMA_VERSION: &str = "v";
const KEY_PROPOSAL: &str = "proposal";
const KEY_SKILL: &str = "skill";
const KEY_BEFORE: &str = "before";
const KEY_AFTER: &str = "after";
const KEY_DISPOSITION: &str = "disposition";
const KEY_CYCLE: &str = "cycle";
const KEY_HELD_OUT: &str = "held_out";
const KEY_HELD_OUT_COUNT: &str = "held_out_count";
const KEY_HELD_OUT_DIGEST: &str = "held_out_digest";
const KEY_HELD_OUT_TRUNCATED: &str = "held_out_truncated";
const KEY_PROPOSAL_DIGEST: &str = "proposal_digest";
const KEY_TARGET_DIGEST: &str = "target_digest";
const KEY_PROPOSAL_TIER: &str = "proposal_tier";
const KEY_ACCEPTED_VERDICT: &str = "accepted_verdict";
const KEY_MISSING_SOURCES: &str = "missing_sources";
const KEY_AT: &str = "at";

/// Domain separator of the canonical SKILL-body content digest.
const BODY_DIGEST_DOMAIN: &[u8] = b"skill_optimize:body:v1\0";

/// Domain separator of the canonical evidence-set digest.
const EVIDENCE_DIGEST_DOMAIN: &[u8] = b"skill_optimize:evidence:v1\0";

const VERDICT_ROW_LABEL: &str = "skill edit verdict row";
const SKILL_EDIT_RECEIPT_PREFIX: &str = "skill_edit:";
