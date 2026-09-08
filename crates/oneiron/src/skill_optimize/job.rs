//! One attempt end to end: rank, read, ask the author, re-check the target under the write txn, land one gated proposal.

use std::collections::HashSet;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::skill::{SKILL_DESC_MAX_BYTES, SkillDependency, SkillLifecycle, SkillRecord};
use crate::skill_convert::PROVENANCE_BIRTH_KEY;
use crate::skill_reliability::SkillReliabilityPosterior;
use crate::temporal::TimeRange;

use super::brief::{
    SKILL_OPTIMIZE_RATIONALE_MAX_BYTES, SkillEditDraft, SkillOptimizeAuthor, SkillOptimizeBrief,
    optimize_brief,
};
use super::dials::{invalid, validate_text};
use super::gate::SkillEditCycle;
use super::selection::optimize_candidates;
use super::tier::{SkillTierVerdict, tier_verdict_in_txn};

/// The [`PROVENANCE_BIRTH_KEY`] value stamped on a drafted proposal.
pub const SKILL_OPTIMIZE_BIRTH_PATH: &str = "skill_optimize";

/// Provenance key naming the optimized parent's `skillId`.
pub const PROVENANCE_OPTIMIZE_OF_KEY: &str = "optimizeOf";

/// Provenance key naming the optimized parent ENTITY, hex.
pub const PROVENANCE_OPTIMIZE_OF_ENTITY_KEY: &str = "optimizeOfEntity";

/// Provenance key naming the optimized parent's version.
pub const PROVENANCE_OPTIMIZE_OF_VERSION_KEY: &str = "optimizeOfVersion";

/// Provenance key carrying the author's rationale.
pub const PROVENANCE_OPTIMIZE_RATIONALE_KEY: &str = "rationale";

/// Provenance key carrying the receipt ids the draft rests on.
pub const PROVENANCE_OPTIMIZE_RECEIPTS_KEY: &str = "evidenceReceipts";

/// Provenance key naming the Dreamer attempt that drafted the proposal.
pub const PROVENANCE_OPTIMIZE_ATTEMPT_KEY: &str = "attempt";

/// Provenance key carrying the Dreamer CYCLE the proposal was drafted in.
///
/// Stamped at BIRTH and immutable thereafter
/// (`gate::check_optimizer_admission_in_txn`), because the per-cycle accept
/// cap is counted against this label: a cycle identity recovered later from a
/// prunable queue row would hand every proposal a private budget the moment the
/// queue was trimmed, and a mutable one would let a relabelled proposal buy a
/// second slot.
pub const PROVENANCE_OPTIMIZE_CYCLE_KEY: &str = "cycle";

/// The label prefix [`proven_cycle`] names a RUN-proven cycle with.
///
/// Pinned here because two modules have to agree on it: this one BUILDS the
/// label, and the attempt queue's run-id validator
/// (`crate::attempt_queue::validate`) sizes its own bound by subtracting this
/// prefix from [`SKILL_EDIT_CYCLE_MAX_BYTES`]. Spelling it twice is how a run
/// id the queue accepted became a cycle label nobody could name.
pub(crate) const SKILL_EDIT_CYCLE_RUN_PREFIX: &str = "run:";

/// Version prefix of a drafted revision.
const OPTIMIZE_VERSION_PREFIX: &str = "opt-";

/// Hex characters of the desc digest a drafted version carries.
const OPTIMIZE_VERSION_HASH_HEX: usize = 16;

/// What one `skill_optimize` attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkillOptimizeOutcome {
    /// The one skill this attempt considered. `None` when the tier-filtered
    /// candidate list was empty — a healthy library is not an error.
    pub skill: Option<EntityId>,
    /// The gated proposal entity, when one was drafted.
    pub proposal: Option<EntityId>,
    /// Why this attempt did what it did, in the words of whoever decided:
    /// the selector's, or the author's own.
    pub rationale: String,
}

/// Runs ONE `skill_optimize` attempt.
///
/// The order of the steps IS the contract:
/// 1. rank the tier-filtered candidates and take the head — one skill, chosen
///    fail-closed;
/// 2. read the evidence: the reliability posterior, its cited receipts, the
///    SK-04 defect receipts, and the OPEN edit proposals for that skill;
/// 3. ask the author, which may decline;
/// 4. re-read the target INSIDE the write transaction and refuse if it moved
///    while the author was thinking (the `skill_convert` merge-target rule):
///    a proposal against a superseded or already-re-proposed revision is one
///    the gate could never admit;
/// 5. land ONE proposal: a new entity, `candidate` + `proposed`, continuing
///    the target's `skillId` and dependency contract, carrying the target's
///    resolved tier forward as an explicit mark.
///
/// # Errors
///
/// Storage and body errors; whatever the author returns; and
/// [`Error::InvalidSkillBody`] when a draft is unusable (empty or oversized
/// text, or a "replacement" identical to the instructions it replaces), or when
/// `attempt` names no stored queue row and so proves no drafting cycle.
pub fn run_skill_optimize(
    vault: &Vault,
    attempt: AttemptId,
    author: &dyn SkillOptimizeAuthor,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<SkillOptimizeOutcome> {
    let Some(candidate) = optimize_candidates(vault)?.into_iter().next() else {
        return Ok(SkillOptimizeOutcome {
            skill: None,
            proposal: None,
            rationale: "no active skill is both optimizable and losing".to_owned(),
        });
    };
    let brief = optimize_brief(vault, &candidate)?;
    let (desc, rationale) = match author.draft(&brief)? {
        SkillEditDraft::Decline { rationale } => {
            validate_text(
                &rationale,
                SKILL_OPTIMIZE_RATIONALE_MAX_BYTES,
                "author rationale must be a non-empty string at most 1024 bytes",
            )?;
            return Ok(SkillOptimizeOutcome {
                skill: Some(candidate.skill),
                proposal: None,
                rationale,
            });
        }
        SkillEditDraft::Edit { desc, rationale } => (desc, rationale),
    };
    validate_text(
        &desc,
        SKILL_DESC_MAX_BYTES,
        "drafted desc must be a non-empty UTF-8 string at most 4096 bytes",
    )?;
    validate_text(
        &rationale,
        SKILL_OPTIMIZE_RATIONALE_MAX_BYTES,
        "author rationale must be a non-empty string at most 1024 bytes",
    )?;
    let SkillOptimizeBrief {
        desc: target_desc,
        version: target_version,
        cited_receipts: cited,
        defect_receipts: defects,
        ..
    } = brief;
    // An "edit" that changes nothing would mint a revision whose version
    // (derived from the text) collides with the one it proposes to replace —
    // and the supersede door would refuse it. Refuse earlier and say why.
    if desc == target_desc {
        return Err(invalid(
            "a drafted edit that restates the current instructions is not an edit",
        ));
    }

    // Resolved BEFORE the write door and persisted with the proposal: the cap
    // this draft will be counted against is a birth fact, not something a later
    // reader reconstructs from a queue row that may have been pruned by then.
    // A proposal whose cycle cannot be PROVEN at this moment is not born at
    // all — a private label is exactly the free budget the cap exists to deny.
    let drafted_in = proven_cycle(vault, attempt)?;
    let proposal_id = EntityId::now();
    vault.with_write_txn(|wtxn| {
        // Resolved at the WRITE door, not carried from the ranking: the
        // author ran outside this transaction, so the target may have been
        // superseded, quarantined or re-proposed in that window. A proposal
        // against a revision the gate can no longer supersede is dead on
        // arrival.
        let target = vault.read_skill_record_in_txn(&*wtxn, &candidate.skill)?;
        if target.lifecycle_status != SkillLifecycle::Active || target.version != target_version {
            return Err(invalid(
                "optimization target moved while the author was drafting",
            ));
        }
        let record = proposal_record(
            &target,
            &desc,
            &rationale,
            &cited,
            &defects,
            &candidate.skill,
            attempt,
            &drafted_in,
            tier_verdict_in_txn(vault, &*wtxn, &candidate.skill, &target)?,
        )?;
        vault.put_skill_record_in_txn(wtxn, &proposal_id, &record, occurred, learned_at)?;
        Ok(())
    })?;

    Ok(SkillOptimizeOutcome {
        skill: Some(candidate.skill),
        proposal: Some(proposal_id),
        rationale,
    })
}

/// The Dreamer cycle `attempt` PROVES — the one resolver, shared by the
/// drafting door (which stamps the label at birth) and the gate (which rules
/// under it).
///
/// Three answers, and the third is the repair:
///
/// | queue row | label |
/// |---|---|
/// | present, names a run | [`SKILL_EDIT_CYCLE_RUN_PREFIX`]`<id>` |
/// | present, no run | `attempt:<hex>` |
/// | ABSENT (pruned, or never enqueued) | typed error, no label |
///
/// The RUN, not the attempt, whenever the attempt names one: a wake that drafts
/// several proposals must count them against one cap, and per-attempt labelling
/// would hand every proposal a private cap that never binds. A genuinely
/// run-less attempt is its own cycle, which is the honest label rather than a
/// fallback — that attempt id is durable and unique either way.
///
/// A MISSING row is not that case, and conflating the two was the defect: a
/// retention sweep that trimmed the queue silently promoted every later
/// proposal to a private budget. Absence proves nothing, so it names nothing,
/// and the caller is refused. Queue read failures PROPAGATE for the same
/// reason: a cap that quietly degrades when the queue cannot be read is a cap
/// that stops binding exactly when it is most needed.
///
/// Every label this can build FITS: the queue's own run-id bound is
/// [`SKILL_EDIT_CYCLE_MAX_BYTES`] minus [`SKILL_EDIT_CYCLE_RUN_PREFIX`]
/// (`crate::attempt_queue::validate`), so a run id the queue admitted always
/// has room for the prefix, and the attempt spelling is a fixed 40 bytes. A
/// producer that could enqueue a run nobody could name a cycle for would have
/// stranded every proposal that run drafted — after the author had been paid.
///
/// # Errors
///
/// Storage/decode errors from the queue; [`Error::InvalidSkillBody`] when no
/// row for `attempt` is stored.
pub(crate) fn proven_cycle(vault: &Vault, attempt: AttemptId) -> Result<SkillEditCycle> {
    let Some(record) = AttemptQueue::new(vault).get(attempt)? else {
        return Err(invalid(
            "no stored attempt row proves this cycle; a cap counted against an unprovable label is not a cap",
        ));
    };
    match record.run_id {
        Some(run_id) => SkillEditCycle::new(format!("{SKILL_EDIT_CYCLE_RUN_PREFIX}{run_id}")),
        None => SkillEditCycle::new(format!(
            "attempt:{}",
            bytes_to_hex_lower(attempt.as_bytes())
        )),
    }
}

/// Builds the gated proposal record.
///
/// Every field is either the target's or the author's, and the two are kept
/// apart deliberately:
/// - `skill_id` and `dependencies` are the TARGET's, so the draft is a
///   REVISION the gate can supersede with rather than a rival skill that
///   declares no requirements;
/// - `desc` is the author's, and is the only content it may move;
/// - `generated` / [`ClaimSource::Generated`] is the honest stamp: an LLM
///   wrote these bytes, so the successor's own posterior starts from the
///   weak `Generated` prior and has to earn its place;
/// - `governance_tier` is the target's resolved tier, stamped EXPLICITLY.
///   The successor is machine-born and would otherwise resolve `Ambiguous`
///   forever, which would quietly retire it from the loop it was born in.
#[expect(
    clippy::too_many_arguments,
    reason = "the proposal's provenance names every input it rests on"
)]
fn proposal_record(
    target: &SkillRecord,
    desc: &str,
    rationale: &str,
    cited_receipts: &[String],
    defect_receipts: &[String],
    parent: &EntityId,
    attempt: AttemptId,
    cycle: &SkillEditCycle,
    tier: SkillTierVerdict,
) -> Result<SkillRecord> {
    let tier = tier.tier().ok_or(invalid(
        "an ambiguous-tier skill is never an optimization target",
    ))?;
    if tier.is_protected() {
        return Err(invalid(
            "identity/alignment-tier skills are never optimization targets",
        ));
    }
    let mut receipts: Vec<Value> = Vec::new();
    let mut seen = HashSet::new();
    for receipt in defect_receipts.iter().chain(cited_receipts) {
        if seen.insert(receipt.as_str()) {
            receipts.push(Value::from(receipt.as_str()));
        }
    }
    let provenance = Value::Map(vec![
        (
            Value::from(PROVENANCE_BIRTH_KEY),
            Value::from(SKILL_OPTIMIZE_BIRTH_PATH),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_OF_KEY),
            Value::from(target.skill_id.as_str()),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_OF_ENTITY_KEY),
            Value::from(parent.to_hex()),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_OF_VERSION_KEY),
            Value::from(target.version.as_str()),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_RATIONALE_KEY),
            Value::from(rationale),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_RECEIPTS_KEY),
            Value::Array(receipts),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_ATTEMPT_KEY),
            Value::from(bytes_to_hex_lower(attempt.as_bytes())),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_CYCLE_KEY),
            Value::from(cycle.as_str()),
        ),
    ]);
    let dependencies: Vec<SkillDependency> = target.dependencies.clone();
    Ok(SkillRecord::new(
        target.skill_id.as_str(),
        desc,
        optimize_version(desc),
        // The gate, in one field: a proposal is PROPOSED. Nothing in this
        // module can write `approved`, so nothing in this module can admit.
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        SkillReliabilityPosterior::seeded_from_provenance(
            crate::skill_reliability::ProvenanceTrustClass::Generated,
        )
        .mean(),
        true,
        false,
        dependencies,
        provenance,
    )
    .with_governance_tier(tier))
}

/// The drafted revision's version string.
///
/// Names the content instead of counting behind it (ARCH-0053 §7, the
/// `skill_convert` revision rule): the drafted text decides the version, so a
/// draft can never collide with the revision it proposes to replace unless it
/// IS that revision — which the caller has already refused.
fn optimize_version(desc: &str) -> String {
    let digest = Sha256::digest(desc.as_bytes());
    let hex = bytes_to_hex_lower(&digest);
    format!(
        "{OPTIMIZE_VERSION_PREFIX}{}",
        &hex[..OPTIMIZE_VERSION_HASH_HEX]
    )
}
