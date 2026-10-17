//! Agent-authored executable helpers (OF-353): a callable SKILL an agent
//! writes for itself, found, promoted and stopped through the skill
//! machinery, with no separate routine entity.
//!
//! - **Catalog.** [`callable_catalog`] lists the loadable callable skills
//!   with their typed call contracts, so an agent can see what a helper takes
//!   and returns before it calls one.
//! - **Promotion.** An agent-born helper lands Candidate + Proposed and can
//!   never activate itself. [`gate_callable_helper`] scores it on frozen
//!   cases the engine splits (the author never picks the held-out half, and
//!   cases the author supplied are refused), through a host-supplied
//!   [`CallableHarness`] that runs the exact source in the sandbox. It
//!   admits only under the Self-Harness rule, Δ_in ≥ 0 ∧ Δ_ho ≥ 0 ∧
//!   max(Δ_in, Δ_ho) > 0, and only when the helper's own anchored
//!   reliability is not worse than its parent's. Raw execution counts never
//!   promote. [`admit_callable_helper`] activates against the standing
//!   verdict for the exact content.
//! - **Stop.** [`suspend_callable_helper`] quarantines a helper on the
//!   owner's word, so no new pack loads it, and cancels every call of it
//!   already running in this vault (FIX 600); the evidence stays.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::Vault;
use crate::claim::ClaimApprovalStatus;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::learning::{LearningCell, LearningPredicate, TypeRef};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::HubFile;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

use super::lifecycle::SkillLifecycle;
use super::pack_load::skill_loadable;
use super::record::SkillRecord;
use super::role::{SkillCallContract, SkillRole};

/// The standing promotion verdict per helper. Key: the skill entity id.
const GATE_VERDICT: SideTable<EntityId, CallableGateVerdict, Named> =
    SideTable::new(&side_table::SKILL_CALLABLE_GATE);

/// The held-out share of a helper's cases, in 256ths of the case hash space.
const HELD_OUT_SHARE_OF_256: u8 = 77;

/// Fewest cases on each side of the split before a verdict can admit.
const MIN_CASES_PER_SPLIT: usize = 1;

/// The axis a helper's reliability is read on.
pub const HELPER_AXIS: &str = "quality";

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}

/// One loadable callable helper as an agent sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct CallableCard {
    pub skill: EntityId,
    pub skill_id: String,
    pub version: String,
    pub desc: String,
    pub call: SkillCallContract,
}

/// Every loadable callable skill and its call contract, ordered by skill id.
///
/// # Errors
///
/// Storage errors.
pub fn callable_catalog(vault: &Vault) -> Result<Vec<CallableCard>> {
    let mut cards = Vec::new();
    for id in vault.entities_by_type(ENTITY_TYPE_SKILL)? {
        let Some(record) = vault.get_skill_record(&id)? else {
            continue;
        };
        if record.role != SkillRole::Callable || !skill_loadable(&record) {
            continue;
        }
        let Some(call) = record.call.clone() else {
            continue;
        };
        cards.push(CallableCard {
            skill: id,
            skill_id: record.skill_id,
            version: record.version,
            desc: record.desc,
            call,
        });
    }
    cards.sort_by(|a, b| a.skill_id.cmp(&b.skill_id).then(a.skill.cmp(&b.skill)));
    Ok(cards)
}

/// A callable card as the SDK returns it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CallableCardView {
    /// The skill entity id, hex.
    pub skill: String,
    pub skill_id: String,
    pub version: String,
    pub desc: String,
    /// The entry file the call runs.
    pub reference: String,
    pub arguments: JsonValue,
    pub returns: JsonValue,
}

impl From<CallableCard> for CallableCardView {
    fn from(card: CallableCard) -> Self {
        Self {
            skill: card.skill.to_hex(),
            skill_id: card.skill_id,
            version: card.version,
            desc: card.desc,
            reference: card.call.reference,
            arguments: card.call.arguments,
            returns: card.call.returns,
        }
    }
}

/// One source file of a saved skill: `SKILL.md`, or a script it calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillSourceFile {
    pub path: String,
    /// UTF-8 file text.
    pub content: String,
}

/// `self.skills.save`: an agent saves a skill it wrote, `SKILL.md` and
/// scripts together. A callable helper declares `role: callable` and its
/// `call` contract in the frontmatter. A new skill lands Candidate +
/// Proposed; nothing here activates it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillSaveRequest {
    /// The skill entity to revise, hex; absent mints a new skill.
    #[serde(default)]
    pub id: Option<String>,
    pub files: Vec<SkillSourceFile>,
    /// The version the caller last read, for an update.
    #[serde(default)]
    pub expected_version: Option<String>,
}

/// `self.skills.fork`: an agent forks a skill under its own identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillForkRequest {
    /// The parent skill entity, hex.
    pub parent: String,
    /// The fork's entity id, hex; absent mints one.
    #[serde(default)]
    pub id: Option<String>,
    /// The fork's own skill identity.
    pub skill_id: String,
}

/// Parses a save request into the entity id, the record its `SKILL.md`
/// frontmatter declares, and the exact source files.
///
/// # Errors
///
/// [`ArtifactError::InvalidSkillBody`] for a malformed tree, frontmatter or
/// call contract; [`Error`] for a malformed id.
pub fn skill_save_parts(input: &SkillSaveRequest) -> Result<(EntityId, SkillRecord, Vec<HubFile>)> {
    let files: Vec<HubFile> = input
        .files
        .iter()
        .map(|file| HubFile::new(file.path.clone(), file.content.clone().into_bytes()))
        .collect();
    let package = crate::skill_hub::package_from_files(files)?;
    let id = match &input.id {
        Some(hex) => EntityId::from_hex(hex)?,
        None => EntityId::now(),
    };
    Ok((id, package.record, package.files))
}

/// The id a fork request names, or a fresh one.
///
/// # Errors
///
/// [`Error`] for a malformed id.
pub fn fork_target(input: &SkillForkRequest) -> Result<(EntityId, EntityId)> {
    let parent = EntityId::from_hex(&input.parent)?;
    let id = match &input.id {
        Some(hex) => EntityId::from_hex(hex)?,
        None => EntityId::now(),
    };
    Ok((parent, id))
}

/// One frozen case: the arguments a call took and the result it should give.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallableCase {
    /// The receipt or task the case was frozen from.
    pub case_ref: String,
    pub arguments: JsonValue,
    pub expected: JsonValue,
    /// Who supplied the case. A helper's own author never supplies its gate.
    pub source_author: Option<EntityId>,
}

/// Which half of the split a case falls in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseSplit {
    InSample,
    HeldOut,
}

/// The engine's split: a keyed hash of the helper and the case reference, so
/// neither the author nor the scorer chooses the held-out half.
#[must_use]
pub fn split_case(skill: &EntityId, case_ref: &str) -> CaseSplit {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron callable helper case split v1");
    hasher.update(skill.as_bytes());
    hasher.update(case_ref.as_bytes());
    if hasher.finalize().as_bytes()[0] < HELD_OUT_SHARE_OF_256 {
        CaseSplit::HeldOut
    } else {
        CaseSplit::InSample
    }
}

/// A pass rate before and after: the incumbent (the parent helper, or no
/// helper at all) against the candidate.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct HarnessScore {
    pub baseline: f64,
    pub candidate: f64,
}

impl HarnessScore {
    #[must_use]
    pub fn delta(&self) -> f64 {
        self.candidate - self.baseline
    }

    fn validate(&self) -> Result<()> {
        if (0.0..=1.0).contains(&self.baseline) && (0.0..=1.0).contains(&self.candidate) {
            Ok(())
        } else {
            Err(invalid("a harness score is a pass rate in [0, 1]"))
        }
    }
}

/// The host's sandboxed runner. It executes the exact source on each case
/// under the callable contract (no host file or credential services) and
/// reports pass rates for the incumbent and the candidate.
pub trait CallableHarness {
    /// # Errors
    ///
    /// Any runner failure; the gate records no verdict on an error.
    fn score(
        &self,
        candidate: &SkillRecord,
        candidate_files: &[HubFile],
        incumbent: Option<(&SkillRecord, &[HubFile])>,
        cases: &[&CallableCase],
    ) -> Result<HarnessScore>;
}

/// A helper's standing promotion verdict, bound to the exact content scored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallableGateVerdict {
    pub skill: EntityId,
    pub content_hash: Option<String>,
    pub in_sample: HarnessScore,
    pub held_out: HarnessScore,
    pub in_sample_cases: usize,
    pub held_out_cases: usize,
    /// The helper's own anchored reliability lower bound, when it has runs.
    pub reliability_lower_bound: Option<f64>,
    /// The parent's reliability mean the helper must not fall below.
    pub parent_reliability: Option<f64>,
    pub accepted: bool,
    pub reason: String,
    pub at: u64,
}

/// The Self-Harness acceptance rule.
#[must_use]
pub fn self_harness_accepts(in_sample: &HarnessScore, held_out: &HarnessScore) -> bool {
    let (d_in, d_ho) = (in_sample.delta(), held_out.delta());
    d_in >= 0.0 && d_ho >= 0.0 && d_in.max(d_ho) > 0.0
}

fn content_hash_text(record: &SkillRecord) -> Option<String> {
    record.content_hash.as_ref().map(|hash| format!("{hash:?}"))
}

fn source_files(vault: &Vault, id: &EntityId, record: &SkillRecord) -> Result<Vec<HubFile>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .runtime_skill_package_in_txn(&rtxn, id, record)?
        .map(|package| package.files)
        .unwrap_or_default())
}

/// The helper's (or its parent's) anchored reliability for `executor`.
fn reliability(
    vault: &Vault,
    skill: &EntityId,
    executor: &str,
    type_ref: &TypeRef,
) -> Result<Option<crate::learning::Estimate>> {
    let cell = LearningCell::new(LearningPredicate::Reliability, *skill)
        .executor(executor)
        .type_ref(type_ref.clone())
        .axis(HELPER_AXIS);
    crate::learning::learning_estimate(vault, &cell)
}

/// Scores a Candidate callable helper and stores the verdict.
///
/// `executor` and `type_ref` name the reliability cell the Bayesian check
/// reads. Cases the helper's own author supplied are refused, and the split
/// is the engine's.
///
/// # Errors
///
/// [`ArtifactError::InvalidSkillBody`] when the skill is not a Candidate
/// callable, a case is the author's own, too few cases fall on a side, or the
/// harness reports a score outside [0, 1]; harness and storage errors.
pub fn gate_callable_helper(
    vault: &Vault,
    skill: &EntityId,
    cases: &[CallableCase],
    harness: &dyn CallableHarness,
    executor: &str,
    type_ref: &TypeRef,
    now: u64,
) -> Result<CallableGateVerdict> {
    let record = vault
        .get_skill_record(skill)?
        .ok_or(Error::EntityNotFound)?;
    if record.role != SkillRole::Callable || record.call.is_none() {
        return Err(invalid("only a callable skill takes the helper gate"));
    }
    if record.lifecycle_status != SkillLifecycle::Candidate {
        return Err(invalid("the helper gate scores a Candidate"));
    }
    let author = {
        let rtxn = vault.store.env.read_txn()?;
        crate::memory::skill_author_in_txn(vault, &rtxn, skill, &record)?
    };
    if author.is_some() && cases.iter().any(|case| case.source_author == author) {
        return Err(invalid(
            "a helper's author never supplies the cases that promote it",
        ));
    }
    let (held_out, in_sample): (Vec<&CallableCase>, Vec<&CallableCase>) = cases
        .iter()
        .partition(|case| split_case(skill, &case.case_ref) == CaseSplit::HeldOut);
    if held_out.len() < MIN_CASES_PER_SPLIT || in_sample.len() < MIN_CASES_PER_SPLIT {
        return Err(invalid(
            "the helper gate needs cases on both sides of the split",
        ));
    }

    let files = source_files(vault, skill, &record)?;
    let parent = match record.forked_from {
        Some(parent) => vault
            .get_skill_record(&parent)?
            .map(|parent_record| -> Result<_> {
                let parent_files = source_files(vault, &parent, &parent_record)?;
                Ok((parent, parent_record, parent_files))
            })
            .transpose()?,
        None => None,
    };
    let incumbent = parent
        .as_ref()
        .map(|(_, parent_record, parent_files)| (parent_record, parent_files.as_slice()));
    let in_score = harness.score(&record, &files, incumbent, &in_sample)?;
    let ho_score = harness.score(&record, &files, incumbent, &held_out)?;
    in_score.validate()?;
    ho_score.validate()?;

    let own = reliability(vault, skill, executor, type_ref)?;
    let parent_estimate = match &parent {
        Some((parent, _, _)) => reliability(vault, parent, executor, type_ref)?,
        None => None,
    };
    let reliability_lower_bound = own
        .as_ref()
        .filter(|e| e.runs > 0.0)
        .map(|e| e.lower_bound());
    let parent_reliability = parent_estimate
        .as_ref()
        .filter(|e| e.runs > 0.0)
        .map(crate::learning::Estimate::mean);
    let not_worse = match (reliability_lower_bound, parent_reliability) {
        (Some(lower), Some(parent_mean)) => own
            .as_ref()
            .is_some_and(|e| e.upper_bound() >= parent_mean || lower >= parent_mean),
        _ => true,
    };
    let harness_ok = self_harness_accepts(&in_score, &ho_score);
    let accepted = harness_ok && not_worse;
    let reason = if !harness_ok {
        "the Self-Harness rule failed: a split got worse or neither improved"
    } else if !not_worse {
        "its anchored reliability is worse than its parent's"
    } else {
        "both splits held or improved, at least one improved"
    };
    let verdict = CallableGateVerdict {
        skill: *skill,
        content_hash: content_hash_text(&record),
        in_sample: in_score,
        held_out: ho_score,
        in_sample_cases: in_sample.len(),
        held_out_cases: held_out.len(),
        reliability_lower_bound,
        parent_reliability,
        accepted,
        reason: reason.to_owned(),
        at: now,
    };
    vault.with_write_txn_grouped(|wtxn| {
        GATE_VERDICT.put(&vault.store, wtxn, skill, &verdict)?;
        Ok(())
    })?;
    Ok(verdict)
}

/// The standing verdict for a helper, if one was scored.
///
/// # Errors
///
/// Storage errors.
pub fn callable_gate_verdict(
    vault: &Vault,
    skill: &EntityId,
) -> Result<Option<CallableGateVerdict>> {
    let rtxn = vault.store.env.read_txn()?;
    GATE_VERDICT.get(&vault.store, &rtxn, skill)
}

/// Activates a helper whose standing verdict accepted its exact content.
///
/// # Errors
///
/// [`ArtifactError::InvalidSkillBody`] when there is no accepted verdict, the
/// content changed since it was scored, or the skill is not a Candidate
/// callable; the skill update door's errors.
pub fn admit_callable_helper(vault: &Vault, skill: &EntityId, now: u64) -> Result<SkillRecord> {
    let verdict = callable_gate_verdict(vault, skill)?.ok_or(invalid(
        "a helper activates only on a standing gate verdict",
    ))?;
    if !verdict.accepted {
        return Err(invalid("the helper's gate verdict did not accept it"));
    }
    let mut record = vault
        .get_skill_record(skill)?
        .ok_or(Error::EntityNotFound)?;
    if record.role != SkillRole::Callable || record.lifecycle_status != SkillLifecycle::Candidate {
        return Err(invalid("only a Candidate callable helper activates here"));
    }
    if content_hash_text(&record) != verdict.content_hash {
        return Err(invalid(
            "the helper changed after its verdict; score it again",
        ));
    }
    record.lifecycle_status = SkillLifecycle::Active;
    record.approval_status = ClaimApprovalStatus::Approved;
    vault.update_skill_record(
        skill,
        &record,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(record)
}

/// Quarantines a helper on the owner's word: no new pack loads it, and its
/// evidence and verdicts stay. Reversible through the ordinary skill doors.
/// Once the quarantine commits, every call of it running in this vault is
/// cancelled: each fails with `code_step_cancelled`, and its caller goes on.
/// It returns once they are signalled, not once their guests have stopped.
///
/// # Errors
///
/// The owner-write refusal; [`ArtifactError::InvalidSkillBody`] for a
/// non-callable skill; the skill update door's errors.
pub fn suspend_callable_helper(
    vault: &Vault,
    owner: &WriteActor,
    skill: &EntityId,
    now: u64,
) -> Result<SkillRecord> {
    {
        let rtxn = vault.store.env.read_txn()?;
        vault.verify_owner_write_actor_in_txn(&rtxn, owner)?;
    }
    let mut record = vault
        .get_skill_record(skill)?
        .ok_or(Error::EntityNotFound)?;
    if record.role != SkillRole::Callable {
        return Err(invalid("only a callable helper is suspended here"));
    }
    record.lifecycle_status = SkillLifecycle::Quarantined;
    record.approval_status = ClaimApprovalStatus::Approved;
    vault.update_skill_record(
        skill,
        &record,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    // No new load admits it now, so the live set holds every call of it
    // that can still run.
    vault.skill_invocations.cancel_skill(skill);
    Ok(record)
}
