//! Promotion under the campaign's goal: an untouched held-out decision, one
//! sealed confirmation on OF-578's cohort ledger, the sufficiency card, and
//! for a skill the skill gate's own accepted verdict.
//!
//! The order is fixed. The held-out basis is decided once per candidate. The
//! confirmation shot is consumed BEFORE the cohort is released, so a crash
//! spends it. Only the sealed referee's win bit and digest leave the sealed
//! side; no sealed score enters search reward. Ties reject, floors never
//! trade, and a mixed vector escalates rather than promotes.
use serde::{Deserialize, Serialize};

use super::super::archive::CampaignArchivePin;
use super::super::beam_promotion::SealedRefereeMeasurement;
use super::super::general::{DecideRules, Measurement, MetricRole, Verdict};
use super::{
    CandidateRef, ResearchBudgetRead, ResearchGoalPin, ResearchTarget, binding, campaign_error,
    check_goal_current, hex, invalid, nodes_in_txn, policy_digest, pruned_lineage,
};
use crate::side_table::{self, Named, SideTable};
use crate::skill_optimize::{
    EvalExposureKind, EvalRelease, SufficiencyCard, SufficiencyInput, skill_edit_verdict,
    sufficiency_card,
};
use crate::{AttemptId, EntityId, Result, Vault};

/// The held-out basis, confirmation and promotion of one candidate, keyed by
/// root attempt then candidate attempt.
const BASIS: SideTable<([u8; 16], [u8; 16]), PromotionBasis, Named> =
    SideTable::new(&side_table::AUTORESEARCH_BASIS);

/// The held-out decision, as decided by the campaign's dominance rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldOutCall {
    Promote,
    Reject,
    EscalateTradeoff,
}

/// The one sealed confirmation of a candidate. `exposure` is empty when the
/// shot was consumed but the release never completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationReceipt {
    pub cohort: EntityId,
    pub consumed_at: u64,
    pub exposure: Option<EntityId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionDisposition {
    /// The candidate is the campaign's new incumbent.
    Promoted,
    /// The sealed referee did not see a strict win.
    LostSealed,
    /// The sufficiency card did not read not-worse.
    HeldInsufficient,
    /// The skill gate's own verdict did not accept the revision.
    HeldGate,
}

/// The durable promotion receipt. It carries the policy version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignPromotionReceipt {
    pub root: AttemptId,
    pub candidate: AttemptId,
    pub incumbent: AttemptId,
    pub candidate_pin: CandidateRef,
    pub parents: Vec<AttemptId>,
    pub config_sha256: String,
    pub goal: Option<ResearchGoalPin>,
    pub policy_digest: String,
    /// The per-cell output archive the candidate's makers drew on (OF-545),
    /// rebuilt by its owner from refs and scoring receipts, and its version.
    pub archive: Option<CampaignArchivePin>,
    pub archive_version: Option<String>,
    pub cohort: EntityId,
    /// The candidate serving, then the promotion serving when promoted.
    pub exposures: Vec<EntityId>,
    pub sufficiency: SufficiencyCard,
    pub sealed_won: bool,
    pub sealed_digest: String,
    pub referee_pin: String,
    /// The skill revision proposal whose gate verdict this stands on.
    pub skill_proposal: Option<EntityId>,
    pub disposition: PromotionDisposition,
    pub budget: ResearchBudgetRead,
    pub at: u64,
}

/// One candidate's held-out basis and what followed from it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionBasis {
    pub root: AttemptId,
    pub candidate: AttemptId,
    pub incumbent: AttemptId,
    pub candidate_pin: CandidateRef,
    pub incumbent_pin: CandidateRef,
    pub config_sha256: String,
    pub goal: Option<ResearchGoalPin>,
    pub policy_digest: String,
    /// The per-cell output archive the candidate's makers drew on (OF-545),
    /// rebuilt by its owner from refs and scoring receipts, and its version.
    pub archive: Option<CampaignArchivePin>,
    pub archive_version: Option<String>,
    pub incumbent_held_out: Measurement,
    pub candidate_held_out: Measurement,
    pub call: HeldOutCall,
    pub merge_crossover_enabled: bool,
    pub decided_at: u64,
    pub confirmation: Option<ConfirmationReceipt>,
    pub promotion: Option<CampaignPromotionReceipt>,
}

/// What the workflow measured on the released sealed cohort.
pub struct ConfirmationOutcome {
    /// Built only by the sealed referee adapter; its raw scores stay inside.
    pub sealed: SealedRefereeMeasurement,
    pub sufficiency: SufficiencyInput,
    /// For a skill campaign: the staged revision proposal the skill gate
    /// scored. A config campaign names none.
    pub skill_proposal: Option<EntityId>,
}

fn consumer(root: AttemptId) -> String {
    format!("autoresearch:{}", hex(&root))
}

fn bases(vault: &Vault, root: AttemptId) -> Result<Vec<PromotionBasis>> {
    let txn = vault.store.env.read_txn()?;
    Ok(BASIS
        .scan_from(&vault.store, &txn, root.as_bytes())?
        .into_iter()
        .map(|(_, basis)| basis)
        .collect())
}

/// Every held-out basis of a campaign, with its confirmation and promotion.
/// # Errors
/// Storage errors.
pub fn research_promotions(vault: &Vault, root: AttemptId) -> Result<Vec<PromotionBasis>> {
    bases(vault, root)
}

/// The campaign's incumbent: its latest promoted candidate, else the root.
/// # Errors
/// Storage errors.
pub fn research_incumbent(vault: &Vault, root: AttemptId) -> Result<AttemptId> {
    Ok(bases(vault, root)?
        .into_iter()
        .filter_map(|basis| basis.promotion)
        .filter(|receipt| receipt.disposition == PromotionDisposition::Promoted)
        .max_by_key(|receipt| receipt.at)
        .map_or(root, |receipt| receipt.candidate))
}

/// Merge crossover is earned by one held-out win with crossover enabled.
pub(super) fn crossover_earned(vault: &Vault, root: AttemptId) -> Result<bool> {
    Ok(bases(vault, root)?
        .iter()
        .any(|basis| basis.call == HeldOutCall::Promote && basis.merge_crossover_enabled))
}

/// Decide a candidate against the incumbent on both nodes' held-out
/// evidence, once. A Promote basis may go on to sealed confirmation; an
/// escalated tradeoff waits for the goal's tradeoff ladder.
/// # Errors
/// An unbound campaign, an OF-366 campaign (it promotes through its own
/// measure-once door), a moved goal, an archive pin of another campaign or
/// none under a coverage floor, the incumbent as candidate, a candidate
/// or incumbent without held-out evidence, a buggy or pruned candidate, an
/// already-decided candidate, or storage errors.
pub fn promotion_basis(
    vault: &Vault,
    root: AttemptId,
    candidate: AttemptId,
    archive: Option<CampaignArchivePin>,
    at: u64,
) -> Result<PromotionBasis> {
    let binding = binding(vault, root)?;
    if matches!(binding.config.decide, DecideRules::Of366 { .. }) {
        return Err(invalid(
            "the OF-366 campaign promotes through its measure-once door",
        ));
    }
    check_goal_current(vault, &binding)?;
    let coverage_floor = binding
        .config
        .metric_set
        .axes
        .iter()
        .any(|axis| axis.name == "coverage" && axis.role == MetricRole::Floor);
    let archive_version = match &archive {
        Some(pin) => {
            if pin.campaign_id() != binding.config.campaign_id {
                return Err(invalid("the archive pin belongs to another campaign"));
            }
            Some(pin.version().map_err(campaign_error)?)
        }
        // Skill coverage may never shrink: a coverage floor reads the archive.
        None if coverage_floor => {
            return Err(invalid("a coverage floor needs the campaign's archive pin"));
        }
        None => None,
    };
    let incumbent = research_incumbent(vault, root)?;
    if candidate == incumbent {
        return Err(invalid("the incumbent is not its own candidate"));
    }
    let txn = vault.store.env.read_txn()?;
    let nodes = nodes_in_txn(vault, &txn, root)?;
    drop(txn);
    let node = nodes.get(candidate.as_bytes()).ok_or(invalid(
        "the candidate is not an experiment of this campaign",
    ))?;
    if node.invalid.is_some() || pruned_lineage(&nodes, &candidate) {
        return Err(invalid("a buggy or pruned candidate is not promoted"));
    }
    let incumbent_node = nodes.get(incumbent.as_bytes()).ok_or(invalid(
        "the incumbent is not an experiment of this campaign",
    ))?;
    let (Some(after), Some(before)) = (&node.held_out, &incumbent_node.held_out) else {
        return Err(invalid(
            "both the candidate and the incumbent need held-out evidence",
        ));
    };
    let decision = binding
        .config
        .decide_held_out(&before.measurement, &after.measurement)
        .map_err(campaign_error)?;
    let policy = super::selection_policy_for(
        vault,
        &binding.config.campaign_id,
        binding.holder.as_deref(),
    )?;
    let basis = PromotionBasis {
        root,
        candidate,
        incumbent,
        candidate_pin: node.candidate.clone(),
        incumbent_pin: incumbent_node.candidate.clone(),
        config_sha256: binding.config_sha256.clone(),
        goal: binding.goal.clone(),
        policy_digest: policy_digest(&policy)?,
        archive,
        archive_version,
        incumbent_held_out: before.measurement.clone(),
        candidate_held_out: after.measurement.clone(),
        call: match decision.verdict() {
            Verdict::Promote => HeldOutCall::Promote,
            Verdict::Reject => HeldOutCall::Reject,
            Verdict::EscalateTradeoff => HeldOutCall::EscalateTradeoff,
        },
        merge_crossover_enabled: decision.merge_crossover_enabled(),
        decided_at: at,
        confirmation: None,
        promotion: None,
    };
    vault.with_write_txn_grouped(|txn| {
        let key = (*root.as_bytes(), *candidate.as_bytes());
        if BASIS.contains(&vault.store, txn, &key)? {
            return Err(invalid("a candidate's held-out decision is made once"));
        }
        BASIS.put(&vault.store, txn, &key, &basis)?;
        Ok(basis)
    })
}

fn update_basis(
    vault: &Vault,
    root: AttemptId,
    candidate: AttemptId,
    change: impl FnOnce(&mut PromotionBasis) -> Result<()>,
) -> Result<PromotionBasis> {
    vault.with_write_txn_grouped(|txn| {
        let key = (*root.as_bytes(), *candidate.as_bytes());
        let mut basis = BASIS
            .get(&vault.store, txn, &key)?
            .ok_or(invalid("the candidate has no held-out basis"))?;
        change(&mut basis)?;
        BASIS.put(&vault.store, txn, &key, &basis)?;
        Ok(basis)
    })
}

/// Spend the candidate's one sealed confirmation: consume the shot, then
/// release the campaign's sealed cohort, counted as a candidate serving.
/// The release goes to the workflow's referee; nothing is scored here.
/// # Errors
/// An unbound campaign, no confirmation cohort, no Promote basis, a shot
/// already spent, a retired cohort, or storage errors. A failed release
/// still spends the shot.
pub fn reserve_confirmation(
    vault: &Vault,
    root: AttemptId,
    candidate: AttemptId,
    at: u64,
) -> Result<EvalRelease> {
    let binding = binding(vault, root)?;
    let seat = binding
        .confirmation
        .ok_or(invalid("this campaign names no sealed confirmation cohort"))?;
    let basis = update_basis(vault, root, candidate, |basis| {
        if basis.call != HeldOutCall::Promote {
            return Err(invalid(
                "only a held-out Promote goes to sealed confirmation",
            ));
        }
        if basis.confirmation.is_some() {
            return Err(invalid(
                "the candidate's sealed confirmation is already spent",
            ));
        }
        basis.confirmation = Some(ConfirmationReceipt {
            cohort: seat.cohort,
            consumed_at: at,
            exposure: None,
        });
        Ok(())
    })?;
    let release = vault.open_eval_cohort(
        &seat.cohort,
        EvalExposureKind::Candidate,
        &consumer(root),
        Some(&basis.candidate_pin.config_sha256),
        at,
    )?;
    update_basis(vault, root, candidate, |basis| {
        if let Some(confirmation) = &mut basis.confirmation {
            confirmation.exposure = Some(release.exposure.id);
        }
        Ok(())
    })?;
    Ok(release)
}

/// Settle the candidate on its sealed confirmation. A strict sealed win, a
/// not-worse sufficiency card and, for a skill, the skill gate's accepted
/// verdict under the bound goal make it the campaign's incumbent; the
/// promotion is then counted on the cohort. Every outcome is receipted.
/// # Errors
/// An unbound campaign, no released confirmation, a settled candidate, a
/// moved goal, an invalid sufficiency input, a skill campaign without its
/// proposal (or a config campaign with one), a proposal scored under another
/// goal, a retired cohort at the promotion serving, or storage errors.
pub fn promote_measured(
    vault: &Vault,
    root: AttemptId,
    candidate: AttemptId,
    outcome: ConfirmationOutcome,
    at: u64,
) -> Result<CampaignPromotionReceipt> {
    let binding = binding(vault, root)?;
    check_goal_current(vault, &binding)?;
    let basis = bases(vault, root)?
        .into_iter()
        .find(|basis| basis.candidate == candidate)
        .ok_or(invalid("the candidate has no held-out basis"))?;
    let Some(ConfirmationReceipt {
        cohort,
        exposure: Some(candidate_exposure),
        ..
    }) = basis.confirmation
    else {
        return Err(invalid("the candidate's sealed cohort was never released"));
    };
    if basis.promotion.is_some() {
        return Err(invalid("the candidate's promotion is already settled"));
    }
    let card = sufficiency_card(outcome.sufficiency)?;
    let gate_accepted = match (&binding.target, outcome.skill_proposal) {
        (ResearchTarget::Skill { .. }, Some(proposal)) => {
            let verdict = skill_edit_verdict(vault, &proposal)?
                .ok_or(invalid("the skill proposal has no gate verdict"))?;
            let pin = binding
                .goal
                .as_ref()
                .ok_or(invalid("a skill campaign pins its goal"))?;
            if verdict.goal_id != Some(pin.goal_id) || verdict.goal_revision != pin.revision {
                return Err(invalid("the skill verdict was scored under another goal"));
            }
            verdict.accepted
        }
        (ResearchTarget::Config { .. }, None) => true,
        _ => {
            return Err(invalid(
                "a skill campaign names its proposal; a config campaign names none",
            ));
        }
    };
    let disposition = if !outcome.sealed.won() {
        PromotionDisposition::LostSealed
    } else if !card.approves() {
        PromotionDisposition::HeldInsufficient
    } else if !gate_accepted {
        PromotionDisposition::HeldGate
    } else {
        PromotionDisposition::Promoted
    };
    let mut exposures = vec![candidate_exposure];
    if disposition == PromotionDisposition::Promoted {
        let served = vault.open_eval_cohort(
            &cohort,
            EvalExposureKind::Promotion,
            &consumer(root),
            Some(&basis.candidate_pin.config_sha256),
            at,
        )?;
        exposures.push(served.exposure.id);
    }
    let txn = vault.store.env.read_txn()?;
    let parents = nodes_in_txn(vault, &txn, root)?
        .get(candidate.as_bytes())
        .map(|node| node.parents.clone())
        .unwrap_or_default();
    drop(txn);
    let policy = super::selection_policy_for(
        vault,
        &binding.config.campaign_id,
        binding.holder.as_deref(),
    )?;
    let receipt = CampaignPromotionReceipt {
        root,
        candidate,
        incumbent: basis.incumbent,
        candidate_pin: basis.candidate_pin.clone(),
        parents,
        config_sha256: binding.config_sha256.clone(),
        goal: binding.goal.clone(),
        policy_digest: policy_digest(&policy)?,
        archive: basis.archive.clone(),
        archive_version: basis.archive_version.clone(),
        cohort,
        exposures,
        sufficiency: card,
        sealed_won: outcome.sealed.won(),
        sealed_digest: outcome.sealed.digest().to_owned(),
        referee_pin: outcome.sealed.referee_pin().to_owned(),
        skill_proposal: outcome.skill_proposal,
        disposition,
        budget: super::research_budget(vault, root)?,
        at,
    };
    update_basis(vault, root, candidate, |basis| {
        if basis.promotion.is_some() {
            return Err(invalid("the candidate's promotion is already settled"));
        }
        basis.promotion = Some(receipt.clone());
        Ok(())
    })?;
    Ok(receipt)
}
