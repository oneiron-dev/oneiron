//! The claim-authoring tournament as a strategy skill on an OF-351 campaign
//! (OF-366).
//!
//! A governed Workflow skill (the hub's claim-authoring strategy) chooses the
//! authoring arm for one claim; the engine checks the choice against the
//! campaign's fixed OF-366 config and hands back the existing admission. It
//! never chooses its own authority. The winner is written by the unchanged
//! gated writer, `run_dreamer_claim_tournament`: rank only picks the draft,
//! and the gate rules the write. This module finalizes what landed: the
//! winner claim's actual approval, one team receipt for the run, and the
//! attempt's terminal pack receipt, which a later anchored outcome settles.
//! A strategy-default change still goes through the held-out KEEP and the one
//! sealed BEAM shot, never through the generic promotion basis.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::beam_promotion::{
    AuthoringStrategyPin, PromotionReceipt, SealedRefereeMeasurement, measure_once,
};
use super::research::{
    CandidateRef, ResearchBindRequest, ResearchTarget, bind_research, research_nodes,
};
use super::{CampaignComparisonReport, CampaignConfig};
use crate::agent_dispatch::TeamRunStamp;
use crate::dreamer_runner::{DreamerClaimAuthoringAdmission, DreamerTournamentClaim};
use crate::dreamer_tournament::{
    DreamerTournamentEvidenceStore, DreamerTournamentRunResult, DreamerTournamentStopReason,
};
use crate::learning::TypeRef;
use crate::limit_ask::EngineLimit;
use crate::side_table::{self, Named, SideTable};
use crate::skill::{SkillLifecycle, SkillRole};
use crate::team::{
    DecidedBy, PatternSkillRef, TeamAxis, TeamOutcome, TeamPattern, TeamReceipt, TeamShape,
    record_team_receipt, settle_team_outcome,
};
use crate::{AttemptId, ClaimApprovalStatus, EntityId, Error, Result, Vault};

/// One claim-authoring campaign, keyed by its root attempt.
const AUTHORING: SideTable<[u8; 16], AuthoringCampaign, Named> =
    SideTable::new(&side_table::AUTORESEARCH_AUTHORING);
/// One finalized tournament run, keyed by root attempt then run attempt.
const AUTHORING_RUN: SideTable<([u8; 16], [u8; 16]), AuthoringFinalization, Named> =
    SideTable::new(&side_table::AUTORESEARCH_AUTHORING_RUN);
/// A deferred tournament-lineage walk's persisted position, keyed by team
/// leader attempt then tournament run attempt.
const TOURNAMENT_CURSOR: SideTable<([u8; 16], [u8; 16]), TournamentLineageCursor, Named> =
    SideTable::new(&side_table::AUTORESEARCH_TOURNAMENT_CURSOR);

const MAX_REF_BYTES: usize = 256;

/// The exact revision of the strategy skill the campaign runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimAuthoringSkillPin {
    pub skill: EntityId,
    pub version: String,
    /// Hex of the skill's content hash.
    pub content_hash: String,
}

/// A bound claim-authoring campaign: its strategy skill, the fixed OF-366
/// config it was evaluated under, that config's content pin, and the BEAM
/// promotion receipt once the one sealed shot is spent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringCampaign {
    pub root: AttemptId,
    pub skill: ClaimAuthoringSkillPin,
    pub config: CampaignConfig,
    pub strategy: AuthoringStrategyPin,
    pub promotion: Option<PromotionReceipt>,
    pub bound_at: u64,
}

/// The typed choice the strategy skill returns for one claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimAuthoringChoice {
    SinglePass,
    Tournament,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TournamentStop {
    Consensus,
    RoundCap,
    ExhaustedRounds,
}

/// What the host observed about one tournament run's team.
#[derive(Debug, Clone, PartialEq)]
pub struct TournamentTeam {
    pub type_ref: TypeRef,
    pub project: Option<EntityId>,
    pub axis: TeamAxis,
    /// Every executor model id the run used.
    pub models: Vec<String>,
    /// Role counts beyond the authors, such as critics and judges.
    pub roles: BTreeMap<String, u32>,
    /// The ranking rule, signed when the host observed it; lateness is labeled on the
    /// finalization, never refused.
    pub referee_rule: String,
    pub rule_signed_at: u64,
    pub confessions: u32,
    pub spend: Option<f64>,
    pub spend_cap: Option<f64>,
    pub elapsed_secs: u64,
    pub calls: u64,
}

/// One finalized tournament run on the campaign.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringFinalization {
    pub root: AttemptId,
    pub attempt: AttemptId,
    pub run_id: String,
    pub winner_claim: EntityId,
    pub winner_candidate_ref: String,
    pub winner_branch: AttemptId,
    pub winner_score: u64,
    pub rounds_executed: u16,
    pub stop: TournamentStop,
    /// The winner claim's approval as the gate left it: rank never approves.
    pub approval: ClaimApprovalStatus,
    pub skill: ClaimAuthoringSkillPin,
    pub strategy: AuthoringStrategyPin,
    pub team_ref: String,
    /// The attempt's terminal pack receipt, stamped when it settles.
    pub terminal_receipt_ref: String,
    /// The anchored outcome, once an observer settles it.
    pub outcome: Option<TeamOutcome>,
    /// The ranking rule was signed after the work began; the run still finalizes
    /// (Orchestrator 10-22 ruling: label, never refusal).
    pub referee_rule_late: bool,
    pub at: u64,
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}

fn campaign_error(error: super::CampaignError) -> Error {
    match error {
        super::CampaignError::Decision(error) => error,
        other => Error::InvalidConfig(other.to_string()),
    }
}

fn bounded(value: &str, what: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > MAX_REF_BYTES {
        return Err(invalid(what));
    }
    Ok(())
}

/// The pinned strategy skill must still be the active, admitted Workflow
/// revision it was pinned at.
fn check_strategy_skill(vault: &Vault, pin: &ClaimAuthoringSkillPin) -> Result<()> {
    let record = vault
        .get_skill_record(&pin.skill)?
        .ok_or(invalid("the strategy skill is missing"))?;
    if record.role != SkillRole::Workflow {
        return Err(invalid("a claim-authoring strategy is a Workflow skill"));
    }
    if record.lifecycle_status != SkillLifecycle::Active
        || !matches!(
            record.approval_status,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        )
    {
        return Err(invalid("the strategy skill is not admitted and active"));
    }
    if record.version != pin.version
        || record.content_hash.map(|hash| hash.to_hex()).as_deref()
            != Some(pin.content_hash.as_str())
    {
        return Err(invalid(
            "the strategy skill moved since it was pinned; bind a new campaign",
        ));
    }
    Ok(())
}

/// Bind a claim-authoring campaign: the root attempt binds as an OF-351
/// config campaign under the fixed OF-366 ruler, pinned to its strategy
/// skill's exact revision and to the config's content pin.
/// # Errors
/// A strategy skill that is not the active admitted Workflow revision, an
/// invalid config, any [`bind_research`] refusal, an already-bound root, or
/// storage errors.
pub fn bind_claim_authoring_campaign(
    vault: &Vault,
    root: AttemptId,
    config: &CampaignConfig,
    skill: ClaimAuthoringSkillPin,
    incumbent: CandidateRef,
    holder: Option<String>,
    share: Option<String>,
    at: u64,
) -> Result<AuthoringCampaign> {
    check_strategy_skill(vault, &skill)?;
    let strategy = AuthoringStrategyPin::from_campaign(config).map_err(campaign_error)?;
    bind_research(
        vault,
        ResearchBindRequest {
            root,
            config: config.as_general().map_err(campaign_error)?,
            target: ResearchTarget::Config {
                subject: format!("claim-authoring:{}@{}", skill.skill.to_hex(), skill.version),
            },
            holder,
            confirmation: None,
            share,
            incumbent,
            prior_ladder: Vec::new(),
            execution: None,
        },
        at,
    )?;
    let campaign = AuthoringCampaign {
        root,
        skill,
        config: config.clone(),
        strategy,
        promotion: None,
        bound_at: at,
    };
    vault.with_write_txn_grouped(|txn| {
        if AUTHORING.contains(&vault.store, txn, root.as_bytes())? {
            return Err(invalid("a claim-authoring campaign binds once"));
        }
        AUTHORING.put(&vault.store, txn, root.as_bytes(), &campaign)?;
        Ok(campaign)
    })
}

/// The claim-authoring campaign bound to a root, if any.
/// # Errors
/// Storage errors.
pub fn authoring_campaign(vault: &Vault, root: AttemptId) -> Result<Option<AuthoringCampaign>> {
    let txn = vault.store.env.read_txn()?;
    AUTHORING.get(&vault.store, &txn, root.as_bytes())
}

fn campaign(vault: &Vault, root: AttemptId) -> Result<AuthoringCampaign> {
    authoring_campaign(vault, root)?.ok_or(invalid("no claim-authoring campaign is bound here"))
}

/// Turn the strategy skill's typed choice for one claim into the existing
/// admission, under the campaign's fixed config. The batch/nightly tier and
/// uncertainty checks stay in the admission's own gate decision.
/// # Errors
/// An unbound campaign, a strategy skill that moved, a tournament the config
/// refuses for this claim, or storage errors.
pub fn claim_authoring_admission(
    vault: &Vault,
    root: AttemptId,
    choice: ClaimAuthoringChoice,
    claim: DreamerTournamentClaim,
) -> Result<DreamerClaimAuthoringAdmission> {
    let campaign = campaign(vault, root)?;
    check_strategy_skill(vault, &campaign.skill)?;
    match choice {
        ClaimAuthoringChoice::SinglePass => Ok(campaign.config.single_pass_admission()),
        ClaimAuthoringChoice::Tournament => campaign
            .config
            .tournament_admission(claim)
            .map_err(campaign_error),
    }
}

/// The team-run stamp of tournament `run_id` (OF-540 (c)). The host passes
/// it as `AgentSpawnContext.team` on the run's author dispatches, so their
/// attempts join the Market team receipt [`finalize_claim_tournament`]
/// records under the same reference.
/// # Errors
/// A run id the team reference bound refuses.
pub fn tournament_team_stamp(run_id: &str) -> Result<TeamRunStamp> {
    TeamRunStamp::new(format!("autoreason:{run_id}"), TeamPattern::Market)
}

/// Hops one tournament-start check walks before it defers with a persisted
/// cursor (FIX 9581): sixteen times the old cutoff, and depth never refuses —
/// a deferred check resumes where it stopped on the next call.
const TOTAL_HOPS_PER_CALL: usize = 4096;

/// A deferred tournament-lineage walk's persisted position (FIX 9581): one
/// row per `(leader, run)`, written only on the defer path and deleted on
/// every terminal path. Plain stored fields, no compat shim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TournamentLineageCursor {
    pub leader: AttemptId,
    pub run: AttemptId,
    pub at: AttemptId,
    pub under_run: bool,
    pub seen: Vec<AttemptId>,
    pub steps: u64,
}

/// Whether a persisted tournament-lineage cursor still names the walk it was
/// written for: the pair, the position's row, and the last visited row's
/// parent still continuing to the position. Anything else means the queue
/// moved under the cursor, and the walk restarts from the leader.
fn tournament_cursor_valid(
    vault: &Vault,
    leader: AttemptId,
    run: AttemptId,
    cursor: &TournamentLineageCursor,
) -> Result<bool> {
    if cursor.leader != leader || cursor.run != run || cursor.seen.is_empty() {
        return Ok(false);
    }
    if cursor.seen[0] != leader || cursor.seen.contains(&cursor.at) {
        return Ok(false);
    }
    let queue = crate::attempt_queue::AttemptQueue::new(vault);
    if queue.get(cursor.at)?.is_none() {
        return Ok(false);
    }
    let Some(last) = cursor.seen.last() else {
        return Ok(false);
    };
    let Some(record) = queue.get(*last)? else {
        return Ok(false);
    };
    Ok(crate::run_tree::effective_parent(&record) == Some(cursor.at))
}

/// The experiment a tournament runs as: its run id is that experiment
/// attempt's id, as hex.
fn tournament_attempt(run_id: &str) -> Option<AttemptId> {
    let id = EntityId::from_hex(run_id).ok()?;
    AttemptId::from_bytes(id.as_bytes()).ok()
}

/// Whether `leader` may start a team in tournament `run_id`, before any
/// member spawns: the run id must name an experiment of the claim-authoring
/// campaign the leader works in (the nearest bound root up its run tree),
/// and the leader must be that experiment, work under it, or be the
/// campaign's root. So a team never joins another campaign's tournament.
///
/// The walk is complete and resumable (FIX 9581): each call walks at most
/// [`TOTAL_HOPS_PER_CALL`] ancestors, persisting its position and answering
/// `team_start_tournament_deferred` past them, so the next call resumes where
/// it stopped. A row visited twice is a cycle
/// (`team_start_tournament_cycle`); `team_start_tournament_unbound` now means
/// the whole chain was walked and holds no bound root, never a cutoff.
/// # Errors
/// Storage errors.
pub(crate) fn tournament_start_check(
    vault: &Vault,
    leader: AttemptId,
    run_id: &str,
) -> Result<std::result::Result<(), &'static str>> {
    let Some(run) = tournament_attempt(run_id) else {
        return Ok(Err("team_start_tournament_unknown"));
    };
    let queue = crate::attempt_queue::AttemptQueue::new(vault);
    let key = (*leader.as_bytes(), *run.as_bytes());
    let txn = vault.store.env.read_txn()?;
    let stored = TOURNAMENT_CURSOR.get(&vault.store, &txn, &key)?;
    drop(txn);
    let had_cursor = stored.is_some();
    let resumed = match stored {
        Some(cursor) => tournament_cursor_valid(vault, leader, run, &cursor)?.then_some(cursor),
        None => None,
    };
    let (mut at, mut under_run, mut visited, mut chain, carried) = match resumed {
        Some(cursor) => {
            let visited: BTreeSet<AttemptId> = cursor.seen.iter().copied().collect();
            (
                cursor.at,
                cursor.under_run,
                visited,
                cursor.seen,
                cursor.steps,
            )
        }
        None => (leader, false, BTreeSet::new(), Vec::new(), 0),
    };
    let mut hops: u64 = 0;
    let mut exhausted = false;
    for _ in 0..TOTAL_HOPS_PER_CALL {
        if !visited.insert(at) {
            if had_cursor {
                vault.with_write_txn_grouped(|txn| {
                    TOURNAMENT_CURSOR.delete(&vault.store, txn, &key)
                })?;
            }
            return Ok(Err("team_start_tournament_cycle"));
        }
        chain.push(at);
        hops += 1;
        under_run |= at == run;
        if authoring_campaign(vault, at)?.is_some() {
            let experiment = research_nodes(vault, at)?
                .iter()
                .any(|node| node.attempt == run);
            if had_cursor {
                vault.with_write_txn_grouped(|txn| {
                    TOURNAMENT_CURSOR.delete(&vault.store, txn, &key)
                })?;
            }
            let _ = vault.measure_limit(EngineLimit::TournamentLineageRows, carried + hops);
            return Ok(if experiment && (under_run || at == leader) {
                Ok(())
            } else {
                Err("team_start_tournament_foreign")
            });
        }
        let Some(record) = queue.get(at)? else {
            exhausted = true;
            break;
        };
        let Some(parent) = crate::run_tree::effective_parent(&record) else {
            exhausted = true;
            break;
        };
        at = parent;
    }
    if exhausted {
        if had_cursor {
            vault
                .with_write_txn_grouped(|txn| TOURNAMENT_CURSOR.delete(&vault.store, txn, &key))?;
        }
        let _ = vault.measure_limit(EngineLimit::TournamentLineageRows, carried + hops);
        return Ok(Err("team_start_tournament_unbound"));
    }
    vault.with_write_txn_grouped(|txn| {
        TOURNAMENT_CURSOR.put(
            &vault.store,
            txn,
            &key,
            &TournamentLineageCursor {
                leader,
                run,
                at,
                under_run,
                seen: chain,
                steps: carried + hops,
            },
        )
    })?;
    let _ = vault.measure_limit(EngineLimit::TournamentLineageRows, carried + hops);
    Ok(Err("team_start_tournament_deferred"))
}

/// Finalize one tournament run after the unchanged gated writer landed its
/// winner: check the run's branch evidence and the winner claim, record the
/// run's team receipt (a Market team decided by its pre-signed ranking rule)
/// and join the attempt's terminal pack receipt.
/// # Errors
/// An unbound campaign, a run attempt that is not a campaign experiment, a
/// failed run with no winner, no persisted evidence for the winner, a winner
/// claim that never landed, a malformed or duplicate team receipt, an
/// already-finalized run, or storage errors.
pub fn finalize_claim_tournament(
    vault: &Vault,
    root: AttemptId,
    attempt: AttemptId,
    run_id: &str,
    result: &DreamerTournamentRunResult,
    team: TournamentTeam,
    at: u64,
) -> Result<AuthoringFinalization> {
    let campaign = campaign(vault, root)?;
    bounded(run_id, "a tournament run names a bounded run id")?;
    if tournament_attempt(run_id) != Some(attempt) {
        return Err(invalid(
            "a tournament's run id is its experiment attempt's id",
        ));
    }
    if !research_nodes(vault, root)?
        .iter()
        .any(|node| node.attempt == attempt)
    {
        return Err(invalid(
            "the run attempt is not an experiment of this campaign",
        ));
    }
    // A failed run (every candidate discarded) has no winner to finalize.
    let stop = match result.stop_reason {
        DreamerTournamentStopReason::Consensus => TournamentStop::Consensus,
        DreamerTournamentStopReason::RoundCap => TournamentStop::RoundCap,
        DreamerTournamentStopReason::ExhaustedRounds => TournamentStop::ExhaustedRounds,
        DreamerTournamentStopReason::AllDiscarded => {
            return Err(invalid("the tournament discarded every candidate"));
        }
    };
    let winner = result
        .winner
        .as_ref()
        .ok_or(invalid("the tournament result names no winner"))?;
    let evidence = DreamerTournamentEvidenceStore::new(vault).list_run(run_id)?;
    if !evidence.iter().any(|row| {
        row.branch_attempt == winner.branch_attempt && row.candidate_ref == winner.candidate_ref
    }) {
        return Err(invalid(
            "the tournament winner has no persisted branch evidence",
        ));
    }
    let claim = vault.get_claim(&winner.claim_id)?.ok_or(invalid(
        "the tournament winner never landed through the gate",
    ))?;
    let referee_rule_late = team.rule_signed_at > at;
    let branches: BTreeSet<[u8; 16]> = evidence
        .iter()
        .map(|row| *row.branch_attempt.as_bytes())
        .collect();
    let width = u32::try_from(branches.len()).map_err(|_| invalid("too many branches"))?;
    let mut roles = team.roles;
    roles.insert("author".to_owned(), width);
    let stamp = tournament_team_stamp(run_id)?;
    // A stamped run attempt worked in this tournament's team, or its terminal
    // receipt would join another run's.
    if let Some(record) = crate::attempt_queue::AttemptQueue::new(vault).get(attempt)?
        && crate::agent_dispatch::attempt_team_stamp(&record)?.is_some_and(|frozen| frozen != stamp)
    {
        return Err(invalid(
            "the run attempt was dispatched into another team run",
        ));
    }
    let team_ref = stamp.team_ref;
    record_team_receipt(
        vault,
        &TeamReceipt {
            team_ref: team_ref.clone(),
            project: team.project,
            type_ref: team.type_ref,
            pattern: TeamPattern::Market,
            pattern_skill: Some(PatternSkillRef {
                skill: campaign.skill.skill,
                version: campaign.skill.version.clone(),
            }),
            axis: team.axis,
            models: team.models,
            shape: TeamShape { width, roles },
            decided_by: DecidedBy::Referee {
                rule: team.referee_rule,
                signed_at: team.rule_signed_at,
            },
            coverage: None,
            confessions: Some(team.confessions),
            spend: team.spend,
            spend_cap: team.spend_cap,
            elapsed_secs: team.elapsed_secs,
            calls: Some(team.calls),
            outcome: None,
            at,
        },
    )?;
    let finalization = AuthoringFinalization {
        root,
        attempt,
        run_id: run_id.to_owned(),
        winner_claim: winner.claim_id,
        winner_candidate_ref: winner.candidate_ref.clone(),
        winner_branch: winner.branch_attempt,
        winner_score: winner.score,
        rounds_executed: result.rounds_executed,
        stop,
        approval: claim.approval,
        skill: campaign.skill,
        strategy: campaign.strategy,
        team_ref,
        terminal_receipt_ref: crate::receipt::attempt_pack_receipt_id(&attempt),
        outcome: None,
        referee_rule_late,
        at,
    };
    vault.with_write_txn_grouped(|txn| {
        let key = (*root.as_bytes(), *attempt.as_bytes());
        if AUTHORING_RUN.contains(&vault.store, txn, &key)? {
            return Err(invalid("the tournament run is already finalized"));
        }
        AUTHORING_RUN.put(&vault.store, txn, &key, &finalization)?;
        Ok(finalization)
    })
}

/// Every finalized tournament run of a campaign, in attempt order.
/// # Errors
/// Storage errors.
pub fn authoring_runs(vault: &Vault, root: AttemptId) -> Result<Vec<AuthoringFinalization>> {
    let txn = vault.store.env.read_txn()?;
    Ok(AUTHORING_RUN
        .scan_from(&vault.store, &txn, root.as_bytes())?
        .into_iter()
        .map(|(_, run)| run)
        .collect())
}

/// Settle a finalized run's anchored outcome on its team receipt, which
/// feeds the existing payoff and learning evidence, and keep it on the run.
/// # Errors
/// An unknown or already-settled run, any [`settle_team_outcome`] refusal,
/// or storage errors.
pub fn settle_claim_tournament_outcome(
    vault: &Vault,
    root: AttemptId,
    attempt: AttemptId,
    outcome: TeamOutcome,
) -> Result<AuthoringFinalization> {
    let key = (*root.as_bytes(), *attempt.as_bytes());
    let txn = vault.store.env.read_txn()?;
    let run = AUTHORING_RUN
        .get(&vault.store, &txn, &key)?
        .ok_or(invalid("the tournament run is not finalized"))?;
    drop(txn);
    if run.outcome.is_some() {
        return Err(invalid("the tournament run's outcome is already settled"));
    }
    settle_team_outcome(vault, &run.team_ref, &outcome)?;
    vault.with_write_txn_grouped(|txn| {
        let mut run = AUTHORING_RUN
            .get(&vault.store, txn, &key)?
            .ok_or(invalid("the tournament run is not finalized"))?;
        run.outcome = Some(outcome);
        AUTHORING_RUN.put(&vault.store, txn, &key, &run)?;
        Ok(run)
    })
}

/// Promote the campaign's authoring strategy through the existing door: the
/// validated held-out comparison of this root must KEEP, then the one sealed
/// BEAM shot is spent on the campaign's own strategy pin. A strict win makes
/// it the default the wake driver reads.
/// # Errors
/// An unbound campaign, a comparison of another root, a strategy skill that
/// moved, an already-promoted campaign, any [`measure_once`] refusal, or
/// storage errors.
pub fn promote_authoring_strategy(
    vault: &Vault,
    root: AttemptId,
    report: &CampaignComparisonReport,
    measure: impl FnOnce() -> Result<SealedRefereeMeasurement>,
) -> Result<PromotionReceipt> {
    let campaign = campaign(vault, root)?;
    if report.campaign_ref != root {
        return Err(invalid("the comparison belongs to another campaign root"));
    }
    if campaign.promotion.is_some() {
        return Err(invalid(
            "the campaign's strategy promotion is already spent",
        ));
    }
    check_strategy_skill(vault, &campaign.skill)?;
    let receipt = measure_once(vault, report, campaign.strategy.clone(), measure)?;
    vault.with_write_txn_grouped(|txn| {
        let mut row = AUTHORING
            .get(&vault.store, txn, root.as_bytes())?
            .ok_or(invalid("no claim-authoring campaign is bound here"))?;
        row.promotion = Some(receipt.clone());
        AUTHORING.put(&vault.store, txn, root.as_bytes(), &row)?;
        Ok(())
    })?;
    Ok(receipt)
}
