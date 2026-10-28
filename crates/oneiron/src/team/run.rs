//! OF-540: a pattern-skill run's own team, from code mode.
//!
//! `self.team.start` opens a team run under a coordination pattern and spawns
//! its members into it. The pattern maps through
//! [`team_pattern`](crate::agent_dispatch::team_pattern), and each member's
//! dispatch freezes the run's stamp, so its attempt joins the run. The leader
//! is the calling agent: its own attempt was dispatched before the team
//! existed and keeps the stamp it has. A team's reference is the leader's
//! attempt and the start's key, so the same start opens the same team. An
//! autoreason tournament's authors start the tournament's own market instead,
//! under the reference its finalizer records. A planned team's leader
//! (DOOR-111) asking for the team its plan launched gets that team back, and
//! no member spawns twice.
//!
//! `self.team.record` writes the team's one receipt once its work is done.
//! The host fills every identity: the type and project the leader was placed
//! with, the members its start spawned ([`super::run_binding`]), the models
//! the leader and each member's newest try ran on, the pattern skill the
//! leader loaded, the leader as the deciding actor, a market's signed
//! referee. It counts the members' confessions, calls and spend itself
//! ([`super::observations`]), and leaves unknown what it cannot count. The
//! guest names only what the host cannot observe: the axis (a planned team's
//! is the one its pattern froze), a vote's tally or an unsigned referee's
//! rule, the roles and coverage. A team below its pattern's floor records
//! what ran, and its receipt says so. A tournament's receipt is its
//! finalizer's, never the leader's. Settlement stays with the anchored outcome
//! ([`settle_team_outcome`](super::settle_team_outcome)), such as the
//! owner's verdict on the team's deliverable ([`super::owner_outcome`]): a
//! run's own word is no anchor.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_dispatch::{
    AgentDispatcher, CoordinationPattern, TeamRunStamp, attempt_team_stamp,
    decode_agent_dispatch_input, team_pattern,
};
use crate::attempt_queue::{AttemptId, AttemptRecord, ManifestKind};
use crate::autoreason_campaign::authoring::tournament_team_stamp;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::learning::TypeRef;

use super::market::market;
use super::observations::team_run_observations;
use super::pattern::{TeamAxis, TeamPattern, pattern_skills};
use super::receipt::{
    Coverage, DecidedBy, PatternSkillRef, TeamReceipt, TeamShape, record_team_receipt, team_receipt,
};
use super::run_binding::team_run_binding;
use super::spawn_intent::FrozenPatternPack;

/// Longest start key; a member's key is bounded the same way.
const MAX_KEY_BYTES: usize = 64;

/// `self.team.start`: a team run under `pattern`, its members spawned into it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamStartInput {
    /// The coordination pattern: `ceo_decides`, `committee`, `vote`,
    /// `market` or `rotation`. `solo` is no team, and is refused.
    pub pattern: String,
    /// The start's own key, 1..=64 bytes: the same key opens the same team.
    pub intent_key: String,
    /// The members, at least one, each spawned into the team as a child of
    /// the run. No count caps them (ARCH-0079); spend caps bound the work.
    pub members: Vec<TeamMemberInput>,
    /// An autoreason tournament's run id: the id, as hex, of the campaign
    /// experiment the tournament runs as, which the leader must be or work
    /// under. Set, the members are its authors, in its market; the pattern
    /// must be `market`.
    pub tournament: Option<String>,
}

/// One member a start spawns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamMemberInput {
    /// The member's AGENT_DEF id, hex.
    pub agent: String,
    /// The member's key within the team, 1..=64 bytes.
    pub intent_key: String,
    /// What the member is asked to do.
    pub briefing: Option<String>,
}

/// `self.team.record`: the receipt of a team this run started.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamRecordInput {
    /// The team's reference, as its start returned it.
    pub team_ref: String,
    /// Members the receipt covers beyond those the host saw its start spawn,
    /// such as an approved widening's: their attempt refs, hex. Each must
    /// carry the team's stamp. A start the host did not record needs them all.
    pub members: Vec<String>,
    /// Whether the team converged on one answer or diverged into many. A
    /// planned team's receipt takes the axis its pattern froze instead.
    pub axis: TeamAxis,
    /// Who decided the team's result. The pattern fixes its kind. A market's
    /// signed referee replaces the rule named here.
    pub decided_by: TeamDecisionInput,
    /// Role name to head count, summing to the leader plus its members.
    /// Absent, the leader leads and the rest are members.
    pub roles: Option<BTreeMap<String, u32>>,
    /// How much of the campaign's cell grid the outputs covered.
    pub coverage: Option<TeamCoverageInput>,
}

/// Who decided. A leader or a chair is the calling agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TeamDecisionInput {
    Leader,
    Chair,
    Vote {
        tally: BTreeMap<String, u32>,
    },
    /// A rule signed before the work: a test suite, a holdout, a pinned judge.
    Referee {
        rule: String,
        #[serde(rename = "signedAt")]
        signed_at: u64,
    },
}

/// Cells filled of the grid's total.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamCoverageInput {
    pub cells_filled: u32,
    pub cells_total: u32,
}

/// One `self.team.*` call. The leader comes from the host binding, never
/// from the guest.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum SelfTeamCall {
    Start(TeamStartInput),
    Record(TeamRecordInput),
}

/// What a `self.team.*` call answered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum TeamRunAnswer {
    #[serde(rename_all = "camelCase")]
    Started {
        team_ref: String,
        pattern: TeamPattern,
        members: Vec<TeamMemberAnswer>,
    },
    /// A start whose every member asked a widening: none launched, so no
    /// team runs yet. Each member answers its proposal.
    #[serde(rename_all = "camelCase")]
    ProposedWiden {
        team_ref: String,
        pattern: TeamPattern,
        members: Vec<TeamMemberAnswer>,
    },
    #[serde(rename_all = "camelCase")]
    Recorded {
        team_ref: String,
        pattern: TeamPattern,
        width: u32,
        /// The team ran with fewer agents than its pattern needs to mean
        /// anything; the receipt records what ran.
        below_floor: bool,
        models: Vec<String>,
        /// The loaded pattern skill the receipt names, hex.
        pattern_skill: Option<String>,
        /// Whether the receipt was already written.
        replay: bool,
    },
}

/// One spawned member: its queued attempt, or the widening its spawn asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemberAnswer {
    pub agent: String,
    pub attempt_ref: Option<String>,
    pub proposal_ref: Option<String>,
}

/// The stamp a start opens: the tournament's market, else the leader's own
/// team. A refusal is the guest's typed failure code.
pub(crate) fn start_stamp(
    leader: AttemptId,
    input: &TeamStartInput,
) -> std::result::Result<TeamRunStamp, &'static str> {
    let coordination = CoordinationPattern::from_token(&input.pattern)
        .map_err(|_| "team_start_unknown_pattern")?;
    let pattern = team_pattern(coordination).ok_or("team_start_solo")?;
    let mut keys = BTreeSet::new();
    if !key_ok(&input.intent_key)
        || input.members.is_empty()
        || !input
            .members
            .iter()
            .all(|member| key_ok(&member.intent_key) && keys.insert(member.intent_key.as_str()))
    {
        return Err("team_start_invalid_input");
    }
    match &input.tournament {
        Some(_) if pattern != TeamPattern::Market => Err("team_start_tournament_not_market"),
        Some(run) => tournament_team_stamp(run).map_err(|_| "team_start_invalid_tournament"),
        None => TeamRunStamp::new(led_team_ref(leader, &input.intent_key), pattern)
            .map_err(|_| "team_start_invalid_input"),
    }
}

/// A start by a planned team's leader (DOOR-111) that asks for the team its
/// plan launched, its pattern and its member count, answers that team's
/// launched members and spawns none; a retry of the leader the launch
/// queued gets that leader's team. `None` when `leader` leads no planned
/// team, or asks for another, which then starts as any start does.
///
/// # Errors
///
/// A damaged planned launch, storage errors and a malformed dispatch
/// payload.
pub(crate) fn planned_start(
    vault: &Vault,
    leader: AttemptId,
    input: &TeamStartInput,
    pattern: TeamPattern,
) -> Result<Option<TeamRunAnswer>> {
    if input.tournament.is_some() {
        return Ok(None);
    }
    let Some(launch) = AgentDispatcher::new(vault).planned_launch_for_leader(leader)? else {
        return Ok(None);
    };
    let Some(bound) = team_run_binding(vault, launch.root, &launch.team_ref)? else {
        return Ok(None);
    };
    if bound.stamp.pattern != pattern || input.members.len() != bound.members.len() {
        return Ok(None);
    }
    let store = DreamerRunnerStore::new(vault);
    let mut members = Vec::with_capacity(bound.members.len());
    for (id, asked) in bound.members.iter().zip(&input.members) {
        // The agent each member runs as, where its row still reads.
        let agent = match store.status(*id)? {
            Some(row) => decode_agent_dispatch_input(&row.payload.input)?
                .target
                .agent_definition_ref()?
                .to_hex(),
            None => asked.agent.clone(),
        };
        members.push(TeamMemberAnswer {
            agent,
            attempt_ref: Some(bytes_to_hex_lower(id.as_bytes())),
            proposal_ref: None,
        });
    }
    Ok(Some(TeamRunAnswer::Started {
        team_ref: launch.team_ref,
        pattern,
        members,
    }))
}

/// The spawn key of a member within its team's start.
pub(crate) fn member_spawn_key(input: &TeamStartInput, member: &TeamMemberInput) -> String {
    format!("team:{}:{}", input.intent_key, member.intent_key)
}

/// Records the receipt of a team `leader` started, or of the planned team
/// it leads as a retry of the leader the launch queued. Storage errors are
/// errors; a refusal is the guest's typed failure code.
///
/// # Errors
///
/// Storage errors and a malformed dispatch payload.
pub(crate) fn record_led_team(
    vault: &Vault,
    leader: AttemptId,
    input: &TeamRecordInput,
    now: u64,
) -> Result<std::result::Result<TeamRunAnswer, &'static str>> {
    let store = DreamerRunnerStore::new(vault);
    let Some(lead) = store.status(leader)? else {
        return Ok(Err("team_unbound"));
    };
    let lead_input = decode_agent_dispatch_input(&lead.payload.input)?;
    // A planned team's launch froze its axis and the pack revision its
    // leader was shown, and bound the team under the leader it queued
    // (DOOR-111).
    let planned = AgentDispatcher::new(vault)
        .planned_launch_for_leader(leader)?
        .filter(|launch| launch.team_ref == input.team_ref);
    let root = planned.as_ref().map_or(leader, |launch| launch.root);
    let prefix = led_team_ref(root, "");
    if !input.team_ref.starts_with(&prefix) || input.team_ref.len() == prefix.len() {
        return Ok(Err("team_record_not_led"));
    }
    let bound = team_run_binding(vault, root, &input.team_ref)?;
    if input.members.is_empty() && bound.is_none() {
        return Ok(Err("team_record_invalid_input"));
    }
    let mut pattern = bound.as_ref().map(|run| run.stamp.pattern);
    let mut started = bound.as_ref().map_or(now, |run| run.started_at.min(now));
    let mut members = bound.map(|run| run.members).unwrap_or_default();
    // The start's own spawns are members on the host's word.
    for id in &members {
        if let Some(row) = store.status(*id)? {
            started = started.min(row.attempt.created_at);
        }
    }
    let mut seen = HashSet::new();
    for member in &input.members {
        let Some(id) = parse_attempt(member).filter(|id| seen.insert(*id)) else {
            return Ok(Err("team_record_invalid_input"));
        };
        if members.contains(&id) {
            continue;
        }
        let Some(row) = store.status(id)? else {
            return Ok(Err("team_record_unknown_member"));
        };
        match attempt_team_stamp(&row.attempt)? {
            Some(stamp) if stamp.team_ref == input.team_ref => pattern = Some(stamp.pattern),
            _ => return Ok(Err("team_record_member_outside_team")),
        }
        started = started.min(row.attempt.created_at);
        members.push(id);
    }
    let Some(pattern) = pattern else {
        return Ok(Err("team_record_invalid_input"));
    };
    let Ok(width) = u32::try_from(members.len() + 1) else {
        return Ok(Err("team_record_invalid_input"));
    };
    let roles = match &input.roles {
        Some(roles) if roles.values().map(|n| u64::from(*n)).sum::<u64>() == u64::from(width) => {
            roles.clone()
        }
        Some(_) => return Ok(Err("team_record_roles")),
        None => BTreeMap::from([("lead".to_owned(), 1), ("member".to_owned(), width - 1)]),
    };
    let actor = lead_input.target.agent_definition_ref()?;
    let decided_by = match &input.decided_by {
        TeamDecisionInput::Leader => DecidedBy::Leader { actor },
        TeamDecisionInput::Chair => DecidedBy::Chair { actor },
        TeamDecisionInput::Vote { tally } => DecidedBy::Vote {
            tally: tally.clone(),
        },
        TeamDecisionInput::Referee { rule, signed_at } => match market(vault, &input.team_ref)? {
            Some(market) => DecidedBy::Referee {
                rule: market.referee.rule_ref,
                signed_at: market.referee.signed_at,
            },
            None => DecidedBy::Referee {
                rule: rule.clone(),
                signed_at: *signed_at,
            },
        },
    };
    if decided_by.kind() != pattern.decider_kind() {
        return Ok(Err("team_record_decider"));
    }
    if let Some(existing) = team_receipt(vault, &input.team_ref)? {
        return Ok(Ok(recorded(&existing, true)));
    }
    let observed = team_run_observations(vault, leader, &members)?;
    // The leader's model, and each member's newest try's, as measured beside
    // its calls and spend (FIX 10192); a model nobody recorded stays out, and
    // a team with none recorded records its models as unknown.
    let mut models: BTreeSet<String> = observed.models.iter().cloned().collect();
    models.extend(crate::skill_attribution::run_executor_model(
        vault,
        &lead.attempt,
    )?);
    let receipt = TeamReceipt {
        team_ref: input.team_ref.clone(),
        project: lead_input.project_ref,
        type_ref: TypeRef::from(&lead_input.type_ref),
        pattern,
        pattern_skill: match &planned {
            Some(launch) => launch
                .pack
                .as_ref()
                .and_then(|pack| frozen_pattern_skill(&lead.attempt, pack)),
            None => loaded_pattern_skill(vault, &lead.attempt, pattern)?,
        },
        axis: planned
            .as_ref()
            .and_then(|launch| launch.start.as_ref())
            .map_or(input.axis, |start| start.axis),
        models: models.into_iter().collect(),
        shape: TeamShape { width, roles },
        decided_by,
        coverage: input.coverage.map(|c| Coverage {
            cells_filled: c.cells_filled,
            cells_total: c.cells_total,
        }),
        confessions: observed.confessions,
        spend: observed.spend,
        spend_cap: observed.spend_cap,
        elapsed_secs: now.saturating_sub(started),
        calls: observed.calls,
        outcome: None,
        at: now,
    };
    if receipt.validate().is_err() {
        return Ok(Err("team_record_invalid_input"));
    }
    record_team_receipt(vault, &receipt)?;
    Ok(Ok(recorded(&receipt, false)))
}

fn recorded(receipt: &TeamReceipt, replay: bool) -> TeamRunAnswer {
    TeamRunAnswer::Recorded {
        team_ref: receipt.team_ref.clone(),
        pattern: receipt.pattern,
        width: receipt.shape.width,
        below_floor: receipt.below_floor(),
        models: receipt.models.clone(),
        pattern_skill: receipt
            .pattern_skill
            .as_ref()
            .map(|skill| skill.skill.to_hex()),
        replay,
    }
}

/// The pattern skill for `pattern` that `lead` loaded, at the revision it
/// loaded.
fn loaded_pattern_skill(
    vault: &Vault,
    lead: &AttemptRecord,
    pattern: TeamPattern,
) -> Result<Option<PatternSkillRef>> {
    for bound in pattern_skills(vault)? {
        if bound.pattern != pattern {
            continue;
        }
        let Some(record) = vault.get_skill_record(&bound.skill)? else {
            continue;
        };
        if let Some(entry) = lead
            .manifest()
            .iter()
            .find(|entry| entry.kind == ManifestKind::Skill && entry.reference == record.skill_id)
        {
            return Ok(Some(PatternSkillRef {
                skill: bound.skill,
                version: entry.version.clone(),
            }));
        }
    }
    Ok(None)
}

/// The revision a planned team froze, when `lead` loaded it: its manifest
/// names that skill at that version. Never another revision or another
/// bound skill.
fn frozen_pattern_skill(lead: &AttemptRecord, pack: &FrozenPatternPack) -> Option<PatternSkillRef> {
    lead.manifest()
        .iter()
        .any(|entry| {
            entry.kind == ManifestKind::Skill
                && entry.reference == pack.skill_id()
                && entry.version == pack.version()
        })
        .then(|| PatternSkillRef {
            skill: pack.entity(),
            version: pack.version().to_owned(),
        })
}

pub(super) fn led_team_ref(leader: AttemptId, key: &str) -> String {
    format!("team:{}:{key}", bytes_to_hex_lower(leader.as_bytes()))
}

fn key_ok(key: &str) -> bool {
    !key.trim().is_empty() && key.len() <= MAX_KEY_BYTES && !key.chars().any(char::is_control)
}

fn parse_attempt(text: &str) -> Option<AttemptId> {
    let id = EntityId::from_hex(text).ok()?;
    AttemptId::from_bytes(id.as_bytes()).ok()
}
