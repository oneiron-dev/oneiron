//! Moved from `crates/oneiron/src/team/run.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::attempt_manifest::ManifestKind;
use crate::team::pattern::TeamAxis;
use crate::team::pattern::TeamPattern;
use crate::team::receipt::PatternSkillRef;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;

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

/// `self.team.vote`: the calling participant's own choice in its team.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeamVoteInput {
    pub team_ref: String,
    pub choice: String,
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
