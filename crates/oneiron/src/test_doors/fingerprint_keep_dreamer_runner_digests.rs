//! K-proof door for dreamer-runner digests that existing records store or compare.
//! Compiled only under `oneiron_test_support`; never part of the engine API.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;

use crate::EntityId;
use crate::claim::learning_evidence::Anchor;
use crate::dreamer_runner::maintenance::agent_health::{self, HealthBriefPin};
use crate::dreamer_runner::maintenance::{self, code_fix, digest, fork_promote, stewardship};
use crate::dreamer_runner::{step_replay, turn_program_test_hooks};
use crate::receipt::task_type_ref::TypeRef;
use crate::store::diagnostic_record::AgentHealthSignal;
use crate::team::{DecidedBy, TeamAxis, TeamOutcome, TeamPattern, TeamReceipt, TeamShape};
use crate::workspace_roster::RoomUpkeepInput;

/// The queued Coach ask's dedupe key.
#[must_use]
pub fn coach_ask_dedupe(handle: &str, at: u64) -> String {
    agent_health::ask_dedupe_key_for_test(handle, at)
}

/// The health_review receipt id of what a card holds for review, over the
/// card fields the id reads.
#[must_use]
pub fn agent_health_review_state(
    subject: EntityId,
    signal: AgentHealthSignal,
    task: Option<EntityId>,
    reviewer: &str,
    diagnostics: &[EntityId],
    evidence: &[EntityId],
    observed_brief: Option<&HealthBriefPin>,
) -> String {
    agent_health::review_state_of_for_test(
        subject,
        signal,
        task,
        reviewer,
        diagnostics,
        evidence,
        observed_brief,
    )
}

/// The terms digest stored in a grant-environment proposal, over the grant's
/// encoded body.
#[must_use]
pub fn environment_grant_terms(encoded: &[u8]) -> [u8; 32] {
    maintenance::grant_terms_digest_for_test(encoded)
}

/// The WORK key of a blocked report's code-fix work.
///
/// # Errors
///
/// The truncated digest is not an entity id.
pub fn code_fix_blocked_work(receipt: &EntityId) -> crate::Result<EntityId> {
    code_fix::blocked_work_key_for_test(receipt)
}

/// A maintenance queue's dedupe key for a wake key under `facet`.
#[must_use]
pub fn maintenance_wake_key(facet: &str, key: &str) -> String {
    stewardship::wake_dedupe_key_for_test(facet, key)
}

/// The urgent-digest harm basis over a candidate's JSON and the question.
#[must_use]
pub fn digest_harm_basis(json: &[u8], question: &str) -> [u8; 32] {
    digest::harm_basis_of_for_test(json, question)
}

/// The host-built assessment witness's dedupe key over the assessment's JSON.
#[must_use]
pub fn digest_harm_host_witness(json: &[u8]) -> String {
    digest::host_witness_key_of_for_test(json)
}

/// The fold-default state over `(kind, keep_last_steps, median_span_steps)` rows.
#[must_use]
pub fn fold_suggestion_state(
    definition: EntityId,
    rows: &[(&'static str, Option<u64>, u64)],
) -> [u8; 32] {
    maintenance::suggestion_state_for_test(definition, rows)
}

/// One team as the project-tree upkeep evidence digest reads its receipt.
pub struct UpkeepTeam<'a> {
    pub team_ref: &'a str,
    pub node_id: &'a str,
    pub tree_version: u64,
    pub pattern: TeamPattern,
    pub models: &'a [String],
    /// `None`: not settled; `Some(success)`: the settled outcome.
    pub outcome: Option<bool>,
    pub at: u64,
}

/// The project-tree upkeep evidence digest of `teams`. The receipt fields the
/// digest never reads hold fixed values.
#[must_use]
pub fn project_tree_upkeep_evidence(
    teams: &[UpkeepTeam<'_>],
    tasks: &BTreeMap<String, String>,
) -> [u8; 32] {
    let receipts: Vec<TeamReceipt> = teams.iter().map(team_receipt).collect();
    fork_promote::evidence_digest_for_test(&receipts, tasks)
}

fn team_receipt(team: &UpkeepTeam<'_>) -> TeamReceipt {
    TeamReceipt {
        team_ref: team.team_ref.to_owned(),
        project: None,
        type_ref: TypeRef {
            node_id: team.node_id.to_owned(),
            tree_version: team.tree_version,
        },
        pattern: team.pattern,
        pattern_skill: None,
        axis: TeamAxis::Converge,
        models: team.models.to_vec(),
        shape: TeamShape::SOLO,
        decided_by: DecidedBy::Vote {
            tally: BTreeMap::new(),
        },
        coverage: None,
        confessions: None,
        spend: None,
        spend_cap: None,
        elapsed_secs: 0,
        calls: None,
        outcome: team.outcome.map(|success| TeamOutcome {
            receipt: String::new(),
            anchor: Anchor::HeldOut,
            success,
            at: 0,
            critics: None,
        }),
        at: team.at,
    }
}

/// The DECLARED room-upkeep source state of `input`.
#[must_use]
pub fn room_upkeep_source_state(input: &RoomUpkeepInput) -> [u8; 32] {
    maintenance::source_state_for_test(input)
}

/// A turn program's STEP row id over its parts.
///
/// # Errors
///
/// The truncated digest is not an entity id.
pub fn turn_program_step_id(parts: &[&[u8]]) -> crate::Result<EntityId> {
    turn_program_test_hooks::step_id_for_test(parts)
}

/// The result digest an outbound step settles with.
///
/// # Errors
///
/// Reading the body fails (a byte slice never does).
pub fn turn_program_outbound_result(
    payload_hash: &[u8; 32],
    body: Option<&[u8]>,
) -> crate::Result<[u8; 32]> {
    turn_program_test_hooks::outbound_result_digest_for_test(payload_hash, body)
}

/// The route-prompt digest a route pin and a capsule's stored rung carry.
#[must_use]
pub fn route_prompt(prompt: Option<&str>) -> [u8; 32] {
    step_replay::route_prompt_digest(prompt)
}
