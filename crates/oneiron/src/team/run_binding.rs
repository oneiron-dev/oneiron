//! OF-540: what the host saw a team start do, and the team a run works in.
//!
//! `self.team.start` spawns its members as the leader's children, each with
//! the team's stamp. The host keeps that start: the stamp, the leader, the
//! TASK the leader ran, the queued members and the widenings a spawn asked
//! instead. Membership is then the host's fact, not the record's list.
//!
//! The leader's own attempt was dispatched before its team existed and keeps
//! the stamp it has. A TASK the leader creates inside its team reads the
//! team through [`team_spawn_context_for_attempt_in_txn`]: the one team the
//! attempt started, else its own stamp. An attempt that started several
//! teams must name one; the host never picks for it.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_dispatch::{TeamRunStamp, attempt_team_stamp};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

/// Team starts. Key: the leader's attempt in hex, `:`, the team reference.
const TEAM_RUN: SideTable<String, TeamRunBinding, Named> = SideTable::new(&side_table::TEAM_RUN);

/// One team start, as the host observed it. Host-only: never guest input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamRunBinding {
    pub stamp: TeamRunStamp,
    pub leader: AttemptId,
    /// The TASK the leader ran, as its queue row names it. The writer fills
    /// it from that row.
    pub root_task: Option<String>,
    pub started_at: u64,
    /// The members' queued attempts, as the start's spawns answered them.
    pub members: Vec<AttemptId>,
    /// The widenings a spawn asked instead. A proposal is not a member until
    /// its approval queues one.
    pub proposals: Vec<String>,
}

fn run_key(leader: AttemptId, team_ref: &str) -> String {
    format!("{}{team_ref}", leader_prefix(leader))
}

fn leader_prefix(leader: AttemptId) -> String {
    format!("{}:", bytes_to_hex_lower(leader.as_bytes()))
}

/// Records a team start. The same start again, as a replayed start answers
/// it, adds what it found to the row; it never changes the stamp or the
/// leader, and never drops a member.
///
/// # Errors
///
/// [`Error::EntityNotFound`] for an unknown leader;
/// [`Error::InvalidClaimBody`] for an invalid stamp or a start that names
/// another stamp; storage errors. No count caps the members or widenings a
/// start binds (ARCH-0079).
pub fn record_team_start(vault: &Vault, run: &TeamRunBinding) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| record_team_start_in_txn(vault, wtxn, run))
}

/// [`record_team_start`] in the caller's transaction.
///
/// # Errors
///
/// As [`record_team_start`].
pub fn record_team_start_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: &TeamRunBinding,
) -> Result<()> {
    run.stamp.validate()?;
    let leader = AttemptQueue::new(vault)
        .get_in_txn(txn, run.leader)?
        .ok_or(Error::EntityNotFound)?;
    let key = run_key(run.leader, &run.stamp.team_ref);
    let mut row = match TEAM_RUN.get(&vault.store, txn, &key)? {
        Some(existing) if existing.stamp != run.stamp => {
            return Err(Error::InvalidClaimBody(
                "a team start keeps the stamp it opened",
            ));
        }
        Some(mut existing) => {
            existing.started_at = existing.started_at.min(run.started_at);
            existing
        }
        None => TeamRunBinding {
            stamp: run.stamp.clone(),
            leader: run.leader,
            root_task: None,
            started_at: run.started_at,
            members: Vec::new(),
            proposals: Vec::new(),
        },
    };
    row.root_task.clone_from(&leader.task_ref);
    for member in &run.members {
        if !row.members.contains(member) {
            row.members.push(*member);
        }
    }
    for proposal in &run.proposals {
        if !row.proposals.contains(proposal) {
            row.proposals.push(proposal.clone());
        }
    }
    TEAM_RUN.put(&vault.store, txn, &key, &row)
}

/// The start of `team_ref` that `leader` made, if the host recorded one.
///
/// # Errors
///
/// Storage errors.
pub fn team_run_binding(
    vault: &Vault,
    leader: AttemptId,
    team_ref: &str,
) -> Result<Option<TeamRunBinding>> {
    let rtxn = vault.store.env.read_txn()?;
    team_run_binding_in_txn(vault, &rtxn, leader, team_ref)
}

/// [`team_run_binding`] in the caller's snapshot.
///
/// # Errors
///
/// Storage errors.
pub fn team_run_binding_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    leader: AttemptId,
    team_ref: &str,
) -> Result<Option<TeamRunBinding>> {
    TEAM_RUN.get(&vault.store, txn, &run_key(leader, team_ref))
}

/// The team a spawn or TASK made by `attempt` works in: the one team the
/// attempt started, else the stamp its own dispatch froze. Team metadata
/// only, never a grant.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the attempt started several teams, since
/// the host never picks one; storage errors.
pub fn team_spawn_context_for_attempt(
    vault: &Vault,
    attempt: AttemptId,
) -> Result<Option<TeamRunStamp>> {
    let rtxn = vault.store.env.read_txn()?;
    team_spawn_context_for_attempt_in_txn(vault, &rtxn, attempt)
}

/// [`team_spawn_context_for_attempt`] in the caller's snapshot.
///
/// # Errors
///
/// As [`team_spawn_context_for_attempt`].
pub fn team_spawn_context_for_attempt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<TeamRunStamp>> {
    let started = TEAM_RUN.scan_from(&vault.store, txn, leader_prefix(attempt).as_bytes())?;
    match started.as_slice() {
        [] => {}
        [(_, run)] => return Ok(Some(run.stamp.clone())),
        _ => {
            return Err(Error::InvalidClaimBody(
                "the attempt started several teams; name the one its work joins",
            ));
        }
    }
    match AttemptQueue::new(vault).get_in_txn(txn, attempt)? {
        Some(record) => attempt_team_stamp(&record),
        None => Ok(None),
    }
}

/// The TASK each recorded team start ran, by team reference: the grouping a
/// comparison of team runs on one task reads. Starts that name no TASK are
/// left out.
///
/// # Errors
///
/// Storage errors.
pub fn team_run_tasks(vault: &Vault) -> Result<std::collections::BTreeMap<String, String>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(TEAM_RUN
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .filter_map(|(_, run)| Some((run.stamp.team_ref, run.root_task?)))
        .collect())
}
