//! Participant choices observed on their own bound code-run invocation.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_dispatch::attempt_team_stamp;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

use super::TeamPattern;
use super::run::{TeamRunAnswer, TeamVoteInput};
use super::run_binding::team_run_binding_in_txn;

const TEAM_BALLOT: SideTable<String, TeamBallot, Named> = SideTable::new(&side_table::TEAM_BALLOT);

#[derive(Serialize, Deserialize)]
struct TeamBallot {
    team_ref: String,
    attempt: AttemptId,
    choice: String,
    at: u64,
}

fn ballot_key(attempt: AttemptId, team_ref: &str) -> String {
    format!("{}:{team_ref}", bytes_to_hex_lower(attempt.as_bytes()))
}

/// The caller is the host's bound attempt, never a field of the vote input.
pub(crate) fn record_vote(
    vault: &Vault,
    caller: AttemptId,
    input: &TeamVoteInput,
    now: u64,
) -> Result<std::result::Result<TeamRunAnswer, &'static str>> {
    vault.with_write_txn_grouped(|txn| {
        let Some(attempt) = AttemptQueue::new(vault).get_in_txn(txn, caller)? else {
            return Ok(Err("team_unbound"));
        };
        let member = attempt_team_stamp(&attempt)?.is_some_and(|stamp| {
            stamp.team_ref == input.team_ref && stamp.pattern == TeamPattern::Vote
        });
        if !member && !is_leader_in_txn(vault, txn, caller, &input.team_ref)? {
            return Ok(Err("team_vote_outside_team"));
        }
        let ballot = TeamBallot {
            team_ref: input.team_ref.clone(),
            attempt: caller,
            choice: input.choice.clone(),
            at: now,
        };
        TEAM_BALLOT.put(
            &vault.store,
            txn,
            &ballot_key(caller, &input.team_ref),
            &ballot,
        )?;
        Ok(Ok(TeamRunAnswer::Voted {
            team_ref: input.team_ref.clone(),
            choice: input.choice.clone(),
        }))
    })
}

pub(super) fn choice_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    team_ref: &str,
) -> Result<Option<String>> {
    Ok(TEAM_BALLOT
        .get(&vault.store, txn, &ballot_key(attempt, team_ref))?
        .filter(|ballot| ballot.attempt == attempt && ballot.team_ref == team_ref)
        .map(|ballot| ballot.choice))
}

/// A planned leader's retry has its own invocation but leads the same start.
fn is_leader_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: AttemptId,
    team_ref: &str,
) -> Result<bool> {
    let root = team_ref
        .strip_prefix("team:")
        .and_then(|rest| rest.split_once(':'))
        .and_then(|(root, _)| EntityId::from_hex(root).ok())
        .and_then(|root| AttemptId::from_bytes(root.as_bytes()).ok());
    let Some(root) = root else {
        return Ok(false);
    };
    let Some(run) = team_run_binding_in_txn(vault, txn, root, team_ref)? else {
        return Ok(false);
    };
    if run.stamp.pattern != TeamPattern::Vote {
        return Ok(false);
    }
    let queue = AttemptQueue::new(vault);
    if queue.get_in_txn(txn, root)?.is_none() {
        return Ok(false);
    }
    Ok(queue.retry_tip_in_txn(txn, root)?.id == caller)
}
