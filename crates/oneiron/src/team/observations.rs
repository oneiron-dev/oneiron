//! OF-540: what the host measured of a team run, for its receipt.
//!
//! Over the team's members the host counts what it can observe itself: the
//! confessions their sealed receipts name, the `self.*` calls their runs
//! made, and the spend their lease scopes settled. A value the host cannot
//! measure in full is `None`, never a guess or a zero: a member with no seal,
//! a run with no replay record, an open or unmetered scope. The leader's own
//! calls and spend are shared with whatever else it runs, so they stay out;
//! the cap is the hard cap the leader runs under.

use std::collections::BTreeSet;

use crate::Vault;
use crate::agent_dispatch::AgentDispatcher;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::run_admission::LeaseUnit;
use crate::self_heal::audit::ObjectiveConfession;

/// The host's measurements over a team's members.
#[derive(Debug, Clone, PartialEq)]
pub struct TeamRunObservations {
    /// Members with a sealed receipt.
    pub sealed: u32,
    /// Members whose sealed confession names a flaw: an objective unmet or a
    /// named flaw. `None` unless every member is sealed.
    pub confessions: Option<u32>,
    /// Logical `self.*` calls the members' runs made, as their replay records
    /// hold them. `None` unless every member's run has one.
    pub calls: Option<u64>,
    /// What the members' closed lease scopes spent, children included, in
    /// the cap's unit. `None` unless every member's scope is closed and
    /// metered in that unit.
    pub spend: Option<f64>,
    /// The hard cap binding the leader's scope; `None` when it is unmetered.
    pub spend_cap: Option<f64>,
}

/// Measures a team run's members. `leader` names the scope whose hard cap
/// binds the team.
///
/// # Errors
///
/// Storage errors.
pub fn team_run_observations(
    vault: &Vault,
    leader: AttemptId,
    members: &[AttemptId],
) -> Result<TeamRunObservations> {
    let mut sealed = 0_u32;
    let mut flawed = 0_u32;
    for member in members {
        if let Some(seal) = vault.sealed_attempt_receipt(*member)? {
            sealed += 1;
            if seal
                .confession
                .objectives
                .iter()
                .any(ObjectiveConfession::confesses_flaw)
            {
                flawed += 1;
            }
        }
    }
    let all_sealed = usize::try_from(sealed).is_ok_and(|n| n == members.len());
    let mut calls = Some(0_u64);
    for member in members {
        let run = EntityId::from_bytes(*member.as_bytes())?;
        calls = match (calls, vault.get_code_run_replay_record(&run)?) {
            (Some(sum), Some(record)) => Some(
                sum.saturating_add(u64::try_from(record.bridge_calls.len()).unwrap_or(u64::MAX)),
            ),
            _ => None,
        };
    }
    let dispatcher = AgentDispatcher::new(vault);
    let cap = match dispatcher.spend_scope_for_attempt(leader)? {
        Some(scope) => {
            let read = dispatcher.spend_read(&scope)?;
            Some((read.unit, read.cap_units))
        }
        None => None,
    };
    let spend = match &cap {
        Some((unit, _)) => member_spend(&dispatcher, members, unit)?,
        None => None,
    };
    #[allow(clippy::cast_precision_loss)]
    let (spend, spend_cap) = (
        spend.map(|units| units as f64),
        cap.map(|(_, units)| units as f64),
    );
    Ok(TeamRunObservations {
        sealed,
        confessions: all_sealed.then_some(flawed),
        calls: calls.filter(|_| !members.is_empty()),
        spend,
        spend_cap,
    })
}

/// The units the members' closed scopes spent, each scope once; `None` when
/// a member is unmetered, still open, or metered in another unit.
fn member_spend(
    dispatcher: &AgentDispatcher<'_>,
    members: &[AttemptId],
    unit: &LeaseUnit,
) -> Result<Option<u64>> {
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    for member in members {
        let Some(id) = dispatcher.spend_scope_for_attempt(*member)? else {
            return Ok(None);
        };
        if !seen.insert(id.clone()) {
            continue;
        }
        let Some(scope) = dispatcher.read_spend_scope(&id)? else {
            return Ok(None);
        };
        if scope.closed_at.is_none() || scope.unit != *unit {
            return Ok(None);
        }
        total = total.saturating_add(scope.spent_units);
    }
    Ok((!members.is_empty()).then_some(total))
}
