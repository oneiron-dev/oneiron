//! OF-397/OF-540: the execution context a host binds on a leased agent run,
//! so its pack receipt closes attributed.
//!
//! The host binds it while the lease still holds, before any close; the
//! terminal transaction then freezes it beside the pack manifest. Every field
//! is a fact of the run, never a guess:
//!
//! - the executor is the model the pack loaded under, else the seat the run
//!   was born on. A run with neither binds nothing and closes unattributed;
//! - the judge is the run's decision ladder at its top model rung, the judge
//!   the run's Done climbs to, else the person;
//! - a team run's pattern and decider are its frozen stamp's: the pattern's
//!   context and the team run's decision, which its `TeamReceipt` names. A
//!   run outside any team is solo, and its own agent decides.
//!
//! Neither pattern context is a loaded skill, so neither earns pack credit: a
//! pattern skill's payoff comes from its team receipt alone. The use lists
//! start empty and only grow from witnessed use; credit follows canon's
//! default, the full used chain with no per-hop check.

use crate::Vault;
use crate::agent_dispatch::{AGENT_DISPATCH_ATTEMPT_TYPE, decode_agent_dispatch_input};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::dreamer_runner::DreamerRunnerStore;
use crate::entity_id::{EntityId, derived_domains};
use crate::error::Result;
use crate::learning::TypeRef;
use crate::llm::decision::{DecisionProvider, HeldLadder, ProviderPin};
use crate::receipt::{CreditOptions, PackAttributionFields};

/// The role a run outside any team plays.
const SOLO_ROLE: &str = "solo";

/// The role a team run's member plays.
const MEMBER_ROLE: &str = "member";

/// Binds the execution context of the leased agent run `attempt`, once.
/// Returns whether it bound one now: a run that is no agent dispatch, no
/// longer holds `lease_owner`'s lease, already carries one, or names no
/// executor binds nothing.
///
/// # Errors
///
/// Storage errors, a malformed dispatch payload, and the attribution door's
/// own refusals.
pub fn bind_agent_run_attribution(
    vault: &Vault,
    attempt: AttemptId,
    lease_owner: &str,
    judges: &HeldLadder,
) -> Result<bool> {
    let Some(status) = DreamerRunnerStore::new(vault).status(attempt)? else {
        return Ok(false);
    };
    let record = &status.attempt;
    if status.payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE
        || !matches!(record.state, AttemptState::Leased | AttemptState::Landing)
        || record.lease_owner.as_deref() != Some(lease_owner)
    {
        return Ok(false);
    }
    {
        let rtxn = vault.store.env.read_txn()?;
        if crate::receipt::has_attempt_pack_attribution_in_txn(&vault.store, &rtxn, attempt)? {
            return Ok(false);
        }
    }
    let Some(executor) = run_executor_model(vault, record)? else {
        return Ok(false);
    };
    let input = decode_agent_dispatch_input(&status.payload.input)?;
    let (pattern, role, decider) = match &input.team {
        Some(team) => (
            pattern_context(team.pattern.as_str())?,
            MEMBER_ROLE,
            EntityId::derive(
                derived_domains::COORDINATION_PATTERN,
                &[b"decider", team.team_ref.as_bytes()],
            )?,
        ),
        None => (
            pattern_context(SOLO_ROLE)?,
            SOLO_ROLE,
            input.target.agent_definition_ref()?,
        ),
    };
    let fields = PackAttributionFields {
        type_ref: TypeRef::from(&input.type_ref),
        executor,
        judge: ladder_judge(judges),
        pattern,
        team_shape: vec![role.to_owned()],
        decider,
        project: input.project_ref,
        output: None,
        contributions: Vec::new(),
        used_edges: Vec::new(),
        credit: CreditOptions {
            enabled: true,
            depth_cap: None,
            check_every_hop: false,
        },
    };
    AttemptQueue::new(vault).set_pack_attribution(
        attempt,
        lease_owner,
        record.attempt_count,
        &fields,
    )?;
    Ok(true)
}

/// The id of a coordination pattern's context: `solo`, or a team pattern's
/// wire token. It names the pattern, never a skill.
fn pattern_context(token: &str) -> Result<EntityId> {
    EntityId::derive(
        derived_domains::COORDINATION_PATTERN,
        &[b"pattern", token.as_bytes()],
    )
}

/// The model that executed `record`: the one its pack loaded under, else the
/// seat its run was born on. A run's id is its attempt's.
pub(crate) fn run_executor_model(vault: &Vault, record: &AttemptRecord) -> Result<Option<String>> {
    if let Some(model) = &record.executor_model {
        return Ok(Some(model.clone()));
    }
    let run = EntityId::from_bytes(*record.id.as_bytes())?;
    Ok(vault
        .model_seat_receipt(run)?
        .map(|seat| seat.model.to_string()))
}

/// The ladder's top model rung, else its person, as `model@revision`.
fn ladder_judge(ladder: &HeldLadder) -> String {
    [
        &ladder.big,
        &ladder.escalation,
        &ladder.system_one,
        &ladder.local,
    ]
    .into_iter()
    .flatten()
    .next()
    .map_or_else(|| pinned(&ladder.human_pin), |rung| pinned(&rung.pin()))
}

fn pinned(pin: &ProviderPin) -> String {
    if pin
        .model
        .rsplit_once('@')
        .is_some_and(|(id, revision)| !id.is_empty() && !revision.is_empty())
    {
        pin.model.clone()
    } else {
        format!("{}@{}", pin.model, pin.version)
    }
}
