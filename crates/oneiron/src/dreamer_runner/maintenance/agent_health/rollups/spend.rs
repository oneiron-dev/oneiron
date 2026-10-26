//! Each rollup member's launch spend scope, read for the trend pass.

use std::collections::BTreeMap;

use super::{Dispatched, Member};
use crate::agent_dispatch::{AgentDispatcher, SpendScope, SpendState};
use crate::attempt_queue::AttemptRecord;
use crate::llm::run_admission::LeaseUnit;
use crate::{Result, Vault};

/// One member's spend.
#[derive(Debug, Clone, Default)]
pub(super) enum Spend {
    /// The spend read failed: nothing counted.
    #[default]
    Unread,
    /// It launched with no scope: its spend is unknown.
    Unmetered,
    /// Its scope is counted on a newer member of the same launch.
    Shared,
    /// Its scope, counted here: own spend once closed, else unknown.
    Scope {
        id: String,
        unit: LeaseUnit,
        own: Option<u64>,
    },
}

/// Each member's launch spend. A launch's retries share one scope, counted
/// once on its newest member; a member that is not that try is `Shared`. A
/// newer try still running, settled today or out of both spans counts on no
/// day, so it never takes the scope from its older members, and the newest
/// member falls in every span an older one does. Every child a member's scope
/// spawned was created after it, so the scopes of the agent attempts created
/// from the earliest member on hold every child to take out.
pub(super) fn read_spend(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    agents: &[(AttemptRecord, Dispatched)],
    members: &[Member],
    earliest: u64,
) -> Result<Vec<Spend>> {
    let dispatcher = AgentDispatcher::new(vault);
    let mut scopes: BTreeMap<String, SpendScope> = BTreeMap::new();
    let mut scope_of: BTreeMap<usize, String> = BTreeMap::new();
    for (at, (record, _)) in agents.iter().enumerate() {
        if record.created_at < earliest {
            continue;
        }
        let Some(scope) = dispatcher.attempt_spend_scope_in_txn(rtxn, record.id)? else {
            continue;
        };
        let name = scope.scope.to_string();
        scope_of.insert(at, name.clone());
        scopes.entry(name).or_insert(scope);
    }
    let mut newest: BTreeMap<&str, usize> = BTreeMap::new();
    for member in members {
        let Some(name) = scope_of.get(&member.index) else {
            continue;
        };
        let record = &agents[member.index].0;
        let newer = newest.get(name.as_str()).is_none_or(|held| {
            let held = &agents[*held].0;
            (held.updated_at, held.id.as_bytes()) <= (record.updated_at, record.id.as_bytes())
        });
        if newer {
            newest.insert(name.as_str(), member.index);
        }
    }
    let mut children: BTreeMap<String, u64> = BTreeMap::new();
    for scope in scopes.values() {
        if scope.state == SpendState::Closed
            && let Some(parent) = &scope.parent
        {
            let spent = children.entry(parent.to_string()).or_default();
            *spent = spent.saturating_add(scope.spent_units);
        }
    }
    let mut spend = Vec::with_capacity(members.len());
    for member in members {
        let Some(name) = scope_of.get(&member.index) else {
            spend.push(Spend::Unmetered);
            continue;
        };
        if newest.get(name.as_str()) != Some(&member.index) {
            spend.push(Spend::Shared);
            continue;
        }
        let scope = &scopes[name];
        spend.push(Spend::Scope {
            id: name.clone(),
            unit: scope.unit.clone(),
            own: (scope.state == SpendState::Closed).then(|| {
                scope
                    .spent_units
                    .saturating_sub(children.get(name).copied().unwrap_or(0))
            }),
        });
    }
    Ok(spend)
}
