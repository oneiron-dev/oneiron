//! FIX 5661 seam (L09's spend tree, Engine-approved 10-20 11:5x): a home
//! move carries each free-time cycle's spend tree beside its cycle, so the
//! remaining allowance moves whole: the root under the cap the owner was
//! shown, and every scope below it, open or settled, with what each spent
//! and holds. The new home opens no root for what remains, and nothing
//! already spent is counted twice.
//!
//! Only free-time trees move: the roots this node's cycles name, and every
//! scope whose parents lead to one. Any other launch's tree stays. Scopes
//! are stored as JSON (`LegacyJson`); they travel as this MessagePack DTO
//! and land through the table's typed write.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::AgentDispatcher;
use super::spend_record::{MAX_SPEND_DEPTH, SCOPE, SpendScope, SpendScopeId, SpendState};
use super::widen_record::invalid;
use crate::attempt_queue::AttemptQueue;
use crate::side_table::{self, SideTableDecl};
use crate::sync::home_handoff::{
    HomeFence, HomeMove, HomeTable, TableAdopt, froze_home_state_in_txn,
};
use crate::{Result, Vault};

/// The free-time spend trees a home move carries.
#[derive(Serialize, Deserialize)]
pub(crate) struct FreeTimeSpendRows {
    scopes: Vec<SpendScope>,
}

impl HomeTable for FreeTimeSpendRows {
    type Rows = Self;
    const TABLE: &'static SideTableDecl = &side_table::AGENT_DISPATCH_SPEND_SCOPE;
    const SCHEMA_VERSION: u16 = 1;

    /// No try still spends under an open scope of a free-time tree: each has
    /// ended, or is a free-time item that never started, which the move
    /// carries and its new home queues again.
    fn quiescent(vault: &Vault, txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        let open: BTreeSet<SpendScopeId> = selected_in_txn(vault, txn)?
            .into_values()
            .filter(|scope| scope.parent.is_some() && scope.state == SpendState::Open)
            .map(|scope| scope.scope)
            .collect();
        if open.is_empty() {
            return Ok(true);
        }
        let dispatcher = AgentDispatcher::new(vault);
        for record in AttemptQueue::new(vault).list_in_txn(txn)? {
            if record.state.is_terminal()
                || crate::dreamer_runner::free_time_item_waits_unstarted(&record)
            {
                continue;
            }
            if dispatcher
                .scope_for_attempt_in_txn(txn, record.id)?
                .is_some_and(|scope| open.contains(&scope))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn export(vault: &Vault, txn: &RoTxn<'_>, _fence: &HomeFence) -> Result<Self> {
        Ok(Self {
            scopes: selected_in_txn(vault, txn)?.into_values().collect(),
        })
    }

    /// Each carried scope lands where this node holds none under its id, or
    /// holds one the carried scope follows. A scope here that is ahead of the
    /// carried one or diverged from it is a Conflict, as is a free-time scope
    /// here the carried trees lack on a node that froze its trees for an
    /// earlier move: that is work its successor never saw.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Self,
    ) -> Result<TableAdopt> {
        let carried = carried_trees(rows.scopes)?;
        if froze_home_state_in_txn(vault, txn)?
            && selected_in_txn(vault, txn)?
                .keys()
                .any(|id| !carried.contains_key(id))
        {
            return Ok(TableAdopt::Conflict);
        }
        for (id, scope) in carried {
            match SCOPE.get(&vault.store, txn, &id.0)? {
                Some(here) if here == scope => {}
                Some(here) if !follows(&here, &scope) => return Ok(TableAdopt::Conflict),
                _ => SCOPE.put(&vault.store, txn, &id.0, &scope)?,
            }
        }
        Ok(TableAdopt::Applied)
    }

    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        Ok(selected_in_txn(vault, txn)?
            .keys()
            .map(|id| SCOPE.key_bytes(&id.0))
            .collect())
    }
}

/// Every scope of every free-time tree here, by id: the roots this node's
/// cycles name, and each scope whose parents lead to one.
fn selected_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<BTreeMap<SpendScopeId, SpendScope>> {
    let roots = crate::dreamer_runner::free_time_root_scopes_in_txn(vault, txn)?;
    if roots.is_empty() {
        return Ok(BTreeMap::new());
    }
    let all = SCOPE
        .iter_from(&vault.store, txn, &[])?
        .map(|row| row.map(|(_, scope)| (scope.scope.clone(), scope)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut selected = BTreeMap::new();
    for (id, scope) in &all {
        if root_of(&all, scope)?.is_some_and(|root| roots.contains(root)) {
            selected.insert(id.clone(), scope.clone());
        }
    }
    Ok(selected)
}

/// The carried scopes by id, refused unless each is one of a whole carried
/// tree: one row per scope, and its parents all carried up to its root.
fn carried_trees(scopes: Vec<SpendScope>) -> Result<BTreeMap<SpendScopeId, SpendScope>> {
    let mut carried = BTreeMap::new();
    for scope in scopes {
        if carried.insert(scope.scope.clone(), scope).is_some() {
            return Err(invalid("a home move carries one spend scope twice"));
        }
    }
    for scope in carried.values() {
        if root_of(&carried, scope)?.is_none() {
            return Err(invalid("a carried spend scope's parent is not carried"));
        }
    }
    Ok(carried)
}

/// The root `scope` spends under, walking its parents within `scopes`;
/// `None` when a parent is not among them.
fn root_of<'a>(
    scopes: &'a BTreeMap<SpendScopeId, SpendScope>,
    scope: &'a SpendScope,
) -> Result<Option<&'a SpendScopeId>> {
    let mut current = scope;
    for _ in 0..MAX_SPEND_DEPTH {
        let Some(parent) = &current.parent else {
            return Ok(Some(&current.scope));
        };
        let Some(next) = scopes.get(parent) else {
            return Ok(None);
        };
        current = next;
    }
    Err(invalid("spend scope ancestor bound"))
}

/// Whether the carried `scope` follows `here`, the same scope further on:
/// the same place in the same tree, unit and payer, a cap and a spend that
/// only grow, closed once. What it holds for its children moves both ways.
fn follows(here: &SpendScope, carried: &SpendScope) -> bool {
    here.parent == carried.parent
        && here.unit == carried.unit
        && here.hard == carried.hard
        && here.opened_at == carried.opened_at
        && here.agent == carried.agent
        && here.payer == carried.payer
        && carried.cap_units >= here.cap_units
        && carried.spent_units >= here.spent_units
        && carried.shown_at_ms >= here.shown_at_ms
        && (here.state == SpendState::Open || carried.state == SpendState::Closed)
        && (here.closed_at.is_none() || here.closed_at == carried.closed_at)
}
