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
//!
//! FIX 8875 stage 2: a scope travels as its content-free skeleton (its id
//! and parent, unit, cap, spend, holds, state and times, and when a payer
//! accepted it), always carried and never scrubbed, with its agent in that
//! agent's compartment and its payer's party and grantor in the party's,
//! each sealed under that actor's erasable key. A compartment that does not
//! open here leaves the field as the scope here holds it, or empty where
//! none is here: an erased payer lands as no payer accepted. The tree and
//! its totals move whole; one actor's compartment never stops a scope or
//! the tree.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::AgentDispatcher;
use super::spend_lease::observe_spend_walk;
use super::spend_record::{SCOPE, SpendPayer, SpendScope, SpendScopeId, SpendState};
use super::widen_record::invalid;
use crate::attempt_queue::AttemptQueue;
use crate::entity_id::EntityId;
use crate::llm::run_admission::LeaseUnit;
use crate::scan_check::EngineScan;
use crate::side_table::{self, SideTableDecl};
use crate::sync::home_handoff::{
    ActorContent, HomeFence, HomeMove, HomeTable, Partitioned, TableAdopt, froze_home_state_in_txn,
};
use crate::{Result, Vault};

/// The free-time spend trees a home move carries: each scope's skeleton,
/// its actors apart.
#[derive(Serialize, Deserialize)]
pub(crate) struct FreeTimeSpendRows {
    scopes: Vec<ScopeSkeleton>,
}

/// One scope without its agent or its payer's actors.
#[derive(Serialize, Deserialize)]
struct ScopeSkeleton {
    scope: SpendScopeId,
    parent: Option<SpendScopeId>,
    unit: LeaseUnit,
    cap_units: u64,
    hard: bool,
    spent_units: u64,
    held_units: u64,
    state: SpendState,
    shown_at_ms: Option<u64>,
    opened_at: u64,
    closed_at: Option<u64>,
    /// Whether an agent's settlement calibrates it.
    calibrates: bool,
    /// When its payer accepted its cap, if one did.
    payer_at_ms: Option<u64>,
}

/// One actor's compartments of the carried scopes, by each scope's place
/// among the skeletons.
#[derive(Serialize, Deserialize)]
pub(crate) struct SpendCompartment {
    actor: EntityId,
    pieces: Vec<SpendPiece>,
}

#[derive(Serialize, Deserialize)]
enum SpendPiece {
    /// The actor is the scope's agent.
    Agent { scope: u32 },
    /// The actor is the scope's payer, its yes taken by `granted_by`.
    Payer { scope: u32, granted_by: EntityId },
}

impl ActorContent for SpendCompartment {
    fn actor(&self) -> EntityId {
        self.actor
    }
}

/// `scopes` split into skeletons and each actor's compartments.
fn partition(scopes: Vec<SpendScope>) -> Result<Partitioned<FreeTimeSpendRows, SpendCompartment>> {
    let mut compartments: BTreeMap<EntityId, Vec<SpendPiece>> = BTreeMap::new();
    let mut skeletons = Vec::with_capacity(scopes.len());
    for (index, scope) in scopes.into_iter().enumerate() {
        let place = u32::try_from(index)
            .map_err(|_| invalid("a home move carries more spend scopes than a place holds"))?;
        if let Some(agent) = scope.agent {
            compartments
                .entry(agent)
                .or_default()
                .push(SpendPiece::Agent { scope: place });
        }
        if let Some(payer) = &scope.payer {
            compartments
                .entry(payer.party)
                .or_default()
                .push(SpendPiece::Payer {
                    scope: place,
                    granted_by: payer.granted_by,
                });
        }
        skeletons.push(ScopeSkeleton {
            calibrates: scope.agent.is_some(),
            payer_at_ms: scope.payer.as_ref().map(|payer| payer.at_ms),
            scope: scope.scope,
            parent: scope.parent,
            unit: scope.unit,
            cap_units: scope.cap_units,
            hard: scope.hard,
            spent_units: scope.spent_units,
            held_units: scope.held_units,
            state: scope.state,
            shown_at_ms: scope.shown_at_ms,
            opened_at: scope.opened_at,
            closed_at: scope.closed_at,
        });
    }
    Ok(Partitioned {
        facts: FreeTimeSpendRows { scopes: skeletons },
        actors: compartments
            .into_iter()
            .map(|(actor, pieces)| SpendCompartment { actor, pieces })
            .collect(),
    })
}

/// Each carried scope rebuilt from its skeleton and the compartments that
/// opened here. An agent or a payer whose compartment did not open takes the
/// one the scope here holds, if any, else none: a scope or a tree never
/// stops for it.
fn rejoin_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    rows: Partitioned<FreeTimeSpendRows, SpendCompartment>,
) -> Result<Vec<SpendScope>> {
    let mut agents = BTreeMap::new();
    let mut payers = BTreeMap::new();
    for compartment in rows.actors {
        for piece in compartment.pieces {
            match piece {
                SpendPiece::Agent { scope } => {
                    agents.insert(scope, compartment.actor);
                }
                SpendPiece::Payer { scope, granted_by } => {
                    payers.insert(scope, (compartment.actor, granted_by));
                }
            }
        }
    }
    let mut scopes = Vec::with_capacity(rows.facts.scopes.len());
    for (place, skeleton) in (0u32..).zip(rows.facts.scopes) {
        let opened_agent = agents.get(&place).copied();
        let opened_payer = payers.get(&place).copied();
        let gone = (skeleton.calibrates && opened_agent.is_none())
            || (skeleton.payer_at_ms.is_some() && opened_payer.is_none());
        let here = if gone {
            SCOPE.get(&vault.store, txn, &skeleton.scope.0)?
        } else {
            None
        };
        let agent = match opened_agent {
            Some(agent) => Some(agent),
            None if skeleton.calibrates => here.as_ref().and_then(|here| here.agent),
            None => None,
        };
        let payer = match (skeleton.payer_at_ms, opened_payer) {
            (Some(at_ms), Some((party, granted_by))) => Some(SpendPayer {
                party,
                granted_by,
                at_ms,
            }),
            (Some(_), None) => here.and_then(|here| here.payer),
            (None, _) => None,
        };
        scopes.push(SpendScope {
            scope: skeleton.scope,
            parent: skeleton.parent,
            unit: skeleton.unit,
            cap_units: skeleton.cap_units,
            hard: skeleton.hard,
            spent_units: skeleton.spent_units,
            held_units: skeleton.held_units,
            state: skeleton.state,
            shown_at_ms: skeleton.shown_at_ms,
            opened_at: skeleton.opened_at,
            closed_at: skeleton.closed_at,
            agent,
            payer,
        });
    }
    Ok(scopes)
}

impl HomeTable for FreeTimeSpendRows {
    type Rows = Self;
    type Actor = SpendCompartment;
    const TABLE: &'static SideTableDecl = &side_table::AGENT_DISPATCH_SPEND_SCOPE;
    const SCHEMA_VERSION: u16 = 2;

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

    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        _fence: &HomeFence,
    ) -> Result<Partitioned<Self, SpendCompartment>> {
        partition(selected_in_txn(vault, txn)?.into_values().collect())
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
        rows: Partitioned<Self, SpendCompartment>,
    ) -> Result<TableAdopt> {
        let scopes = rejoin_in_txn(vault, txn, rows)?;
        let mut longest = 0;
        let carried = carried_trees(scopes, &mut longest);
        observe_spend_walk(
            &vault.store,
            txn,
            EngineScan::SpendAncestorScopes,
            &[],
            longest,
        );
        let carried = carried?;
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

    /// FIX 5661 C2b: a restore keeps live every scope of a free-time tree,
    /// in the image or here: each whose parents, walked through the image's
    /// scopes and this node's, lead to a root a free-time cycle names, in the
    /// image or here. Any other launch's scope stays content. An image row
    /// that does not decode, or a chain past the depth bound, is content.
    fn manages(
        vault: &Vault,
        txn: &RoTxn<'_>,
        image: &crate::sync::home_handoff::ImageRows,
    ) -> Result<Vec<Vec<u8>>> {
        let cycles = side_table::DREAMER_FREE_TIME_CYCLE.prefix;
        let mut roots = crate::dreamer_runner::free_time_root_scopes_in_txn(vault, txn)?;
        let mut all = SCOPE
            .iter_from(&vault.store, txn, &[])?
            .map(|row| row.map(|(_, scope)| (scope.scope.clone(), scope)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        for (key, value) in image {
            if key.starts_with(cycles) {
                let cycle = <side_table::Named as side_table::SideCodec<
                    crate::dreamer_runner::FreeTimeCycle,
                >>::decode(value);
                if let Ok(cycle) = cycle {
                    roots.insert(cycle.root_scope);
                }
            } else if key.starts_with(SCOPE.decl().prefix)
                && let Ok(scope) = SCOPE.decode_value(value)
            {
                all.entry(scope.scope.clone()).or_insert(scope);
            }
        }
        let mut longest = 0;
        let managed: Vec<Vec<u8>> = all
            .iter()
            .filter(|(_, scope)| {
                matches!(root_of(&all, scope, &mut longest), Ok(Some(root)) if roots.contains(root))
            })
            .map(|(id, _)| SCOPE.key_bytes(&id.0))
            .collect();
        observe_spend_walk(
            &vault.store,
            txn,
            EngineScan::SpendAncestorScopes,
            &[],
            longest,
        );
        Ok(managed)
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
    let mut longest = 0;
    let chosen = select_trees(&all, &roots, &mut selected, &mut longest);
    observe_spend_walk(
        &vault.store,
        txn,
        EngineScan::SpendAncestorScopes,
        &[],
        longest,
    );
    chosen?;
    Ok(selected)
}

/// Each scope of `all` whose parents lead to one of `roots`, into
/// `selected`; the longest walk in `longest`.
fn select_trees(
    all: &BTreeMap<SpendScopeId, SpendScope>,
    roots: &BTreeSet<SpendScopeId>,
    selected: &mut BTreeMap<SpendScopeId, SpendScope>,
    longest: &mut usize,
) -> Result<()> {
    for (id, scope) in all {
        if root_of(all, scope, longest)?.is_some_and(|root| roots.contains(root)) {
            selected.insert(id.clone(), scope.clone());
        }
    }
    Ok(())
}

/// The carried scopes by id, refused unless each is one of a whole carried
/// tree: one row per scope, and its parents all carried up to its root. The
/// longest parent walk lands in `longest`.
fn carried_trees(
    scopes: Vec<SpendScope>,
    longest: &mut usize,
) -> Result<BTreeMap<SpendScopeId, SpendScope>> {
    let mut carried = BTreeMap::new();
    for scope in scopes {
        if carried.insert(scope.scope.clone(), scope).is_some() {
            return Err(invalid("a home move carries one spend scope twice"));
        }
    }
    for scope in carried.values() {
        if root_of(&carried, scope, longest)?.is_none() {
            return Err(invalid("a carried spend scope's parent is not carried"));
        }
    }
    Ok(carried)
}

/// The root `scope` spends under, walking its parents within `scopes`,
/// however many (rule 5), each once: `None` when a parent is not among
/// them, an error when a parent comes back. The walk's length raises
/// `longest`.
fn root_of<'a>(
    scopes: &'a BTreeMap<SpendScopeId, SpendScope>,
    scope: &'a SpendScope,
    longest: &mut usize,
) -> Result<Option<&'a SpendScopeId>> {
    let mut seen = BTreeSet::from([&scope.scope]);
    let mut current = scope;
    let root = loop {
        let Some(parent) = &current.parent else {
            break Ok(Some(&current.scope));
        };
        if !seen.insert(parent) {
            break Err(invalid("spend scope ancestor cycle"));
        }
        let Some(next) = scopes.get(parent) else {
            break Ok(None);
        };
        current = next;
    };
    *longest = (*longest).max(seen.len());
    root
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
