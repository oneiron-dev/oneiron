//! The launch statement (OF-532, ARCH-0079 #budget): before every agent
//! launch, the whole tree's agent count, its calibrated expected spend and
//! the hard spend cap it runs under.
//!
//! [`AgentDispatcher::plan_launch`] states it without launching anything.
//! Every launch arm computes the same plan in its own transaction, reserves
//! the launch's scope, and freezes the statement into the dispatch input (a
//! workflow freezes it into its record), so what the caller saw is what the
//! launch ran under. The budget is an input to the plan, never a refusal: an
//! expected spend above what is available is stated (`over_available`,
//! `more_would_buy`), not refused. The runtime refuses only spend beyond the
//! cap.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::run_admission::LeaseUnit;

use super::spend_calibration::ExpectedSpend;
use super::spend_record::{ChildSpend, SCOPE, SpendScope, SpendScopeId, SpendState};
use super::widen_record::invalid;
use super::{AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent};

/// A root launch's spend: the root scope the host opened with
/// [`AgentDispatcher::open_root_spend_scope`]. A child launch never names one;
/// it spends under its parent's scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnSpend {
    pub scope: SpendScopeId,
}

/// One agent the launch starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LaunchRole {
    Agent,
    /// A saved workflow's leaf. The inert workflow wrapper is not an agent.
    WorkflowLeaf {
        ordinal: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchNode {
    /// The AGENT_DEF the launch requests, before attenuation (the
    /// calibration key).
    pub definition_ref: EntityId,
    pub role: LaunchRole,
    pub expected: ExpectedSpend,
}

/// The hard cap a launch runs under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendCapView {
    /// The nearest hard scope above the launch; `None` for a `budget` pinned
    /// outside any tree.
    pub scope: Option<SpendScopeId>,
    pub unit: LeaseUnit,
    /// The binding hard cap: the spawn's own `budget` when set (a carve), else
    /// the nearest hard ancestor's cap.
    pub cap_units: u64,
    /// What the launch's parent chain can still give, now.
    pub available_units: u64,
    /// The launch carves its own hard cap (`budget`), rather than holding its
    /// expected spend under the ancestor's.
    pub hard: bool,
}

/// What a launch will start and spend, stated before it starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchPlan {
    /// Actual agents: workflow leaves count, the inert wrapper does not.
    pub agent_count: u64,
    /// The sum over `nodes`; a prior if any node's is.
    pub expected: ExpectedSpend,
    /// `None`: the launch spends unmetered by any lease tree (a root launched
    /// without a scope), exactly as before OF-532. No cap is invented.
    pub cap: Option<SpendCapView>,
    pub nodes: Vec<LaunchNode>,
    /// The expected spend exceeds what the launch may spend now.
    pub over_available: bool,
    /// One line on what more budget would buy, when `over_available`.
    pub more_would_buy: Option<String>,
}

/// The cost part of a launch's spawn receipt, frozen into its dispatch input
/// at launch. The launch's own scope is its attempt's
/// ([`SpendScopeId::for_attempt`]); a workflow's is its wrapper attempt's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchStatement {
    pub agent_count: u64,
    pub expected: ExpectedSpend,
    pub unit: LeaseUnit,
    /// `None`: cap none, the launch is unmetered.
    pub cap_units: Option<u64>,
    pub available_units: Option<u64>,
    /// A `budget` carve, rather than a hold under the ancestor's cap.
    pub hard: bool,
    /// What the launch reserved from its parent at launch.
    pub reserved_units: u64,
    /// The nearest hard scope above the launch.
    pub scope: Option<SpendScopeId>,
    /// The scope the launch reserved under.
    pub parent_scope: Option<SpendScopeId>,
    /// Unix seconds.
    pub stated_at: u64,
}

/// A planned launch: its plan, its statement, and the reservation still to
/// make once the launch's attempt id exists.
pub(super) struct LaunchAdmission {
    pub plan: LaunchPlan,
    pub statement: LaunchStatement,
    reserve: LaunchReserve,
}

enum LaunchReserve {
    Unmetered,
    Pinned {
        unit: LeaseUnit,
        cap_units: u64,
    },
    Child {
        parent: SpendScopeId,
        ask: ChildSpend,
    },
}

impl LaunchAdmission {
    /// Reserves the launch's own scope, keyed by `attempt`, in the launch's
    /// transaction. A carve the cap cannot cover refuses, and the caller's
    /// transaction (with its enqueue) aborts. Returns the scope, if metered.
    pub(super) fn reserve_in_txn(
        &self,
        dispatcher: &AgentDispatcher<'_>,
        txn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        agent: Option<EntityId>,
        now: u64,
    ) -> Result<Option<SpendScope>> {
        Ok(match &self.reserve {
            LaunchReserve::Unmetered => None,
            LaunchReserve::Pinned { unit, cap_units } => {
                Some(dispatcher.open_pinned_scope_in_txn(
                    txn,
                    &attempt,
                    agent,
                    unit.clone(),
                    *cap_units,
                    now,
                )?)
            }
            LaunchReserve::Child { parent, ask } => {
                Some(dispatcher.reserve_agent_in_txn(txn, parent, &attempt, agent, *ask, now)?)
            }
        })
    }
}

impl AgentDispatcher<'_> {
    /// States a launch before it happens: a pure read. Resolves the target as
    /// dispatch does (an AGENT_DEF is one agent; a saved workflow is one agent
    /// per leaf), reads the parent attempt's scope or the root scope the
    /// caller names, and never refuses an expected spend above what is
    /// available: it says so.
    pub fn plan_launch(
        &self,
        input: &DispatchAgent,
        spawn: &AgentSpawnContext,
    ) -> Result<LaunchPlan> {
        let txn = self.vault.store.env.read_txn()?;
        Ok(self
            .admit_launch_in_txn(
                &txn,
                input.parent_attempt,
                spawn.spend.as_ref(),
                spawn.budget,
                &input.target,
                spawn.plan.as_ref().map(|plan| &plan.plan.model),
                input.now,
            )?
            .plan)
    }

    /// The plan [`Self::plan_launch`] states, computed inside a launch's
    /// transaction. `model` is the plan's resolved model, which prices the
    /// dollar figure when given (FIX 3043).
    #[expect(
        clippy::too_many_arguments,
        reason = "a launch states its parent, spend, budget, target, model and time"
    )]
    pub(super) fn admit_launch_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        parent: Option<AttemptId>,
        spend: Option<&SpawnSpend>,
        budget: Option<u64>,
        target: &AgentDispatchTarget,
        model: Option<&crate::llm::ModelId>,
        now: u64,
    ) -> Result<LaunchAdmission> {
        let tree = self.caller_tree_in_txn(txn, parent, spend)?;
        let unit = tree
            .as_ref()
            .map_or_else(LeaseUnit::tokens, |scope| scope.unit.clone());
        let nodes = self.launch_nodes_in_txn(txn, target, &unit, model)?;
        self.admit_nodes_in_txn(txn, tree, budget, nodes, unit, now)
    }

    /// The effective scope a caller spends under: its parent attempt's, or
    /// the open root scope a root names. `None`: unmetered by any lease tree.
    /// Shared by every launch and fan-out statement, so each reads the
    /// caller's cap once, the same way.
    pub(super) fn caller_tree_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        parent: Option<AttemptId>,
        spend: Option<&SpawnSpend>,
    ) -> Result<Option<SpendScope>> {
        Ok(match (parent, spend) {
            (Some(_), Some(_)) => {
                return Err(invalid(
                    "a child spends under its parent's scope; only a root names one",
                ));
            }
            (Some(parent), None) => {
                if let Some(row) = AttemptQueue::new(self.vault).get_in_txn(txn, parent)? {
                    super::workflow_record::reject_wrapper_parent(&row)?;
                }
                match self.scope_for_attempt_in_txn(txn, parent)? {
                    Some(scope) => Some(self.effective_scope_in_txn(txn, &scope)?),
                    None => None,
                }
            }
            (None, Some(spend)) => {
                // Only a root the host opened under a shown cap; never a
                // child's or a pinned scope.
                let root = SCOPE
                    .get(&self.vault.store, txn, &spend.scope.0)?
                    .filter(|root| {
                        root.parent.is_none()
                            && root.shown_at_ms.is_some()
                            && root.state == SpendState::Open
                    })
                    .ok_or_else(|| invalid("a root launch names an open root spend scope"))?;
                Some(root)
            }
            (None, None) => None,
        })
    }

    /// One workflow leaf's launch under its wrapper's scope, at its release,
    /// priced at the frozen plan's `model` when it has one.
    pub(super) fn admit_leaf_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        wrapper: AttemptId,
        definition_ref: EntityId,
        ordinal: usize,
        model: Option<&crate::llm::ModelId>,
        now: u64,
    ) -> Result<LaunchAdmission> {
        // An unmetered workflow has no wrapper scope; its leaves are unmetered.
        let scope = SpendScopeId::for_attempt(&wrapper);
        let tree = if SCOPE.contains(&self.vault.store, txn, &scope.0)? {
            Some(self.effective_scope_in_txn(txn, &scope)?)
        } else {
            None
        };
        let unit = tree
            .as_ref()
            .map_or_else(LeaseUnit::tokens, |scope| scope.unit.clone());
        let node = LaunchNode {
            definition_ref,
            role: LaunchRole::WorkflowLeaf { ordinal },
            expected: self.expected_agent_spend_for_model_in_txn(
                txn,
                definition_ref,
                &unit,
                model,
            )?,
        };
        self.admit_nodes_in_txn(txn, tree, None, vec![node], unit, now)
    }

    pub(super) fn launch_nodes_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        target: &AgentDispatchTarget,
        unit: &LeaseUnit,
        model: Option<&crate::llm::ModelId>,
    ) -> Result<Vec<LaunchNode>> {
        match target {
            AgentDispatchTarget::Custom(id) => {
                self.dispatchable_definition_in_txn(txn, target)?;
                Ok(vec![LaunchNode {
                    definition_ref: *id,
                    role: LaunchRole::Agent,
                    expected: self.expected_agent_spend_for_model_in_txn(txn, *id, unit, model)?,
                }])
            }
            AgentDispatchTarget::Workflow(id) => {
                let definition = self.workflow_definition_in_txn(txn, *id)?;
                let mut nodes = Vec::with_capacity(definition.steps.len());
                for (ordinal, step) in definition.steps.iter().enumerate() {
                    self.dispatchable_definition_in_txn(txn, &AgentDispatchTarget::Custom(*step))?;
                    nodes.push(LaunchNode {
                        definition_ref: *step,
                        role: LaunchRole::WorkflowLeaf { ordinal },
                        expected: self
                            .expected_agent_spend_for_model_in_txn(txn, *step, unit, model)?,
                    });
                }
                Ok(nodes)
            }
        }
    }

    fn admit_nodes_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        tree: Option<SpendScope>,
        budget: Option<u64>,
        nodes: Vec<LaunchNode>,
        unit: LeaseUnit,
        now: u64,
    ) -> Result<LaunchAdmission> {
        let expected = ExpectedSpend::sum(nodes.iter().map(|node| node.expected));
        let agent_count = u64::try_from(nodes.len()).unwrap_or(u64::MAX);
        let terms = self.spend_terms_in_txn(txn, tree, budget, expected.units, &unit)?;
        let (over_available, more_would_buy) = terms.shortfall(
            expected.units,
            &unit,
            "launch",
            &format!("{agent_count} agent(s)"),
        );
        let SpendTerms {
            cap,
            reserve,
            reserved_units,
            parent_scope,
            ..
        } = terms;
        let statement = LaunchStatement {
            agent_count,
            expected,
            unit,
            cap_units: cap.as_ref().map(|view| view.cap_units),
            available_units: cap.as_ref().map(|view| view.available_units),
            hard: cap.as_ref().is_some_and(|view| view.hard),
            reserved_units,
            scope: cap.as_ref().and_then(|view| view.scope.clone()),
            parent_scope,
            stated_at: now,
        };
        Ok(LaunchAdmission {
            plan: LaunchPlan {
                agent_count,
                expected,
                cap,
                nodes,
                over_available,
                more_would_buy,
            },
            statement,
            reserve,
        })
    }

    /// The cap a caller's work runs under and what it would reserve, for an
    /// expected spend of `expected_units`, read once from the caller's tree.
    pub(super) fn spend_terms_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        tree: Option<SpendScope>,
        budget: Option<u64>,
        expected_units: u64,
        unit: &LeaseUnit,
    ) -> Result<SpendTerms> {
        if budget == Some(0) {
            return Err(invalid("a spawn budget is more than zero units"));
        }
        Ok(match (tree, budget) {
            (None, None) => SpendTerms {
                cap: None,
                reserve: LaunchReserve::Unmetered,
                reserved_units: 0,
                parent_scope: None,
                spendable: None,
            },
            (None, Some(cap_units)) => SpendTerms {
                cap: Some(SpendCapView {
                    scope: None,
                    unit: unit.clone(),
                    cap_units,
                    available_units: cap_units,
                    hard: true,
                }),
                reserve: LaunchReserve::Pinned {
                    unit: unit.clone(),
                    cap_units,
                },
                reserved_units: cap_units,
                parent_scope: None,
                spendable: Some(cap_units),
            },
            (Some(host), budget) => {
                let available = self.available_from_in_txn(txn, &host)?;
                let binding = self.binding_cap_in_txn(txn, &host)?;
                let parent = host.scope.clone();
                match budget {
                    Some(cap_units) => SpendTerms {
                        cap: Some(SpendCapView {
                            scope: Some(binding.scope),
                            unit: unit.clone(),
                            cap_units,
                            available_units: available,
                            hard: true,
                        }),
                        reserve: LaunchReserve::Child {
                            parent: parent.clone(),
                            ask: ChildSpend::Carve { cap_units },
                        },
                        reserved_units: cap_units,
                        parent_scope: Some(parent),
                        spendable: Some(cap_units.min(available)),
                    },
                    None => SpendTerms {
                        cap: Some(SpendCapView {
                            scope: Some(binding.scope),
                            unit: unit.clone(),
                            cap_units: binding.cap_units,
                            available_units: available,
                            hard: false,
                        }),
                        reserve: LaunchReserve::Child {
                            parent: parent.clone(),
                            ask: ChildSpend::Hold { expected_units },
                        },
                        reserved_units: expected_units.min(available),
                        parent_scope: Some(parent),
                        spendable: Some(available),
                    },
                }
            }
        })
    }
}

/// A caller's cap view and the reservation a launch would make under it.
pub(super) struct SpendTerms {
    pub(super) cap: Option<SpendCapView>,
    reserve: LaunchReserve,
    reserved_units: u64,
    parent_scope: Option<SpendScopeId>,
    /// The most the work may spend now; `None` when unmetered.
    spendable: Option<u64>,
}

impl SpendTerms {
    /// Whether `expected_units` exceeds what may be spent now, and one line
    /// on what more budget would buy. Stated, never refused.
    pub(super) fn shortfall(
        &self,
        expected_units: u64,
        unit: &LeaseUnit,
        what: &str,
        items: &str,
    ) -> (bool, Option<String>) {
        let carve_short = self.cap.as_ref().filter(|view| {
            view.hard && view.scope.is_some() && view.cap_units > view.available_units
        });
        let over_available = self.spendable.is_some_and(|most| expected_units > most);
        let more_would_buy = match (carve_short, self.spendable) {
            (Some(view), _) => Some(format!(
                "the {} {} budget exceeds the {} available under the cap, so this {what} would be refused; {} more would let it start",
                view.cap_units,
                unit.as_str(),
                view.available_units,
                view.cap_units - view.available_units,
            )),
            (None, Some(most)) if over_available => Some(format!(
                "{} more {} would cover the expected {} for {items}; {} can be spent now",
                expected_units - most,
                unit.as_str(),
                expected_units,
                most,
            )),
            _ => None,
        };
        (over_available, more_would_buy)
    }
}
