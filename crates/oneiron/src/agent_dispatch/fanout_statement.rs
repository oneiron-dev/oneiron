//! The fan-out statement (OF-393, ARCH-0079 #width): before every fan-out,
//! the total count, the per-peer breakdown, the expected spend and the hard
//! spend cap the work runs under, or no cap.
//!
//! [`AgentDispatcher::plan_fanout`] states it without launching or minting
//! anything. Every fan-out door computes it once its work is resolved and
//! before any TASK exists, freezes it with the run, and returns the frozen
//! copy on every later read, so what the caller saw is what ran. Width is a
//! check, never a limit: a count above the exceptional-width threshold
//! carries an [`ExceptionalWidthCheck`] in every approval mode, and the check
//! itself never holds; the mode, not the width, decides whether a fan-out
//! pauses. The budget
//! is an input, never a refusal: an expected spend above what is available is
//! stated (`over_available`, `more_would_buy`), not refused.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::run_admission::LeaseUnit;

use super::launch::{LaunchRole, SpawnSpend, SpendCapView};
use super::spend_calibration::{DollarBasis, ExpectedSpend};
use super::{AgentDispatcher, DispatchAgent};

/// Whose cap a fan-out runs under. The host binds it from authenticated
/// context (the running agent's own attempt, or a root scope it opened);
/// never from a guest-supplied id. The default is a root without a scope:
/// no cap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FanoutCaller {
    /// The calling agent's attempt; its scope's hard cap binds the fan-out.
    pub parent_attempt: Option<AttemptId>,
    /// A root caller's open root scope. A caller with a parent names none.
    pub spend: Option<SpawnSpend>,
    /// A hard carve for the whole fan-out under the caller's cap (the canon
    /// spawn table's `budget`).
    pub budget: Option<u64>,
}

/// One item of fan-out work. Every item is one TASK the fan-out mints.
#[derive(Debug, Clone, PartialEq)]
pub enum FanoutWork {
    /// A TASK a local AGENT_DEF realizes (a saved workflow: one per leaf).
    Agent(DispatchAgent),
    /// A consult TASK delivered to a peer: a delivery, never a local agent.
    PeerConsult { peer: EntityId },
    /// Any other TASK: a person, a running child, or (`None`) the default
    /// realization.
    Task { assignee: Option<EntityId> },
}

/// TASK deliveries to one recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PeerCount {
    pub peer: EntityId,
    pub count: u64,
}

/// How the approval ladder classified an exceptional-width check. No arm
/// holds, refuses or narrows the work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WidthCheckClass {
    /// AUTO cleared it; `policy_ref` names the standing policy row that
    /// covered it, when one did.
    AutoClear { policy_ref: Option<String> },
    /// The next authorised role is asked: on a non-blocking question row when
    /// the work proceeds unclassified (full access), or on the run's own
    /// pause row when its approval mode or a pathology holds it.
    Asked { row_ref: String },
}

/// The typed "is everything okay" check a very large count raises. It is a
/// check, never a limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExceptionalWidthCheck {
    pub count: u64,
    pub threshold: u64,
    pub classification: WidthCheckClass,
}

/// What a fan-out will mint and spend, stated before any of it exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FanoutStatement {
    /// Local agent launches only (workflow leaves count, the wrapper does
    /// not). Consults are never agents.
    pub agent_count: u64,
    /// Consult TASKs delivered to peers, repeats included.
    pub consult_count: u64,
    /// Every TASK the fan-out mints, agent-realized and consult TASKs
    /// included: the width. Never added to the other two counts.
    pub task_count: u64,
    /// TASK deliveries per recipient actor, sorted by recipient. Agent
    /// launches are counted in `agent_count`, not here.
    pub per_peer: Vec<PeerCount>,
    /// The sum over every item; a prior if any item's is.
    pub expected: ExpectedSpend,
    /// The checked sum of the priced parts' dollar figures, in millionths of
    /// a US dollar: a known subtotal, never the expected total while any part
    /// is unpriced. `None` when no part is priced or the sum overflows.
    pub priced_subtotal_usd_micros: Option<u64>,
    /// Each part with no dollar figure, by its work index and what realizes
    /// it (an agent or a workflow leaf, a peer, a TASK's assignee), with why:
    /// an unknown price (in the unit, when it is not tokens) or an overflow.
    pub unpriced_parts: Vec<String>,
    pub unit: LeaseUnit,
    /// `None`: no cap. The caller is a root unmetered by any lease tree; the
    /// statement never invents a zero.
    pub cap: Option<SpendCapView>,
    /// The expected spend exceeds what the caller may spend now.
    pub over_available: bool,
    /// One line on what more budget would buy, when `over_available`.
    pub more_would_buy: Option<String>,
    pub width_check: Option<ExceptionalWidthCheck>,
    /// Unix seconds.
    pub stated_at: u64,
}

impl FanoutStatement {
    /// Whether the width crosses `threshold` and so raises the check.
    #[must_use]
    pub const fn crosses(&self, threshold: u64) -> bool {
        self.task_count > threshold
    }

    /// Attaches the exceptional-width check as the ladder classified it.
    pub fn raise_width_check(&mut self, threshold: u64, classification: WidthCheckClass) {
        self.width_check = Some(ExceptionalWidthCheck {
            count: self.task_count,
            threshold,
            classification,
        });
    }

    /// The expected spend as the statement states it, in dollars, never
    /// native units: the total's [`ExpectedSpend::dollar_line`] when the
    /// total is known, an empty fan-out's $0 included; else that unknown
    /// total, the labelled subtotal of the priced parts when there is one,
    /// and each unpriced part.
    #[must_use]
    pub fn dollar_line(&self) -> String {
        let total = self.expected.dollar_line();
        if self.expected.expected_usd_micros.is_some() {
            return total;
        }
        let subtotal = self
            .priced_subtotal_usd_micros
            .map(|micros| format!(" priced_subtotal={}", usd(micros)))
            .unwrap_or_default();
        let unpriced = if self.unpriced_parts.is_empty() {
            String::new()
        } else {
            format!(" unpriced=[{}]", self.unpriced_parts.join("; "))
        };
        format!("{total}{subtotal}{unpriced}")
    }
}

impl AgentDispatcher<'_> {
    /// States a fan-out before it happens: a pure read. Reads the caller's
    /// cap once for the whole fan-out, prices each agent item as its launch
    /// would (`expected_agent_spend`, workflow leaves expanded), each peer
    /// consult under its own consult key, and any other TASK at the labelled
    /// prior, and names each part with no dollar figure. Never refuses an
    /// expected spend above what is available: it says so. The width check
    /// is the caller's to classify.
    pub fn plan_fanout(
        &self,
        caller: &FanoutCaller,
        work: &[FanoutWork],
        now: u64,
    ) -> Result<FanoutStatement> {
        let txn = self.vault.store.env.read_txn()?;
        self.plan_fanout_in_txn(&txn, caller, work, now)
    }

    /// [`Self::plan_fanout`] inside the fan-out's own transaction.
    pub(crate) fn plan_fanout_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        caller: &FanoutCaller,
        work: &[FanoutWork],
        now: u64,
    ) -> Result<FanoutStatement> {
        let tree = self.caller_tree_in_txn(txn, caller.parent_attempt, caller.spend.as_ref())?;
        let unit = tree
            .as_ref()
            .map_or_else(LeaseUnit::tokens, |scope| scope.unit.clone());
        let mut agent_count: u64 = 0;
        let mut consult_count: u64 = 0;
        let mut per_peer: BTreeMap<EntityId, u64> = BTreeMap::new();
        let mut parts = Vec::with_capacity(work.len());
        for (index, item) in work.iter().enumerate() {
            match item {
                FanoutWork::Agent(agent) => {
                    let nodes = self.launch_nodes_in_txn(txn, &agent.target, &unit, None)?;
                    agent_count =
                        agent_count.saturating_add(u64::try_from(nodes.len()).unwrap_or(u64::MAX));
                    // Each node keeps its name past the collapse to its spend.
                    parts.extend(nodes.into_iter().map(|node| {
                        let of = PartOf::Agent {
                            definition_ref: node.definition_ref,
                            role: node.role,
                        };
                        (index, of, node.expected)
                    }));
                }
                FanoutWork::PeerConsult { peer } => {
                    consult_count = consult_count.saturating_add(1);
                    let count = per_peer.entry(*peer).or_default();
                    *count = count.saturating_add(1);
                    let expected = self.expected_consult_spend_in_txn(txn, *peer, &unit)?;
                    parts.push((index, PartOf::Consult { peer: *peer }, expected));
                }
                FanoutWork::Task { assignee } => {
                    if let Some(assignee) = assignee {
                        let count = per_peer.entry(*assignee).or_default();
                        *count = count.saturating_add(1);
                    }
                    let of = PartOf::Task {
                        assignee: *assignee,
                    };
                    parts.push((index, of, ExpectedSpend::prior()));
                }
            }
        }
        let task_count = u64::try_from(work.len()).unwrap_or(u64::MAX);
        let expected = ExpectedSpend::sum(parts.iter().map(|&(_, _, part)| part));
        let (priced_subtotal_usd_micros, unpriced_parts) = dollar_parts(&parts, &unit);
        let terms = self.spend_terms_in_txn(txn, tree, caller.budget, expected.units, &unit)?;
        let (over_available, more_would_buy) =
            terms.shortfall(expected, &unit, "fan-out", &format!("{task_count} task(s)"));
        Ok(FanoutStatement {
            agent_count,
            consult_count,
            task_count,
            per_peer: per_peer
                .into_iter()
                .map(|(peer, count)| PeerCount { peer, count })
                .collect(),
            expected,
            priced_subtotal_usd_micros,
            unpriced_parts,
            unit,
            cap: terms.cap,
            over_available,
            more_would_buy,
            width_check: None,
            stated_at: now,
        })
    }
}

/// What realizes one part of a fan-out, to name a part with no dollar
/// figure.
#[derive(Clone, Copy)]
enum PartOf {
    /// An agent launch, or one leaf of a saved workflow.
    Agent {
        definition_ref: EntityId,
        role: LaunchRole,
    },
    Consult {
        peer: EntityId,
    },
    /// `None`: the default realization.
    Task {
        assignee: Option<EntityId>,
    },
}

impl PartOf {
    /// This part of work item `index`, as an unpriced part names it.
    fn name(self, index: usize) -> String {
        match self {
            Self::Agent {
                definition_ref,
                role: LaunchRole::Agent,
            } => format!("work[{index}] agent={}", definition_ref.to_hex()),
            Self::Agent {
                definition_ref,
                role: LaunchRole::WorkflowLeaf { ordinal },
            } => format!(
                "work[{index}] agent={} leaf={ordinal}",
                definition_ref.to_hex()
            ),
            Self::Consult { peer } => format!("work[{index}] consult peer={}", peer.to_hex()),
            Self::Task {
                assignee: Some(assignee),
            } => format!("work[{index}] task assignee={}", assignee.to_hex()),
            Self::Task { assignee: None } => format!("work[{index}] task assignee=default"),
        }
    }
}

/// The checked subtotal of the priced parts' dollar figures, `None` when no
/// part is priced or once the sum overflows, and each part with no figure,
/// named with why: an unknown price (in `unit`, when it is not tokens) or an
/// overflow of its own figure. A zero figure is priced.
fn dollar_parts(
    parts: &[(usize, PartOf, ExpectedSpend)],
    unit: &LeaseUnit,
) -> (Option<u64>, Vec<String>) {
    let unknown = if *unit == LeaseUnit::tokens() {
        "unknown_price".to_owned()
    } else {
        format!("unknown_price unit={}", unit.as_str())
    };
    let mut sum: u64 = 0;
    let mut priced = false;
    let mut overflowed = false;
    let mut unpriced = Vec::new();
    for &(index, of, part) in parts {
        if let Some(micros) = part.expected_usd_micros {
            priced = true;
            match sum.checked_add(micros) {
                Some(next) => sum = next,
                None => overflowed = true,
            }
        } else {
            let reason = if part.dollar_basis == DollarBasis::IncompleteOrOverflow {
                "overflow"
            } else {
                unknown.as_str()
            };
            unpriced.push(format!("{} reason={reason}", of.name(index)));
        }
    }
    ((priced && !overflowed).then_some(sum), unpriced)
}

/// `micros` millionths of a dollar as [`ExpectedSpend::dollar_line`] states
/// them.
fn usd(micros: u64) -> String {
    format!("${}.{:06}", micros / 1_000_000, micros % 1_000_000)
}
