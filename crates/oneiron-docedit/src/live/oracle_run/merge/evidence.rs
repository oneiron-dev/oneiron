//! Both landing orders' evidence (FIX 8591): each order's merged head is
//! exported and kept, as a candidate under `<case>.a_then_b` and
//! `<case>.b_then_a` or as a note naming why it did not export, before any
//! check can return; and the two orders' heads are compared node by node,
//! every node's children as a complete ordered list. In the fork-replay
//! cases that comparison is landing-order evidence, never a convergence
//! verdict: a review lands its forks in landing order. Step 4's convergence
//! verdict is the two Loro peers' case ([`super::peers`]).

use super::super::checks::dangling;
use super::super::record::{Emit, Lane, ORACLE, OfficeCheck, Res, Run, text};
use super::{Merged, ORDERS};
use crate::deck::DeckView;
use crate::edit::NoAssets;
use crate::live::deck_export::{ExportOutcome, ExportProfile, project};
use crate::live::{Conflict, LiveDeck};
use crate::retained_opc::{Limits, Package};
use std::collections::BTreeSet;

/// One case's captured evidence: each order's export or its reason, and
/// what comparing the orders found.
#[derive(Default)]
pub(super) struct Evidence {
    exports: Vec<(&'static str, Result<Vec<u8>, String>)>,
    notes: Vec<String>,
}

impl Evidence {
    /// Keep one order's export bytes, or why it has none.
    pub(super) fn keep(&mut self, order: &'static str, export: Result<Vec<u8>, String>) {
        self.exports.push((order, export));
    }

    /// Export both orders' merged heads over `package`, keeping each, then
    /// hand them back, or the first order's reason.
    pub(super) fn export_both(
        &mut self,
        orders: &[Merged; 2],
        package: &Package,
    ) -> Res<[ExportOutcome; 2]> {
        let [a, b] = [0, 1].map(|at| export_over(&orders[at].deck, package, ORDERS[at]));
        for (order, outcome) in ORDERS.into_iter().zip([&a, &b]) {
            self.keep(
                order,
                outcome
                    .as_ref()
                    .map(|out| out.bytes.clone())
                    .map_err(Clone::clone),
            );
        }
        Ok([a?, b?])
    }

    /// Whether the two kept exports are the same bytes; `None` until both
    /// orders exported.
    pub(super) fn same_exports(&self) -> Option<bool> {
        match self.exports.as_slice() {
            [(_, Ok(a)), (_, Ok(b))] => Some(a == b),
            _ => None,
        }
    }

    /// The two fork-replay orders compared, as landing-order evidence.
    pub(super) fn compare(&mut self, orders: &[Merged; 2]) {
        let found = differences(&orders[0].deck, &orders[1].deck);
        self.notes.push(if found.is_empty() {
            "landing-order evidence (fork replay): both orders hold the same deck, every node's children in the same order".to_owned()
        } else {
            format!(
                "landing-order evidence (fork replay, not CRDT convergence): {}",
                found.join("; ")
            )
        });
    }

    /// The two kept exports compared, as landing-order evidence.
    pub(super) fn compare_exports(&mut self) {
        if self.same_exports() == Some(false) {
            self.notes.push(
                "landing-order evidence (fork replay): the two orders export different bytes"
                    .to_owned(),
            );
        }
    }

    /// Journal the evidence in `run` under case `id`: each kept export a
    /// candidate the Office half opens, each missing one and each comparison
    /// a note. `baseline` and `origin` are the deck it came from.
    pub(super) fn flush(
        self,
        run: &mut Run,
        id: &str,
        baseline: &[String],
        origin: &[u8],
    ) -> Res<()> {
        for (order, export) in self.exports {
            let at = format!("{id}.{}", order.replace(' ', "_"));
            match export {
                Ok(bytes) => {
                    let count = slides(&bytes, run.limits)?;
                    run.candidate(Emit {
                        id: &at,
                        bytes: &bytes,
                        steps: &[ORACLE],
                        lane: Lane::Core,
                        checks: vec![OfficeCheck::Slides { count }, OfficeCheck::Pages { count }],
                        baseline,
                        origin,
                    })?;
                }
                Err(why) => run.note(&at, format!("{order}: no export: {why}")),
            }
        }
        for note in self.notes {
            run.note(id, note);
        }
        Ok(())
    }
}

/// Where two merged decks differ: a node one holds and the other does not,
/// a node's own fields, its children as a complete ordered list, text and
/// opaque parts. Empty when they are one deck.
pub(super) fn differences(a: &LiveDeck, b: &LiveDeck) -> Vec<String> {
    let mut out = Vec::new();
    if a.texts != b.texts {
        out.push("the two hold different text".to_owned());
    }
    if a.opaque_parts != b.opaque_parts {
        out.push("the two hold different opaque parts".to_owned());
    }
    let ids: BTreeSet<_> = a.nodes.keys().chain(b.nodes.keys()).copied().collect();
    for id in ids {
        let (Some(x), Some(y)) = (a.nodes.get(&id), b.nodes.get(&id)) else {
            out.push(format!("node {} exists in one only", id.0));
            continue;
        };
        if x.children != y.children {
            let order = |children: &[crate::live::NodeId]| -> Vec<u64> {
                children.iter().map(|child| child.0).collect()
            };
            out.push(format!(
                "node {}'s children are {:?} {} and {:?} {}",
                id.0,
                order(&x.children),
                ORDERS[0],
                order(&y.children),
                ORDERS[1]
            ));
        }
        let own = |node: &crate::live::DeckNode| crate::live::DeckNode {
            children: Vec::new(),
            ..node.clone()
        };
        if own(x) != own(y) {
            out.push(format!("node {} differs", id.0));
        }
    }
    out
}

/// Both forks landed in both orders and left whole trees.
pub(super) fn landed(orders: &[Merged; 2]) -> Res<()> {
    for (order, merged) in ORDERS.iter().zip(orders) {
        if !merged.landed {
            return Err(format!(
                "{order}: the second fork was held: conflicts {:?}, refusals {:?}",
                merged.second.diff.conflicts, merged.second.replay_refusals
            ));
        }
        dangling(&merged.deck).map_err(|why| format!("{order}: {why}"))?;
    }
    Ok(())
}

/// The second fork is held in both orders on the expected conflict, and the
/// held head is whole.
pub(super) fn surfaced(
    orders: &[Merged; 2],
    what: &str,
    wanted: impl Fn(&Conflict) -> bool,
) -> Res<()> {
    for (order, merged) in ORDERS.iter().zip(orders) {
        if merged.landed {
            return Err(format!(
                "{order}: the second fork landed; no {what} conflict was surfaced"
            ));
        }
        if !merged.second.diff.conflicts.iter().any(&wanted) {
            return Err(format!(
                "{order}: expected a {what} conflict, the preflight reports {:?}",
                merged.second.diff.conflicts
            ));
        }
        dangling(&merged.deck).map_err(|why| format!("{order}: {why}"))?;
    }
    Ok(())
}

pub(super) fn export_over(deck: &LiveDeck, package: &Package, order: &str) -> Res<ExportOutcome> {
    project(
        deck,
        package,
        super::super::record::DOCUMENT,
        &ExportProfile::default(),
        &NoAssets,
    )
    .map_err(|error| format!("{order}: the merged head does not export: {error}"))
}

/// How many slides an export holds.
fn slides(bytes: &[u8], limits: Limits) -> Res<usize> {
    Ok(DeckView::read(
        &Package::open(bytes, limits, &crate::resource::Resources::measuring()).map_err(text)?,
    )
    .map_err(text)?
    .slides
    .len())
}
