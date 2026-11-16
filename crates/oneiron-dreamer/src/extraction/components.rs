//! Builds ready components in route order without calls or operand rewriting.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::conflict_resolution::{self, Plan, SetPlan};
use crate::extraction_decisions::Outcome;
use crate::extraction_reply::BoundExtractionReply;
use crate::extraction_routing::Route;
use crate::extraction_selection::{CandidateGroup, CandidateGroups, union_operands};

use super::Error;

/// Holds one candidate or set item at its first ready route's place.
#[derive(Debug, Clone, PartialEq)]
pub struct Component {
    /// Names the representative's position in the decisions operand array.
    pub representative_index: usize,
    /// Names the set in route-plan order, absent for a plain candidate.
    pub set: Option<usize>,
    /// Preserves the set's exact plan, absent for a plain candidate.
    pub planned: Option<SetPlan>,
    /// Holds the complete derive item with no stripped operand fields.
    pub item: Value,
}

/// Holds the items to commit and the routes deliberately writing nothing.
#[derive(Debug, Clone, PartialEq)]
pub struct Components {
    /// Holds components in first-route order.
    pub items: Vec<Component>,
    /// Counts AlreadyRepresented routes omitted from the items.
    pub already_represented: usize,
}

/// Builds exact union operands through the same helper the decisions used.
///
/// New, Attach and ObservedBeside all become ordinary candidate items; the
/// engine may refuse them, including an attachment the item cannot express.
/// Each Judge set appears only at its first route. Unreferenced sets do not
/// appear; generated route plans always assign at least one member per set.
///
/// # Errors
///
/// Rejects a route missing its union or set plan, or invalid group member facts.
pub fn build(
    reply: &BoundExtractionReply,
    outcome: &Outcome,
    plan: &Plan,
) -> Result<Components, Error> {
    let groups = CandidateGroups {
        groups: outcome
            .selection
            .groups
            .iter()
            .map(|group| CandidateGroup {
                representative_index: group.representative_index,
                member_indexes: group.member_indexes.clone(),
                corrects: group.corrects.clone(),
            })
            .collect(),
        pending_bindings: outcome.selection.pending_bindings.clone(),
    };
    let unions = union_operands(&outcome.operands, &groups);
    let unions: BTreeMap<usize, Value> = groups
        .groups
        .iter()
        .map(|group| group.representative_index)
        .zip(unions)
        .collect();
    let mut components = Components {
        items: Vec::new(),
        already_represented: 0,
    };
    let mut seen_sets = BTreeSet::new();
    for route in &outcome.route.routes {
        let representative = route.representative_index;
        let component = match &route.choice {
            Route::AlreadyRepresented { .. } => {
                components.already_represented += 1;
                continue;
            }
            Route::Judge { set } => {
                if !seen_sets.insert(*set) {
                    continue;
                }
                let planned = plan
                    .sets
                    .get(*set)
                    .ok_or_else(|| component_error("a route names no set plan"))?;
                Component {
                    representative_index: representative,
                    set: Some(*set),
                    item: planned.item().clone(),
                    planned: Some(planned.clone()),
                }
            }
            Route::New | Route::Attach { .. } | Route::ObservedBeside { .. } => {
                let union = unions
                    .get(&representative)
                    .ok_or_else(|| component_error("a route names no group union"))?;
                let facts = conflict_resolution::group_facts(reply, outcome, representative)
                    .map_err(Error::Plan)?;
                Component {
                    representative_index: representative,
                    set: None,
                    planned: None,
                    item: json!({
                        "kind": "candidate",
                        "spec": {
                            "local": format!("candidate-{representative}"),
                            "member": {
                                "candidate": union,
                                "confidence": facts.confidence,
                                "prospective_queries": facts.prospective_queries,
                            },
                        },
                    }),
                }
            }
        };
        components.items.push(component);
    }
    Ok(components)
}

/// Names malformed component data without inventing a new engine error.
fn component_error(message: &str) -> Error {
    Error::Decode {
        verb: "vault.derive.commit",
        message: message.to_owned(),
    }
}
