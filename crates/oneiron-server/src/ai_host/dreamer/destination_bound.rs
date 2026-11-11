//! Where a Dreamer pass's every leg sends what it reads (FIX 12735): the
//! bound the vending factory states for the executors it vends at that vend,
//! and the ladder each role's route sends on under it.
//!
//! A pass is bound to this device when every role's route has each of its
//! rungs on the device and the decision host lends no model rung that the
//! pass's typed questions, its write gate's auto check or its notes could
//! step up to. Each route is then held on the device for that pass
//! ([`OfferLadder::held_on_device`]): no owner's fallback past the device is
//! taken, and an on-device rung that fails fails its call closed. Every
//! other pass states a destination nobody proved and sends as it did before.
//! No mesh machine is named: a route off the device states that destination.
use std::sync::Arc;

use oneiron::authority::PeerMachine;
use oneiron::llm::manifest::ModelRole;
use oneiron::settings::ReadDestination;

use crate::decision_host::DecisionHost;
use crate::models::{OfferLadder, RoleRoute};

/// One pass's destination bound, and the ladder each role's route sends on
/// under it, in the order of the routes it was made from.
pub(super) struct PassBound {
    pub(super) destination: ReadDestination,
    pub(super) ladders: Vec<Arc<OfferLadder>>,
}

/// The bound of a pass that sends on `routes`, its typed questions on
/// `decisions`' ladder when the server staffed one: this device, each route
/// held there, when every route can be held there and no decision slot
/// lends a model; else a destination nobody proved, each route as it is.
pub(super) fn pass_bound(
    routes: &[(ModelRole, RoleRoute)],
    decisions: Option<&DecisionHost>,
) -> PassBound {
    let held = if routes.is_empty() || decisions.is_some_and(lends_model_rung) {
        None
    } else {
        routes
            .iter()
            .map(|(_, route)| route.ladder.held_on_device())
            .collect::<Option<Vec<_>>>()
    };
    match held {
        Some(ladders) => PassBound {
            destination: ReadDestination::on_device(),
            ladders,
        },
        None => PassBound {
            destination: ReadDestination::toward(PeerMachine::Unknown),
            ladders: routes
                .iter()
                .map(|(_, route)| Arc::clone(&route.ladder))
                .collect(),
        },
    }
}

/// Whether `host`'s ladder seats a model in any slot a consolidation's
/// question, its auto check or its notes can reach: only the rule table and
/// the owner's own ask queue answer without one.
fn lends_model_rung(host: &DecisionHost) -> bool {
    let ladder = host.ladder();
    ladder.local.is_some()
        || ladder.system_one.is_some()
        || ladder.escalation.is_some()
        || ladder.big.is_some()
}
