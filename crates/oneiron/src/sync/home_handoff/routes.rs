//! FIX 6459: the routes a home move's target is captured at. The host feeds
//! this node's catalog of them: each home candidate's sync endpoint when its
//! topology names them, and the route residence reads take when it names
//! none (the host's residence route, else the configured server). The
//! catalog rides the carrier's head row, fed before each topology election
//! and on each delivery round, so the election's own writer captures every
//! move's route as it commits it ([`super::request_move_in_txn`]); a move
//! committed before any feed is captured at the next one. A node the
//! catalog names no endpoint for keeps that as its route, never one
//! invented. Nothing here elects, dials or waits.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::store::{self, HandoffHead, HandoffRoute};
use crate::Vault;
use crate::error::Result;

/// CALLS route catalog: what the host last fed this node, kept on the head.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct RouteCatalog {
    /// Each candidate's WebSocket endpoint by sync node id, when the host's
    /// topology names them; `None` when it names none.
    endpoints: Option<BTreeMap<u64, String>>,
    /// The route residence reads take where the topology names no
    /// endpoints: the host's residence route, else the configured server.
    fallback: Option<String>,
}

impl RouteCatalog {
    /// Node `to`'s endpoint: the one the topology names for it, or none when
    /// it names others only; the fallback where it names none.
    fn endpoint(&self, to: u64) -> Option<String> {
        match &self.endpoints {
            Some(endpoints) => endpoints.get(&to).cloned(),
            None => self.fallback.clone(),
        }
    }
}

/// The route of a move to node `to`, from the catalog `head` keeps; `None`
/// while no catalog was fed.
pub(super) fn route_for(head: &HandoffHead, to: u64) -> Option<HandoffRoute> {
    head.routes.as_ref().map(|catalog| HandoffRoute {
        to,
        endpoint: catalog.endpoint(to),
    })
}

/// Feeds a topology snapshot's endpoints, and the route residence reads take,
/// before the election they inform.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn feed_routes(
    vault: &Vault,
    endpoints: Option<BTreeMap<u64, String>>,
    fallback: String,
) -> Result<()> {
    feed(vault, |catalog| {
        catalog.endpoints.clone_from(&endpoints);
        catalog.fallback = Some(fallback.clone());
    })
}

/// Feeds the route residence reads take now, keeping the endpoints the
/// host's topology last named.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn feed_fallback_route(vault: &Vault, fallback: String) -> Result<()> {
    feed(vault, |catalog| catalog.fallback = Some(fallback.clone()))
}

/// Writes the catalog `update` makes, and captures the route of the move
/// this node's election recorded when none is captured yet. Writes nothing
/// when neither changes.
fn feed(vault: &Vault, update: impl Fn(&mut RouteCatalog)) -> Result<()> {
    let changed = {
        let txn = vault.store.env.read_txn()?;
        let head = store::head_in_txn(vault, &txn)?;
        let node = crate::identity::read_client_id_in_txn(vault, &txn)?;
        let mut fed = head.clone();
        apply(&mut fed, node, &update);
        fed != head
    };
    if !changed {
        return Ok(());
    }
    vault.with_write_txn(|txn| {
        let mut head = store::head_in_txn(vault, txn)?;
        let node = crate::identity::read_client_id_in_txn(vault, txn)?;
        apply(&mut head, node, &update);
        store::put_head_in_txn(vault, txn, &head)
    })
}

/// `head` with its catalog updated and, where its election recorded a move
/// to another node with no route captured, that move's route.
fn apply(head: &mut HandoffHead, node: Option<u64>, update: &impl Fn(&mut RouteCatalog)) {
    let mut catalog = head.routes.take().unwrap_or_default();
    update(&mut catalog);
    head.routes = Some(catalog);
    if head.route.is_none()
        && let Some(to) = head.request.and_then(|request| request.to)
        && Some(to) != node
    {
        head.route = route_for(head, to);
    }
}
