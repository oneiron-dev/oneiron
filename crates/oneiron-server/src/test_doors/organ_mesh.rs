//! Doors for the two-server organ call test (OF-575; pass 33 row R0,
//! `tests/organ_mesh_two_server_e2e.rs`): the router a server's own organ
//! calls take, an organ on a server's one host, and that organ's status.

use std::sync::Arc;

use oneiron_organ_host::{OrganRouter, OrganSpec, OrganStatus};

use crate::server::SyncServer;

/// The router `server`'s own organ calls take, as the image edit doors take
/// it (`handler::mesh::organ_router`): this machine's host first, else one
/// of the owner's other nodes granted organ calls, over the endpoint the
/// server's mesh listener attached. Built inside a runtime; call it from a
/// blocking thread.
#[must_use]
pub fn organ_router(server: &Arc<SyncServer>) -> OrganRouter {
    crate::handler::mesh::organ_router(server)
}

/// Installs `spec` on `server`'s one organ host, the host its mesh listener
/// offers the owner's other nodes, as the server installs an organ it names
/// by its program (the image organ, L4-15): unpinned, so the listener's pack
/// organ pass leaves it installed.
pub fn install_organ(server: &SyncServer, spec: OrganSpec) {
    server.organs.install(spec);
}

/// What `server`'s host says about `organ`; `None` when it is not installed.
#[must_use]
pub fn organ_status(server: &SyncServer, organ: &str) -> Option<OrganStatus> {
    server.organs.status(organ)
}
