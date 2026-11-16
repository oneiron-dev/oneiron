//! Door for `tests/esign_signing_session.rs` (census L3-22; review round 1
//! of #7663): the public signing routes over a session registry the test
//! can read, so a case sees what an abandoned session leaves held.

use std::sync::Arc;

use crate::api::{SigningRegistry, public_routes_with_registry};
use crate::server::SyncServer;

/// What a signing router's registry holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Held {
    /// Links with a pending exchange or an open session.
    pub links: usize,
    /// Pending exchanges.
    pub exchanges: usize,
    /// Open sessions.
    pub sessions: usize,
}

/// A read of one signing router's registry.
pub struct SessionsRead(SigningRegistry);

impl SessionsRead {
    /// What the registry holds now.
    pub fn held(&self) -> Held {
        let (links, exchanges, sessions) = self.0.held();
        Held {
            links,
            exchanges,
            sessions,
        }
    }
}

/// The public signing routes on `server`, as `build_app` merges them, and
/// a read of what their sessions hold.
pub fn signing_routes(server: Arc<SyncServer>) -> (axum::Router, SessionsRead) {
    let (routes, registry) = public_routes_with_registry();
    (routes.with_state(server), SessionsRead(registry))
}
