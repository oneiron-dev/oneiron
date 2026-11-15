//! Door for `tests/found_key_member_verb.rs`: a server with the managed
//! issuer managed boot installs (`managed::state_serve`), so the managed
//! ingress in front of it (`managed::build_managed_app`) verifies a
//! supervisor-signed person action as a managed vault's does.

use oneiron::authority::HostSlipIssuer;

use crate::server::{ManagedIssuer, SyncServer};

/// `server` as managed boot leaves it once it has provisioned the vault's
/// root: its managed issuer signs with `issuer`.
#[must_use]
pub fn with_managed_issuer(mut server: SyncServer, issuer: HostSlipIssuer) -> SyncServer {
    server.managed_issuer = Some(ManagedIssuer::new(Some(issuer)));
    server
}
