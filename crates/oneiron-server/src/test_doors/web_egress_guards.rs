//! Door to a server's two egress guards (HOSTED-EGRESS-OPERATOR-SETTING): the
//! hosted guard a managed node checks its owner's fetches with, over a config
//! that carries the managed args' egress exceptions as managed boot carries
//! them, and the guard for a URL an outside party names.

use std::sync::Arc;

use oneiron::web_fetch::HostedEgressGuard;

use crate::config::SyncServerConfig;
use crate::managed::ManagedArgs;
use crate::server::{ManagedIssuer, SyncServer};

/// The guards of a server over `vault` whose config carries `managed`'s
/// hosted egress exceptions (`ManagedArgs::carry_hosted_egress`, as managed
/// boot does): the hosted guard, `None` unless `managed_node`, and the
/// outside party's guard. A managed node here has no host root issuer.
///
/// # Errors
///
/// What `SyncServer::new` returns.
pub fn egress_guards(
    vault: Arc<oneiron::Vault>,
    managed: &ManagedArgs,
    managed_node: bool,
) -> Result<(Option<Arc<HostedEgressGuard>>, Arc<HostedEgressGuard>), oneiron::Error> {
    let mut config = SyncServerConfig::default();
    managed.carry_hosted_egress(&mut config);
    let mut server = SyncServer::new(vault, config)?;
    if managed_node {
        server.managed_issuer = Some(ManagedIssuer::new(None));
    }
    Ok((
        server.hosted_egress_guard(),
        server.untrusted_url_egress_guard(),
    ))
}
