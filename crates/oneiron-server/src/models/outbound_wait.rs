//! Server policy for shedding during a long journaled model wait.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron::slim::OutboundWaitHost;

/// A host policy value, not an engine or reap-predicate constant.
const LONG_OUTBOUND_WAIT: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct ServerOutboundWait;

impl OutboundWaitHost for ServerOutboundWait {
    fn long_wait(&self) -> Pin<Box<dyn Future<Output = u64> + Send + '_>> {
        Box::pin(async {
            let started = Instant::now();
            tokio::time::sleep(LONG_OUTBOUND_WAIT).await;
            started.elapsed().as_secs().max(1)
        })
    }
}

/// Readback of the policy installed on every served vault.
pub(crate) fn policy() -> oneiron::slim::public::SlimIdlePolicy {
    oneiron::slim::public::SlimIdlePolicy {
        long_outbound_wait_secs: LONG_OUTBOUND_WAIT.as_secs(),
        exits_on_idle: false,
        lazy_rebuild: true,
    }
}

pub(crate) fn install(vault: &Vault) {
    vault.set_outbound_wait_host(Some(Arc::new(ServerOutboundWait)));
}
