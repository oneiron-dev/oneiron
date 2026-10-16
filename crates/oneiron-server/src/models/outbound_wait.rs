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

pub(crate) fn install(vault: &Vault) {
    vault.set_outbound_wait_host(Some(Arc::new(ServerOutboundWait)));
}
