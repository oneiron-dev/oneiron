//! The served sinks' connector calls (FIX 1168): a served send that rides an
//! installed connector's tools (LinkedIn's) makes each tool call here, as an
//! admitted installed-tool call for its sender on this server's connector
//! call host, the path every connector tool call takes.

use std::sync::{Arc, Weak};

use oneiron::outbound::ServedConnectorCalls;
use oneiron::outbound_consent::{
    ConnectorCallInvocation, ConnectorCallOutcome, ConnectorCallRequest,
};
use oneiron::outbound_intent_ledger::IntentLedgerError;
use oneiron::{EdgeActorClass, EntityId};

use super::ServedConnectorCallHost;
use crate::server::SyncServer;

/// This server's connector calls, installed on its vault's served
/// transports. It holds the server weakly: the vault it is installed on is
/// the server's own.
pub(crate) struct ServerConnectorCalls {
    server: Weak<SyncServer>,
}

impl ServerConnectorCalls {
    pub(crate) fn new(server: &Arc<SyncServer>) -> Self {
        Self {
            server: Arc::downgrade(server),
        }
    }
}

impl std::fmt::Debug for ServerConnectorCalls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConnectorCalls")
            .finish_non_exhaustive()
    }
}

impl ServedConnectorCalls for ServerConnectorCalls {
    fn call(
        &self,
        caller: EntityId,
        caller_class: EdgeActorClass,
        request: ConnectorCallRequest,
        invocation: Option<ConnectorCallInvocation>,
    ) -> Result<ConnectorCallOutcome, IntentLedgerError> {
        let server = self.server.upgrade().ok_or_else(|| {
            oneiron::Error::InvalidConfig("the server is stopping; no connector call runs".into())
        })?;
        // A blocking client: the served sink calls from a blocking thread.
        let mut host = ServedConnectorCallHost::new(&server)?;
        let vault = server.vault();
        let memory = vault.memory(caller, caller_class);
        vault.call_connector(&memory, request, invocation, &mut host)
    }
}
