//! The vault's broker for git exchanges (ARCH-0069 OSH-3): the same site the
//! vault-secret keys send through, reached for one exchange at a time. This
//! module reads no key: the caller reads its own effector's credential at
//! the custody door once the broker has acknowledged the exchange's body.

use std::sync::{Arc, Weak};
use std::time::Duration;

use oneiron_broker::{BrokerConnection, Isolation};

use super::{BrokerContext, Inner};

/// A broker context held without keeping it alive: the vault's own
/// transports hold this, since the context's custody door holds the vault
/// (FIX 19083).
#[derive(Clone)]
pub(crate) struct WeakBrokerContext {
    inner: Weak<Inner>,
}

impl WeakBrokerContext {
    /// The context, while serve still holds it.
    pub(crate) fn upgrade(&self) -> Option<BrokerContext> {
        self.inner.upgrade().map(|inner| BrokerContext { inner })
    }
}

impl BrokerContext {
    /// This context, held weakly.
    pub(crate) fn downgrade(&self) -> WeakBrokerContext {
        WeakBrokerContext {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// The serve runtime a git relay of this context serves on.
    pub(crate) fn runtime(&self) -> &tokio::runtime::Handle {
        &self.inner.runtime
    }

    /// A peer-checked connection to the broker for one git exchange, and how
    /// the broker is isolated, for the exchange's record. Each step on it
    /// waits at most `idle` without progress (the host's transfer idle
    /// limit); the same-user child starts here at its first call.
    ///
    /// # Errors
    ///
    /// No broker to send through, one this server may not use, or one that
    /// cannot be reached; nothing was written.
    pub(crate) async fn git_connection(
        &self,
        idle: Duration,
    ) -> Result<(BrokerConnection, Isolation), String> {
        let site = self.site().as_ref().map_err(Clone::clone)?;
        let client = site.client(idle).map_err(|error| error.to_string())?;
        client.ready().map_err(|error| error.to_string())?;
        let isolation = client.isolation();
        let connection = client.connect().await.map_err(|error| error.to_string())?;
        Ok((connection, isolation))
    }
}
