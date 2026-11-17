//! Doors for `tests/system_one_broker_budget.rs` (#7827 review round 2): the
//! System One seat's transport over the credential broker, as serve builds it
//! for a seat whose binding names a `key_secret`. Thin wrappers over crate
//! items only. Compiled only under `--cfg oneiron_test_support`; hidden,
//! never API.

use std::sync::Arc;
use std::time::Duration;

use oneiron_llm::systemone::SystemOneTransport;

use crate::config::models::BrokerConfig;
use crate::models::{BrokerContext, KeyDoor};

/// The longest one send runs in the broker: the System One seat's ceiling.
const BROKER_SEND: Duration = Duration::from_secs(60);

/// The System One seat's transport over the broker `broker` names, its key
/// the vault secret `secret`, read at `keys`. Built inside a tokio runtime,
/// which the broker context's blocking callers run on.
///
/// # Panics
/// Outside a tokio runtime.
#[doc(hidden)]
#[must_use]
pub fn system_one_broker_leg(
    keys: Arc<dyn KeyDoor>,
    broker: &BrokerConfig,
    secret: &str,
) -> Box<dyn SystemOneTransport> {
    BrokerContext::new(keys, broker, BROKER_SEND, tokio::runtime::Handle::current())
        .system_one(secret)
}
