//! The bridge's wake pump (OF-385): it polls `oneiron/wakes` for one host
//! instance on its own cadence and hands each batch to that instance's
//! adapters ([`crate::wake_adapters`]), never to MCP stdout.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::{Bridge, Refusal};

/// Poll cadence and request bound for this small handoff, independent of
/// the potentially much longer deadline of an agent's tool call.
const WAKE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const WAKE_POLL_TIMEOUT: Duration = Duration::from_secs(8);

pub(super) struct WakePump(tokio::task::JoinHandle<()>);

impl WakePump {
    pub(super) fn start(bridge: Arc<Bridge>, path: &Path) -> anyhow::Result<Self> {
        let instance = crate::wake_adapters::Instance::load(path)?;
        let runtime = tokio::runtime::Handle::try_current()?;
        Ok(Self(runtime.spawn(async move {
            let mut failed = false;
            loop {
                let polling = Arc::clone(&bridge);
                let key = instance.key.clone();
                let polled = tokio::task::spawn_blocking(move || polling.wakes(&key)).await;
                match polled {
                    Ok(Ok(delivery)) => {
                        failed = false;
                        instance.deliver(delivery, &bridge.named_env).await;
                    }
                    Ok(Err(refusal)) => {
                        if !failed {
                            eprintln!(
                                "oneiron wake: {}",
                                refusal.rpc_error(&Value::Null, &bridge.auth)
                            );
                        }
                        failed = true;
                    }
                    Err(error) => {
                        if !failed {
                            eprintln!("oneiron wake poll did not finish: {error}");
                        }
                        failed = true;
                    }
                }
                tokio::time::sleep(WAKE_POLL_INTERVAL).await;
            }
        })))
    }
}

impl Drop for WakePump {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Bridge {
    /// One host instance's wake handoff, never forwarded to MCP stdout.
    fn wakes(
        &self,
        instance_key: &str,
    ) -> Result<crate::wake_adapters::board_stream::BoardDelivery, Refusal> {
        let id = json!("oneiron-wake-adapter");
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "oneiron/wakes",
            "params": { "instance_key": instance_key },
        });
        let until = Instant::now() + self.deadline.min(WAKE_POLL_TIMEOUT);
        // The wake poll's own cap is inside the global deadline; its error
        // keeps naming that one, as before.
        let answer = self
            .post(body.to_string().into_bytes(), until, self.deadline, None)?
            .answer_to(&id)?;
        let Some(delivery) = answer.get("result").cloned() else {
            return Err(Refusal::Refused(answer));
        };
        serde_json::from_value(delivery)
            .map_err(|error| Refusal::Server(format!("invalid wake handoff: {error}"), answer))
    }
}
