//! The bridge's wake pump (OF-385): it polls `oneiron/wakes` for one host
//! instance on its own cadence and hands each batch to that instance's
//! adapters ([`crate::wake_adapters`]), never to MCP stdout.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::context_board::HANDED_WAKES_CAP;
use serde_json::{Value, json};

use super::{Bridge, Refusal};
use crate::wake_adapters::board_stream::BoardDelivery;

/// Poll cadence and request bound for this small handoff, independent of
/// the potentially much longer deadline of an agent's tool call.
const WAKE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const WAKE_POLL_TIMEOUT: Duration = Duration::from_secs(8);

pub(super) struct WakePump(tokio::task::JoinHandle<()>);

impl WakePump {
    /// Polls this host instance's wakes on [`WAKE_POLL_INTERVAL`] and hands
    /// each batch to its adapters, with the wakes an earlier batch left
    /// undelivered (FIX 6187). What no adapter took comes back from
    /// `Instance::deliver` and is kept here, one wake per existing
    /// `event_ref`, for the next poll on the same cadence. Each retry goes
    /// through the server's current reader before any adapter sees it. A
    /// failed poll keeps the wakes for a later poll without offering them.
    /// The kept wakes live in this process only: the TASK in the vault stays
    /// the durable source, and a bridge that exits drops them.
    ///
    /// Each poll also reports the envelope ids this host acknowledged since
    /// the last one (RC99), out of those it was handed; the server records
    /// each as that one occurrence's acknowledgement. An id the poll failed
    /// to report is reported again at the next one.
    pub(super) fn start(bridge: Arc<Bridge>, path: &Path) -> anyhow::Result<Self> {
        let instance = crate::wake_adapters::Instance::load(path)?;
        let runtime = tokio::runtime::Handle::try_current()?;
        Ok(Self(runtime.spawn(async move {
            let mut failed = false;
            let mut undelivered = Vec::new();
            // The envelope ids this host was handed and has not reported
            // acknowledged yet, oldest first, as many as the server keeps.
            let mut unreported: VecDeque<String> = VecDeque::new();
            loop {
                let polling = Arc::clone(&bridge);
                let key = instance.key.clone();
                let retained = undelivered.clone();
                let acked: Vec<String> = unreported
                    .iter()
                    .filter(|event_ref| instance.acknowledged(event_ref))
                    .cloned()
                    .collect();
                let reported = acked.clone();
                let polled =
                    tokio::task::spawn_blocking(move || polling.wakes(&key, &retained, &reported))
                        .await;
                let delivery = match polled {
                    Ok(Ok(delivery)) => {
                        failed = false;
                        unreported.retain(|event_ref| !acked.contains(event_ref));
                        Some(delivery)
                    }
                    Ok(Err(refusal)) => {
                        if !failed {
                            eprintln!(
                                "oneiron wake: {}",
                                refusal.rpc_error(&Value::Null, &bridge.auth)
                            );
                        }
                        failed = true;
                        None
                    }
                    Err(error) => {
                        if !failed {
                            eprintln!("oneiron wake poll did not finish: {error}");
                        }
                        failed = true;
                        None
                    }
                };
                if let Some(delivery) = delivery {
                    for wake in &delivery.wakes {
                        if unreported.contains(&wake.event_ref) {
                            continue;
                        }
                        if unreported.len() >= HANDED_WAKES_CAP {
                            unreported.pop_front();
                        }
                        unreported.push_back(wake.event_ref.clone());
                    }
                    undelivered = instance.deliver(delivery, &bridge.named_env).await.wakes;
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
        retained: &[oneiron::context_board::WakeEnvelope],
        acked: &[String],
    ) -> Result<crate::wake_adapters::board_stream::BoardDelivery, Refusal> {
        let id = json!("oneiron-wake-adapter");
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "oneiron/wakes",
            "params": { "instance_key": instance_key, "retained": retained, "acked": acked },
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
