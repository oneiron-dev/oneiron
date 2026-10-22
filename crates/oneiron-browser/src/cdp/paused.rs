//! Each paused request's host worker (FIX 7651, FIX 6302). A
//! `Fetch.requestPaused` the seed slot did not take is performed off the
//! reader, on a host thread the run's relay charges to its host floor
//! ([`oneiron_container::EgressRelay::host_net_floor`]) before the thread
//! starts. A full floor never refuses a request: it waits in the pipe's
//! queue, in order, still paused, until a worker of the pipe finishes and
//! takes it on its own room, or the next message the pipe routes finds
//! room. No count bounds the queue; only the host's floor paces it.

use super::Pipe;
use base64::Engine as _;
use oneiron_container::{EgressRelay, HostNetPermit};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The paused requests waiting for a host worker, in the order they paused.
pub(super) type Waiting = Arc<Mutex<VecDeque<Paused>>>;

/// One paused request: its page session, its request id and its event.
pub(super) struct Paused {
    relay: Arc<dyn EgressRelay>,
    session: String,
    id: String,
    event: Value,
}

impl Pipe {
    /// Hands paused request `id` of page `session` to a host worker, once
    /// the relay's floor has room for one.
    pub(super) fn admit_paused(
        &self,
        relay: Arc<dyn EgressRelay>,
        session: String,
        id: String,
        event: Value,
    ) {
        if let Ok(mut waiting) = self.paused.lock() {
            waiting.push_back(Paused {
                relay,
                session,
                id,
                event,
            });
        }
        self.drain_paused();
    }

    /// Starts a worker for each waiting request, in order, while the floor
    /// has room. Called on the reader: it never waits.
    pub(super) fn drain_paused(&self) {
        loop {
            let Ok(mut waiting) = self.paused.lock() else {
                return;
            };
            let Some(next) = waiting.front() else {
                return;
            };
            let Ok(permit) = next.relay.host_net_floor().acquire(0, 1) else {
                return;
            };
            let Some(paused) = waiting.pop_front() else {
                return;
            };
            drop(waiting);
            let pipe = self.clone();
            std::thread::spawn(move || pipe.work(paused, permit));
        }
    }

    /// Serves `paused`, then each request waiting after it, on the one
    /// worker `permit` holds.
    fn work(&self, mut paused: Paused, permit: HostNetPermit) {
        loop {
            self.serve(paused);
            let next = self
                .paused
                .lock()
                .ok()
                .and_then(|mut waiting| waiting.pop_front());
            match next {
                Some(more) => paused = more,
                None => break,
            }
        }
        drop(permit);
    }

    /// Performs one paused request: its body read, then the host's handler
    /// or the relay, then its answer to the page.
    fn serve(&self, paused: Paused) {
        let Paused {
            relay,
            session,
            id,
            event,
        } = paused;
        let request = &event["params"]["request"];
        let headers = request["headers"]
            .as_object()
            .map(|h| {
                h.iter()
                    .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        let Some(body) = self.paused_body(&session, &event) else {
            self.fail_paused(&session, &id, "Failed");
            return;
        };
        let asked = oneiron_container::HttpRequest {
            url: request["url"].as_str().unwrap_or("").to_owned(),
            method: request["method"].as_str().unwrap_or("GET").to_owned(),
            headers,
            body,
            follow_redirects: false,
        };
        // The host's handler takes it where the session has one, else the
        // relay; a refusal it gave is kept before the request fails.
        match self.fetch_paused(&relay, &session, &event, asked) {
            Some(response) => {
                let headers: Vec<_> = response
                    .headers
                    .into_iter()
                    .map(|(name, value)| json!({"name": name, "value": value}))
                    .collect();
                let _ = self.call(
                    Some(&session),
                    "Fetch.fulfillRequest",
                    json!({"requestId": id,
                    "responseCode": response.status, "responseHeaders": headers,
                    "body": base64::engine::general_purpose::STANDARD.encode(response.body)}),
                    Instant::now() + Duration::from_secs(30),
                );
            }
            None => self.fail_paused(&session, &id, "BlockedByClient"),
        }
    }

    /// A paused request's body: its entries decoded, its inline data, or
    /// the data the browser holds for it; none where one did not read.
    fn paused_body(&self, session: &str, event: &Value) -> Option<Vec<u8>> {
        let request = &event["params"]["request"];
        if let Some(entries) = request["postDataEntries"].as_array() {
            let mut body = Vec::new();
            for entry in entries {
                let bytes = entry["bytes"].as_str()?;
                body.extend(
                    base64::engine::general_purpose::STANDARD
                        .decode(bytes)
                        .ok()?,
                );
            }
            Some(body)
        } else if let Some(data) = request["postData"].as_str() {
            Some(data.as_bytes().to_vec())
        } else if request["hasPostData"].as_bool() == Some(true) {
            let network_id = event.pointer("/params/networkId").and_then(Value::as_str)?;
            let data = self
                .call(
                    Some(session),
                    "Network.getRequestPostData",
                    json!({"requestId": network_id}),
                    Instant::now() + Duration::from_secs(30),
                )
                .ok()?;
            data["postData"].as_str().map(|s| s.as_bytes().to_vec())
        } else {
            Some(Vec::new())
        }
    }

    /// Fails paused request `id` of page `session` for `reason`.
    fn fail_paused(&self, session: &str, id: &str, reason: &str) {
        let _ = self.call(
            Some(session),
            "Fetch.failRequest",
            json!({"requestId": id, "errorReason": reason}),
            Instant::now() + Duration::from_secs(30),
        );
    }
}
