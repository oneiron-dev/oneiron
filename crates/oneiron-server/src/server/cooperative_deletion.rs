//! Delivers queued courtesy deletion asks and answers (OF-273). Each try
//! POSTs the signed bytes unchanged to the destination frozen when they were
//! queued, with redirects off; the engine settles the ledger. Runs on the
//! housekeeping pass's blocking worker. On a vault whose root a re-root
//! handed on, each try first POSTs the succession pages to the peer's
//! succession route, in order, so a peer that pinned an earlier root still
//! verifies the try (FIX 3014); a page the peer does not take settles the
//! try as its answer would.

use std::time::Duration;

use oneiron::deletion::CooperativeDeletionTry;

use super::SyncServer;

/// Tries per pass; the rest wait for the next tick.
const TRIES_PER_PASS: usize = 16;
const TRY_TIMEOUT: Duration = Duration::from_secs(30);

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// One POST of `body` to `destination`, read as a try's result.
fn post(
    client: &reqwest::blocking::Client,
    destination: &str,
    body: &[u8],
) -> CooperativeDeletionTry {
    match client
        .post(destination)
        .header("Content-Type", "application/msgpack")
        .header("User-Agent", "oneiron-courtesy-delete")
        .body(body.to_vec())
        .send()
    {
        Ok(response) if response.status().is_success() => CooperativeDeletionTry::Delivered,
        Ok(response) => {
            let status = response.status().as_u16();
            if (400..500).contains(&status) && !matches!(status, 408 | 429) {
                CooperativeDeletionTry::Refused(status)
            } else {
                CooperativeDeletionTry::Failed(format!("http {status}"))
            }
        }
        Err(error) if error.is_timeout() => CooperativeDeletionTry::Failed("timeout".to_owned()),
        Err(_) => CooperativeDeletionTry::Failed("network".to_owned()),
    }
}

impl SyncServer {
    /// One bounded delivery pass. Blocking: call it off the runtime.
    pub(super) fn deliver_cooperative_deletions(&self) {
        let vault = self.vault();
        let lease_owner = format!("courtesy-delete:{}", std::process::id());
        let mut client = None;
        for _ in 0..TRIES_PER_PASS {
            let delivery = match vault.claim_cooperative_deletion_delivery(&lease_owner, unix_now())
            {
                Ok(Some(delivery)) => delivery,
                Ok(None) => return,
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "courtesy delete claim failed");
                    return;
                }
            };
            if client.is_none() {
                client = reqwest::blocking::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(TRY_TIMEOUT)
                    .build()
                    .ok();
            }
            let result = match client.as_ref() {
                None => CooperativeDeletionTry::Failed("client".to_owned()),
                Some(client) => match vault.cooperative_deletion_succession(&delivery) {
                    Err(error) => {
                        tracing::warn!(kind = ?error.kind(), "courtesy delete succession failed");
                        CooperativeDeletionTry::Failed("succession".to_owned())
                    }
                    Ok(succession) => succession
                        .iter()
                        .flat_map(|succession| {
                            succession
                                .pages
                                .iter()
                                .map(move |page| (succession.destination.as_str(), page))
                        })
                        .map(|(destination, page)| post(client, destination, page))
                        .find(|result| *result != CooperativeDeletionTry::Delivered)
                        .unwrap_or_else(|| post(client, &delivery.destination, &delivery.bytes)),
                },
            };
            match vault.settle_cooperative_deletion_delivery(&delivery, result, unix_now()) {
                Ok(status) => {
                    tracing::info!(status = status.as_str(), "courtesy delete try settled")
                }
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "courtesy delete settle failed");
                }
            }
        }
    }
}
