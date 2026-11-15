//! Door for `tests/sync_upgrade_forbidden.rs`, mounted inside
//! `sync::connection` so it runs a peer session's probe of the home without
//! changing that probe's visibility. Reached as
//! `oneiron::test_doors::home_probe` (re-exported there); compiled only under
//! `oneiron_test_support`.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::Vault;
use crate::sync::client::SyncClientConfig;

/// Runs a peer session's probe of `config`'s home for at most `wait`, as a
/// peer session's steady loop runs it. Returns the home's answer that ends
/// the peer session, by its `Debug` form (`None` when none came within
/// `wait`), and every event the probe told, by its `Debug` form.
pub async fn home_answer_within(
    vault: &Arc<Vault>,
    config: &SyncClientConfig,
    wait: Duration,
) -> (Option<String>, Vec<String>) {
    let (events, mut told) = mpsc::unbounded_channel();
    let mut probe = super::peer_session::HomeProbe::new(true, vault, config, &events);
    let answer = tokio::time::timeout(wait, probe.home_answer())
        .await
        .ok()
        .map(|answer| format!("{answer:?}"));
    drop(probe);
    let mut told_events = Vec::new();
    while let Ok(event) = told.try_recv() {
        told_events.push(format!("{event:?}"));
    }
    (answer, told_events)
}
