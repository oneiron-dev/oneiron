//! One retained set of managed workers, drained on startup errors and normal stop.

use std::path::PathBuf;

use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::{Arc, Host, ManagedState, SyncServer, WakeLedger};
use crate::managed::host::ManagedHost;

#[derive(Default)]
pub(super) struct StartingHandles {
    pub(super) host: Option<ManagedHost>,
    pub(super) host_legal: Option<crate::managed::host_legal::HostLegalService>,
    pub(super) server: Option<Arc<SyncServer>>,
    pub(super) state: Option<Arc<ManagedState>>,
    pub(super) ledger: Option<WakeLedger>,
    pub(super) gpu_poller: Option<JoinHandle<()>>,
    pub(super) tagger_close: Option<crate::oneironer::SlotClose>,
    pub(super) ai: Option<crate::ai_host::AiHost>,
    pub(super) oversight: Option<crate::server::HealerOversight>,
    pub(super) hooks_stop: Option<watch::Sender<bool>>,
    pub(super) fact_hooks: Option<JoinHandle<()>>,
    pub(super) linear: Option<JoinHandle<()>>,
    pub(super) ctl_task: Option<JoinHandle<()>>,
    pub(super) artifact_task: Option<JoinHandle<std::io::Result<()>>>,
    pub(super) preview_task: Option<JoinHandle<std::io::Result<()>>>,
    #[cfg(unix)]
    pub(super) voice: Option<crate::voice_host::VoiceBoot>,
    pub(super) background: Option<crate::server::ServeBackground>,
    pub(super) connector_events: Option<JoinHandle<()>>,
    pub(super) connector_sends: Option<JoinHandle<()>>,
    pub(super) builtin_host: Option<JoinHandle<()>>,
    pub(super) coach_host: Option<JoinHandle<()>>,
    pub(super) failure_signals: Option<JoinHandle<()>>,
    pub(super) tagging: Option<JoinHandle<()>>,
    pub(super) ladder_workers: Vec<JoinHandle<()>>,
    pub(super) ledger_report: Option<JoinHandle<()>>,
    pub(super) ctl_owned_path: Option<PathBuf>,
    pub(super) http_owned_path: Option<PathBuf>,
    pub(super) artifacts_owned_path: Option<PathBuf>,
}

pub(super) async fn stop(mut handles: StartingHandles) -> (anyhow::Result<()>, anyhow::Result<()>) {
    // Both hosts trigger shutdown before any fallible stop notification. Even
    // when that notification fails, every retained worker still gets its drain.
    let stopped = match handles.host.as_mut() {
        Some(host) => host.on_stop(),
        None => Ok(()),
    };
    // Every HOST legal capture but a prospective order's ends and joins
    // here; prospective connections drain at the end, after every writer.
    if let Some(legal) = handles.host_legal.as_mut() {
        legal.quiesce().await;
    }
    if let Some(task) = handles.ctl_task {
        let _ = task.await;
    }
    if let Some(task) = handles.artifact_task {
        let _ = task.await;
    }
    if let Some(task) = handles.preview_task {
        let _ = task.await;
    }
    if let Some(path) = handles.ctl_owned_path {
        unlink(path, "ctl socket unlink failed");
    }
    // A call in flight ends through its usual teardown before the freeze.
    #[cfg(unix)]
    if let Some(voice) = handles.voice {
        voice.stop().await;
    }
    if let Some(server) = &handles.server {
        // A reap's freeze leaves public voice sessions open; only this stop
        // finishes their journals and prevents another session (FIX 5324).
        server.live_voice.stop_all().await;
        // Buffered retrieval rows land while the vault still takes writes.
        server.flush_retrieval_meters();
    }
    // Drain observation writes without thawing a previously quiescent process.
    let telemetry_drained = match &handles.state {
        Some(state) => state.freeze().map_err(anyhow::Error::from),
        None => Ok(()),
    };
    if let Some(background) = handles.background {
        background.stop().await;
    }
    for worker in [
        handles.connector_events,
        handles.connector_sends,
        handles.builtin_host,
        handles.coach_host,
        handles.failure_signals,
    ]
    .into_iter()
    .flatten()
    {
        worker.abort();
        let _ = worker.await;
    }
    // Never abort tagging: every call it made must settle before the platform
    // children close and reap on their blocking unit (FIX 7304, FIX 7383).
    if let Some(tagging) = handles.tagging {
        let _ = tagging.await;
    }
    if let Some(closer) = handles.tagger_close {
        closer.close().await;
    }
    for worker in handles
        .ladder_workers
        .into_iter()
        .chain(handles.linear)
        .chain(handles.gpu_poller)
    {
        worker.abort();
        let _ = worker.await;
    }
    // Scheduled and idle backups and relay deletes finish their current unit.
    if let Some(server) = &handles.server
        && let Some(host) = &server.owner_host
    {
        host.resident_stopped().await;
    }
    if let Some(state) = &handles.state {
        state.idle_backup.stopped().await;
        state.relay_delete.stopped().await;
    }
    // A hook pass commits or fails whole before its runner stops.
    if let Some(stop) = handles.hooks_stop {
        let _ = stop.send(true);
    }
    if let Some(hooks) = handles.fact_hooks {
        let _ = hooks.await;
    }
    // Passes and steps reach their existing boundaries, then oversight ends.
    if let Some(ai) = handles.ai {
        ai.shutdown().await;
    }
    if let Some(oversight) = handles.oversight {
        oversight.stop().await;
    }
    // Every writer has stopped: each HOST prospective order drains its last
    // entries and names its next ordinal before the vault closes.
    if let Some(legal) = handles.host_legal {
        legal.finish().await;
    }
    // An inherited socket belongs to the supervisor. Only paths actually
    // created by this process were retained here.
    if let Some(path) = handles.http_owned_path {
        unlink(path, "http socket unlink failed");
    }
    if let Some(path) = handles.artifacts_owned_path {
        unlink(path, "artifact socket unlink failed");
    }
    // Stop the report task before the final push re-reads current facts. A
    // loaded ledger also reports a failed start before ManagedState exists.
    if let Some(report) = handles.ledger_report {
        report.abort();
        let _ = report.await;
    }
    if let Some(server) = &handles.server {
        if let Some(state) = &handles.state {
            super::super::final_ledger_push(state, server).await;
        } else if let Some(ledger) = &handles.ledger {
            super::super::final_ledger_push_from(ledger, server).await;
        }
        // Keep every env in the final full-replacement wake snapshot, then
        // stop. A start that never opened them stops nothing.
        server.stop_shared_envs().await;
    }
    (stopped, telemetry_drained)
}

fn unlink(path: PathBuf, message: &'static str) {
    if let Err(error) = std::fs::remove_file(&path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(%error, path = %path.display(), "{message}");
    }
}
