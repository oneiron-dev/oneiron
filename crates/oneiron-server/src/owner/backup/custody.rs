//! Custody heads beside the backups (KS-4A1, FIX 5685). A backup never holds
//! the vault's exterior key custody; its sealed, recovery-wrapped head and
//! keyless log publish to the folder beside the backups
//! (`<backups>/oneiron-custody/`), then the anchor advances when the owner
//! set an anchor root up (CALLS CUSTODY_ANCHOR_ROOT, unset by default).
//! `oneiron backup` publishes once after its backup; a running server
//! publishes at start and then whenever the status read shows the head
//! behind or a step pending. No backup or save waits on a pass or refuses
//! for one: a step that does not go through stays pending by name on the
//! owner's status read, and the next pass retries.

use std::sync::Arc;
use std::time::Duration;

use oneiron::recovery::checkpoint::{
    CUSTODY_ANCHOR_PENDING, CUSTODY_FENCED, CUSTODY_NONE, CUSTODY_PUBLISHED,
    CUSTODY_TARGET_PENDING, CustodyStatus,
};
use serde::Serialize;

use super::{BackupOutcome, BackupPlan, take};
use crate::config::BackupConfig;
use crate::owner::schedule::OwnerHost;
use crate::server::SyncServer;

/// How often a running server checks whether its custody head is behind.
const CUSTODY_TICK: Duration = Duration::from_secs(60);

impl BackupPlan {
    /// The plan with the custody anchor root `backup` names, if any.
    pub(crate) fn anchored_at(mut self, backup: &BackupConfig) -> Self {
        self.custody_anchor = backup.custody_anchor_root.clone();
        self
    }
}

impl OwnerHost {
    /// The host with its vault's custody anchored where `backup` names.
    pub(crate) fn anchored_at(mut self, backup: &BackupConfig) -> Self {
        self.backups.custody_anchor = backup.custody_anchor_root.clone();
        self
    }
}

/// What `oneiron backup` did: the backup, then where the vault's custody
/// publication stands.
#[derive(Serialize)]
pub(crate) struct BackupWithCustody {
    #[serde(flatten)]
    taken: BackupOutcome,
    custody: CustodyStatus,
}

/// [`take`], then one custody publication pass. The backup stands whatever
/// the pass does; where the pass got is in `custody`.
pub(crate) fn take_publishing(
    vault: &oneiron::Vault,
    plan: &BackupPlan,
) -> anyhow::Result<BackupWithCustody> {
    let taken = take(vault, plan)?;
    Ok(BackupWithCustody {
        custody: publish(vault, plan),
        taken,
    })
}

/// A custody status for a pass or read that did not run: the engine's
/// error, which names no key, as its detail.
fn not_run(error: &oneiron::Error, what: &str) -> CustodyStatus {
    CustodyStatus {
        state: CUSTODY_TARGET_PENDING,
        writer_epoch: None,
        log_seq: None,
        published_seq: None,
        anchored_seq: None,
        detail: Some(format!("{what}: {error}")),
    }
}

/// One publication pass of `vault`'s custody to `plan`'s directory and
/// anchor root. A fault in the local custody is the status's detail here,
/// never the caller's error.
fn publish(vault: &oneiron::Vault, plan: &BackupPlan) -> CustodyStatus {
    vault
        .publish_custody(&plan.dir, plan.custody_anchor.as_deref())
        .unwrap_or_else(|error| not_run(&error, "the custody publication pass did not run"))
}

/// Where `vault`'s custody publication stands, for the owner's status read.
pub(crate) fn custody_status(vault: &oneiron::Vault) -> CustodyStatus {
    vault
        .custody_status()
        .unwrap_or_else(|error| not_run(&error, "the custody status does not read"))
}

/// Whether the last pass left another nothing to do: published and
/// anchored, nothing in custody, fenced by a newer writer, or, with no
/// anchor root set up, the head at the local position on the target.
fn settled(status: &CustodyStatus, anchored: bool) -> bool {
    match status.state {
        CUSTODY_NONE | CUSTODY_PUBLISHED | CUSTODY_FENCED => true,
        CUSTODY_ANCHOR_PENDING => {
            !anchored && status.published_seq.is_some() && status.published_seq == status.log_seq
        }
        _ => false,
    }
}

/// Logs a pass's state when it changes: positions and the pending step's
/// reason, never a key.
fn log_pass(status: &CustodyStatus, anchored: bool) {
    match status.state {
        CUSTODY_NONE => {}
        CUSTODY_PUBLISHED => tracing::info!(
            state = status.state,
            log_seq = ?status.log_seq,
            "custody head published and anchored"
        ),
        CUSTODY_ANCHOR_PENDING if !anchored => tracing::info!(
            state = status.state,
            log_seq = ?status.log_seq,
            published_seq = ?status.published_seq,
            "custody head published; no custody anchor root is set up"
        ),
        _ => tracing::warn!(
            state = status.state,
            log_seq = ?status.log_seq,
            published_seq = ?status.published_seq,
            anchored_seq = ?status.anchored_seq,
            detail = status.detail.as_deref().unwrap_or(""),
            "custody publication pending; the next pass retries"
        ),
    }
}

impl SyncServer {
    /// Starts the custody publication of a server that keeps backups: a
    /// pass at start, then one on each tick whose status read shows the head
    /// behind or a step pending.
    pub(crate) fn spawn_custody_publication(
        self: &Arc<Self>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let host = Arc::clone(self.owner_host.as_ref()?);
        let server = Arc::clone(self);
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(CUSTODY_TICK);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let anchored = host.backups.custody_anchor.is_some();
            let mut last: Option<&'static str> = None;
            loop {
                interval.tick().await;
                let (host, server) = (Arc::clone(&host), Arc::clone(&server));
                let first = last.is_none();
                let pass = tokio::task::spawn_blocking(move || {
                    let vault = server.vault();
                    if !first
                        && let Ok(status) = vault.custody_status()
                        && settled(&status, anchored)
                    {
                        return status;
                    }
                    publish(vault, &host.backups)
                })
                .await;
                match pass {
                    Ok(status) => {
                        if last != Some(status.state) {
                            log_pass(&status, anchored);
                        }
                        last = Some(status.state);
                    }
                    Err(error) => tracing::warn!(
                        panicked = error.is_panic(),
                        "custody publication task failed"
                    ),
                }
            }
        }))
    }
}
