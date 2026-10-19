//! Custody heads beside the backups (KS-4A1/KS-4A2, FIX 5685). A backup
//! never holds the vault's exterior key custody; its sealed, recovery-wrapped
//! head and keyless log publish to the folder beside the backups
//! (`<backups>/oneiron-custody/`) and to every other member of the vault's
//! required target set (a residence home through its machines' sync, a
//! declared hosted holder once its adapter lands in KS-C4), then the anchor
//! advances when the owner set one up: a mounted root (CALLS
//! CUSTODY_ANCHOR_ROOT) or another install's door (CALLS CUSTODY_ANCHOR_URL,
//! [`anchor_client`]), unset by default. A backup publishes right after it
//! lands (FIX 5790); a running server also publishes at start and then
//! whenever the status read shows a member behind, a step or a retirement
//! pending, or a head without the data-key wrap the key now allows (FIX
//! 5791). No backup or save waits on a pass or refuses for one: a step that
//! does not go through stays pending by name on the owner's status read,
//! and the next pass retries.

mod anchor_client;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use oneiron::recovery::checkpoint::{
    CUSTODY_ANCHOR_PENDING, CUSTODY_FENCED, CUSTODY_NONE, CUSTODY_PUBLISHED,
    CUSTODY_RETIREMENT_COMPLETE, CUSTODY_TARGET_PENDING, CustodyRecovery, CustodyStatus,
};
use oneiron::store::custody_protocol::{AnchorStore, TargetSpec};
use serde::Serialize;

use self::anchor_client::HttpAnchor;
use super::{BackupOutcome, BackupPlan, take};
use crate::config::BackupConfig;
use crate::owner::schedule::OwnerHost;
use crate::server::{HousekeepingAdmission, SyncServer, admit_every_pass};

/// How often a running server checks whether its custody head is behind.
const CUSTODY_TICK: Duration = Duration::from_secs(60);

/// Where a vault's custody anchors and which hosted members it declares.
#[derive(Clone, Debug, Default)]
pub(crate) struct CustodyPlan {
    /// The owner-selected anchor root (CALLS CUSTODY_ANCHOR_ROOT).
    pub(crate) anchor_root: Option<PathBuf>,
    /// Another install's anchor door (CALLS CUSTODY_ANCHOR_URL).
    anchor_url: Option<String>,
    /// The hosted members the config declares (CALLS
    /// CUSTODY_HOSTED_TARGETS), each pending until its adapter acks.
    declared: Vec<TargetSpec>,
}

impl CustodyPlan {
    fn of(backup: &BackupConfig) -> Self {
        Self {
            anchor_root: backup.custody_anchor_root.clone(),
            anchor_url: backup.custody_anchor_url.clone(),
            // The config's own check refused a target that does not parse.
            declared: backup
                .custody_targets
                .iter()
                .filter_map(|target| TargetSpec::declared(target).ok())
                .collect(),
        }
    }

    fn anchored(&self) -> bool {
        self.anchor_root.is_some() || self.anchor_url.is_some()
    }

    /// The anchor `vault` publishes to: the root, refused inside the vault
    /// or its key custody, or the door.
    fn anchor(&self, vault: &oneiron::Vault) -> oneiron::Result<Option<Box<dyn AnchorStore>>> {
        if let Some(root) = &self.anchor_root {
            return Ok(Some(Box::new(vault.custody_anchor_root(root)?)));
        }
        Ok(self
            .anchor_url
            .as_deref()
            .map(|url| Box::new(HttpAnchor::at(url)) as Box<dyn AnchorStore>))
    }
}

impl BackupPlan {
    /// The plan with the custody anchor and hosted members `backup` names.
    pub(crate) fn anchored_at(mut self, backup: &BackupConfig) -> Self {
        self.custody = CustodyPlan::of(backup);
        self
    }
}

impl OwnerHost {
    /// The host with its vault's custody anchored where `backup` names.
    pub(crate) fn anchored_at(mut self, backup: &BackupConfig) -> Self {
        self.backups.custody = CustodyPlan::of(backup);
        self
    }
}

/// A restore's custody source beside `backup`, checked against the anchor
/// `config` names: its root, or its door (FIX 5788).
pub(crate) fn custody_recovery(
    backup: &std::path::Path,
    config: &BackupConfig,
) -> CustodyRecovery<'static> {
    let recovery = CustodyRecovery::beside(backup).anchored_at(config.custody_anchor_root.clone());
    match &config.custody_anchor_url {
        Some(url) if config.custody_anchor_root.is_none() => {
            recovery.anchored_by(Box::new(HttpAnchor::at(url)))
        }
        _ => recovery,
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

/// [`take`], which publishes the custody once its backup lands, then the
/// status that pass left. The backup stands whatever the pass does.
pub(crate) fn take_publishing(
    vault: &oneiron::Vault,
    plan: &BackupPlan,
) -> anyhow::Result<BackupWithCustody> {
    let taken = take(vault, plan)?;
    Ok(BackupWithCustody {
        custody: custody_status(vault),
        taken,
    })
}

/// The pass right after a backup lands (FIX 5790), so no newest backup is
/// left without its head beside it until the next tick. Never the backup's
/// error.
pub(super) fn publish_after_take(vault: &oneiron::Vault, plan: &BackupPlan) {
    let status = publish(vault, plan);
    if status.state != CUSTODY_PUBLISHED {
        log_pass(&status, plan.custody.anchored());
    }
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
        data_key_wrapped: None,
        retirement: None,
    }
}

/// One publication pass of `vault`'s custody to `plan`'s directory, every
/// registered and declared member, and its anchor. A fault in the local
/// custody is the status's detail here, never the caller's error; an
/// anchor that cannot be used leaves the anchor step pending with why.
fn publish(vault: &oneiron::Vault, plan: &BackupPlan) -> CustodyStatus {
    let (anchor, unusable) = match plan.custody.anchor(vault) {
        Ok(anchor) => (anchor, None),
        Err(error) => (None, Some(error.to_string())),
    };
    let mut status = vault
        .publish_custody(&plan.dir, &plan.custody.declared, anchor.as_deref())
        .unwrap_or_else(|error| not_run(&error, "the custody publication pass did not run"));
    if status.state == CUSTODY_ANCHOR_PENDING
        && let Some(unusable) = unusable
    {
        status.detail = Some(format!("the custody anchor is not usable: {unusable}"));
    }
    status
}

/// Where `vault`'s custody publication stands, for the owner's status read.
pub(crate) fn custody_status(vault: &oneiron::Vault) -> CustodyStatus {
    vault
        .custody_status()
        .unwrap_or_else(|error| not_run(&error, "the custody status does not read"))
}

/// Whether the last pass left another nothing to do: published and
/// anchored, nothing in custody, fenced by a newer writer, or, with no
/// anchor set up, the head at the local position on every member; and in
/// each case no retirement pending and no head that waits for the data-key
/// wrap (FIX 5791).
fn settled(status: &CustodyStatus, anchored: bool) -> bool {
    if status.data_key_wrapped == Some(false)
        || status
            .retirement
            .as_ref()
            .is_some_and(|retirement| retirement.state != CUSTODY_RETIREMENT_COMPLETE)
    {
        return status.state == CUSTODY_FENCED;
    }
    match status.state {
        CUSTODY_NONE | CUSTODY_PUBLISHED | CUSTODY_FENCED => true,
        CUSTODY_ANCHOR_PENDING => {
            !anchored && status.published_seq.is_some() && status.published_seq == status.log_seq
        }
        _ => false,
    }
}

/// Logs a pass's state when it changes: positions, the pending step's
/// reason and each owed retirement step by name, never a key.
fn log_pass(status: &CustodyStatus, anchored: bool) {
    let owed = status
        .retirement
        .as_ref()
        .map_or_else(String::new, |retirement| retirement.names.join(", "));
    match status.state {
        CUSTODY_NONE => {}
        CUSTODY_PUBLISHED => tracing::info!(
            state = status.state,
            log_seq = ?status.log_seq,
            retirement = owed,
            "custody head published and anchored"
        ),
        CUSTODY_ANCHOR_PENDING if !anchored => tracing::info!(
            state = status.state,
            log_seq = ?status.log_seq,
            published_seq = ?status.published_seq,
            retirement = owed,
            "custody head published; no custody anchor is set up"
        ),
        _ => tracing::warn!(
            state = status.state,
            log_seq = ?status.log_seq,
            published_seq = ?status.published_seq,
            anchored_seq = ?status.anchored_seq,
            detail = status.detail.as_deref().unwrap_or(""),
            retirement = owed,
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
        self.spawn_custody_publication_admitted(admit_every_pass())
    }

    /// [`Self::spawn_custody_publication`] on a host with a write freeze
    /// (managed serve, FIX 5789): each pass is admitted through `admit` and
    /// holds that admission on its blocking thread; a refused tick waits for
    /// the next.
    pub(crate) fn spawn_custody_publication_admitted(
        self: &Arc<Self>,
        admit: HousekeepingAdmission,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let host = Arc::clone(self.owner_host.as_ref()?);
        let server = Arc::clone(self);
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(CUSTODY_TICK);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let anchored = host.backups.custody.anchored();
            let mut last: Option<&'static str> = None;
            loop {
                interval.tick().await;
                let Some(admission) = admit() else {
                    continue;
                };
                let (host, server) = (Arc::clone(&host), Arc::clone(&server));
                let first = last.is_none();
                let pass = tokio::task::spawn_blocking(move || {
                    let _admission = admission;
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
