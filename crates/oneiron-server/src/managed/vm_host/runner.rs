//! `oneiron-server host vm`'s runner: one vault VM behind one unix socket.

use super::ledger_io::{self, LedgerCommit, MAX_LEDGER_PEERS};
use super::provision;
use super::{
    API_TIMEOUT, STOP_GRACE, SleepOutcome, VaultVm, VaultVmConfig, VmAnchorHostIo, VmRestoreFds,
};
use crate::managed::listener::bind_unix_socket;
use crate::managed::vault_gates::read_managed_credentials;
use oneiron_vault_contract::vm_provision::VmFscryptKey;
use oneiron_vault_contract::{Credentials, CtlRequest, CtlResponse, TokenHex, now_ts};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::signal::unix::Signal;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

/// `oneiron-server host vm`: one vault VM behind one unix socket. It starts
/// the VM on the first connection or a due wake, proxies HTTP into it, takes
/// its ledger pushes on tasks of their own (FIX 9502, [`ledger_io`]), and
/// sleeps it after `idle` without traffic. Every start is dropped by a
/// SIGTERM that comes first (FIX 9501). With
/// `restore` it starts the VM at once with a cold restore (FIX 6584), and
/// binds its socket only once the restored vault is ready. With a custody
/// anchor URL it binds every serving boot's anchor to it (FIX 6517).
pub struct VaultVmRun {
    pub config: PathBuf,
    pub vault_name: String,
    pub listen: PathBuf,
    pub credentials_fd: std::os::fd::RawFd,
    /// Carries exactly the vault's 64-byte fscrypt key; read once, and sent
    /// to the guest on each cold boot.
    pub fscrypt_key_fd: std::os::fd::RawFd,
    /// A cold restore's two pipes (`--restore`); the credential frame then
    /// follows the restore's input.
    pub restore: Option<VmRestoreFds>,
    /// The anchor URL the vault's effective settings bind, exactly as they
    /// spell it; never logged (`--custody-anchor-url`).
    pub custody_anchor_url: Option<String>,
    /// The pipe the door's owner credential arrives on, which needs the URL
    /// (`--custody-anchor-credentials-fd`): read once, after the first
    /// credential frame went to the guest, and held for every later boot.
    pub custody_anchor_credentials_fd: Option<std::os::fd::RawFd>,
    pub idle: Duration,
}

/// Starts the VM unless a SIGTERM comes first (FIX 9501): then the start is
/// dropped, which ends its waits and its supervisor pipe's read and joins
/// that read, and the runner stops the VM. Whether it started.
async fn start_or_terminate(
    vm: &mut VaultVm,
    credentials: &Credentials,
    fscrypt_key: &VmFscryptKey,
    terminate: &mut Signal,
) -> anyhow::Result<bool> {
    let timeout = vm.boot_timeout();
    tokio::select! {
        started = vm.start(credentials, fscrypt_key, timeout) => started.map(|()| true),
        _ = terminate.recv() => Ok(false),
    }
}

pub async fn run_vault_vm(run: VaultVmRun) -> anyhow::Result<()> {
    let config: VaultVmConfig = serde_json::from_slice(&std::fs::read(&run.config)?)?;
    anyhow::ensure!(
        run.fscrypt_key_fd != run.credentials_fd,
        "--fscrypt-key-fd and --credentials-fd name one descriptor"
    );
    // The anchor credential's pipe is proven and taken over before any
    // descriptor is read, refused when it names another flag's.
    let mut taken = vec![
        ("--credentials-fd", run.credentials_fd),
        ("--fscrypt-key-fd", run.fscrypt_key_fd),
    ];
    taken.extend(run.restore.iter().flat_map(|fds| {
        [
            ("--restore-input-fd", fds.input_fd),
            ("--restore-result-fd", fds.result_fd),
        ]
    }));
    let anchor = VmAnchorHostIo::adopt(
        run.custody_anchor_url,
        run.custody_anchor_credentials_fd,
        &taken,
    )?;
    // A restore's pipes are proven and taken over before any descriptor is
    // read, and its credential frame follows its input: the VM starts on the
    // fscrypt key alone.
    let restore = run
        .restore
        .map(|fds| fds.adopt(run.credentials_fd, run.fscrypt_key_fd))
        .transpose()?;
    let credentials = match restore {
        Some(_) => None,
        None => Some(read_managed_credentials(run.credentials_fd)?),
    };
    let fscrypt_key = provision::read_fscrypt_key(run.fscrypt_key_fd)?;
    let mut vm = VaultVm::prepare(config, run.vault_name.clone())?;
    vm.attach_anchor(anchor)?;
    let ledger = bind_unix_socket(&vm.ledger_socket())?;
    // Heard from here on, through a restore too (FIX 7078): a SIGTERM drops
    // the restore, which wakes its read of C, then stops the VM, and the
    // socket is never bound.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let credentials = match (restore, credentials) {
        (Some(io), _) => {
            let timeout = vm.boot_timeout();
            let restored = tokio::select! {
                restored = vm.start_restore(io, &fscrypt_key, timeout) => Some(restored?),
                _ = terminate.recv() => None,
            };
            match restored {
                Some(credentials) => credentials,
                None => {
                    if vm.is_running() {
                        vm.stop(STOP_GRACE).await?;
                    }
                    return Ok(());
                }
            }
        }
        (None, credentials) => {
            credentials.ok_or_else(|| anyhow::anyhow!("no credential frame was read"))?
        }
    };
    let token = TokenHex::from_token(&credentials.token);
    let front = bind_unix_socket(&run.listen)?;
    let open = Arc::new(AtomicUsize::new(0));
    let mut last_activity = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    // Ledger peers run as tasks this loop owns; their complete reports come
    // back here, to the schedule's one owner, to commit.
    let mut peers = JoinSet::new();
    let (reports, mut commits) = mpsc::channel::<LedgerCommit>(MAX_LEDGER_PEERS);
    loop {
        tokio::select! {
            _ = terminate.recv() => break,
            accepted = front.accept() => {
                let (mut client, _) = accepted?;
                if !vm.is_running()
                    && !start_or_terminate(&mut vm, &credentials, &fscrypt_key, &mut terminate).await?
                {
                    break;
                }
                last_activity = Instant::now();
                let mut guest = vm.http().await?;
                let open = Arc::clone(&open);
                open.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut guest).await;
                    open.fetch_sub(1, Ordering::SeqCst);
                });
            }
            pushed = ledger.accept(), if peers.len() < MAX_LEDGER_PEERS => {
                let (stream, _) = pushed?;
                peers.spawn(ledger_io::take_push(
                    stream,
                    run.vault_name.clone(),
                    token.clone(),
                    reports.clone(),
                ));
            }
            Some(commit) = commits.recv() => {
                let _ = commit.answer.send(vm.schedule.replace(commit.report));
            }
            Some(_) = peers.join_next(), if !peers.is_empty() => {}
            _ = tick.tick() => {
                if !vm.is_running() && vm.schedule.has_due(now_ts()) {
                    if !start_or_terminate(&mut vm, &credentials, &fscrypt_key, &mut terminate).await? {
                        break;
                    }
                    last_activity = Instant::now();
                }
                if vm.is_running() {
                    for entry in vm.schedule.due(now_ts()) {
                        let response = vm.ctl(&CtlRequest::AlarmDue {
                            id: entry.id.clone(), reason_tag: entry.reason_tag.clone(),
                        }).await?;
                        anyhow::ensure!(matches!(response, CtlResponse::Ok { ok: true }), "alarm_due was not acknowledged");
                        vm.schedule.delivered(&entry)?;
                        last_activity = Instant::now();
                    }
                    if open.load(Ordering::SeqCst) == 0 && last_activity.elapsed() >= run.idle {
                        match vm.sleep(&token, API_TIMEOUT).await? {
                            SleepOutcome::Busy => last_activity = Instant::now(),
                            SleepOutcome::Snapshotted { .. } | SleepOutcome::Stopped { .. } => {}
                        }
                    }
                }
            }
        }
    }
    // Every ledger peer ends with the runner; a report not yet committed is
    // owed to the next push.
    peers.shutdown().await;
    if vm.is_running() {
        vm.stop(STOP_GRACE).await?;
    }
    Ok(())
}
