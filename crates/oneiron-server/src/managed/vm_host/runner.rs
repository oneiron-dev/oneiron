//! `oneiron-server host vm`'s runner: one vault VM behind one unix socket.

use super::provision;
use super::{
    API_TIMEOUT, STOP_GRACE, SleepOutcome, VaultVm, VaultVmConfig, VmAnchorHostIo, VmRestoreFds,
};
use crate::managed::listener::bind_unix_socket;
use crate::managed::vault_gates::read_managed_credentials;
use crate::managed::vm_schedule::VmWakeSchedule;
use oneiron_vault_contract::{
    CtlRequest, CtlResponse, LedgerAck, LedgerUpdate, MAX_CTL_LINE, TokenHex, now_ts,
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// `oneiron-server host vm`: one vault VM behind one unix socket. It starts
/// the VM on the first connection or a due wake, proxies HTTP into it, takes
/// its ledger pushes, and sleeps it after `idle` without traffic. With
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

async fn take_ledger_push(
    stream: UnixStream,
    vault: &str,
    token: &TokenHex,
    schedule: &mut VmWakeSchedule,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut line = String::new();
    BufReader::new(reader.take(MAX_CTL_LINE as u64 + 2))
        .read_line(&mut line)
        .await?;
    let update: anyhow::Result<()> = serde_json::from_str(line.trim_end_matches(['\r', '\n']))
        .map_err(anyhow::Error::from)
        .and_then(|update: LedgerUpdate| {
            update.validate()?;
            anyhow::ensure!(
                update.vault == vault && update.token.ct_eq(token),
                "foreign ledger push"
            );
            schedule.replace(update.rev, update.entries)
        });
    let ack = match &update {
        Ok(_) => LedgerAck {
            ok: true,
            error: None,
        },
        Err(error) => LedgerAck {
            ok: false,
            error: Some(error.to_string()),
        },
    };
    let mut reply = serde_json::to_string(&ack)?;
    reply.push('\n');
    writer.write_all(reply.as_bytes()).await?;
    update
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
            let restored = tokio::select! {
                restored = vm.start_restore(io, &fscrypt_key, API_TIMEOUT) => Some(restored?),
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
    loop {
        tokio::select! {
            _ = terminate.recv() => break,
            accepted = front.accept() => {
                let (mut client, _) = accepted?;
                if !vm.is_running() {
                    vm.start(&credentials, &fscrypt_key, API_TIMEOUT).await?;
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
            pushed = ledger.accept() => {
                let (stream, _) = pushed?;
                if let Err(error) = take_ledger_push(stream, &run.vault_name, &token, &mut vm.schedule).await {
                    tracing::warn!(%error, "vault VM ledger push refused");
                }
            }
            _ = tick.tick() => {
                if !vm.is_running() && vm.schedule.has_due(now_ts()) {
                    vm.start(&credentials, &fscrypt_key, API_TIMEOUT).await?;
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
                        match vm.sleep(API_TIMEOUT).await? {
                            SleepOutcome::Busy => last_activity = Instant::now(),
                            SleepOutcome::Snapshotted { .. } | SleepOutcome::Stopped { .. } => {}
                        }
                    }
                }
            }
        }
    }
    if vm.is_running() {
        vm.stop(STOP_GRACE).await?;
    }
    Ok(())
}
