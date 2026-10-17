//! The microVM adapter's host half: one Firecracker VM per vault.
//!
//! VAULT-VM = B is the ruled direction and OF-307 = A builds it now: this
//! driver boots, sleeps, restores and stops a vault VM, and `oneiron-server
//! host vm` runs one vault behind it. No deployment adopts it until the
//! owner answers the wake-budget bench, and nothing here is tuned for it.
//!
//! The guest is the managed engine with `--vsock-guest`. The host hands it
//! the credential frame on the boot port, waits for the ready byte, then
//! drives its lifecycle connection. Sleep freezes the vault through ctl,
//! asks the guest for its next wake, and snapshots RAM only when the guest
//! says no off-record stretch is open (OFFREC-SNAPSHOT = A); otherwise the
//! vault stops, as a reap does on a node. A snapshot is published by rename
//! and consumed by rename before it is loaded, so one RAM image never resumes
//! twice. Placement, the jailer, cgroups and per-vault UIDs stay with the
//! supervisor that runs this driver.

use super::listener::bind_unix_socket;
use super::vault_gates::read_managed_credentials;
use super::vm_schedule::VmWakeSchedule;
use oneiron_vault_contract::vm::{
    MAX_VM_FRAME, VM_ARTIFACT_PORT, VM_BOOT_PORT, VM_CTL_PORT, VM_GUEST_CID, VM_HTTP_PORT,
    VM_LEDGER_PORT, VmGuestFrame, VmHostFrame, decode_vm_frame, encode_vm_frame,
    guest_initiated_socket, host_connect_line,
};
use oneiron_vault_contract::{
    CREDENTIALS_LEN, Credentials, CtlRequest, CtlResponse, DEK_LEN, LedgerAck, LedgerUpdate,
    MAX_CTL_LINE, READY_BYTE, TokenHex, UnixTs, now_ts, valid_vault_name,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{
    UnixListener, UnixStream,
    unix::{OwnedReadHalf, OwnedWriteHalf},
};
use zeroize::Zeroizing;

const API_TIMEOUT: Duration = Duration::from_secs(10);
const API_SOCKET_WAIT: Duration = Duration::from_secs(5);
const STOP_GRACE: Duration = Duration::from_secs(10);

/// Host paths and sizes for one vault VM. Unix socket paths are short, so
/// `state_dir` should be too.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultVmConfig {
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    /// The engine image, read-only.
    pub rootfs: PathBuf,
    /// This vault's own disk, read-write; the guest mounts its data dir here.
    pub vault_disk: PathBuf,
    /// Owner-only directory for the API and vsock sockets and the snapshot.
    pub state_dir: PathBuf,
    pub vcpus: u8,
    pub mem_mib: u32,
    #[serde(default = "default_boot_args")]
    pub boot_args: String,
    /// External web client origins, passed to the guest's managed HTTP app.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Whether the guest serves an artifact origin, reached on
    /// [`VM_ARTIFACT_PORT`] (OF-356).
    #[serde(default)]
    pub artifact_origin: bool,
    /// The domains that origin answers under (`<vault>.<domain>`).
    #[serde(default)]
    pub artifact_domains: Vec<String>,
}
fn default_boot_args() -> String {
    "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/sbin/oneiron-vault-init".into()
}

/// What a sleep did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SleepOutcome {
    /// Work was in flight; the vault was thawed and keeps running.
    Busy,
    /// RAM is on disk and the VMM is gone. The next start restores it.
    Snapshotted { next_wake: Option<UnixTs> },
    /// An off-record stretch was open, so the vault stopped instead.
    Stopped { next_wake: Option<UnixTs> },
}

struct Lifecycle {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

/// One vault's VM and the host sockets that reach it.
pub struct VaultVm {
    config: VaultVmConfig,
    vault: String,
    boot: UnixListener,
    child: Option<tokio::process::Child>,
    lifecycle: Option<Lifecycle>,
    schedule: VmWakeSchedule,
}

impl VaultVm {
    /// Makes the state directory and binds the boot port's host socket, both
    /// before any VMM runs, so a guest never dials an unbound port.
    pub fn prepare(config: VaultVmConfig, vault: String) -> anyhow::Result<Self> {
        anyhow::ensure!(valid_vault_name(&vault), "invalid vault name");
        crate::web_client::parse_allowed_origins(&config.allowed_origins)?;
        std::fs::create_dir_all(&config.state_dir)?;
        std::fs::set_permissions(&config.state_dir, std::fs::Permissions::from_mode(0o700))?;
        let schedule = VmWakeSchedule::load(config.state_dir.join("wake-ledger.json"), &vault)?;
        let vsock = config.state_dir.join("vsock.sock");
        let boot = bind_unix_socket(&guest_initiated_socket(&vsock, VM_BOOT_PORT))?;
        Ok(Self {
            config,
            vault,
            boot,
            child: None,
            lifecycle: None,
            schedule,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.config.state_dir.join(name)
    }

    /// Where the guest's ledger pushes arrive. The supervisor binds it.
    pub fn ledger_socket(&self) -> PathBuf {
        guest_initiated_socket(&self.path("vsock.sock"), VM_LEDGER_PORT)
    }

    pub fn has_snapshot(&self) -> bool {
        self.path("vm.snap").is_file() && self.path("vm.mem").is_file()
    }

    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }

    /// Restores the published snapshot if there is one, else boots cold.
    /// Returns once the vault reported ready (cold) or rejoined (restore).
    pub async fn start(
        &mut self,
        credentials: &Credentials,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        if self.has_snapshot() {
            self.restore(timeout).await
        } else {
            self.cold_boot(credentials, timeout).await
        }
    }

    async fn spawn_vmm(&mut self) -> anyhow::Result<()> {
        let api = self.path("api.sock");
        for stale in [&api, &self.path("vsock.sock")] {
            match std::fs::remove_file(stale) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let mut command =
            tokio::process::Command::from(oneiron_spawn::command(&self.config.firecracker));
        command
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .arg("--api-sock")
            .arg(&api);
        self.child = Some(command.spawn()?);
        let deadline = Instant::now() + API_SOCKET_WAIT;
        while !api.exists() {
            anyhow::ensure!(
                Instant::now() < deadline,
                "firecracker API socket never appeared"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }

    /// One Firecracker API call. A non-2xx answer carries its fault message.
    async fn api(&self, method: &str, path: &str, body: serde_json::Value) -> anyhow::Result<()> {
        let call = async {
            let body = body.to_string();
            let mut stream = UnixStream::connect(self.path("api.sock")).await?;
            let request = format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(request.as_bytes()).await?;
            let mut reader = BufReader::new(stream);
            let mut status = String::new();
            reader.read_line(&mut status).await?;
            let code: u16 = status
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse().ok())
                .ok_or_else(|| anyhow::anyhow!("firecracker answered without a status"))?;
            if (200..300).contains(&code) {
                return Ok(());
            }
            let mut length = 0usize;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).await? == 0 || header == "\r\n" {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut fault = vec![0u8; length.min(4096)];
            reader.read_exact(&mut fault).await?;
            anyhow::bail!(
                "firecracker {method} {path}: {code} {}",
                String::from_utf8_lossy(&fault)
            )
        };
        tokio::time::timeout(API_TIMEOUT, call).await?
    }

    async fn cold_boot(
        &mut self,
        credentials: &Credentials,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        self.spawn_vmm().await?;
        let config = &self.config;
        let mut boot_args = config.boot_args.clone();
        let origins = crate::web_client::parse_allowed_origins(&config.allowed_origins)?;
        if !origins.is_empty() {
            let origins = origins
                .iter()
                .map(|origin| origin.to_str())
                .collect::<Result<Vec<_>, _>>()?;
            boot_args.push_str(" oneiron.allowed_origins=");
            boot_args.push_str(&origins.join(","));
        }
        if config.artifact_origin {
            boot_args.push_str(" oneiron.artifact_origin=1");
            let domains: Vec<String> = config
                .artifact_domains
                .iter()
                .map(|domain| {
                    oneiron_vault_contract::artifact_origin::normalize_artifact_domain(domain)
                })
                .filter(|domain| !domain.is_empty())
                .collect();
            anyhow::ensure!(
                domains.iter().all(|domain| domain
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')),
                "an artifact domain is letters, digits, '-' and '.'"
            );
            if !domains.is_empty() {
                boot_args.push_str(" oneiron.artifact_domains=");
                boot_args.push_str(&domains.join(","));
            }
        }
        self.api(
            "PUT",
            "/boot-source",
            json!({
                "kernel_image_path": config.kernel, "boot_args": boot_args,
            }),
        )
        .await?;
        self.api(
            "PUT",
            "/drives/rootfs",
            json!({
                "drive_id": "rootfs", "path_on_host": config.rootfs,
                "is_root_device": true, "is_read_only": true,
            }),
        )
        .await?;
        self.api(
            "PUT",
            "/drives/vault",
            json!({
                "drive_id": "vault", "path_on_host": config.vault_disk,
                "is_root_device": false, "is_read_only": false,
            }),
        )
        .await?;
        self.api(
            "PUT",
            "/machine-config",
            json!({
                "vcpu_count": config.vcpus, "mem_size_mib": config.mem_mib, "smt": false,
            }),
        )
        .await?;
        self.api(
            "PUT",
            "/vsock",
            json!({
                "guest_cid": VM_GUEST_CID, "uds_path": self.path("vsock.sock"),
            }),
        )
        .await?;
        self.api("PUT", "/actions", json!({ "action_type": "InstanceStart" }))
            .await?;

        // The credential connection: the frame, a half-close for the guest's
        // EOF check, then the ready byte back.
        let (mut stream, _) = tokio::time::timeout(timeout, self.boot.accept()).await??;
        let mut frame = Zeroizing::new([0u8; CREDENTIALS_LEN]);
        frame[..DEK_LEN].copy_from_slice(&credentials.dek);
        frame[DEK_LEN..].copy_from_slice(&credentials.token);
        stream.write_all(&frame[..]).await?;
        stream.shutdown().await?;
        let ready = tokio::time::timeout(timeout, stream.read_u8()).await??;
        anyhow::ensure!(ready == READY_BYTE, "vault VM sent a wrong ready byte");
        self.accept_join(timeout).await
    }

    async fn accept_join(&mut self, timeout: Duration) -> anyhow::Result<()> {
        let (stream, _) = tokio::time::timeout(timeout, self.boot.accept()).await??;
        let (reader, writer) = stream.into_split();
        self.lifecycle = Some(Lifecycle {
            reader: BufReader::new(reader),
            writer,
        });
        match self.read_guest(timeout).await? {
            VmGuestFrame::Join { vault } if vault == self.vault => Ok(()),
            _ => anyhow::bail!("vault VM joined as another vault"),
        }
    }

    async fn send(&mut self, frame: &VmHostFrame) -> anyhow::Result<()> {
        let line = encode_vm_frame(frame)?;
        let lifecycle = self
            .lifecycle
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("vault VM has no lifecycle connection"))?;
        lifecycle.writer.write_all(line.as_bytes()).await?;
        Ok(lifecycle.writer.flush().await?)
    }

    async fn read_guest(&mut self, timeout: Duration) -> anyhow::Result<VmGuestFrame> {
        let lifecycle = self
            .lifecycle
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("vault VM has no lifecycle connection"))?;
        let mut line = String::new();
        let mut bounded = (&mut lifecycle.reader).take(MAX_VM_FRAME as u64 + 1);
        anyhow::ensure!(
            tokio::time::timeout(timeout, bounded.read_line(&mut line)).await?? > 0,
            "vault VM closed its lifecycle connection"
        );
        decode_vm_frame(&line)
    }

    /// A host-initiated stream to a guest port, past Firecracker's handshake.
    pub async fn connect(&self, port: u32) -> anyhow::Result<UnixStream> {
        let mut stream = UnixStream::connect(self.path("vsock.sock")).await?;
        stream.write_all(host_connect_line(port).as_bytes()).await?;
        // Byte by byte, so no guest byte after the handshake is consumed.
        let mut answer = Vec::new();
        loop {
            let byte = stream.read_u8().await?;
            if byte == b'\n' {
                break;
            }
            answer.push(byte);
            anyhow::ensure!(answer.len() < 64, "vsock handshake overran");
        }
        anyhow::ensure!(answer.starts_with(b"OK "), "guest port {port} refused");
        Ok(stream)
    }

    /// The vault's HTTP surface.
    pub async fn http(&self) -> anyhow::Result<UnixStream> {
        self.connect(VM_HTTP_PORT).await
    }

    /// The vault's artifact origin, when its profile serves one.
    pub async fn artifacts(&self) -> anyhow::Result<UnixStream> {
        self.connect(VM_ARTIFACT_PORT).await
    }

    /// One ctl verb, exactly as a node's supervisor sends it.
    pub async fn ctl(&self, request: &CtlRequest) -> anyhow::Result<CtlResponse> {
        let stream = self.connect(VM_CTL_PORT).await?;
        let (reader, mut writer) = stream.into_split();
        let mut line = serde_json::to_string(request)?;
        line.push('\n');
        writer.write_all(line.as_bytes()).await?;
        let mut reply = String::new();
        let mut reader = BufReader::new(reader.take(MAX_CTL_LINE as u64 + 2));
        tokio::time::timeout(API_TIMEOUT, reader.read_line(&mut reply)).await??;
        let response: CtlResponse = serde_json::from_str(reply.trim_end_matches(['\r', '\n']))?;
        response.validate()?;
        Ok(response)
    }

    /// Pauses the guest in RAM, the cheapest sleep. [`Self::resume`] undoes it.
    pub async fn pause(&self) -> anyhow::Result<()> {
        self.api("PATCH", "/vm", json!({ "state": "Paused" })).await
    }

    pub async fn resume(&mut self) -> anyhow::Result<()> {
        self.api("PATCH", "/vm", json!({ "state": "Resumed" }))
            .await?;
        self.send(&VmHostFrame::Resumed).await
    }

    /// Freezes the vault, asks for its next wake, and snapshots or stops it.
    pub async fn sleep(&mut self, timeout: Duration) -> anyhow::Result<SleepOutcome> {
        let CtlResponse::PrepareReap {
            quiescent,
            ledger_rev,
            next_wake,
        } = self.ctl(&CtlRequest::PrepareReap).await?
        else {
            anyhow::bail!("prepare_reap answered with another verb");
        };
        self.schedule.replace(ledger_rev, next_wake)?;
        if !quiescent {
            self.ctl(&CtlRequest::ReapAbort).await?;
            return Ok(SleepOutcome::Busy);
        }
        self.send(&VmHostFrame::Sleep).await?;
        let (next_wake, snapshot_ok) = loop {
            if let VmGuestFrame::Idle {
                next_wake,
                snapshot_ok,
            } = self.read_guest(timeout).await?
            {
                break (next_wake, snapshot_ok);
            }
        };
        if !snapshot_ok {
            self.stop(STOP_GRACE).await?;
            return Ok(SleepOutcome::Stopped { next_wake });
        }
        self.pause().await?;
        let (snap_tmp, mem_tmp) = (self.path("vm.snap.tmp"), self.path("vm.mem.tmp"));
        self.api(
            "PUT",
            "/snapshot/create",
            json!({
                "snapshot_type": "Full", "snapshot_path": snap_tmp, "mem_file_path": mem_tmp,
            }),
        )
        .await?;
        for file in [&mem_tmp, &snap_tmp] {
            std::fs::File::open(file)?.sync_all()?;
        }
        // The state file last: its presence is what publishes the snapshot.
        std::fs::rename(&mem_tmp, self.path("vm.mem"))?;
        std::fs::rename(&snap_tmp, self.path("vm.snap"))?;
        std::fs::File::open(&self.config.state_dir)?.sync_all()?;
        self.kill().await;
        Ok(SleepOutcome::Snapshotted { next_wake })
    }

    async fn restore(&mut self, timeout: Duration) -> anyhow::Result<()> {
        // Consumed before load: a crash from here on never resumes this RAM
        // a second time, it boots cold from the vault disk instead.
        let (snap, mem) = (self.path("vm.snap.taken"), self.path("vm.mem.taken"));
        std::fs::rename(self.path("vm.snap"), &snap)?;
        std::fs::rename(self.path("vm.mem"), &mem)?;
        self.spawn_vmm().await?;
        let loaded = self
            .api(
                "PUT",
                "/snapshot/load",
                json!({
                    "snapshot_path": snap,
                    "mem_backend": { "backend_type": "File", "backend_path": mem },
                    "resume_vm": true,
                }),
            )
            .await;
        let _ = std::fs::remove_file(&snap);
        loaded?;
        self.accept_join(timeout).await?;
        self.send(&VmHostFrame::Resumed).await?;
        // The memory file backs guest RAM until the VMM exits; unlinking it
        // keeps the pages and leaves nothing to resume twice.
        let _ = std::fs::remove_file(&mem);
        // Thaw the reap freeze taken before the snapshot.
        self.ctl(&CtlRequest::ReapAbort).await?;
        Ok(())
    }

    /// Asks the vault to stop and kills the VMM when the grace runs out.
    pub async fn stop(&mut self, grace: Duration) -> anyhow::Result<()> {
        if self.lifecycle.is_some() {
            let _ = self.send(&VmHostFrame::Stop).await;
        }
        if let Some(child) = self.child.as_mut()
            && tokio::time::timeout(grace, child.wait()).await.is_err()
        {
            let _ = child.kill().await;
        }
        self.child = None;
        self.lifecycle = None;
        Ok(())
    }

    async fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
        }
        self.lifecycle = None;
    }
}

/// `oneiron-server host vm`: one vault VM behind one unix socket. It starts
/// the VM on the first connection or a due wake, proxies HTTP into it, takes
/// its ledger pushes, and sleeps it after `idle` without traffic.
pub struct VaultVmRun {
    pub config: PathBuf,
    pub vault_name: String,
    pub listen: PathBuf,
    pub credentials_fd: std::os::fd::RawFd,
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
    let credentials = read_managed_credentials(run.credentials_fd)?;
    let token = TokenHex::from_token(&credentials.token);
    let mut vm = VaultVm::prepare(config, run.vault_name.clone())?;
    let front = bind_unix_socket(&run.listen)?;
    let ledger = bind_unix_socket(&vm.ledger_socket())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let open = Arc::new(AtomicUsize::new(0));
    let mut last_activity = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = terminate.recv() => break,
            accepted = front.accept() => {
                let (mut client, _) = accepted?;
                if !vm.is_running() {
                    vm.start(&credentials, API_TIMEOUT).await?;
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
                    vm.start(&credentials, API_TIMEOUT).await?;
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
