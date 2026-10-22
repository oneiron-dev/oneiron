//! The microVM adapter's host half: one Firecracker VM per vault.
//!
//! VAULT-VM = B is the ruled direction and OF-307 = A builds it now: this
//! driver boots, sleeps, restores and stops a vault VM, and `oneiron-server
//! host vm` runs one vault behind it. No deployment adopts it until the
//! owner answers the wake-budget bench, and nothing here is tuned for it.
//!
//! The guest is the managed engine with `--vsock-guest`, started by the
//! image's root bootstrap as the vault's own non-root UID. On a cold boot the
//! host first answers that bootstrap's provision connection with the vault's
//! binding and fscrypt key (FIX 6308, [`provision`]), then hands the engine
//! the credential frame on the boot port, waits for the ready byte, then
//! drives its lifecycle connection. Sleep freezes the vault through ctl,
//! asks the guest for its next wake, and snapshots RAM only when the guest
//! says no off-record stretch is open (OFFREC-SNAPSHOT = A); otherwise the
//! vault stops, as a reap does on a node. A snapshot is published by rename
//! and consumed by rename before it is loaded, so one RAM image never resumes
//! twice. Placement, the jailer and cgroups stay with the supervisor that
//! runs this driver; the guest's UID is the one its provision binding names.
//! A profile with an `outbox` binds the outbox carrier's attachment before
//! the VMM starts (FIX 5235, `VmOutboxAttachment`): parked before a
//! snapshot, opened on each start, drained on a stop. Every cold boot opens
//! with the guest's restore channel, which names the boot's mode before
//! anything is provisioned: an ordinary open, a cold restore of a plan the
//! supervisor streams in, or an inspection of the disk's restore commit
//! marker (FIX 6584, [`restore`]). A running VMM's exit is watched through
//! a pidfd taken at its spawn, which tasks await beside the driver's other
//! calls (FIX 7047, [`VmExitWatch`]). A boot that serves then reads the
//! custody anchor's header, and gets the door's owner credential after its
//! credential frame; each generation's proxy carries the guest's streams to
//! the one anchor URL the supervisor bound (FIX 6517, [`anchor`]). A profile
//! with a `network` has the supervisor's TAP attached as the guest's one NIC
//! on every boot, before the instance starts (FIX 6808, [`network`]).
//! Every reap of a VMM reads its exit through the watch first, a dropped
//! driver's on a thread of its own (FIX 7126, [`reaper`]), and each spawn
//! first drops what an earlier, reaped generation left queued on the boot
//! port's, the restore channel's and the custody anchor's two sockets (FIX
//! 7077, FIX 7480, FIX 7182, [`backlog`]).

mod anchor;
mod backlog;
mod credentials;
mod exit;
mod network;
mod provision;
mod reaper;
mod restore;
mod runner;

pub use self::anchor::VmAnchorHostIo;
pub use self::exit::VmExitWatch;
pub use self::restore::{VaultVmInspect, VmRestoreFds, VmRestoreHostIo, inspect_vault_vm};
pub use self::runner::{VaultVmRun, run_vault_vm};
use super::listener::bind_unix_socket;
use super::vm_outbox::{VmOutboxAttachment, VmOutboxHostRoots};
use super::vm_schedule::VmWakeSchedule;
use oneiron_vault_contract::vm::{
    MAX_VM_FRAME, VM_ARTIFACT_PORT, VM_BOOT_PORT, VM_CTL_PORT, VM_GUEST_CID, VM_HTTP_PORT,
    VM_LEDGER_PORT, VM_OUTBOX_PORT, VM_RESTORE_PORT, VM_VOICE_PORT, VmGuestFrame, VmHostFrame,
    VmTapAttachment, decode_vm_frame, encode_vm_frame, guest_initiated_socket, host_connect_line,
};
use oneiron_vault_contract::vm_provision::{VmFscryptKey, VmProvisionBinding};
use oneiron_vault_contract::vm_restore::VmRestoreBoot;
use oneiron_vault_contract::{
    CREDENTIALS_LEN, Credentials, CtlRequest, CtlResponse, DEK_LEN, MAX_CTL_LINE, READY_BYTE,
    UnixTs, valid_vault_name,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Stdio,
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
    /// This vault's own disk, read-write: ext4 with its `encrypt` feature,
    /// which the guest mounts at `/vault` and keeps its fscrypt storage, data
    /// directory and key directory on.
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
    /// [`VM_ARTIFACT_PORT`] (OF-356). It answers on the vault's internal
    /// authority, `<vault_id>.artifact.invalid`, bound to the vault the boot
    /// arguments name (FIX 6716).
    #[serde(default)]
    pub artifact_origin: bool,
    /// This vault's managed settings files, as a read-only ext4 image the
    /// supervisor builds (FIX 2168, FIX 3487, FIX 777). The guest mounts it
    /// at `/config` and passes each file it holds to the engine:
    /// `settings.toml`, the owner's settings in the server's config schema
    /// (`[models]`, `[embedder]` and `[gpu]` among them), as
    /// `--settings-file`, and under `seal/` `key.pem`, `chain.pem`,
    /// `trust.pem` and `organ` as the matching `--seal-*-file` and
    /// `--seal-organ` flags, the one-line `tsa-url` and `signing-url` as
    /// `--seal-tsa-url` and `--seal-signing-url`, the one-line
    /// `oauth-resource-indicator` and `kit-bundle-public-urls` (the host's
    /// public https origin, and the comma-separated URLs a kit dials) as the
    /// flags of those names, and each line of `trusted-organ-builds`, an organ
    /// build's blake3, as its own `--trusted-organ-build` (FIX 7889, an image
    /// whose manifest names `vm_trusted_organ_builds_revision`). Files a
    /// settings path names may sit beside it.
    /// The guest's bootstrap reads its typed files itself: `network.json`
    /// (below), and the managed profile's five files (FIX 6809), which give
    /// the engine its `--organization-owner`, `--member-vault`,
    /// `--failure-signal-export`, `--failure-signal-training` and
    /// `--fast-dims`. It reads the guests' one-line runtime bindings,
    /// `browser-runtime` and `desktop-runtime`, itself too (FIX 7671): each
    /// must name the image's own guest-local container CLI, and the engine
    /// gets it only once the bootstrap has prepared that runtime for the
    /// vault's UID; no host path is a binding. Without it the guest runs
    /// with none of them.
    #[serde(default)]
    pub config_disk: Option<PathBuf>,
    /// The vault's provision binding (FIX 6308): the UID its engine runs as,
    /// its derivation owner, `vault_disk`'s filesystem UUID and its fscrypt
    /// key's identifier. Required: a profile without a valid one never boots,
    /// and a guest that finds it contradicted refuses its provisioning.
    pub provision: VmProvisionBinding,
    /// Where this host keeps the vault's outboxes and the carrier's records
    /// (FIX 5235): the trees its shippers read. Without it no attachment is
    /// bound, and the guest keeps its outbox work, deferred.
    #[serde(default)]
    pub outbox: Option<VmOutboxHostRoots>,
    /// A cold restore's source drive (FIX 6584): a read-only ext4 image the
    /// supervisor stages with the sealed artifact and its keyless custody
    /// head, never a secret or unsealed bytes. Only a restore's boot attaches
    /// it, after the drives above, and the guest mounts it at `/restore`,
    /// below which the plan names its paths. Without it the plan's sources
    /// are ones the guest already reads.
    #[serde(default)]
    pub restore_source_disk: Option<PathBuf>,
    /// The guest's one NIC (FIX 6808, [`network`]): the TAP the supervisor
    /// made and ruled for this vault, and the MAC the guest's NIC takes on
    /// it, attached on every boot. It needs `config_disk`, whose
    /// `network.json` gives the guest the same plan's addresses. Required:
    /// `null` for a VM with no network.
    #[serde(deserialize_with = "Option::deserialize")]
    pub network: Option<VmTapAttachment>,
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
    /// An off-record stretch was open, or the VM's boot attached a cold
    /// restore's source drive, so the vault stopped instead.
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
    /// The restore channel's host socket, every cold boot's first dial.
    restore: UnixListener,
    /// The running generation's boot attached the restore's source drive,
    /// so it never takes a RAM snapshot: a snapshot loads its drives again
    /// from their host paths, and the staged source may be gone by then, so
    /// a sleep stops it instead.
    source_attached: bool,
    child: Option<tokio::process::Child>,
    /// The watch on `child`'s exit, held with it.
    exit: Option<VmExitWatch>,
    lifecycle: Option<Lifecycle>,
    schedule: VmWakeSchedule,
    outbox: Option<VmOutboxAttachment>,
    /// The custody anchor's exchange and proxy, and what they are bound to.
    anchor: anchor::HostAnchor,
}

impl VaultVm {
    /// Makes the state directory and binds the boot port's, the restore
    /// channel's and the custody anchor's host sockets, and the outbox
    /// carrier's when the profile names its roots, all before any VMM runs,
    /// so a guest never dials an unbound port. A profile not in its form is
    /// refused before any of it.
    pub fn prepare(config: VaultVmConfig, vault: String) -> anyhow::Result<Self> {
        anyhow::ensure!(valid_vault_name(&vault), "invalid vault name");
        if let Err(fault) = config.provision.validate() {
            anyhow::bail!("the VM profile's provision binding: {fault}");
        }
        crate::web_client::parse_allowed_origins(&config.allowed_origins)?;
        network::validate(&config)?;
        std::fs::create_dir_all(&config.state_dir)?;
        std::fs::set_permissions(&config.state_dir, std::fs::Permissions::from_mode(0o700))?;
        let schedule = VmWakeSchedule::load(config.state_dir.join("wake-ledger.json"), &vault)?;
        let vsock = config.state_dir.join("vsock.sock");
        let boot = bind_unix_socket(&guest_initiated_socket(&vsock, VM_BOOT_PORT))?;
        let restore = bind_unix_socket(&guest_initiated_socket(&vsock, VM_RESTORE_PORT))?;
        let anchor = anchor::HostAnchor::bind(&vsock)?;
        let outbox = config
            .outbox
            .clone()
            .map(|roots| {
                let socket = guest_initiated_socket(&vsock, VM_OUTBOX_PORT);
                VmOutboxAttachment::bind(&socket, vault.clone(), roots)
            })
            .transpose()?;
        Ok(Self {
            config,
            vault,
            boot,
            restore,
            source_attached: false,
            child: None,
            exit: None,
            lifecycle: None,
            schedule,
            outbox,
            anchor,
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

    /// A watch on the running VMM's exit, which any number of tasks await
    /// while others use this VM ([`VmExitWatch::wait`]). `None` when no VMM
    /// child is held, or when the host's kernel gave no pidfd for it. Each
    /// start runs a new VMM, which a watch taken before it does not see.
    pub fn exit_watch(&self) -> Option<VmExitWatch> {
        self.exit.clone()
    }

    /// Restores the published snapshot if there is one, else boots cold,
    /// provisioning the guest with `fscrypt_key` first. Returns once the
    /// vault reported ready (cold) or rejoined (restore).
    pub async fn start(
        &mut self,
        credentials: &Credentials,
        fscrypt_key: &VmFscryptKey,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        if let Some(outbox) = &self.outbox {
            outbox.resume();
        }
        if self.has_snapshot() {
            self.restore(timeout).await
        } else {
            self.cold_boot(credentials, fscrypt_key, timeout).await
        }
    }

    async fn spawn_vmm(&mut self) -> anyhow::Result<()> {
        // Before the new VMM exists, and only once the last one is reaped.
        self.drop_stale_connections()?;
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
        let child = command.spawn()?;
        // A host whose kernel gives no pidfd runs the VMM all the same,
        // without an exit watch.
        self.exit = match VmExitWatch::of(&child) {
            Ok(exit) => Some(exit),
            Err(error) => {
                tracing::warn!(
                    reason = "vm_exit_watch_unavailable",
                    vault = %self.vault,
                    %error,
                    "the host gave no pidfd for the vault VM's VMM; it runs without an exit watch"
                );
                None
            }
        };
        self.child = Some(child);
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
        fscrypt_key: &VmFscryptKey,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        self.boot_vmm(false).await?;
        // An ordinary boot's restore channel says only that it opens.
        drop(self.answer_hello(&VmRestoreBoot::Open, timeout).await?);
        self.provision(fscrypt_key, timeout).await?;
        let anchor = self.send_anchor_header(timeout).await?;
        let mut stream = self.send_credentials(credentials, timeout).await?;
        self.deliver_anchor(anchor, timeout).await?;
        let ready = tokio::time::timeout(timeout, stream.read_u8()).await??;
        anyhow::ensure!(ready == READY_BYTE, "vault VM sent a wrong ready byte");
        self.accept_join(timeout).await
    }

    /// A fresh VMM, its kernel, drives, machine and vsock device and the
    /// profile's NIC set, and started. `with_source` attaches the profile's
    /// restore source drive read-only after the others, when it names one.
    async fn boot_vmm(&mut self, with_source: bool) -> anyhow::Result<()> {
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
        if config.config_disk.is_some() {
            boot_args.push_str(" oneiron.config=1");
        }
        if config.artifact_origin {
            boot_args.push_str(" oneiron.artifact_origin=1");
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
        // The third drive, `/dev/vdc` in the guest.
        if let Some(config_disk) = &config.config_disk {
            self.api(
                "PUT",
                "/drives/config",
                json!({
                    "drive_id": "config", "path_on_host": config_disk,
                    "is_root_device": false, "is_read_only": true,
                }),
            )
            .await?;
        }
        // After them, `/dev/vdc` or `/dev/vdd` in the guest.
        if let Some(source) = config.restore_source_disk.as_ref().filter(|_| with_source) {
            self.api(
                "PUT",
                "/drives/restore",
                json!({
                    "drive_id": "restore", "path_on_host": source,
                    "is_root_device": false, "is_read_only": true,
                }),
            )
            .await?;
        }
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
        self.attach_network().await?;
        self.api("PUT", "/actions", json!({ "action_type": "InstanceStart" }))
            .await
    }

    /// The credential connection: the frame and a half-close for the
    /// guest's EOF check. The ready byte comes back on the stream returned.
    async fn send_credentials(
        &mut self,
        credentials: &Credentials,
        timeout: Duration,
    ) -> anyhow::Result<UnixStream> {
        let (mut stream, _) = tokio::time::timeout(timeout, self.boot.accept()).await??;
        let mut frame = Zeroizing::new([0u8; CREDENTIALS_LEN]);
        frame[..DEK_LEN].copy_from_slice(&credentials.dek);
        frame[DEK_LEN..].copy_from_slice(&credentials.token);
        stream.write_all(&frame[..]).await?;
        stream.shutdown().await?;
        Ok(stream)
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

    /// The vault's voice loop, when its `[models.voice]` names a socket in
    /// `VM_VOICE_DIR` (FIX 2391): a call's audio sibling dials this.
    pub async fn voice(&self) -> anyhow::Result<UnixStream> {
        self.connect(VM_VOICE_PORT).await
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
            training: _,
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
        if !snapshot_ok || self.source_attached {
            self.stop(STOP_GRACE).await?;
            return Ok(SleepOutcome::Stopped { next_wake });
        }
        // No carrier commit is in flight on this end when RAM is taken.
        if let Some(outbox) = &self.outbox {
            outbox.park();
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
        // Beside the RAM, the anchor URL its guest was handed (FIX 7183).
        self.keep_snapshot_anchor()?;
        std::fs::rename(&mem_tmp, self.path("vm.mem"))?;
        // The state file last, once the files beside it are durable: its
        // presence is what publishes the snapshot.
        std::fs::File::open(&self.config.state_dir)?.sync_all()?;
        std::fs::rename(&snap_tmp, self.path("vm.snap"))?;
        std::fs::File::open(&self.config.state_dir)?.sync_all()?;
        self.kill().await;
        Ok(SleepOutcome::Snapshotted { next_wake })
    }

    async fn restore(&mut self, timeout: Duration) -> anyhow::Result<()> {
        // Consumed before load: a crash from here on never resumes this RAM
        // a second time, it boots cold from the vault disk instead. A restore
        // that fails, or is dropped, after a rename unlinks the name it took
        // (FIX 7702).
        let snap = TakenSnapshotFile::take(self.path("vm.snap"), self.path("vm.snap.taken"))?;
        let mem = TakenSnapshotFile::take(self.path("vm.mem"), self.path("vm.mem.taken"))?;
        let anchor = self.take_snapshot_anchor()?;
        self.spawn_vmm().await?;
        let loaded = self
            .api(
                "PUT",
                "/snapshot/load",
                json!({
                    "snapshot_path": snap.taken,
                    "mem_backend": { "backend_type": "File", "backend_path": mem.taken },
                    "resume_vm": true,
                }),
            )
            .await;
        snap.remove();
        loaded?;
        // The guest's anchor is the one its cold boot was handed, kept with
        // its snapshot whatever was attached since (FIX 7183).
        self.resume_anchor_proxy(anchor);
        self.accept_join(timeout).await?;
        self.send(&VmHostFrame::Resumed).await?;
        // The memory file backs guest RAM until the VMM exits; unlinking it
        // keeps the pages and leaves nothing to resume twice.
        mem.remove();
        // Thaw the reap freeze taken before the snapshot.
        self.ctl(&CtlRequest::ReapAbort).await?;
        Ok(())
    }

    /// Asks the vault to stop and kills the VMM when the grace runs out.
    /// The outbox attachment denies new transfers from here on and lets its
    /// commit in flight finish; the next start opens it again. The VMM's
    /// exit is read through the exit watch before it is reaped, whether the
    /// grace saw it or a kill ended it, so its waiters get the status (FIX
    /// 7126).
    pub async fn stop(&mut self, grace: Duration) -> anyhow::Result<()> {
        if let Some(outbox) = &self.outbox {
            outbox.drain();
        }
        if self.lifecycle.is_some() {
            let _ = self.send(&VmHostFrame::Stop).await;
        }
        let exit = self.exit.as_ref();
        let graceful = match self.child.as_mut() {
            // The watch reads the exit without reaping it; with none, or
            // one that fails, the reap is the grace's own.
            Some(child) => {
                let exited = async {
                    if let Some(exit) = exit
                        && exit.wait().await.is_ok()
                    {
                        return true;
                    }
                    child.wait().await.is_ok()
                };
                matches!(tokio::time::timeout(grace, exited).await, Ok(true))
            }
            None => true,
        };
        self.end_vmm(!graceful).await;
        self.lifecycle = None;
        self.source_attached = false;
        self.anchor.end_proxy();
        Ok(())
    }

    async fn kill(&mut self) {
        self.end_vmm(true).await;
        self.lifecycle = None;
        self.source_attached = false;
        self.anchor.end_proxy();
    }
}

/// A published snapshot file its restore consumed: renamed to its `.taken`
/// name, which only this restore holds. Dropped while armed, as a restore
/// that failed returns or is dropped, it unlinks that name, so no RAM-sized
/// file is left behind (FIX 7702). It never names the published file, which
/// the rename gave up.
struct TakenSnapshotFile {
    taken: PathBuf,
    /// Still to unlink when dropped: false once [`Self::remove`] did.
    armed: bool,
}

impl TakenSnapshotFile {
    /// Renames `source` to `taken`; the guard exists only once that rename
    /// did.
    fn take(source: PathBuf, taken: PathBuf) -> std::io::Result<Self> {
        std::fs::rename(source, &taken)?;
        Ok(Self { taken, armed: true })
    }

    /// Unlinks the taken name now, where the restore is done with it, and
    /// disarms the guard.
    fn remove(mut self) {
        self.armed = false;
        let _ = std::fs::remove_file(&self.taken);
    }
}

impl Drop for TakenSnapshotFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.taken);
        }
    }
}
