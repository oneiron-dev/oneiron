//! `oneiron-server host vm`: one vault as a Firecracker VM behind a unix
//! socket.

use clap::Args;
use std::fmt;
use std::path::PathBuf;

#[derive(Args, Clone)]
pub struct HostVmArgs {
    /// JSON VM profile: firecracker, kernel, rootfs, vault_disk, state_dir,
    /// vcpus, mem_mib, the provision binding (guest_uid, derivation_owner,
    /// vault_disk_uuid, fscrypt_key_identifier), network (the guest NIC's
    /// tap_name and guest_mac, or null for none) and optional boot_args,
    /// allowed_origins, artifact_origin, config_disk, outbox and
    /// restore_source_disk.
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub vault_name: String,
    /// The unix socket clients connect to; each connection is proxied into
    /// the vault's HTTP surface. An inspection takes none.
    #[arg(long, required_unless_present = "restore_marker_identity_fd")]
    pub listen: Option<PathBuf>,
    /// Inherited descriptor carrying the 64-byte DEK and spawn-token frame.
    /// With `--restore` it is read only once the restore's input has ended.
    /// An inspection takes none.
    #[arg(long, required_unless_present = "restore_marker_identity_fd")]
    pub credentials_fd: Option<i32>,
    /// Inherited descriptor carrying exactly the vault's 64-byte name-bound
    /// fscrypt v2 master key (FIX 6308). It is read once and sent to the
    /// guest on each cold boot; its owner keeps it, and the profile never
    /// holds it. A restore and an inspection read it first, so its owner
    /// writes it before the restore's input or beside it.
    #[arg(long)]
    pub fscrypt_key_fd: i32,
    /// Starts the VM at once with a cold restore of the vault into its disk
    /// (FIX 6584): the guest's engine takes `--restore-input-fd`'s bytes as
    /// its own input pipe and its result frames come back on
    /// `--restore-result-fd`, exactly as a node's child takes and writes
    /// them. The socket is bound once the restored vault is ready.
    #[arg(long, requires_all = ["restore_input_fd", "restore_result_fd"])]
    pub restore: bool,
    /// Inherited descriptor, the read end of a pipe, carrying the restore's
    /// input: one `ManagedRestoreInput` JSON object, then EOF.
    #[arg(long, requires = "restore")]
    pub restore_input_fd: Option<i32>,
    /// Inherited descriptor, the write end of a pipe, taking the restore's
    /// result frames, one JSON line each; closed after the last.
    #[arg(long, requires = "restore")]
    pub restore_result_fd: Option<i32>,
    /// Inspects the vault's disk for a restore whose result was lost while
    /// no guest serves it, then exits (FIX 6584): inherited descriptor, the
    /// read end of a pipe, carrying the restore's `ManagedRestoreIdentity`,
    /// one JSON object, then EOF. Every other generation of the vault is
    /// confirmed dead first.
    #[arg(
        long,
        requires = "restore_marker_result_fd",
        conflicts_with_all = [
            "listen",
            "credentials_fd",
            "restore",
            "custody_anchor_url",
            "custody_anchor_credentials_fd",
        ]
    )]
    pub restore_marker_identity_fd: Option<i32>,
    /// The inspection's answer: inherited descriptor, the write end of a
    /// pipe, taking one `VmRestoreMarkerObservation` JSON object, then EOF.
    #[arg(long, requires = "restore_marker_identity_fd")]
    pub restore_marker_result_fd: Option<i32>,
    /// The custody anchor URL the vault's effective settings bind, a
    /// restore's plan included, exactly as they spell it (FIX 6517): every
    /// serving boot's guest is told it, and the host's anchor proxy reaches
    /// its host and port and nothing else. It is never logged. An inspection
    /// takes none.
    #[arg(long)]
    pub custody_anchor_url: Option<String>,
    /// Inherited descriptor, the read end of a pipe, carrying the custody
    /// anchor door's owner credential for `--custody-anchor-url`, exactly as
    /// a node's engine takes it: one JSON object, then EOF. It is read once,
    /// after the first credential frame went to the guest, held in memory
    /// and handed to the guest after each cold boot's credential frame.
    #[arg(long, requires = "custody_anchor_url")]
    pub custody_anchor_credentials_fd: Option<i32>,
    /// Seconds without traffic before the vault sleeps.
    #[arg(long, default_value_t = 300)]
    pub idle_secs: u64,
}

impl fmt::Debug for HostVmArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostVmArgs")
            .field("config", &self.config)
            .field("vault_name", &self.vault_name)
            .field("listen", &self.listen)
            .field("credentials_fd", &self.credentials_fd)
            .field("fscrypt_key_fd", &self.fscrypt_key_fd)
            .field("restore", &self.restore)
            .field("restore_input_fd", &self.restore_input_fd)
            .field("restore_result_fd", &self.restore_result_fd)
            .field(
                "restore_marker_identity_fd",
                &self.restore_marker_identity_fd,
            )
            .field("restore_marker_result_fd", &self.restore_marker_result_fd)
            .field(
                "custody_anchor_url",
                &self.custody_anchor_url.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "custody_anchor_credentials_fd",
                &self.custody_anchor_credentials_fd,
            )
            .field("idle_secs", &self.idle_secs)
            .finish()
    }
}

#[cfg(target_os = "linux")]
pub(super) async fn run(args: HostVmArgs) -> anyhow::Result<()> {
    if let (Some(identity_fd), Some(result_fd)) = (
        args.restore_marker_identity_fd,
        args.restore_marker_result_fd,
    ) {
        return crate::managed::inspect_vault_vm(crate::managed::VaultVmInspect {
            config: args.config,
            vault_name: args.vault_name,
            fscrypt_key_fd: args.fscrypt_key_fd,
            identity_fd,
            result_fd,
        })
        .await;
    }
    let (Some(listen), Some(credentials_fd)) = (args.listen, args.credentials_fd) else {
        anyhow::bail!("host vm takes --listen and --credentials-fd unless it inspects");
    };
    let restore = match (args.restore_input_fd, args.restore_result_fd) {
        (Some(input_fd), Some(result_fd)) if args.restore => Some(crate::managed::VmRestoreFds {
            input_fd,
            result_fd,
        }),
        _ => None,
    };
    crate::managed::run_vault_vm(crate::managed::VaultVmRun {
        config: args.config,
        vault_name: args.vault_name,
        listen,
        credentials_fd,
        fscrypt_key_fd: args.fscrypt_key_fd,
        restore,
        custody_anchor_url: args.custody_anchor_url,
        custody_anchor_credentials_fd: args.custody_anchor_credentials_fd,
        idle: std::time::Duration::from_secs(args.idle_secs),
    })
    .await
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn run(_args: HostVmArgs) -> anyhow::Result<()> {
    anyhow::bail!("vault VMs need Linux with KVM")
}
