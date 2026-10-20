//! `oneiron-server host vm`: one vault as a Firecracker VM behind a unix
//! socket.

use clap::Args;
use std::path::PathBuf;

#[derive(Args, Clone, Debug)]
pub struct HostVmArgs {
    /// JSON VM profile: firecracker, kernel, rootfs, vault_disk, state_dir,
    /// vcpus, mem_mib and optional boot_args and allowed_origins.
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub vault_name: String,
    /// The unix socket clients connect to; each connection is proxied into
    /// the vault's HTTP surface.
    #[arg(long)]
    pub listen: PathBuf,
    /// Inherited descriptor carrying the 64-byte DEK and spawn-token frame.
    #[arg(long)]
    pub credentials_fd: i32,
    /// Seconds without traffic before the vault sleeps.
    #[arg(long, default_value_t = 300)]
    pub idle_secs: u64,
}

#[cfg(target_os = "linux")]
pub(super) async fn run(args: HostVmArgs) -> anyhow::Result<()> {
    crate::managed::run_vault_vm(crate::managed::VaultVmRun {
        config: args.config,
        vault_name: args.vault_name,
        listen: args.listen,
        credentials_fd: args.credentials_fd,
        idle: std::time::Duration::from_secs(args.idle_secs),
    })
    .await
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn run(_args: HostVmArgs) -> anyhow::Result<()> {
    anyhow::bail!("vault VMs need Linux with KVM")
}
