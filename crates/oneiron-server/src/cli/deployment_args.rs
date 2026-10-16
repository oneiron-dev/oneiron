//! Host-only deployment commands; neither opens a local vault.

use clap::Args;
use std::path::PathBuf;

#[derive(Args, Clone, Debug)]
pub struct HostRelayArgs {
    /// JSON room profile: vault_id, listen, locker_dir, access_token_file,
    /// relay_binary, relay_bind, relay_url, endpoint_keys,
    /// relay_metrics_bind, optional allowed_origins and max_object_bytes.
    /// relay_binary is iroh-relay built from the engine's pinned fork revision.
    #[arg(long)]
    pub config: PathBuf,
}
