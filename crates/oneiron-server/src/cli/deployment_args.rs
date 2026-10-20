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
    /// The supervisor's restricted hold-guard broker socket, an absolute
    /// path (FIX 6826). With any hold-guard flag the room starts guarded: its
    /// vault's engine executes each locker delete inside its backup-hold
    /// exclusion, the room keeps the directory modes its host provisioned
    /// (objects 02770) and uploads 0660, and a broker or engine it cannot
    /// reach defers every delete. With none it starts as before.
    #[arg(long, requires = "hold_guard_vault")]
    pub hold_guard_socket: Option<PathBuf>,
    /// The room's vault, by its registry id: a canonical lowercase UUID,
    /// never derived from the config's engine `vault_id`.
    #[arg(long, requires = "hold_guard_socket")]
    pub hold_guard_vault: Option<String>,
    /// Refuse to start unless the room is guarded: both other hold-guard
    /// flags are given.
    #[arg(long, requires = "hold_guard_socket")]
    pub hold_guard_required: bool,
}
