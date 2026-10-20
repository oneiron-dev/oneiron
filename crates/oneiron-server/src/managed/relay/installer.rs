//! The `host relay` installer (FIX 6826, Engine 10-21).
//!
//! With no hold-guard flag the room starts as it always has
//! ([`run_relay`]). With any of `--hold-guard-socket`, `--hold-guard-vault`
//! or `--hold-guard-required` it starts guarded: it needs the broker socket
//! and the vault's registry id both, refuses to start without them, and
//! installs a [`CtlRelayHoldGuard`] for the room's engine vault id before
//! its first replay or listener. A broker or engine it cannot reach then
//! leaves every delete deferred; it never falls back to the plain room.

use std::sync::Arc;

use oneiron_vault_contract::relay_delete::valid_registry_uuid;

use super::ctl_hold_guard::CtlRelayHoldGuard;
use super::{RelayConfig, run_relay, run_relay_with_hold_guard};
use crate::cli::HostRelayArgs;

/// Starts the room `args` names: guarded when any hold-guard flag is given,
/// plain when none is.
pub(crate) async fn run_host_relay(args: &HostRelayArgs) -> anyhow::Result<()> {
    let guarded = args.hold_guard_required
        || args.hold_guard_socket.is_some()
        || args.hold_guard_vault.is_some();
    if !guarded {
        return run_relay(&args.config).await;
    }
    let (Some(socket), Some(vault)) = (&args.hold_guard_socket, &args.hold_guard_vault) else {
        anyhow::bail!("a guarded relay needs --hold-guard-socket and --hold-guard-vault");
    };
    anyhow::ensure!(
        socket.is_absolute(),
        "--hold-guard-socket must be an absolute path"
    );
    anyhow::ensure!(
        valid_registry_uuid(vault),
        "--hold-guard-vault must be the vault's registry id, a canonical lowercase UUID"
    );
    // The room's engine vault id and objects directory, as the room reads
    // them: never derived from the registry id.
    let config: RelayConfig = serde_json::from_slice(&std::fs::read(&args.config)?)?;
    config.validate()?;
    let engine_vault_id = oneiron_vault_contract::from_hex(&config.vault_id)
        .and_then(|id| <[u8; 32]>::try_from(id).ok())
        .ok_or_else(|| anyhow::anyhow!("vault_id must be 32 bytes of lowercase hex"))?;
    let objects = config.locker_dir.join(&config.vault_id).join("objects");
    let guard = CtlRelayHoldGuard::new(vault.clone(), engine_vault_id, socket.clone(), objects);
    run_relay_with_hold_guard(&args.config, Some(Arc::new(guard))).await
}
