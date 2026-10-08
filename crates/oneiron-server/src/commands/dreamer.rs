//! `oneiron dreamer grant`: the owner's one-time weave grant, made offline.
//!
//! Possession of the stopped vault and its configured host issuer is the
//! admission, exactly as for `token bootstrap`: the vault's own embedded
//! owner makes the grant. Nothing is sent over HTTP.

use std::io::Write;

use super::{ensure_existing_vault_for_revoke, init_tracing};
use crate::config::{ServeArgs, resolve_serve_config};

pub fn dreamer_grant(args: ServeArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        !args.managed_by_hypnos,
        "managed vaults take policy from their supervisor; this grant is self-host only"
    );
    let config = resolve_serve_config(&args)?;
    init_tracing(&config.log_level);
    ensure_existing_vault_for_revoke(&config.vault_path)?;
    let secret = config
        .sync_server_config()
        .auth_secret
        .filter(|secret| !secret.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the Dreamer writes with the host's machine identity: set ONEIRON_AUTH_SECRET (or auth_secret) first"
            )
        })?;
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())?;
    let vault = oneiron::Vault::open_owned(&config.vault_path, config.vault_config())?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.provision_engine_machine_identities(&issuer)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        oneiron::store::GateDecisionId::now(),
    )?;
    vault.grant_dreamer_weave(&owner, vault.now_recorded_at())?;
    let reach = vault.dreamer_weave_reach()?;
    anyhow::ensure!(reach.ready(), "the grant did not take: {reach:?}");
    writeln!(
        std::io::stdout().lock(),
        "{}",
        serde_json::json!({"dreamer": "granted"})
    )?;
    Ok(())
}
