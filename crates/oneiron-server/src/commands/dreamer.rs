//! `oneiron dreamer grant`: the owner's weave grant, made offline, for a
//! vault created before the Dreamer's rows shipped in the seeded policy.
//!
//! Possession of the stopped vault and its configured host issuer is the
//! admission, exactly as for `token bootstrap`: the vault's own embedded
//! owner makes the grant. Nothing is sent over HTTP.

use std::io::Write;

use super::{ensure_existing_vault_for_revoke, init_tracing};
use crate::cli::DreamerGrantArgs;
use crate::config::resolve_serve_config;

pub fn dreamer_grant(grant: DreamerGrantArgs) -> anyhow::Result<()> {
    let args = grant.serve;
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
    let granted = vault.grant_dreamer_weave(&owner, vault.now_recorded_at())?;
    let reach = vault.dreamer_weave_reach()?;
    anyhow::ensure!(
        reach.ready(),
        "the vault's policy still keeps the Dreamer out ({reach:?}); an owner row naming the Dreamer may narrow it"
    );
    let routed = match grant.extraction_route {
        Some(locality) => crate::ai_host::route_dreamer_extraction(&vault, locality)?,
        None => false,
    };
    writeln!(
        std::io::stdout().lock(),
        "{}",
        serde_json::json!({
            "dreamer": "granted",
            "policy_changed": granted,
            "extraction_route_changed": routed,
        })
    )?;
    Ok(())
}
