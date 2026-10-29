//! `oneiron token operator`: the host operator's own credential (FIX 1814),
//! minted on a stopped self-hosted vault by the same host issuer as the
//! host's root, so the operator reaches the operator's doors
//! (`/v1/operator/*`) without holding the root, which acts there as the
//! vault's owner. The credential is a class of its own
//! (`auth::operator_credential`): holder `operator`, the one verb
//! `operator`, never a person or an owner's proof. `oneiron token revoke`
//! takes the slip id it prints. A managed vault's operator gets none here.

use clap::Args;
use ed25519_dalek::SigningKey;
use rand_core::RngCore;

use crate::config::{ServeArgs, resolve_serve_config};

/// How long an operator credential lasts when the operator names no
/// lifetime: 30 days, as `token read` and `token agent` mint (CALLS `FIX
/// 1814 operator credential class`). The host's root's own expiry caps it.
pub const OPERATOR_CREDENTIAL_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;

/// The operator's own credential, minted on the stopped self-hosted vault.
/// The issuer key comes from the config or `ONEIRON_AUTH_SECRET`, never
/// argv.
#[derive(Args, Clone, Debug)]
pub struct TokenOperatorArgs {
    /// The credential's lifetime in seconds, capped by the host's root.
    #[arg(long = "lifetime-secs", default_value_t = OPERATOR_CREDENTIAL_LIFETIME_SECS)]
    pub lifetime_secs: u64,

    #[command(flatten)]
    pub serve: ServeArgs,
}

/// What `token operator` prints: the credential in the SDK's one-string
/// form and in the CLI's slip-plus-seed form, its holder, its expiry and
/// the slip id `token revoke` takes.
#[derive(serde::Serialize)]
struct MintedOperatorCredential {
    holder: &'static str,
    expires_at: u64,
    slip_id: String,
    credential: String,
    token: String,
    binding_key: String,
}

/// Mints the operator's own credential on the stopped self-hosted vault
/// and prints it.
pub fn token_operator(args: TokenOperatorArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        !args.serve.managed_by_hypnos,
        "a managed vault's operator acts through its supervisor; an operator credential is minted on a self-hosted vault only"
    );
    anyhow::ensure!(
        args.serve.auth_secret.is_none(),
        "set ONEIRON_AUTH_SECRET or a protected config file; never pass the issuer key in argv"
    );
    anyhow::ensure!(args.lifetime_secs > 0, "--lifetime-secs must be positive");
    let config = resolve_serve_config(&args.serve)?;
    super::ensure_existing_vault_for_revoke(&config.vault_path)?;
    config
        .sync_server_config()
        .auth_secret
        .ok_or_else(|| anyhow::anyhow!("configured host issuer secret is required"))?;
    let vault = oneiron::Vault::open_owned(&config.vault_path, config.vault_config())?;
    // The same host issuer that mints the host's root signs this credential.
    let issuer = super::owner::host_issuer(&config, &vault, true)?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let mut slip_id = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut slip_id);
    let issued_at = oneiron_vault_contract::now_ts();
    let expires_at = issued_at
        .saturating_add(args.lifetime_secs)
        .min(root.claims.expires_at);
    let slip = vault.mint_capability_slip(
        &issuer,
        crate::auth::operator_slip_claims(
            root.claims.vault_id,
            slip_id,
            key.verifying_key().to_bytes(),
            issued_at,
            expires_at,
        ),
    )?;
    let token = slip.to_token()?;
    let seed = super::hex(key.as_bytes());
    let credential = format!(
        "v2.cred.{}.{seed}",
        token.strip_prefix("v2.slip.").unwrap_or(&token)
    );
    let minted = MintedOperatorCredential {
        holder: crate::auth::OPERATOR_HOLDER,
        expires_at: slip.claims.expires_at,
        slip_id: super::hex(&slip.claims.slip_id),
        credential,
        token,
        binding_key: seed,
    };
    println!("{}", serde_json::to_string_pretty(&minted)?);
    Ok(())
}
