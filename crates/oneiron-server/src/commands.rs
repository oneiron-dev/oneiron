//! The native serve listener is intentionally plain TCP: TLS terminates at a reverse proxy.
//! Native rustls support is out of scope for this serve path. The default
//! `0.0.0.0:9090` bind is self-host-by-design; operators exposing it beyond a
//! trusted local network should place it behind a TLS-terminating reverse proxy.

use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::http::HeaderValue;
#[cfg(test)]
use rmpv::Value as MsgpackValue;
use serde_json::{Value as JsonValue, json};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing_subscriber::EnvFilter;

use crate::auth::{CoreScope, revoke_token_jti};
use crate::cli::{
    AgentTier, ProvenanceArgs, RevokeArgs, SkillsPackArgs, TokenAgentArgs, TokenBootstrapArgs,
    TokenPairArgs, TokenReadArgs, TokenRevokeArgs, VaultArgs,
};
#[cfg(test)]
use crate::config::ServeConfig;
use crate::config::{ServeArgs, SyncServerConfig, resolve_serve_config};
use crate::managed;
use crate::server::SyncServer;
use crate::skills_pack::{self, OutputMode};

/// `oneiron api …`: the bash-native lane. It is curl-backed rather than a
/// second HTTP stack, and its whole surface is routes this server already
/// serves — no endpoint, no authority model, and no response interpretation is
/// added here.
mod api;
mod host_init;
pub use self::host_init::host_init;

pub use self::api::api;
mod mcp_bridge;
pub use self::mcp_bridge::mcp;

pub const NO_CJK_DICT_WARNING: &str = "NO CJK DICTIONARY FOUND: Japanese, Chinese, and Korean text will use portable n-gram tokenization. Install dictionaries under an XDG oneiron dict root or set --dict-search-paths.";
/// Below this the auth secret is weak MAC key material; warn, do not refuse.
const MIN_RECOMMENDED_AUTH_SECRET_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictSearchResolution {
    pub paths: Vec<PathBuf>,
    pub warning: Option<&'static str>,
}

/// Runs the daemon.
///
/// The one fork in the road: with `--managed-by-hypnos` this becomes a
/// supervised child process whose configuration is argv alone; without it,
/// nothing below this line has changed. `ManagedArgs::from_serve_args` returns
/// `None` for every argv that does not carry the switch, so the unmanaged path
/// is reached exactly as often as it was before.
pub async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    if let Some(managed) = managed::ManagedArgs::from_serve_args(&args)? {
        return managed::serve_managed(&args, managed).await;
    }
    let config = resolve_serve_config(&args)?;
    init_tracing(&config.log_level);
    serve_with_config(config).await
}

mod history_import;
mod init;
pub use init::init;
mod reembed;
pub use reembed::reembed;
mod serve;
use self::serve::serve_with_config;
mod dreamer;
pub use self::dreamer::dreamer_grant;
mod owner;
pub use owner::{backup, doctor, export, import, restore, runs, secret_scan, whoami};
mod msgpack_json;
pub(crate) use msgpack_json::msgpack_value_json;

pub fn provenance(args: ProvenanceArgs) -> anyhow::Result<()> {
    let vault_args = VaultArgs {
        path: args.vault_path,
        dimensions: args.dimensions,
        map_size: args.map_size,
        dict_search_paths: args.dict_search_paths,
    };
    let vault = open_vault_for_command(&vault_args)?;
    let output = if let Some(sha) = args.sha {
        provenance_for_commit(
            &vault,
            &args.repo_path,
            &sha,
            args.git_notes,
            args.include_payload,
        )?
    } else if let Some(claim_id) = args.claim_id {
        provenance_for_claim(
            &vault,
            &args.repo_path,
            &claim_id,
            args.git_notes,
            args.include_payload,
        )?
    } else {
        anyhow::bail!("provenance requires a SHA or --claim-id");
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

/// First-owner pairing from the local vault, with the daemon stopped.
/// The command is intentionally not an HTTP route: possession of the host's
/// local vault and issuer key is the admission. No bearer-only credential is
/// revived and no root slip or signing key is printed.
pub fn token_bootstrap(args: TokenBootstrapArgs) -> anyhow::Result<()> {
    let link = token_bootstrap_link(&args)?;
    println!("{link}");
    Ok(())
}

fn token_bootstrap_link(args: &TokenBootstrapArgs) -> anyhow::Result<String> {
    anyhow::ensure!(
        !args.serve.managed_by_hypnos,
        "managed vaults pair through their supervisor; local bootstrap is self-host only"
    );
    anyhow::ensure!(
        args.serve.auth_secret.is_none(),
        "set ONEIRON_AUTH_SECRET or a protected config file; never pass the issuer key in argv"
    );
    let origin = api::normalized_base(&args.url)?;
    let url = reqwest::Url::parse(&origin)?;
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "pairing origin cannot contain userinfo"
    );
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    anyhow::ensure!(
        url.scheme() == "https" || loopback,
        "non-loopback pairing origins must use HTTPS"
    );
    let config = resolve_serve_config(&args.serve)?;
    ensure_existing_vault_for_revoke(&config.vault_path)?;
    let secret = config
        .sync_server_config()
        .auth_secret
        .ok_or_else(|| anyhow::anyhow!("configured host issuer secret is required"))?;
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())?;
    let vault = oneiron::Vault::open_owned(&config.vault_path, config.vault_config())?;
    // Init seeds the embedded owner. Never accept a caller-chosen holder on
    // this offline root link, and never re-create a deleted owner actor.
    let owner = vault.ensure_embedded_owner_actor()?;
    vault.ensure_host_root_slip(&issuer)?;
    let link = vault.issue_pairing_link_for_principal(
        &issuer,
        oneiron::federation::Scope::top(),
        args.lifetime_secs.unwrap_or(u64::MAX),
        oneiron::authority::PairingPrincipal {
            holder_ref: Some(owner.to_hex()),
            actor_class: Some("human".into()),
            org_ref: None,
        },
    )?;
    Ok(oneiron::authority::format_pairing_link(
        &origin,
        &link.code,
        &owner.to_hex(),
    ))
}

/// What `token read` and `token agent` print: the credential in the SDK's
/// one-string form and in the CLI's slip-plus-seed form, and the slip id
/// `token revoke` takes.
#[derive(serde::Serialize)]
struct PairedCredential {
    principal_ref: String,
    actor_class: String,
    expires_at: u64,
    slip_id: String,
    credential: String,
    token: String,
    binding_key: String,
}

/// A read-only credential for a local agent, minted on the stopped vault.
///
/// The same host-rooted doors as `token bootstrap` and `/v1/core/pairing/redeem`:
/// the host issues a one-use link for an existing principal carrying only
/// `core:read`, and this process redeems it at once with a fresh connection
/// key. The slip is logged like every paired slip and revoked by its id.
pub fn token_read(args: TokenReadArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        !args.serve.managed_by_hypnos,
        "managed vaults pair through their supervisor; local minting is self-host only"
    );
    anyhow::ensure!(
        args.serve.auth_secret.is_none(),
        "set ONEIRON_AUTH_SECRET or a protected config file; never pass the issuer key in argv"
    );
    let config = resolve_serve_config(&args.serve)?;
    ensure_existing_vault_for_revoke(&config.vault_path)?;
    let secret = config
        .sync_server_config()
        .auth_secret
        .ok_or_else(|| anyhow::anyhow!("configured host issuer secret is required"))?;
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())?;
    let vault = oneiron::Vault::open_owned(&config.vault_path, config.vault_config())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let principal_ref = args.principal_ref.unwrap_or_else(|| owner.to_hex());
    // Pairing names an existing actor whose kind can act as the class asked
    // for; it never manufactures one. Checked before the vault is rooted.
    let (principal, _) =
        oneiron::memory::parse_actor_key(&vault, &format!("{}:{principal_ref}", args.actor_class))
            .map_err(|error| {
                anyhow::anyhow!(
                    "{principal_ref} cannot hold a {} credential: {}",
                    args.actor_class,
                    error.message
                )
            })?;
    let principal = principal.to_hex();
    vault.ensure_host_root_slip(&issuer)?;
    let credential = mint_paired_credential(
        &vault,
        &issuer,
        &principal,
        &args.actor_class,
        [CoreScope::Read.as_str().to_owned()].into_iter().collect(),
        args.lifetime_secs,
    )?;
    println!("{}", serde_json::to_string_pretty(&credential)?);
    Ok(())
}

/// A credential for one named agent, minted on the stopped vault.
///
/// The agent acts as a PERSON principal derived from its name (so a second
/// mint for one name is the same agent with a new slip), of class `agent`,
/// never the owner. Its tier is ARCH-0028's registration-time tier (see
/// `agent_tier_authority`); the latest mint sets the agent's ceiling. The
/// slip comes through the host-rooted pairing doors `token read` uses and
/// carries only its tier's verbs: scoped, paired and bound to a fresh
/// connection key, never owner-grade. `token revoke` takes its slip id.
pub fn token_agent(args: TokenAgentArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        !args.serve.managed_by_hypnos,
        "managed vaults pair through their supervisor; local minting is self-host only"
    );
    anyhow::ensure!(
        args.serve.auth_secret.is_none(),
        "set ONEIRON_AUTH_SECRET or a protected config file; never pass the issuer key in argv"
    );
    anyhow::ensure!(
        !args.name.is_empty()
            && args.name.len() <= 64
            && args
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
        "an agent name is 1 to 64 letters, digits, `-`, `_` or `.`"
    );
    anyhow::ensure!(args.lifetime_secs > 0, "--lifetime-secs must be at least 1");
    // The file exists before the slip does, so a path that cannot be written
    // fails here rather than after a slip nobody holds is logged.
    let mut out = match &args.out {
        Some(path) => Some((path, create_owner_only(path)?)),
        None => None,
    };
    let minted = mint_agent_credential(&args, |credential| match out.as_mut() {
        Some((path, file)) => file
            .write_all(format!("{}\n", credential.credential).as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| anyhow::anyhow!("write {}: {error}", path.display())),
        None => {
            let printed = serde_json::to_string_pretty(credential)?;
            writeln!(io::stdout().lock(), "{printed}")
                .map_err(|error| anyhow::anyhow!("print the credential: {error}"))
        }
    });
    match (minted, out) {
        (Ok((credential, ceiling)), Some((path, _))) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "principal_ref": credential.principal_ref,
                    "actor_class": credential.actor_class,
                    "ceiling": ceiling.as_str(),
                    "expires_at": credential.expires_at,
                    "slip_id": credential.slip_id,
                    "credential_file": path,
                }))?
            );
            Ok(())
        }
        (Ok(_), None) => Ok(()),
        (Err(error), out) => {
            if let Some((path, _)) = out {
                let _ = std::fs::remove_file(path);
            }
            Err(error)
        }
    }
}

/// ARCH-0028's tiers as stored authority: the verbs the slip carries and the
/// agent's ceiling. Both tiers that write carry `core:propose` and
/// `core:write`; the ceiling, not the verbs, decides whether a write lands
/// (`auto`) or waits for review (`proposed`). Nothing else — `core:auth`, an
/// organization power, a companion scope — is ever an agent's.
fn agent_tier_authority(
    tier: AgentTier,
) -> (
    std::collections::BTreeSet<String>,
    oneiron::agent_def::AgentCeiling,
) {
    use oneiron::agent_def::AgentCeiling;
    let reads: &[CoreScope] = &[CoreScope::Read];
    let writes: &[CoreScope] = &[CoreScope::Read, CoreScope::Propose, CoreScope::Write];
    let (verbs, ceiling) = match tier {
        AgentTier::ReadOnly => (reads, AgentCeiling::Proposed),
        AgentTier::ProposeOnly => (writes, AgentCeiling::Proposed),
        AgentTier::FullAccess => (writes, AgentCeiling::Auto),
    };
    (
        verbs.iter().map(|verb| verb.as_str().to_owned()).collect(),
        ceiling,
    )
}

/// `token agent`'s vault half: principal, slip and grant, on the stopped vault.
/// `deliver` hands the credential to the owner between the slip and the grant.
fn mint_agent_credential(
    args: &TokenAgentArgs,
    deliver: impl FnOnce(&PairedCredential) -> anyhow::Result<()>,
) -> anyhow::Result<(PairedCredential, oneiron::agent_def::AgentCeiling)> {
    let config = resolve_serve_config(&args.serve)?;
    ensure_existing_vault_for_revoke(&config.vault_path)?;
    let secret = config
        .sync_server_config()
        .auth_secret
        .ok_or_else(|| anyhow::anyhow!("configured host issuer secret is required"))?;
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())?;
    let vault = oneiron::Vault::open_owned(&config.vault_path, config.vault_config()).map_err(
        |error| match error {
            oneiron::Error::ConcurrentWrite(oneiron::VAULT_WRITER_LEASE_HELD) => anyhow::anyhow!(
                "vault {} is open in a running `oneiron serve`; stop it, mint, and start it again",
                config.vault_path.display()
            ),
            error => anyhow::anyhow!("open vault {}: {error}", config.vault_path.display()),
        },
    )?;
    let owner = crate::owner::local_owner(&vault)?;
    let principal = vault
        .ensure_agent_principal(&args.name)
        .map_err(|error| anyhow::anyhow!("agent {}: {}", args.name, error.message))?;
    let principal = principal.to_hex();
    // The same store-truth class check `token read` makes, before rooting.
    oneiron::memory::parse_actor_key(&vault, &format!("agent:{principal}")).map_err(|error| {
        anyhow::anyhow!(
            "agent {} cannot hold a credential: {}",
            args.name,
            error.message
        )
    })?;
    vault.ensure_host_root_slip(&issuer)?;
    let (verbs, ceiling) = agent_tier_authority(args.tier);
    // The slip, then its delivery, then the grant. Earlier slips for this
    // agent keep reading its live ceiling, so a mint that fails anywhere must
    // leave that ceiling as it was; a delivery or grant that fails takes the
    // new slip back.
    let credential = mint_paired_credential(
        &vault,
        &issuer,
        &principal,
        "agent",
        verbs,
        args.lifetime_secs,
    )?;
    let granted = deliver(&credential).and_then(|()| {
        vault
            .grant_agent_principal(&owner, &principal, ceiling)
            .map_err(anyhow::Error::from)
    });
    if let Err(error) = granted {
        let slip = oneiron::authority::CapabilitySlip::from_token(&credential.token)?;
        vault
            .revoke_capability_slip_once(&issuer, slip.claims.slip_id)
            .map_err(|revoke| {
                anyhow::anyhow!(
                    "agent {}: {error}; then revoking its new slip {}: {revoke}",
                    args.name,
                    credential.slip_id
                )
            })?;
        return Err(error);
    }
    Ok((credential, ceiling))
}

/// Issues a one-use link for an existing `principal` carrying `verbs`, and
/// redeems it at once with a fresh connection key: the host-rooted pairing
/// doors `/v1/core/pairing/redeem` uses, on the stopped vault. The slip is
/// logged like every paired slip and revoked by its id.
fn mint_paired_credential(
    vault: &oneiron::Vault,
    issuer: &oneiron::authority::HostSlipIssuer,
    principal: &str,
    actor_class: &str,
    verbs: std::collections::BTreeSet<String>,
    lifetime_secs: u64,
) -> anyhow::Result<PairedCredential> {
    use ed25519_dalek::{Signer, SigningKey};
    let mut scope = oneiron::federation::Scope::top();
    scope.verbs = oneiron::federation::ScopeAxis::Some(verbs);
    let link = vault.issue_pairing_link_for_principal(
        issuer,
        scope,
        lifetime_secs,
        oneiron::authority::PairingPrincipal {
            holder_ref: Some(principal.to_owned()),
            actor_class: Some(actor_class.to_owned()),
            org_ref: None,
        },
    )?;
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let binding_key = key.verifying_key().to_bytes();
    let transcript =
        oneiron::authority::pairing_binding_transcript(&link.code, &binding_key, principal)?;
    let slip = vault.redeem_pairing_link(
        issuer,
        &link.code,
        principal,
        binding_key,
        &key.sign(&transcript).to_bytes(),
    )?;
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let token = slip.to_token()?;
    let seed = hex(key.as_bytes());
    let credential = format!(
        "v2.cred.{}.{seed}",
        token.strip_prefix("v2.slip.").unwrap_or(&token)
    );
    Ok(PairedCredential {
        principal_ref: principal.to_owned(),
        actor_class: actor_class.to_owned(),
        expires_at: slip.claims.expires_at,
        slip_id: hex(&slip.claims.slip_id),
        credential,
        token,
        binding_key: seed,
    })
}

/// A new file only its owner can read. It must not exist yet: a credential
/// never lands on top of a file someone else may already hold open.
fn create_owner_only(path: &Path) -> anyhow::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", path.display()))
}

/// Creates a pairing link on the running server and prints it.
///
/// stdout is exactly one line, the link, so piping it yields nothing else; the
/// expiry goes to stderr. It opens no vault, so it runs beside a live server,
/// and the slip plus holder proof reach curl only on its config channel.
pub fn token_pair(args: TokenPairArgs) -> anyhow::Result<()> {
    let token = std::env::var(&args.token_env)
        .map_err(|_| anyhow::anyhow!("{} holds no capability slip", args.token_env))?;
    let binding = api::signed_binding(&token, &args.binding_key_env)?;
    let mut scope = oneiron::federation::Scope::top();
    if let Some(verbs) = args.scope {
        scope.verbs = oneiron::federation::ScopeAxis::Some(verbs.into_iter().collect());
    }
    let principal = oneiron::authority::PairingPrincipal {
        holder_ref: Some(args.principal_ref.clone()),
        actor_class: args.actor_class,
        org_ref: None,
    };
    let body = serde_json::to_vec(&json!({
        "scope": scope,
        "lifetime_secs": args.lifetime_secs,
        "principal": principal,
    }))?;
    let (origin, link) = api::create_pairing_link(&args.url, &token, &binding, body)?;
    println!(
        "{}",
        oneiron::authority::format_pairing_link(&origin, &link.code, &args.principal_ref)
    );
    eprintln!(
        "the pairing link expires at unix second {}",
        link.expires_at
    );
    Ok(())
}

/// Revokes one previously minted token by its id.
///
/// Its own explicit act, on one named identity, against the server's
/// persistent registry — never a side effect of rotation. Idempotent:
/// revoking an already-revoked id succeeds and reports `false`.
pub fn token_revoke(args: TokenRevokeArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    init_tracing(&config.log_level);

    let dicts = resolve_dict_search_paths(&config.dict_search_paths);
    let mut vault_config = config.vault_config();
    vault_config.dict_search_paths = dicts.paths;
    // A fresh vault holds no tokens, so creating one here would report a
    // successful revocation against storage the server does not read.
    ensure_existing_vault_for_revoke(&config.vault_path)?;
    let vault = oneiron::Vault::open_owned(&config.vault_path, vault_config)
        .map_err(|e| anyhow::anyhow!("open vault {} failed: {e}", config.vault_path.display()))?;

    let revoked = if args.jti.len() == 64 {
        anyhow::ensure!(
            args.jti
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid slip id"
        );
        let secret = config
            .sync_server_config()
            .auth_secret
            .ok_or_else(|| anyhow::anyhow!("host secret required"))?;
        let issuer = oneiron::authority::HostSlipIssuer::from_secret(secret.as_bytes())?;
        let bytes = (0..64)
            .step_by(2)
            .map(|index| u8::from_str_radix(&args.jti[index..index + 2], 16))
            .collect::<Result<Vec<_>, _>>()?;
        let id: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid slip id"))?;
        vault.revoke_capability_slip_once(&issuer, id)?
    } else {
        revoke_token_jti(&vault, &args.jti)?
    };
    println!("{}", serde_json::json!({ "revoked": revoked }));
    Ok(())
}

/// Returns whether a configured host is loopback-only for startup warning purposes.
/// Unparseable hostnames are treated as public, except for the conventional localhost name.
fn is_loopback(host: &str) -> bool {
    let host = host.trim();
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn should_warn_public_bind_without_auth(
    auth_secret: Option<&str>,
    allow_unauthenticated: bool,
    host: &str,
) -> bool {
    auth_secret.is_none() && !allow_unauthenticated && !is_loopback(host)
}

/// The secret is the MAC key for every minted token, and BLAKE3 is fast: a
/// recipient holding a token holds a known claims/MAC pair to test guesses
/// against offline. Warned at both doors that handle the secret — serve and
/// mint — because an operator who only ever mints never sees the other one.
fn weak_auth_secret_warning(secret: &str) -> Option<String> {
    (secret.len() < MIN_RECOMMENDED_AUTH_SECRET_BYTES).then(|| {
        format!(
            "configured auth_secret is shorter than {MIN_RECOMMENDED_AUTH_SECRET_BYTES} bytes; it is the MAC key for every minted bearer token"
        )
    })
}

pub fn skills_pack(args: SkillsPackArgs) -> anyhow::Result<()> {
    let mode = if args.json {
        OutputMode::Json
    } else if args.path {
        OutputMode::Path
    } else {
        OutputMode::Markdown
    };
    let output = skills_pack::render(mode)?;
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    if let Err(error) = stdout.write_all(output.as_bytes()) {
        if error.kind() == io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        anyhow::bail!("write skills pack to stdout failed: {error}");
    }
    Ok(())
}

fn provenance_for_commit(
    vault: &oneiron::Vault,
    repo_path: &Path,
    sha: &str,
    git_notes: bool,
    include_payload: bool,
) -> anyhow::Result<JsonValue> {
    let link = oneiron::repo_commit_provenance(repo_path, sha)?
        .ok_or_else(|| anyhow::anyhow!("commit {sha} has no Oneiron provenance trailer"))?;
    let commit_sha = link.commit_sha;
    let claim_id = link.claim_id;
    let mut output = json!({
        "commit": commit_sha,
        "claim_id": claim_id.to_hex(),
        "claim": claim_json(vault, &claim_id, include_payload)?,
    });
    if git_notes {
        oneiron::export_repo_provenance_git_note(repo_path, &commit_sha, &claim_id)?;
        output["git_notes"] = json!({
            "exported": true,
            "ref": oneiron::REPO_PROVENANCE_NOTES_REF,
        });
    }
    Ok(output)
}

fn provenance_for_claim(
    vault: &oneiron::Vault,
    repo_path: &Path,
    claim_id: &str,
    git_notes: bool,
    include_payload: bool,
) -> anyhow::Result<JsonValue> {
    let claim_id = oneiron::EntityId::from_hex(claim_id)
        .map_err(|_| anyhow::anyhow!("claim id must be a 32-hex entity id"))?;
    let commit = oneiron::repo_commit_for_provenance_claim(repo_path, &claim_id)?
        .ok_or_else(|| anyhow::anyhow!("claim {} has no linked commit", claim_id.to_hex()))?;
    let claim = claim_json(vault, &claim_id, include_payload)?;
    let mut git_notes_exported = None;
    if git_notes {
        oneiron::export_repo_provenance_git_note(repo_path, &commit, &claim_id)?;
        git_notes_exported = Some(json!({
            "exported": commit,
            "ref": oneiron::REPO_PROVENANCE_NOTES_REF,
        }));
    }
    let mut output = json!({
        "claim_id": claim_id.to_hex(),
        "commit": commit,
        "claim": claim,
    });
    if let Some(exported) = git_notes_exported {
        output["git_notes"] = exported;
    }
    Ok(output)
}

fn claim_json(
    vault: &oneiron::Vault,
    claim_id: &oneiron::EntityId,
    include_payload: bool,
) -> anyhow::Result<JsonValue> {
    let body = vault
        .get_claim(claim_id)?
        .ok_or_else(|| anyhow::anyhow!("claim {} was not found in the vault", claim_id.to_hex()))?;
    Ok(claim_body_json(&body, include_payload))
}

fn claim_body_json(body: &oneiron::ClaimBody, include_payload: bool) -> JsonValue {
    let mut claim = json!({
        "predicate": body.predicate,
        "subject": claim_subject_json(&body.subject),
        "confidence": body.confidence,
        "approval": body.approval.as_str(),
        "lifecycle": body.lifecycle.as_str(),
        "salience": body.salience,
        "valid_from": body.valid_from,
        "valid_to": body.valid_to,
        "source": body.source.map(oneiron::ClaimSource::as_str),
        "world": body.world.map(|id| id.to_hex()),
        "stale": body.stale,
    });
    if include_payload {
        claim["value"] = msgpack_value_json(&body.value);
        claim["evidence"] = body
            .evidence
            .as_ref()
            .map_or(JsonValue::Null, msgpack_value_json);
        claim["scope"] = body
            .scope
            .as_ref()
            .map_or(JsonValue::Null, msgpack_value_json);
    }
    claim
}

fn claim_subject_json(subject: &oneiron::ClaimSubject) -> JsonValue {
    match subject {
        oneiron::ClaimSubject::Entity(id) => json!({
            "kind": "entity",
            "id": id.to_hex(),
        }),
        oneiron::ClaimSubject::Edge {
            source,
            kind,
            target,
        } => json!({
            "kind": "edge",
            "source": source.to_hex(),
            "edge_kind": *kind as u8,
            "target": target.to_hex(),
        }),
    }
}

pub async fn revoke(args: RevokeArgs) -> anyhow::Result<()> {
    let client_id = parse_client_id_hex(&args.client)?;
    let config = resolve_serve_config(&args.serve)?;
    init_tracing(&config.log_level);

    let dicts = resolve_dict_search_paths(&config.dict_search_paths);
    if let Some(warning) = dicts.warning {
        tracing::warn!(dict_paths = ?dicts.paths, "{warning}");
    }
    let mut vault_config = config.vault_config();
    vault_config.dict_search_paths = dicts.paths;
    ensure_existing_vault_for_revoke(&config.vault_path)?;
    let vault = oneiron::Vault::open_owned(&config.vault_path, vault_config)
        .map_err(|e| anyhow::anyhow!("open vault {} failed: {e}", config.vault_path.display()))?;
    let server = SyncServer::new(Arc::new(vault), config.sync_server_config())
        .map_err(|e| anyhow::anyhow!("sync server init failed: {e}"))?;

    let revoked = server
        .revoke_lease(client_id)
        .await
        .map_err(|e| anyhow::anyhow!("lease revoke failed: {e}"))?
        .is_some();
    println!("{}", serde_json::json!({ "revoked": revoked }));
    Ok(())
}

fn ensure_existing_vault_for_revoke(path: &Path) -> anyhow::Result<()> {
    if !path.join("data.mdb").is_file() {
        anyhow::bail!(
            "vault {} does not exist; refusing to create a new vault for revoke",
            path.display()
        );
    }
    Ok(())
}

fn parse_client_id_hex(client: &str) -> anyhow::Result<u64> {
    if client.len() != 16
        || !client
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        anyhow::bail!("client id must be exactly 16 lowercase hex characters");
    }
    u64::from_str_radix(client, 16).map_err(|e| anyhow::anyhow!("parse client id {client:?}: {e}"))
}

fn open_vault_for_command(args: &VaultArgs) -> anyhow::Result<oneiron::Vault> {
    let mut config = oneiron::VaultConfig::server();
    config.dimensions = args.dimensions;
    config.map_size = args.map_size;
    let configured_paths = args.dict_search_paths.clone().unwrap_or_default();
    config.dict_search_paths = resolve_dict_search_paths(&configured_paths).paths;

    oneiron::Vault::open_owned(&args.path, config)
        .map_err(|e| anyhow::anyhow!("open vault {} failed: {e}", args.path.display()))
}

fn print_doctor_report(vault: &oneiron::Vault) -> anyhow::Result<()> {
    let report = vault.doctor()?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn init_tracing(log_level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

pub fn resolve_dict_search_paths(configured_paths: &[PathBuf]) -> DictSearchResolution {
    resolve_dict_search_paths_from_candidates(configured_paths, standard_cjk_dict_roots())
}

pub fn resolve_dict_search_paths_from_candidates(
    configured_paths: &[PathBuf],
    candidates: Vec<PathBuf>,
) -> DictSearchResolution {
    let paths = if configured_paths.is_empty() {
        candidates
            .into_iter()
            .filter(|path| root_has_cjk_dict(path))
            .collect()
    } else {
        configured_paths.to_vec()
    };
    let warning =
        (!paths.iter().any(|path| root_has_cjk_dict(path))).then_some(NO_CJK_DICT_WARNING);

    DictSearchResolution { paths, warning }
}

fn standard_cjk_dict_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(xdg_data_home) = std::env::var_os("XDG_DATA_HOME") {
        push_unique(
            &mut roots,
            PathBuf::from(xdg_data_home).join("oneiron").join("dicts"),
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        push_unique(
            &mut roots,
            home.join(".local")
                .join("share")
                .join("oneiron")
                .join("dicts"),
        );
        push_unique(
            &mut roots,
            home.join(".config").join("oneiron").join("dicts"),
        );
        push_unique(
            &mut roots,
            home.join("Library")
                .join("Application Support")
                .join("Oneiron")
                .join("dicts"),
        );
    }
    if let Some(xdg_config_home) = std::env::var_os("XDG_CONFIG_HOME") {
        push_unique(
            &mut roots,
            PathBuf::from(xdg_config_home).join("oneiron").join("dicts"),
        );
    }
    push_unique(
        &mut roots,
        PathBuf::from("/opt/homebrew/share/oneiron/dicts"),
    );
    push_unique(&mut roots, PathBuf::from("/usr/local/share/oneiron/dicts"));
    push_unique(&mut roots, PathBuf::from("/usr/share/oneiron/dicts"));
    push_unique(
        &mut roots,
        PathBuf::from("/Library/Application Support/Oneiron/dicts"),
    );

    roots
}

fn push_unique(paths: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !paths.iter().any(|path| path == &candidate) {
        paths.push(candidate);
    }
}

fn root_has_cjk_dict(root: &Path) -> bool {
    root.join("ja").join("system.dic").is_file()
        || root.join("zh").join("jieba.dict.utf8").is_file()
        || root.join("ko").join("metadata.json").is_file()
}

fn build_cors_layer(config: &SyncServerConfig) -> anyhow::Result<CorsLayer> {
    let allowed_origins = parse_allowed_origins(&config.allowed_origins)?;

    if allowed_origins.is_empty() {
        Ok(CorsLayer::new())
    } else {
        Ok(CorsLayer::new().allow_origin(AllowOrigin::list(allowed_origins)))
    }
}

fn parse_allowed_origins(origins: &[String]) -> anyhow::Result<Vec<HeaderValue>> {
    origins
        .iter()
        .filter_map(|origin| {
            let trimmed = origin.trim();
            (!trimmed.is_empty()).then_some(trimmed)
        })
        .map(|origin| {
            if origin == "*" {
                anyhow::bail!("wildcard CORS origin is not allowed");
            }
            origin
                .parse::<HeaderValue>()
                .map_err(|e| anyhow::anyhow!("invalid CORS origin {origin:?}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests;
#[cfg(all(test, unix))]
mod writer_lease_tests;
