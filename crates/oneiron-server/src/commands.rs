//! The native serve listener is intentionally plain TCP: TLS terminates at a reverse proxy.
//! Native rustls support is out of scope for this serve path. The default
//! `0.0.0.0:9090` bind is self-host-by-design; operators exposing it beyond a
//! trusted local network should place it behind a TLS-terminating reverse proxy.

use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::http::HeaderValue;
use rmpv::Value as MsgpackValue;
use serde_json::{Value as JsonValue, json};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing_subscriber::EnvFilter;

use crate::auth::{mint_identified_core_token_v2, revoke_token_jti, validate_bearer_claims};
use crate::build_app;
use crate::cli::{
    ProvenanceArgs, RevokeArgs, SkillsPackArgs, TokenMintArgs, TokenRevokeArgs, VaultArgs,
};
use crate::config::{ServeArgs, ServeConfig, SyncServerConfig, resolve_serve_config};
use crate::server::SyncServer;
use crate::skills_pack::{self, OutputMode};

/// `oneiron api …`: the bash-native lane. It is curl-backed rather than a
/// second HTTP stack, and its whole surface is routes this server already
/// serves — no endpoint, no authority model, and no response interpretation is
/// added here.
mod api;

pub use self::api::api;

pub const NO_CJK_DICT_WARNING: &str = "NO CJK DICTIONARY FOUND: Japanese, Chinese, and Korean text will use portable n-gram tokenization. Install dictionaries under an XDG oneiron dict root or set --dict-search-paths.";
const MAX_MSGPACK_JSON_DEPTH: usize = 32;
/// Below this the auth secret is weak MAC key material; warn, do not refuse.
const MIN_RECOMMENDED_AUTH_SECRET_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictSearchResolution {
    pub paths: Vec<PathBuf>,
    pub warning: Option<&'static str>,
}

pub async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args)?;
    init_tracing(&config.log_level);
    serve_with_config(config).await
}

pub fn init(args: VaultArgs) -> anyhow::Result<()> {
    let vault = open_vault_for_command(&args)?;
    print_doctor_report(&vault)
}

pub fn doctor(args: VaultArgs) -> anyhow::Result<()> {
    let vault = open_vault_for_command(&args)?;
    print_doctor_report(&vault)
}

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

/// Mints a v2 core bearer token and prints it to stdout.
///
/// The secret resolves through the normal serve-config precedence and is
/// never printed or logged. Claims are validated before minting, so a token
/// that would 401 is never emitted. Every minted token carries a fresh `jti`
/// so it can later be revoked individually; the id is printed to stderr so
/// piping stdout still yields exactly the token.
pub fn token_mint(args: TokenMintArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    let auth_secret = config
        .sync_server_config()
        .auth_secret
        .filter(|secret| !secret.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no auth secret configured; set --auth-secret, ONEIRON_AUTH_SECRET, or auth_secret in the config file"
            )
        })?;

    let mint = prepare_token_mint(
        &auth_secret,
        args.scope.as_deref(),
        args.principal_ref.as_deref(),
    )?;

    if let Some(warning) = &mint.warning {
        eprintln!("warning: {warning}");
    }
    eprintln!("token id (jti): {}", mint.jti);
    println!("{}", mint.token);
    Ok(())
}

/// One minted token plus everything the operator must be told about it.
struct TokenMint {
    token: String,
    jti: String,
    warning: Option<String>,
}

/// The whole mint decision, with no IO, so what the operator is told is
/// testable rather than inferred from a `println!`.
fn prepare_token_mint(
    auth_secret: &str,
    scope: Option<&[String]>,
    principal_ref: Option<&str>,
) -> anyhow::Result<TokenMint> {
    let claims = build_token_claims(scope, principal_ref);
    validate_bearer_claims(&claims).map_err(|_| {
        anyhow::anyhow!("refusing to mint a token the server would reject: {claims}")
    })?;

    let (token, jti) = mint_identified_core_token_v2(auth_secret, &claims);
    Ok(TokenMint {
        token,
        jti,
        warning: weak_auth_secret_warning(auth_secret),
    })
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
    let vault = oneiron::Vault::open(&config.vault_path, vault_config)
        .map_err(|e| anyhow::anyhow!("open vault {} failed: {e}", config.vault_path.display()))?;

    let revoked = revoke_token_jti(&vault, &args.jti)?;
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

/// Assembles a claims string in the bearer grammar. No flags yields an empty
/// claims string, which mints an owner-grade token.
fn build_token_claims(scope: Option<&[String]>, principal_ref: Option<&str>) -> String {
    let mut claims = String::new();
    if let Some(scope) = scope.filter(|scope| !scope.is_empty()) {
        claims.push_str("scope=");
        claims.push_str(&scope.join(","));
    }
    if let Some(principal_ref) = principal_ref {
        if !claims.is_empty() {
            claims.push(';');
        }
        claims.push_str("principal_ref=");
        claims.push_str(principal_ref);
    }
    claims
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

fn msgpack_value_json(value: &MsgpackValue) -> JsonValue {
    msgpack_value_json_with_depth(value, MAX_MSGPACK_JSON_DEPTH)
}

fn msgpack_value_json_with_depth(value: &MsgpackValue, remaining_depth: usize) -> JsonValue {
    match value {
        MsgpackValue::Nil => JsonValue::Null,
        MsgpackValue::Boolean(value) => json!(value),
        MsgpackValue::Integer(value) => value
            .as_i64()
            .map_or_else(|| json!(value.as_u64()), |value| json!(value)),
        MsgpackValue::F32(value) => json!(value),
        MsgpackValue::F64(value) => json!(value),
        MsgpackValue::String(value) => value.as_str().map_or_else(
            || json!({ "string": value.to_string() }),
            |value| json!(value),
        ),
        MsgpackValue::Binary(value) => json!({ "binary_hex": hex_bytes(value) }),
        MsgpackValue::Array(_) | MsgpackValue::Map(_) if remaining_depth == 0 => {
            json!({ "truncated": "max_depth" })
        }
        MsgpackValue::Array(values) => JsonValue::Array(
            values
                .iter()
                .map(|value| msgpack_value_json_with_depth(value, remaining_depth - 1))
                .collect(),
        ),
        MsgpackValue::Map(values) => {
            let mut map = serde_json::Map::new();
            for (key, value) in values {
                insert_json_map_value(
                    &mut map,
                    msgpack_map_key(key, remaining_depth - 1),
                    msgpack_value_json_with_depth(value, remaining_depth - 1),
                );
            }
            JsonValue::Object(map)
        }
        MsgpackValue::Ext(tag, value) => json!({
            "ext_type": tag,
            "data_hex": hex_bytes(value),
        }),
    }
}

fn msgpack_map_key(value: &MsgpackValue, remaining_depth: usize) -> String {
    match value {
        MsgpackValue::String(value) => value
            .as_str()
            .map_or_else(|| value.to_string(), std::borrow::ToOwned::to_owned),
        _ => serde_json::to_string(&msgpack_value_json_with_depth(value, remaining_depth))
            .unwrap_or_else(|_| format!("{value:?}")),
    }
}

fn insert_json_map_value(
    map: &mut serde_json::Map<String, JsonValue>,
    key: String,
    value: JsonValue,
) {
    if !map.contains_key(&key) {
        map.insert(key, value);
        return;
    }
    for index in 2.. {
        let candidate = format!("{key}#{index}");
        if !map.contains_key(&candidate) {
            map.insert(candidate, value);
            return;
        }
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

async fn serve_with_config(config: ServeConfig) -> anyhow::Result<()> {
    tracing::info!(
        vault_path = %config.vault_path.display(),
        dimensions = config.dimensions,
        "starting oneiron sync server"
    );

    let dicts = resolve_dict_search_paths(&config.dict_search_paths);
    if let Some(warning) = dicts.warning {
        tracing::warn!(dict_paths = ?dicts.paths, "{warning}");
    } else {
        tracing::info!(dict_paths = ?dicts.paths, "using CJK dictionary search paths");
    }

    let mut vault_config = config.vault_config();
    vault_config.dict_search_paths = dicts.paths;
    let vault = oneiron::Vault::open(&config.vault_path, vault_config)?;

    let server_config = config.sync_server_config();
    match server_config.auth_secret.as_deref() {
        None if !server_config.allow_unauthenticated => {
            tracing::warn!(
                "server started with no auth_secret and allow_unauthenticated=false; refusing all requests; set ONEIRON_AUTH_SECRET or pass --insecure-allow-unauthenticated for local dev"
            );
            if should_warn_public_bind_without_auth(
                server_config.auth_secret.as_deref(),
                server_config.allow_unauthenticated,
                &config.host,
            ) {
                tracing::warn!(
                    host = %config.host,
                    "server listener is network-exposed while refusing unauthenticated requests"
                );
            }
        }
        // A nudge, not a wall: short dev secrets keep working.
        Some(secret) => {
            if let Some(warning) = weak_auth_secret_warning(secret) {
                tracing::warn!("{warning}");
            }
        }
        None => {}
    }
    let cors_layer = build_cors_layer(&server_config)?;

    // Reloads persisted CRDT state (d:root + d:w:* in sync_state) — a fresh
    // boot must not silently discard previously relayed updates/tombstones.
    let sync_server = Arc::new(
        SyncServer::new(Arc::new(vault), server_config)
            .map_err(|e| anyhow::anyhow!("sync server init failed: {e}"))?,
    );
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    tracing::info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let lifecycle_handle = sync_server.spawn_lifecycle_scheduler();
    let app = build_app(sync_server).layer(cors_layer);
    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await;
    lifecycle_handle.abort();
    let _ = lifecycle_handle.await;
    result?;

    Ok(())
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
    let vault = oneiron::Vault::open(&config.vault_path, vault_config)
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

    oneiron::Vault::open(&args.path, config)
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
