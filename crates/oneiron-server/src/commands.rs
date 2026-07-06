use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::http::HeaderValue;
use rmpv::Value as MsgpackValue;
use serde_json::{Value as JsonValue, json};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing_subscriber::EnvFilter;

use crate::build_app;
use crate::cli::{ProvenanceArgs, RevokeArgs, SkillsPackArgs, VaultArgs};
use crate::config::{ServeArgs, ServeConfig, SyncServerConfig, resolve_serve_config};
use crate::server::SyncServer;
use crate::skills_pack::{self, OutputMode};

pub const NO_CJK_DICT_WARNING: &str = "NO CJK DICTIONARY FOUND: Japanese, Chinese, and Korean text will use portable n-gram tokenization. Install dictionaries under an XDG oneiron dict root or set --dict-search-paths.";
const MAX_MSGPACK_JSON_DEPTH: usize = 32;

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
            .map(msgpack_value_json)
            .unwrap_or(JsonValue::Null);
        claim["scope"] = body
            .scope
            .as_ref()
            .map(msgpack_value_json)
            .unwrap_or(JsonValue::Null);
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
    if server_config.auth_secret.is_none() && !server_config.allow_unauthenticated {
        tracing::warn!(
            "server started with no auth_secret and allow_unauthenticated=false; refusing all requests; set ONEIRON_AUTH_SECRET or pass --insecure-allow-unauthenticated for local dev"
        );
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
    let result = axum::serve(listener, app).await;
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
mod tests {
    use super::*;

    #[test]
    fn empty_cors_origin_list_stays_restrictive() {
        let config = SyncServerConfig::default();

        let parsed = parse_allowed_origins(&config.allowed_origins).unwrap();

        assert!(parsed.is_empty());
        assert!(build_cors_layer(&config).is_ok());
    }

    #[test]
    fn configured_cors_origin_is_parsed() {
        let config = SyncServerConfig {
            allowed_origins: vec!["https://app.oneiron.dev".to_owned(), "  ".to_owned()],
            ..Default::default()
        };

        assert_eq!(
            parse_allowed_origins(&config.allowed_origins).unwrap(),
            vec![HeaderValue::from_static("https://app.oneiron.dev")]
        );
        assert!(build_cors_layer(&config).is_ok());
    }

    #[test]
    fn wildcard_cors_origin_is_rejected() {
        let origins = vec!["*".to_owned()];

        let error = parse_allowed_origins(&origins).unwrap_err().to_string();

        assert!(error.contains("wildcard CORS origin is not allowed"));
    }

    #[test]
    fn provenance_claim_json_omits_payload_by_default() {
        let body = oneiron::ClaimBody::new(
            oneiron::REPO_PROVENANCE_PREDICATE,
            oneiron::ClaimSubject::Edge {
                source: oneiron::EntityId::now(),
                kind: oneiron::EdgeKind::Mentions,
                target: oneiron::EntityId::now(),
            },
            MsgpackValue::from("private payload"),
            1.0,
            oneiron::ClaimApprovalStatus::Auto,
            oneiron::ClaimLifecycleStatus::Active,
        );

        let redacted = claim_body_json(&body, false);
        assert!(redacted.get("value").is_none());
        assert!(redacted.get("scope").is_none());
        assert!(redacted.get("evidence").is_none());

        let included = claim_body_json(&body, true);
        assert_eq!(included["value"], "private payload");
    }

    #[test]
    fn msgpack_json_conversion_truncates_deep_arrays() {
        let value = MsgpackValue::Array(vec![MsgpackValue::Array(vec![MsgpackValue::from(
            "private payload",
        )])]);

        let rendered = msgpack_value_json_with_depth(&value, 1);

        assert_eq!(rendered, json!([{ "truncated": "max_depth" }]));
    }

    #[test]
    fn init_creates_vault_and_doctor_reports() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault");
        let args = VaultArgs {
            path: vault_path.clone(),
            dimensions: 32,
            map_size: 64 * 1024 * 1024,
            dict_search_paths: Some(Vec::new()),
        };

        init(args.clone()).unwrap();
        assert!(vault_path.join("data.mdb").is_file());

        let vault = open_vault_for_command(&args).unwrap();
        let report = vault.doctor().unwrap();
        assert!(report.storage_abi_version.is_some());
        assert!(report.db_manifest.missing_names.is_empty());
    }

    #[test]
    fn doctor_opens_existing_vault() {
        let dir = tempfile::tempdir().unwrap();
        let args = VaultArgs {
            path: dir.path().join("vault"),
            dimensions: 32,
            map_size: 64 * 1024 * 1024,
            dict_search_paths: Some(Vec::new()),
        };

        init(args.clone()).unwrap();
        doctor(args).unwrap();
    }

    #[tokio::test]
    async fn revoke_command_refuses_missing_vault_path_without_creating_storage() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("missing-vault");

        let err = revoke(RevokeArgs {
            client: "0123456789abcdef".to_string(),
            serve: ServeArgs {
                vault_path: Some(vault_path.clone()),
                dimensions: Some(32),
                map_size: Some(64 * 1024 * 1024),
                dict_search_paths: Some(Vec::new()),
                ..Default::default()
            },
        })
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("refusing to create a new vault for revoke")
        );
        assert!(
            !vault_path.join("data.mdb").exists(),
            "bad revoke path must not create LMDB storage"
        );
    }

    #[tokio::test]
    async fn revoke_command_flips_existing_binding_and_preserves_pubkey_floor() {
        use ed25519_dalek::{Signer, SigningKey};
        use oneiron::sync::lease::{
            self, LEASE_DURATION_SECS, LeaseRecord, LeaseStatus, ROOT_LEASES_MAP,
        };

        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault");
        let mut vault_config = oneiron::VaultConfig::server();
        vault_config.dimensions = 32;
        vault_config.map_size = 64 * 1024 * 1024;
        let vault = Arc::new(oneiron::Vault::open(&vault_path, vault_config.clone()).unwrap());
        let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();

        let client_id = 0x0123_4567_89ab_cdefu64;
        let signer = SigningKey::from_bytes(&[77u8; 32]);
        let pubkey = signer.verifying_key().to_bytes();
        let record = LeaseRecord {
            vault_id: 0,
            status: LeaseStatus::Active,
            pubkey,
            granted_at: 1_000,
            renewed_at: 1_000,
            expires_at: 1_000 + LEASE_DURATION_SECS,
        };
        server
            .root_doc
            .get_map(ROOT_LEASES_MAP)
            .insert(
                lease::client_id_hex(client_id).as_str(),
                lease::encode_lease_record(&record).as_slice(),
            )
            .unwrap();
        server.root_doc.commit();
        oneiron::sync::server_state::persist_root_snapshot(&vault, &server.root_doc).unwrap();
        lease::mirror_leases_from_root(&vault, &server.root_doc).unwrap();
        drop(server);
        drop(vault);

        revoke(RevokeArgs {
            client: lease::client_id_hex(client_id),
            serve: ServeArgs {
                vault_path: Some(vault_path.clone()),
                dimensions: Some(32),
                map_size: Some(64 * 1024 * 1024),
                dict_search_paths: Some(Vec::new()),
                ..Default::default()
            },
        })
        .await
        .unwrap();

        let vault = Arc::new(oneiron::Vault::open(&vault_path, vault_config).unwrap());
        let revoked = vault
            .sync_state_get(&lease::lease_key(0, client_id))
            .unwrap()
            .unwrap();
        assert_eq!(revoked[1], 0x03, "CLI revoke flips status to revoked");

        let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
        let other_client = 0x1111_2222_3333_4444u64;
        let pop = signer
            .sign(&lease::lease_pop_transcript(other_client, &pubkey))
            .to_bytes();
        let decision = server
            .register_lease(other_client, &pubkey, &pop)
            .await
            .unwrap();
        assert!(
            !decision.granted,
            "revoked pubkey remains terminal across fresh client ids"
        );
        assert!(
            vault
                .sync_state_get(&lease::lease_key(0, other_client))
                .unwrap()
                .is_none(),
            "pubkey floor writes no fresh active row"
        );
    }

    #[test]
    fn missing_dicts_returns_loud_startup_warning() {
        let resolution = resolve_dict_search_paths_from_candidates(&[], Vec::new());

        assert!(resolution.paths.is_empty());
        assert_eq!(resolution.warning, Some(NO_CJK_DICT_WARNING));
        assert!(NO_CJK_DICT_WARNING.contains("NO CJK DICTIONARY FOUND"));
    }

    #[test]
    fn auto_discovers_candidate_with_cjk_dict_marker() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("dicts");
        std::fs::create_dir_all(root.join("zh")).unwrap();
        std::fs::write(root.join("zh").join("jieba.dict.utf8"), "token 1 n\n").unwrap();

        let resolution = resolve_dict_search_paths_from_candidates(&[], vec![root.clone()]);

        assert_eq!(resolution.paths, vec![root]);
        assert_eq!(resolution.warning, None);
    }
}
