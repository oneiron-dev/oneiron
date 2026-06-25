use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::http::HeaderValue;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing_subscriber::EnvFilter;

use crate::build_app;
use crate::cli::VaultArgs;
use crate::config::{ServeArgs, ServeConfig, SyncServerConfig, resolve_serve_config};
use crate::server::SyncServer;

pub const NO_CJK_DICT_WARNING: &str = "NO CJK DICTIONARY FOUND: Japanese, Chinese, and Korean text will use portable n-gram tokenization. Install dictionaries under an XDG oneiron dict root or set --dict-search-paths.";

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

    let app = build_app(sync_server).layer(cors_layer);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    tracing::info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
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
