//! A relay room has no engine, vault key, Loro document or inference worker.
//! The pinned iroh-relay executable forwards the encrypted transport. This
//! process owns only a vault-scoped ciphertext locker and its access token.
//! Devices still verify the MACHINE roster and grants above iroh; relay
//! admission is not vault authority. TLS and public routing belong to the edge.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::{
    future::IntoFuture,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path as FsPath, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

/// The relay executable must be built from the same fork revision as the
/// engine's mesh adapter. It remains a sidecar, not another engine transport.
pub const IROH_RELAY_REVISION: &str = "17c0612f80f78f5288e97b818b1360ae6ea0a51a";
const DEFAULT_OBJECT_BYTES: usize = 64 * 1024 * 1024;
fn default_object_bytes() -> usize {
    DEFAULT_OBJECT_BYTES
}

/// One vault room, not a multi-tenant registry or a billing control plane.
/// The operator supplies only endpoint public keys and locker authentication;
/// no field can supply a vault decryption key or a model credential.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    pub vault_id: String,
    /// Locker and discovery listener. TLS terminates at the edge.
    pub listen: SocketAddr,
    pub locker_dir: PathBuf,
    /// A bearer token for the locker, not a data key or a capability slip.
    pub access_token_file: PathBuf,
    pub relay_binary: PathBuf,
    /// Private listener reached by the relay's public TLS endpoint.
    pub relay_bind: SocketAddr,
    /// Public iroh relay URL advertised to clients.
    pub relay_url: String,
    /// Device transport keys already enrolled for this vault. An empty room
    /// admits nobody, rather than silently becoming a public relay.
    pub endpoint_keys: Vec<String>,
    /// Private iroh metrics listener; the operator meters relay bytes here.
    pub relay_metrics_bind: SocketAddr,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_object_bytes")]
    pub max_object_bytes: usize,
}

fn hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl RelayConfig {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            hex_id(&self.vault_id),
            "vault_id must be 32 bytes of lowercase hex"
        );
        anyhow::ensure!(
            self.max_object_bytes > 0,
            "max_object_bytes must be positive"
        );
        anyhow::ensure!(
            !self.endpoint_keys.is_empty() && self.endpoint_keys.iter().all(|key| hex_id(key)),
            "endpoint_keys must contain enrolled 32-byte transport public keys"
        );
        anyhow::ensure!(
            self.relay_bind.ip().is_loopback() && self.relay_metrics_bind.ip().is_loopback(),
            "relay and metrics listeners must be loopback; terminate public TLS at the edge"
        );
        for path in [
            &self.locker_dir,
            &self.access_token_file,
            &self.relay_binary,
        ] {
            anyhow::ensure!(path.is_absolute(), "relay paths must be absolute");
        }
        let url = reqwest::Url::parse(&self.relay_url)?;
        anyhow::ensure!(
            matches!(url.scheme(), "https" | "http")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "relay_url must be an HTTP(S) URL without credentials"
        );
        Ok(())
    }
}

struct RelayRoom {
    vault: String,
    objects: PathBuf,
    token: Zeroizing<String>,
    received: AtomicU64,
    sent: AtomicU64,
    next_write: AtomicU64,
}

type HttpResult<T> = Result<T, (StatusCode, &'static str)>;

impl RelayRoom {
    fn object(&self, vault: &str, object: &str) -> HttpResult<PathBuf> {
        if vault != self.vault || !(hex_id(object) || object == "manifest") {
            return Err((StatusCode::NOT_FOUND, "unknown locker object"));
        }
        Ok(self.objects.join(object))
    }
}

async fn authorize(State(room): State<Arc<RelayRoom>>, request: Request, next: Next) -> Response {
    let valid = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|token| bool::from(token.as_bytes().ct_eq(room.token.as_bytes())));
    if !valid {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}

fn storage_error(error: std::io::Error) -> (StatusCode, &'static str) {
    if error.kind() == std::io::ErrorKind::NotFound {
        (StatusCode::NOT_FOUND, "unknown locker object")
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "locker storage unavailable",
        )
    }
}

#[derive(Serialize)]
struct LockerObject {
    id: String,
    bytes: u64,
}

async fn list(
    State(room): State<Arc<RelayRoom>>,
    Path(vault): Path<String>,
) -> HttpResult<Json<Vec<LockerObject>>> {
    room.object(&vault, "manifest")?;
    let mut directory = tokio::fs::read_dir(&room.objects)
        .await
        .map_err(storage_error)?;
    let mut objects = Vec::new();
    while let Some(entry) = directory.next_entry().await.map_err(storage_error)? {
        let id = entry.file_name().to_string_lossy().into_owned();
        if hex_id(&id) || id == "manifest" {
            let metadata = entry.metadata().await.map_err(storage_error)?;
            if metadata.is_file() {
                objects.push(LockerObject {
                    id,
                    bytes: metadata.len(),
                });
            }
        }
    }
    objects.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(Json(objects))
}

async fn read(
    State(room): State<Arc<RelayRoom>>,
    Path((vault, object)): Path<(String, String)>,
) -> HttpResult<impl IntoResponse> {
    let path = room.object(&vault, &object)?;
    let bytes = tokio::fs::read(path).await.map_err(storage_error)?;
    room.sent.fetch_add(bytes.len() as u64, Ordering::Relaxed);
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    ))
}

async fn write(
    State(room): State<Arc<RelayRoom>>,
    Path((vault, object)): Path<(String, String)>,
    headers: HeaderMap,
    bytes: Bytes,
) -> HttpResult<StatusCode> {
    let path = room.object(&vault, &object)?;
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
    {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected opaque ciphertext bytes",
        ));
    }
    // Clients encrypt before upload, including the manifest. The relay never
    // interprets an object's contents or makes authority from its name.
    let sequence = room.next_write.fetch_add(1, Ordering::Relaxed);
    let temporary = room
        .objects
        .join(format!(".{}-{sequence}.tmp", std::process::id()));
    let result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .await?;
        file.write_all(&bytes).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temporary, &path).await?;
        let directory = tokio::fs::File::open(&room.objects).await?;
        directory.sync_all().await
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
    }
    result.map_err(storage_error)?;
    room.received
        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
    Ok(StatusCode::NO_CONTENT)
}

async fn delete(
    State(room): State<Arc<RelayRoom>>,
    Path((vault, object)): Path<(String, String)>,
) -> HttpResult<StatusCode> {
    tokio::fs::remove_file(room.object(&vault, &object)?)
        .await
        .map_err(storage_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct LockerBytes {
    received: u64,
    sent: u64,
}

async fn meter(
    State(room): State<Arc<RelayRoom>>,
    Path(vault): Path<String>,
) -> HttpResult<Json<LockerBytes>> {
    room.object(&vault, "manifest")?;
    Ok(Json(LockerBytes {
        received: room.received.load(Ordering::Relaxed),
        sent: room.sent.load(Ordering::Relaxed),
    }))
}

fn relay_profile(config: &RelayConfig) -> anyhow::Result<String> {
    // iroh-relay's configuration and packet framing stay upstream. The
    // room's public-key allowlist is only transport admission, never a grant.
    #[derive(Serialize)]
    struct Profile<'a> {
        http_bind_addr: SocketAddr,
        enable_metrics: bool,
        metrics_bind_addr: SocketAddr,
        access: Access<'a>,
    }
    #[derive(Serialize)]
    struct Access<'a> {
        allowlist: &'a [String],
    }
    Ok(toml::to_string(&Profile {
        http_bind_addr: config.relay_bind,
        enable_metrics: true,
        metrics_bind_addr: config.relay_metrics_bind,
        access: Access {
            allowlist: &config.endpoint_keys,
        },
    })?)
}

/// Starts a single blind room and its iroh sidecar. No `Vault::open` path is
/// reachable here. A sidecar failure stops the locker too, rather than
/// advertising a healthy relay that cannot forward packets.
pub async fn run_relay(config_path: &FsPath) -> anyhow::Result<()> {
    crate::commands::init_tracing("info");
    let config: RelayConfig = serde_json::from_slice(&std::fs::read(config_path)?)?;
    config.validate()?;
    let cors = crate::web_client::cors_layer(&config.allowed_origins)?;
    let token_file = Zeroizing::new(std::fs::read_to_string(&config.access_token_file)?);
    let token = Zeroizing::new(token_file.trim().to_owned());
    drop(token_file);
    anyhow::ensure!(
        token.len() >= 32,
        "locker access token must contain at least 32 bytes"
    );
    let directory = config.locker_dir.join(&config.vault_id);
    let objects = directory.join("objects");
    std::fs::create_dir_all(&objects)?;
    for path in [&config.locker_dir, &directory, &objects] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    let room = Arc::new(RelayRoom {
        vault: config.vault_id.clone(),
        objects,
        token,
        received: AtomicU64::new(0),
        sent: AtomicU64::new(0),
        next_write: AtomicU64::new(0),
    });
    let locker = Router::new()
        .route("/v1/relay/{vault}/locker", get(list))
        .route(
            "/v1/relay/{vault}/locker/{object}",
            get(read).put(write).delete(delete),
        )
        .route("/v1/relay/{vault}/bytes", get(meter))
        .layer(DefaultBodyLimit::max(config.max_object_bytes))
        .route_layer(middleware::from_fn_with_state(Arc::clone(&room), authorize))
        .with_state(room);
    let app = locker
        .merge(crate::web_client::routes(
            crate::web_client::EndpointDescriptor::relay(
                config.relay_url.clone(),
                &config.vault_id,
            ),
        ))
        .layer(cors);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let profile = directory.join("iroh-relay.toml");
    std::fs::write(&profile, relay_profile(&config)?)?;
    let mut command = tokio::process::Command::from(oneiron_spawn::command(&config.relay_binary));
    command
        .env_clear()
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .arg("--config-path")
        .arg(&profile);
    let mut child = command.spawn()?;
    tracing::info!(vault = %config.vault_id, required_relay_revision = IROH_RELAY_REVISION, "blind relay room started");
    let serving = axum::serve(listener, app)
        .with_graceful_shutdown(crate::commands::stop_requested())
        .into_future();
    let result = tokio::select! {
        result = serving => result.map_err(anyhow::Error::from),
        status = child.wait() => Err(anyhow::anyhow!("iroh relay exited: {:?}", status?)),
    };
    let _ = child.kill().await;
    result
}
