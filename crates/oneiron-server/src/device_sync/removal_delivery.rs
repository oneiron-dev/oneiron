//! The device's receiver of the archives its person's removals kept for it
//! (FIX 3215, 3396). It holds delivery sessions with its home back to back,
//! each on the paired credential, revoked or not, and a fresh holder proof,
//! so it needs no live membership and runs on after the device's sync lane
//! has ended for good. Each archive a session sends is checked (its digest,
//! and that it is this person's), written beside the credential file,
//! readable by its owner alone, and acknowledged; one already written is
//! acknowledged again. A live member's device holds the same sessions, and a
//! removal wakes them. A failed session is tried again after a wait that
//! doubles from [`REMOVAL_DELIVERY_RETRY_FIRST`] to
//! [`REMOVAL_DELIVERY_RETRY_MAX`]. Logs name receipts, never a slip or a key.
#![cfg_attr(not(feature = "mesh"), allow(dead_code))]

use std::path::{Path, PathBuf};
#[cfg(feature = "mesh")]
use std::sync::Arc;
use std::time::Duration;

use oneiron::federation::RemovalExportCopy;
use oneiron::sync::SyncTransportCredential;
use serde::Deserialize;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::DeviceSyncHost;
use super::dial::Dial;
use crate::commands::credential_file::PairedCredentialFile;
use crate::handler::mesh::MeshHost;

/// The first wait after a failed session (a call).
const REMOVAL_DELIVERY_RETRY_FIRST: Duration = Duration::from_secs(5);
/// The longest wait between failed sessions (a call).
const REMOVAL_DELIVERY_RETRY_MAX: Duration = Duration::from_secs(5 * 60);
/// How long one request may take, a held session's wait included (a call):
/// past it the connection is taken as lost.
const REMOVAL_DELIVERY_REQUEST_TIMEOUT: Duration = Duration::from_secs(2 * 60);
/// The directory beside the credential file the archives are written in.
const ARCHIVE_DIR: &str = "removal-archives";
const DELIVERY_PATH: &str = "/v1/shared/removal-delivery";
const ACK_PATH: &str = "/v1/shared/removal-delivery/ack";

/// The running receiver.
pub(super) struct Receiver {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Receiver {
    /// The receiver for `dial`'s home: at its URL where that URL takes one
    /// (`wss`, or `ws` to a loopback host, as the device's own link requires
    /// off the mesh), else over the mesh to the home machine where the link
    /// has a mesh host (FIX 11196). `None` where neither is in reach.
    #[cfg(feature = "mesh")]
    pub(super) fn start(dial: &Dial, mesh: Option<&MeshHost>) -> Option<Self> {
        use oneiron_mesh_transport::sync_dialer::MeshSyncDialer;

        let credential_file = dial.credential_file.clone();
        let archives = credential_file
            .parent()
            .map_or_else(|| PathBuf::from(ARCHIVE_DIR), |dir| dir.join(ARCHIVE_DIR));
        let (stop, stopped) = oneshot::channel();
        if super::direct(&dial.url).is_ok() {
            let base = http_base(&dial.url)?;
            let task = tokio::spawn(receive(base, credential_file, archives, stopped));
            return Some(Self { stop, task });
        }
        let mesh = mesh?;
        let dialer: Arc<dyn oneiron::sync::SyncDialer> =
            Arc::new(MeshSyncDialer::new(mesh.transport(), dial.home));
        let host = mesh_host(&dial.url);
        let task = tokio::spawn(receive_mesh(
            dialer,
            host,
            credential_file,
            archives,
            stopped,
        ));
        Some(Self { stop, task })
    }

    /// No receiver in a build without the `mesh` feature, whose device sync
    /// never starts.
    #[cfg(not(feature = "mesh"))]
    pub(super) fn start(_dial: &Dial, _mesh: Option<&MeshHost>) -> Option<Self> {
        None
    }

    /// Stops the receiver and waits for its task: a session in flight is
    /// dropped, and its archives go again at the next one.
    pub(super) async fn stop(self) {
        let _ = self.stop.send(());
        if let Err(error) = self.task.await {
            tracing::warn!(%error, "removal archive receiver task");
        }
    }
}

impl DeviceSyncHost {
    /// This host with `removal`, its archive receiver.
    pub(super) fn with_removal(mut self, removal: Option<Receiver>) -> Self {
        self.removal = removal;
        self
    }

    /// A host whose link to the home did not open, kept for its archive
    /// receiver alone: a device its person's removal left unenrolled still
    /// receives its archives.
    pub(super) fn receiving(removal: Receiver) -> Self {
        let (stop, _) = oneshot::channel();
        Self {
            stop,
            task: tokio::spawn(async {}),
            removal: Some(removal),
        }
    }
}

/// The home's HTTP origin for its sync URL.
fn http_base(url: &str) -> Option<reqwest::Url> {
    let http = if let Some(rest) = url.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = url.strip_prefix("ws://") {
        format!("http://{rest}")
    } else {
        url.to_owned()
    };
    reqwest::Url::parse(&http).ok()
}

fn endpoint(base: &reqwest::Url, path: &str) -> reqwest::Url {
    let mut url = base.clone();
    url.set_path(path);
    url.set_query(None);
    url
}

/// The `Host` a mesh delivery request carries: the home URL's authority
/// where it names one, else the mesh itself.
#[cfg(feature = "mesh")]
fn mesh_host(url: &str) -> String {
    http_base(url)
        .map(|base| base.authority().to_owned())
        .filter(|host| !host.is_empty())
        .unwrap_or_else(|| "mesh".to_owned())
}

/// Sessions back to back until `stop`, waiting after each failed one.
async fn receive(
    base: reqwest::Url,
    credential_file: PathBuf,
    archives: PathBuf,
    mut stop: oneshot::Receiver<()>,
) {
    // FIX 6969: a redirect is answered, never followed with the slip
    // headers; without a client the receiver cannot run.
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(%error, "removal archive receiver client");
            return;
        }
    };
    let mut wait = REMOVAL_DELIVERY_RETRY_FIRST;
    loop {
        let session = tokio::select! {
            biased;
            _ = &mut stop => return,
            session = session(&client, &base, &credential_file, &archives) => session,
        };
        match session {
            Ok(()) => wait = REMOVAL_DELIVERY_RETRY_FIRST,
            Err(error) => {
                tracing::debug!(error = %format!("{error:#}"), "removal archive session");
                tokio::select! {
                    biased;
                    _ = &mut stop => return,
                    () = tokio::time::sleep(wait) => {}
                }
                wait = (wait * 2).min(REMOVAL_DELIVERY_RETRY_MAX);
            }
        }
    }
}

/// Sessions over the mesh back to back until `stop`, waiting after each
/// failed one, as at the home's URL.
#[cfg(feature = "mesh")]
async fn receive_mesh(
    dialer: Arc<dyn oneiron::sync::SyncDialer>,
    host: String,
    credential_file: PathBuf,
    archives: PathBuf,
    mut stop: oneshot::Receiver<()>,
) {
    let mut wait = REMOVAL_DELIVERY_RETRY_FIRST;
    loop {
        let session = tokio::select! {
            biased;
            _ = &mut stop => return,
            session = session_mesh(dialer.as_ref(), &host, &credential_file, &archives) => session,
        };
        match session {
            Ok(()) => wait = REMOVAL_DELIVERY_RETRY_FIRST,
            Err(error) => {
                tracing::debug!(error = %format!("{error:#}"), "removal archive session");
                tokio::select! {
                    biased;
                    _ = &mut stop => return,
                    () = tokio::time::sleep(wait) => {}
                }
                wait = (wait * 2).min(REMOVAL_DELIVERY_RETRY_MAX);
            }
        }
    }
}

#[derive(Deserialize)]
struct Deliveries {
    deliveries: Vec<Delivery>,
}

#[derive(Deserialize)]
struct Delivery {
    version: u64,
    copy: RemovalExportCopy,
}

#[derive(Deserialize)]
struct Acknowledged {
    state: String,
}

/// One session: what the home sends is written and acknowledged. A session
/// that sent archives but took no acknowledgement fails, so the next one
/// waits.
async fn session(
    client: &reqwest::Client,
    base: &reqwest::Url,
    credential_file: &Path,
    archives: &Path,
) -> anyhow::Result<()> {
    let paired = PairedCredentialFile::read(credential_file)?;
    let slip = oneiron::authority::CapabilitySlip::from_token(&paired.token)
        .map_err(|_| anyhow::anyhow!("the paired credential's slip does not decode"))?;
    let person = oneiron::EntityId::from_hex(&slip.claims.holder_ref)?;
    let credential = SyncTransportCredential::new(paired.token.clone(), paired.signing_key()?);
    let answer: Deliveries = post(client, endpoint(base, DELIVERY_PATH), &credential, None)
        .await?
        .json()
        .await?;
    if answer.deliveries.is_empty() {
        return Ok(());
    }
    let mut acked = false;
    for delivery in answer.deliveries {
        let archives = archives.to_owned();
        let delivery = tokio::task::spawn_blocking(move || {
            store(&archives, person, &delivery).map(|()| delivery)
        })
        .await??;
        let receipt_id = delivery.copy.receipt_id;
        let body = serde_json::json!({ "receipt_id": &receipt_id, "version": delivery.version });
        let answer: Acknowledged = post(client, endpoint(base, ACK_PATH), &credential, Some(body))
            .await?
            .json()
            .await?;
        tracing::info!(
            receipt = %receipt_id,
            version = delivery.version,
            state = %answer.state,
            "removal archive received"
        );
        acked |= answer.state == "acked";
    }
    anyhow::ensure!(acked, "the home took no acknowledgement");
    Ok(())
}

/// One session over the mesh (FIX 11196): what the home sends is written
/// and acknowledged, as at the home's URL. A session that sent archives
/// but took no acknowledgement fails, so the next one waits.
#[cfg(feature = "mesh")]
async fn session_mesh(
    dialer: &dyn oneiron::sync::SyncDialer,
    host: &str,
    credential_file: &Path,
    archives: &Path,
) -> anyhow::Result<()> {
    let paired = PairedCredentialFile::read(credential_file)?;
    let slip = oneiron::authority::CapabilitySlip::from_token(&paired.token)
        .map_err(|_| anyhow::anyhow!("the paired credential's slip does not decode"))?;
    let person = oneiron::EntityId::from_hex(&slip.claims.holder_ref)?;
    let credential = SyncTransportCredential::new(paired.token.clone(), paired.signing_key()?);
    let answer: Deliveries =
        serde_json::from_slice(&post_mesh(dialer, host, DELIVERY_PATH, &credential, None).await?)?;
    if answer.deliveries.is_empty() {
        return Ok(());
    }
    let mut acked = false;
    for delivery in answer.deliveries {
        let archives = archives.to_owned();
        let delivery = tokio::task::spawn_blocking(move || {
            store(&archives, person, &delivery).map(|()| delivery)
        })
        .await??;
        let receipt_id = delivery.copy.receipt_id;
        let body = serde_json::json!({ "receipt_id": &receipt_id, "version": delivery.version });
        let answer: Acknowledged = serde_json::from_slice(
            &post_mesh(dialer, host, ACK_PATH, &credential, Some(body)).await?,
        )?;
        tracing::info!(
            receipt = %receipt_id,
            version = delivery.version,
            state = %answer.state,
            "removal archive received"
        );
        acked |= answer.state == "acked";
    }
    anyhow::ensure!(acked, "the home took no acknowledgement");
    Ok(())
}

/// One request under a fresh holder proof, its nonce new.
async fn post(
    client: &reqwest::Client,
    url: reqwest::Url,
    credential: &SyncTransportCredential,
    body: Option<serde_json::Value>,
) -> anyhow::Result<reqwest::Response> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let headers = credential
        .left_notice_headers(now)
        .map_err(anyhow::Error::msg)?;
    let mut request = client.post(url).timeout(REMOVAL_DELIVERY_REQUEST_TIMEOUT);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    Ok(request.send().await?.error_for_status()?)
}

/// One delivery request over one fresh mesh stream to the home (FIX 11196):
/// the same path, slip headers and body the URL call sends, answered by the
/// same route, its answer read whole up to the remote bound. The dial, the
/// handshake, the exchange and the connection's drive meet one request
/// timeout, as the renewal's mesh call does.
#[cfg(feature = "mesh")]
async fn post_mesh(
    dialer: &dyn oneiron::sync::SyncDialer,
    host: &str,
    path: &str,
    credential: &SyncTransportCredential,
    body: Option<serde_json::Value>,
) -> anyhow::Result<Vec<u8>> {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, header};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let headers = credential
        .left_notice_headers(now)
        .map_err(anyhow::Error::msg)?;
    let mut request = Request::post(path).header(header::HOST, host.to_owned());
    for (name, value) in headers {
        request = request.header(name, value);
    }
    request = request
        .header(header::ACCEPT, "application/json")
        .header(header::CONNECTION, "close");
    let body = match body {
        Some(body) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    let request = request.body(body)?;
    let round = async {
        let stream = dialer.dial().await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake::<_, Body>(hyper_util::rt::TokioIo::new(stream))
                .await?;
        let exchange = async move {
            let response = sender.send_request(request).await?;
            let status = response.status();
            let bytes = to_bytes(
                Body::new(response.into_body()),
                oneiron_remote::MAX_REMOTE_RESPONSE_BYTES,
            )
            .await?;
            Ok::<_, anyhow::Error>((status, bytes))
        };
        // The connection is driven here, beside its one exchange, never on a
        // task of its own, so an aborted request leaves none of it behind.
        tokio::pin!(exchange, connection);
        let mut driving = true;
        Ok::<_, anyhow::Error>(loop {
            tokio::select! {
                exchanged = &mut exchange => break exchanged?,
                _ = &mut connection, if driving => driving = false,
            }
        })
    };
    let (status, bytes) = tokio::time::timeout(REMOVAL_DELIVERY_REQUEST_TIMEOUT, round)
        .await
        .map_err(|_| anyhow::anyhow!("the delivery request over the mesh timed out"))??;
    anyhow::ensure!(status.is_success(), "the home answered {status}");
    Ok(bytes.to_vec())
}

/// Writes `delivery` under `archives` as `<receipt>.<version>.json`, once it
/// checks: this person's, under a well-formed receipt id, its bytes the
/// digest says. The file is written whole before it takes its name, and only
/// its owner may read it; one already written stays as it is.
fn store(archives: &Path, person: oneiron::EntityId, delivery: &Delivery) -> anyhow::Result<()> {
    let copy = &delivery.copy;
    anyhow::ensure!(
        oneiron::EntityId::from_hex(&copy.member).is_ok_and(|member| member == person),
        "a removal archive for another person"
    );
    let receipt = oneiron::EntityId::from_hex(&copy.receipt_id)?;
    anyhow::ensure!(
        blake3::hash(&copy.export.archive).to_hex().as_str() == copy.export.digest,
        "a removal archive whose bytes are not its digest's"
    );
    std::fs::create_dir_all(archives)?;
    owner_only(archives, 0o700)?;
    let path = archives.join(format!("{}.{}.json", receipt.to_hex(), delivery.version));
    if path.exists() {
        return Ok(());
    }
    let part = path.with_extension("json.part");
    {
        use std::io::Write;

        let mut file = std::fs::File::create(&part)?;
        owner_only(&part, 0o600)?;
        file.write_all(&serde_json::to_vec(copy)?)?;
        file.sync_all()?;
    }
    std::fs::rename(&part, &path)?;
    Ok(())
}

/// Leaves `path` to its owner alone.
fn owner_only(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}
