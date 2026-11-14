//! The device's receiver of the archives its person's removals kept for it
//! (FIX 3215, 3396). It holds delivery sessions with its home back to back,
//! each on the paired credential, revoked or not, and a fresh holder proof,
//! so it needs no live membership and runs on after the device's sync lane
//! has ended for good. Each archive a session sends is checked (its digest,
//! and that it is this person's), written beside the credential file,
//! readable by its owner alone, and acknowledged; one already written is
//! acknowledged again. Each written archive is then taken into the device's
//! vault, which tells its person it arrived (FIX 11197,
//! [`oneiron::Vault::import_removal_archive`]), and its file is deleted once
//! the import has committed, never before (FIX 11797); one that does not
//! import stays on disk as written, and each start takes in those not yet
//! taken in before its first session, and deletes the file of each one taken
//! in before and of each whose term has passed unimported. On a managed
//! vault each import holds a device sync admission (FIX 11796): a frozen
//! vault takes none, the archive waits on disk, and the sessions pause until
//! the vault thaws (FIX 12038); at the thaw the receiver takes in the kept
//! archives again in the same run, beside a session in flight (FIX 12154).
//! A live member's device holds the same sessions, and a removal wakes them.
//! Each answer is spooled to a file and each archive decoded from it into a
//! spool file of the vault's own, so no archive is held whole (FIX 21529,
//! [`copy_json`]).
//! A failed session is tried again after a wait that doubles from
//! [`REMOVAL_DELIVERY_RETRY_FIRST`] to [`REMOVAL_DELIVERY_RETRY_MAX`]. Logs
//! name receipts, never a slip or a key.
#![cfg_attr(not(feature = "mesh"), allow(dead_code))]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use oneiron::federation::{REMOVAL_EXPORT_RETAIN_SECS, RemovalExportFile};
use oneiron::sync::SyncTransportCredential;
use serde::Deserialize;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::DeviceSyncHost;
use super::ReapFreeze;
use super::dial::Dial;
use crate::commands::credential_file::PairedCredentialFile;
#[cfg(not(feature = "mesh"))]
use crate::handler::mesh::MeshHost;
use crate::server::HousekeepingAdmission;

mod copy_json;
mod import_gate;
mod kept_files;
use copy_json::Delivery;
use import_gate::ImportGate;
use kept_files::{remove_imported, remove_lapsed};

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
    /// has a mesh host (FIX 11196). `None` where neither is in reach. What
    /// it receives goes into `vault`, this device's own, each import admitted
    /// under `freeze` (FIX 12038); an import it refuses is tried again at
    /// its thaw (FIX 12154).
    #[cfg(feature = "mesh")]
    pub(super) fn start(
        dial: &Dial,
        transport: Option<Arc<dyn oneiron_mesh_transport::MeshTransport>>,
        vault: &Arc<oneiron::Vault>,
        freeze: ReapFreeze,
    ) -> Option<Self> {
        use oneiron_mesh_transport::sync_dialer::MeshSyncDialer;

        let credential_file = dial.credential_file.clone();
        let archives = credential_file
            .parent()
            .map_or_else(|| PathBuf::from(ARCHIVE_DIR), |dir| dir.join(ARCHIVE_DIR));
        let vault = Arc::clone(vault);
        let gate = ImportGate::new(freeze);
        let (stop, stopped) = oneshot::channel();
        if super::direct(&dial.url).is_ok() {
            let base = http_base(&dial.url)?;
            let task = tokio::spawn(receive(
                base,
                vault,
                gate,
                credential_file,
                archives,
                stopped,
            ));
            return Some(Self { stop, task });
        }
        let transport = transport?;
        let dialer: Arc<dyn oneiron::sync::SyncDialer> =
            Arc::new(MeshSyncDialer::new(transport, dial.home));
        let host = mesh_host(&dial.url);
        let task = tokio::spawn(receive_mesh(
            dialer,
            host,
            vault,
            gate,
            credential_file,
            archives,
            stopped,
        ));
        Some(Self { stop, task })
    }

    /// No receiver in a build without the `mesh` feature, whose device sync
    /// never starts.
    #[cfg(not(feature = "mesh"))]
    pub(super) fn start(
        _dial: &Dial,
        _mesh: Option<&MeshHost>,
        _vault: &Arc<oneiron::Vault>,
        _freeze: ReapFreeze,
    ) -> Option<Self> {
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
            #[cfg(oneiron_test_support)]
            dials_peers: false,
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

/// Sessions back to back until `stop`, waiting after each failed one, once
/// the archives an earlier run kept but did not import are taken in. On a
/// managed vault the sessions pause while the vault is frozen for reap (FIX
/// 12038), and what an import skipped is taken in again after the thaw. When
/// the freeze that refused an import lifts, the kept archives are taken in
/// again beside the session in flight, which runs on (FIX 12154).
async fn receive(
    base: reqwest::Url,
    vault: Arc<oneiron::Vault>,
    gate: ImportGate,
    credential_file: PathBuf,
    archives: PathBuf,
    mut stop: oneshot::Receiver<()>,
) {
    let admit = &gate.admit;
    let mut freeze = gate.freeze();
    if freeze.admit().is_none() {
        let Some(_thawed) = freeze.resumed(&mut stop).await else {
            return;
        };
    }
    tokio::select! {
        biased;
        _ = &mut stop => return,
        () = import_kept(&vault, admit, &credential_file, &archives) => {}
    }
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
            session = session(&client, &base, &vault, admit, &credential_file, &archives) => {
                session
            }
            never = gate.retry_after_thaws(&vault, &credential_file, &archives) => match never {},
        };
        match session {
            Ok(()) => wait = REMOVAL_DELIVERY_RETRY_FIRST,
            Err(error) => {
                if freeze.admit().is_none() {
                    tracing::info!("removal archive receiver paused: the vault is frozen for reap");
                    let Some(_thawed) = freeze.resumed(&mut stop).await else {
                        return;
                    };
                    tracing::info!("removal archive receiver resumes: the vault thawed");
                    tokio::select! {
                        biased;
                        _ = &mut stop => return,
                        () = gate.import_after_thaw(&vault, &credential_file, &archives) => {}
                    }
                    continue;
                }
                tracing::debug!(error = %format!("{error:#}"), "removal archive session");
                tokio::select! {
                    biased;
                    _ = &mut stop => return,
                    () = tokio::time::sleep(wait) => {}
                    never = gate.retry_after_thaws(&vault, &credential_file, &archives) => {
                        match never {}
                    }
                }
                wait = (wait * 2).min(REMOVAL_DELIVERY_RETRY_MAX);
            }
        }
    }
}

/// Sessions over the mesh back to back until `stop`, waiting after each
/// failed one, as at the home's URL, once the archives an earlier run kept
/// but did not import are taken in, and again, beside the session in flight,
/// when the reap freeze that refused an import lifts (FIX 12154). They pause
/// while the vault is frozen for reap, as at the home's URL.
#[cfg(feature = "mesh")]
async fn receive_mesh(
    dialer: Arc<dyn oneiron::sync::SyncDialer>,
    host: String,
    vault: Arc<oneiron::Vault>,
    gate: ImportGate,
    credential_file: PathBuf,
    archives: PathBuf,
    mut stop: oneshot::Receiver<()>,
) {
    let admit = &gate.admit;
    let mut freeze = gate.freeze();
    if freeze.admit().is_none() {
        let Some(_thawed) = freeze.resumed(&mut stop).await else {
            return;
        };
    }
    tokio::select! {
        biased;
        _ = &mut stop => return,
        () = import_kept(&vault, admit, &credential_file, &archives) => {}
    }
    let mut wait = REMOVAL_DELIVERY_RETRY_FIRST;
    loop {
        let session = tokio::select! {
            biased;
            _ = &mut stop => return,
            session = session_mesh(
                dialer.as_ref(),
                &host,
                &vault,
                admit,
                &credential_file,
                &archives,
            ) => session,
            never = gate.retry_after_thaws(&vault, &credential_file, &archives) => match never {},
        };
        match session {
            Ok(()) => wait = REMOVAL_DELIVERY_RETRY_FIRST,
            Err(error) => {
                if freeze.admit().is_none() {
                    tracing::info!("removal archive receiver paused: the vault is frozen for reap");
                    let Some(_thawed) = freeze.resumed(&mut stop).await else {
                        return;
                    };
                    tracing::info!("removal archive receiver resumes: the vault thawed");
                    tokio::select! {
                        biased;
                        _ = &mut stop => return,
                        () = gate.import_after_thaw(&vault, &credential_file, &archives) => {}
                    }
                    continue;
                }
                tracing::debug!(error = %format!("{error:#}"), "removal archive session");
                tokio::select! {
                    biased;
                    _ = &mut stop => return,
                    () = tokio::time::sleep(wait) => {}
                    never = gate.retry_after_thaws(&vault, &credential_file, &archives) => {
                        match never {}
                    }
                }
                wait = (wait * 2).min(REMOVAL_DELIVERY_RETRY_MAX);
            }
        }
    }
}

#[derive(Deserialize)]
struct Acknowledged {
    state: String,
}

/// One session: what the home sends is written, taken into `vault` and
/// acknowledged. A session that sent archives but took no acknowledgement
/// fails, so the next one waits. Each import holds a device sync admission
/// (FIX 12038); while the vault is frozen the session fails before the
/// skipped archive's acknowledgement, so the session after the thaw takes
/// it again.
async fn session(
    client: &reqwest::Client,
    base: &reqwest::Url,
    vault: &Arc<oneiron::Vault>,
    admit: &HousekeepingAdmission,
    credential_file: &Path,
    archives: &Path,
) -> anyhow::Result<()> {
    let paired = PairedCredentialFile::read(credential_file)?;
    let slip = oneiron::authority::CapabilitySlip::from_token(&paired.token)
        .map_err(|_| anyhow::anyhow!("the paired credential's slip does not decode"))?;
    let person = oneiron::EntityId::from_hex(&slip.claims.holder_ref)?;
    let credential = SyncTransportCredential::new(paired.token.clone(), paired.signing_key()?);
    let mut response = post(client, endpoint(base, DELIVERY_PATH), &credential, None).await?;
    let mut spool = tokio::fs::File::from_std(vault.archive_spool_file()?);
    while let Some(piece) = response.chunk().await? {
        spool.write_all(&piece).await?;
    }
    let (spooled, deliveries) = read_answer(spool).await?;
    if deliveries.is_empty() {
        return Ok(());
    }
    let mut acked = false;
    for delivery in deliveries {
        let (receipt_id, version) =
            take_in(vault, admit, archives, person, &spooled, delivery).await?;
        let body = serde_json::json!({ "receipt_id": &receipt_id, "version": version });
        let answer: Acknowledged = post(client, endpoint(base, ACK_PATH), &credential, Some(body))
            .await?
            .json()
            .await?;
        tracing::info!(
            receipt = %receipt_id,
            version,
            state = %answer.state,
            "removal archive received"
        );
        acked |= answer.state == "acked";
    }
    anyhow::ensure!(acked, "the home took no acknowledgement");
    Ok(())
}

/// The deliveries of a session's answer, spooled in `spool`, read off the
/// async runtime ([`copy_json::read_deliveries`]), and the answer's file,
/// which keeps their archives.
async fn read_answer(mut spool: tokio::fs::File) -> anyhow::Result<(std::fs::File, Vec<Delivery>)> {
    spool.flush().await?;
    let mut answer = spool.into_std().await;
    Ok(tokio::task::spawn_blocking(move || {
        let deliveries = copy_json::read_deliveries(&mut answer)?;
        Ok::<_, std::io::Error>((answer, deliveries))
    })
    .await??)
}

/// Writes and imports one `delivery` of the session answer `answer`, under
/// an admission `admit` grants, off the async runtime: [`store`], then
/// [`import`]. Answers its receipt and version for its acknowledgement.
async fn take_in(
    vault: &Arc<oneiron::Vault>,
    admit: &HousekeepingAdmission,
    archives: &Path,
    person: oneiron::EntityId,
    answer: &std::fs::File,
    delivery: Delivery,
) -> anyhow::Result<(String, u64)> {
    let Some(admitted) = admit() else {
        anyhow::bail!("the vault is frozen for reap");
    };
    let archives = archives.to_owned();
    let vault = Arc::clone(vault);
    let mut answer = answer.try_clone()?;
    tokio::task::spawn_blocking(move || {
        let _admitted = admitted;
        let taken = (delivery.copy.receipt_id.clone(), delivery.version);
        let (path, mut copy) = store(&vault, &archives, person, &mut answer, delivery)?;
        import(&vault, person, &mut copy, &path);
        Ok::<_, anyhow::Error>(taken)
    })
    .await?
}

/// One session over the mesh (FIX 11196): what the home sends is written,
/// taken into `vault` and acknowledged, as at the home's URL. A session that
/// sent archives but took no acknowledgement fails, so the next one waits.
/// Each import holds a device sync admission, as at the home's URL.
#[cfg(feature = "mesh")]
async fn session_mesh(
    dialer: &dyn oneiron::sync::SyncDialer,
    host: &str,
    vault: &Arc<oneiron::Vault>,
    admit: &HousekeepingAdmission,
    credential_file: &Path,
    archives: &Path,
) -> anyhow::Result<()> {
    let paired = PairedCredentialFile::read(credential_file)?;
    let slip = oneiron::authority::CapabilitySlip::from_token(&paired.token)
        .map_err(|_| anyhow::anyhow!("the paired credential's slip does not decode"))?;
    let person = oneiron::EntityId::from_hex(&slip.claims.holder_ref)?;
    let credential = SyncTransportCredential::new(paired.token.clone(), paired.signing_key()?);
    let spool = tokio::fs::File::from_std(vault.archive_spool_file()?);
    let spool = post_mesh(dialer, host, DELIVERY_PATH, &credential, None, |body| {
        spool_body(body, spool)
    })
    .await?;
    let (spooled, deliveries) = read_answer(spool).await?;
    if deliveries.is_empty() {
        return Ok(());
    }
    let mut acked = false;
    for delivery in deliveries {
        let (receipt_id, version) =
            take_in(vault, admit, archives, person, &spooled, delivery).await?;
        let body = serde_json::json!({ "receipt_id": &receipt_id, "version": version });
        let answer: Acknowledged = serde_json::from_slice(
            &post_mesh(
                dialer,
                host,
                ACK_PATH,
                &credential,
                Some(body),
                |body| async move {
                    let bytes =
                        axum::body::to_bytes(body, oneiron_remote::MAX_REMOTE_RESPONSE_BYTES)
                            .await?;
                    Ok::<_, anyhow::Error>(bytes)
                },
            )
            .await?,
        )?;
        tracing::info!(
            receipt = %receipt_id,
            version,
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
/// same route, its answer's body read by `read`: an acknowledgement whole up
/// to the remote bound, a session's archives into a spool file however long
/// (FIX 21529). The dial, the handshake, the exchange, the body's read and
/// the connection's drive meet one request timeout, as the renewal's mesh
/// call does.
#[cfg(feature = "mesh")]
async fn post_mesh<T, Answer>(
    dialer: &dyn oneiron::sync::SyncDialer,
    host: &str,
    path: &str,
    credential: &SyncTransportCredential,
    body: Option<serde_json::Value>,
    read: impl FnOnce(axum::body::Body) -> Answer,
) -> anyhow::Result<T>
where
    Answer: std::future::Future<Output = anyhow::Result<T>>,
{
    use axum::body::Body;
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
            let answer = read(Body::new(response.into_body())).await?;
            Ok::<_, anyhow::Error>((status, answer))
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
    let (status, answer) = tokio::time::timeout(REMOVAL_DELIVERY_REQUEST_TIMEOUT, round)
        .await
        .map_err(|_| anyhow::anyhow!("the delivery request over the mesh timed out"))??;
    anyhow::ensure!(status.is_success(), "the home answered {status}");
    Ok(answer)
}

/// `body` written to the end of `spool` piece by piece as it arrives.
#[cfg(feature = "mesh")]
async fn spool_body(
    body: axum::body::Body,
    mut spool: tokio::fs::File,
) -> anyhow::Result<tokio::fs::File> {
    use futures_util::StreamExt as _;

    let mut pieces = body.into_data_stream();
    while let Some(piece) = pieces.next().await {
        spool.write_all(&piece?).await?;
    }
    Ok(spool)
}

/// Writes `delivery` of the session answer `answer` under `archives` as
/// `<receipt>.<version>.json`, once it checks: this person's, under a
/// well-formed receipt id, its archive the bytes the digest says, decoded
/// into a spool file of `vault`'s own as it is checked. The file is the
/// copy's JSON as the answer carries it, copied from the answer's file
/// whole before it takes its name, and only its owner may read it; one
/// already written stays as it is. Answers the file's path and the copy.
fn store(
    vault: &oneiron::Vault,
    archives: &Path,
    person: oneiron::EntityId,
    answer: &mut std::fs::File,
    delivery: Delivery,
) -> anyhow::Result<(PathBuf, RemovalExportFile)> {
    let copy = &delivery.copy;
    anyhow::ensure!(
        oneiron::EntityId::from_hex(&copy.member).is_ok_and(|member| member == person),
        "a removal archive for another person"
    );
    let receipt = oneiron::EntityId::from_hex(&copy.receipt_id)?;
    let (archive, digest) =
        copy_json::decode_archive(answer, delivery.archive, vault.archive_spool_file()?)?;
    anyhow::ensure!(
        digest == copy.export.digest,
        "a removal archive whose bytes are not its digest's"
    );
    std::fs::create_dir_all(archives)?;
    owner_only(archives, 0o700)?;
    let path = archives.join(format!("{}.{}.json", receipt.to_hex(), delivery.version));
    if !path.exists() {
        let part = path.with_extension("json.part");
        {
            let mut file = std::fs::File::create(&part)?;
            owner_only(&part, 0o600)?;
            copy_json::copy_span(answer, delivery.json, &mut file)?;
            file.sync_all()?;
        }
        std::fs::rename(&part, &path)?;
    }
    Ok((path, RemovalExportFile::received(delivery.copy, archive)))
}

/// Takes `copy`, the archive written at `path` beside the credential for
/// `person`, into `vault` (FIX 11197), and logs what came of it by its
/// receipt; its caller holds the import's admission (FIX 11796). One that
/// does not import stays on disk as written, and the next start tries it
/// again. Once its import has committed, by this call or an earlier one, its
/// file goes ([`remove_imported`]).
fn import(
    vault: &oneiron::Vault,
    person: oneiron::EntityId,
    copy: &mut RemovalExportFile,
    path: &Path,
) {
    match vault.import_removal_archive(person, copy) {
        Ok(Some(records)) => tracing::info!(
            receipt = %copy.receipt_id(),
            version = copy.delivered_at(),
            records,
            "removal archive imported"
        ),
        Ok(None) => tracing::debug!(
            receipt = %copy.receipt_id(),
            version = copy.delivered_at(),
            "removal archive imported before"
        ),
        Err(error) => {
            tracing::warn!(
                receipt = %copy.receipt_id(),
                version = copy.delivered_at(),
                %error,
                "removal archive kept on disk, not imported"
            );
            return;
        }
    }
    remove_imported(path, copy.receipt_id(), copy.delivered_at());
}

/// Takes into `vault` each archive kept under `archives` that it has not
/// taken in yet: one an earlier import refused or never reached. Each is
/// logged as [`import`] logs it; a sweep that cannot run is logged once and
/// leaves every file as it is. Each import holds an admission `admit`
/// grants; one skipped while frozen stays for the sweep after the thaw.
async fn import_kept(
    vault: &Arc<oneiron::Vault>,
    admit: &HousekeepingAdmission,
    credential_file: &Path,
    archives: &Path,
) {
    let (vault, admit) = (Arc::clone(vault), Arc::clone(admit));
    let (credential_file, archives) = (credential_file.to_owned(), archives.to_owned());
    let swept = tokio::task::spawn_blocking(move || {
        import_dir(&vault, &admit, &credential_file, &archives)
    })
    .await;
    match swept {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(
            error = %format!("{error:#}"),
            "kept removal archives not imported"
        ),
        Err(error) => tracing::warn!(%error, "kept removal archive import task"),
    }
}

/// [`import_kept`]'s sweep: each archive under `archives` not yet taken in
/// is read and imported for the paired credential's holder, and the file of
/// each one taken in before goes, its import committed (FIX 11797): one
/// whose delete failed, or whose row has since lapsed at its term. The file
/// of one whose term has passed unimported goes too ([`remove_lapsed`]). No
/// directory, no sweep. Each import holds an admission `admit` grants; one
/// skipped while frozen stays on disk for the sweep after the thaw.
fn import_dir(
    vault: &oneiron::Vault,
    admit: &HousekeepingAdmission,
    credential_file: &Path,
    archives: &Path,
) -> anyhow::Result<()> {
    let entries = match std::fs::read_dir(archives) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let paired = PairedCredentialFile::read(credential_file)?;
    let slip = oneiron::authority::CapabilitySlip::from_token(&paired.token)
        .map_err(|_| anyhow::anyhow!("the paired credential's slip does not decode"))?;
    let person = oneiron::EntityId::from_hex(&slip.claims.holder_ref)?;
    // The wall clock, which the store clock never trails: a term passed on it
    // has passed on the store clock the import reads.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    for entry in entries {
        let path = entry?.path();
        let Some((receipt, version)) = archive_name(&path) else {
            continue;
        };
        if vault.removal_archive_imported(person, receipt, version)? {
            remove_imported(&path, &receipt.to_hex(), version);
            continue;
        }
        if version.saturating_add(REMOVAL_EXPORT_RETAIN_SECS) <= now {
            remove_lapsed(&path, &receipt.to_hex(), version);
            continue;
        }
        let mut copy = match read_kept(vault, &path) {
            Ok(copy) => copy,
            Err(error) => {
                tracing::warn!(
                    receipt = %receipt.to_hex(),
                    version,
                    error = %format!("{error:#}"),
                    "kept removal archive does not read"
                );
                continue;
            }
        };
        let Some(_admitted) = admit() else {
            tracing::info!(
                receipt = %copy.receipt_id(),
                version = copy.delivered_at(),
                "removal archive kept on disk for the sweep after the thaw: the vault is paused \
                 for reap preparation"
            );
            continue;
        };
        import(vault, person, &mut copy, &path);
    }
    Ok(())
}

/// The receipt and delivery version an archive file's name carries,
/// `<receipt>.<version>.json` as [`store`] writes it; `None` for any other
/// file, one still being written included.
fn archive_name(path: &Path) -> Option<(oneiron::EntityId, u64)> {
    let name = path.file_name()?.to_str()?.strip_suffix(".json")?;
    let (receipt, version) = name.rsplit_once('.')?;
    let receipt = oneiron::EntityId::from_hex(receipt).ok()?;
    Some((receipt, version.parse().ok()?))
}

/// The archive kept at `path`, as [`store`] wrote it, its archive decoded
/// into a spool file of `vault`'s own.
fn read_kept(vault: &oneiron::Vault, path: &Path) -> anyhow::Result<RemovalExportFile> {
    Ok(copy_json::read_kept(path, vault.archive_spool_file()?)?)
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
