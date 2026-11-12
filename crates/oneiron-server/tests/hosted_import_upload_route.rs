//! [HOSTED-IMPORT-UPLOAD-ROUTE] (census item 14, L2-19; ARCH-0027:151
//! #hosted-import: "Upload bytes go straight to the vault's own hostname";
//! the Engine's rulings of 13 Nov 07:14, HI-SEAM = A: the HTTP route stages
//! through the same writer). The owner declares an upload of a ChatGPT
//! export at `POST /v1/owner/imports/hosted` and sends it in parts with
//! `PUT /v1/owner/imports/hosted/{import}/upload?offset=N`. The upload's
//! state between two parts is its staging folder alone: a server dropped
//! and built again between the parts answers the upload's offset at
//! `GET .../upload`, refuses a part at another offset, and takes the next
//! part there. The part that reaches the declared size stages the export,
//! and the vault's hosted-import worker lands it as a job. A part past the
//! declared size, declared or counted, writes nothing, and a declared size
//! the vault's disk floor has no room for is refused. A caller without the
//! owner's proof is refused every route.
//!
//! Each case drives the real routes in process (`build_app(..).oneshot(..)`,
//! no TCP ports, no sleeps, no models) with the owner's host-root
//! credential, on an engine-sized stack, and runs the worker's pass through
//! `oneiron_server::test_doors::hosted_import`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test hosted_import_upload_route`.
#![cfg(all(oneiron_test_support, unix))]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::ingest::history::{HostedImportId, HostedImportJob, HostedImportState};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::test_doors::hosted_import::pass;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Map, Value, json};
use tower::ServiceExt;

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

const DECLARE: &str = "/v1/owner/imports/hosted";
/// Three conversations of 2, 3 and 4 messages.
const SIZES: [u32; 3] = [2, 3, 4];
const MESSAGES: u64 = 9;

/// Runs `case` on an engine-sized stack and runtime, as the served doors
/// need more than a test thread's default stack.
fn run_on_engine_stack(
    name: &str,
    case: impl std::future::Future<Output = TestResult> + Send + 'static,
) {
    let run = std::thread::Builder::new()
        .name(name.into())
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("engine-sized test runtime")
                .block_on(case)
        })
        .expect("spawn the engine-sized test thread");
    match run.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => panic!("{error}"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// A ChatGPT export (`conversations.json`) of one linear thread per entry
/// of [`SIZES`], user and assistant in turn, created 100 s apart. Message
/// ids are unique across the export, as ChatGPT's are.
fn export_bytes() -> Result<Vec<u8>, TestError> {
    let mut export = Vec::new();
    for (number, &messages) in SIZES.iter().enumerate() {
        let created = 1_757_840_000 + 100 * u32::try_from(number)?;
        let id = format!("upload-conversation-{number}");
        let key = |index: u32| format!("upload-c{number}-m{index}");
        let mut mapping = Map::new();
        mapping.insert(
            "root".to_owned(),
            json!({ "id": "root", "message": null, "parent": null, "children": [key(0)] }),
        );
        for index in 0..messages {
            let role = if index % 2 == 0 { "user" } else { "assistant" };
            let parent = if index == 0 {
                "root".to_owned()
            } else {
                key(index - 1)
            };
            let children: Vec<String> = (index + 1 < messages)
                .then(|| key(index + 1))
                .into_iter()
                .collect();
            mapping.insert(
                key(index),
                json!({
                    "id": key(index),
                    "parent": parent,
                    "children": children,
                    "message": {
                        "id": key(index),
                        "author": { "role": role, "name": null, "metadata": {} },
                        "create_time": f64::from(created) + f64::from(index),
                        "update_time": null,
                        "content": {
                            "content_type": "text",
                            "parts": [format!("Notes on the orchard plan, part {number}.{index}.")]
                        },
                        "status": "finished_successfully",
                        "end_turn": true,
                        "weight": 1.0,
                        "metadata": {},
                        "recipient": "all",
                        "channel": null
                    }
                }),
            );
        }
        export.push(json!({
            "title": format!("The orchard plan {number}"),
            "create_time": f64::from(created),
            "update_time": f64::from(created + messages),
            "mapping": Value::Object(mapping),
            "current_node": key(messages - 1),
            "conversation_id": id,
            "id": id,
        }));
    }
    Ok(serde_json::to_vec(&export)?)
}

/// A served vault, as `serve` holds it: this process holds its writer
/// lease, its install is rooted and profiled, and its owner acts through
/// the host-root credential.
struct Host {
    dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Option<Arc<SyncServer>>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
}

/// A server over `vault`, as a start of `serve` builds it.
fn serve(vault: &Arc<Vault>) -> Result<(Arc<SyncServer>, Router), TestError> {
    let server = Arc::new(SyncServer::new(
        Arc::clone(vault),
        SyncServerConfig {
            auth_secret: Some("hosted-import-upload-route".into()),
            ..Default::default()
        },
    )?);
    let app = build_app(Arc::clone(&server));
    Ok((server, app))
}

impl Host {
    fn new() -> Result<Self, TestError> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 64 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let (server, app) = serve(&vault)?;
        let issuer = vault.load_host_slip_issuer()?;
        let owner_slip = vault.ensure_host_root_slip(&issuer)?;
        let owner_token = owner_slip.to_token()?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        vault.ensure_embedded_owner_actor()?;
        Ok(Self {
            dir,
            vault,
            server: Some(server),
            app,
            issuer,
            owner_slip,
            owner_token,
        })
    }

    /// The server dropped and built again over the same vault, as a restart
    /// of `serve` does: nothing of the upload outlives it but its folder.
    fn restart(&mut self) -> TestResult {
        self.app = Router::new();
        drop(self.server.take());
        let (server, app) = serve(&self.vault)?;
        self.server = Some(server);
        self.app = app;
        Ok(())
    }

    fn vault_dir(&self) -> &Path {
        self.dir.path()
    }

    fn folder(&self, import: &str) -> PathBuf {
        self.dir.path().join("imports").join(import)
    }

    /// The upload folders under `imports/`.
    fn folders(&self) -> Result<usize, TestError> {
        match std::fs::read_dir(self.dir.path().join("imports")) {
            Ok(entries) => Ok(entries.count()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(error.into()),
        }
    }

    /// The length of the upload's `export.part`.
    fn part_len(&self, import: &str) -> Result<u64, TestError> {
        Ok(std::fs::metadata(self.folder(import).join("export.part"))?.len())
    }

    fn binding(&self) -> Result<String, TestError> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .issuer
            .binding_proof(&self.owner_slip, challenge.as_bytes())?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string())
    }

    /// `request` with the owner's credential when `as_owner`, sent to the
    /// served app: its status and its answer, as text when it is not JSON.
    async fn send(
        &self,
        request: axum::http::request::Builder,
        body: Body,
        as_owner: bool,
    ) -> Result<(StatusCode, Value), TestError> {
        let request = if as_owner {
            request
                .header("authorization", format!("Bearer {}", self.owner_token))
                .header("x-oneiron-binding", self.binding()?)
        } else {
            request
        };
        let response = self.app.clone().oneshot(request.body(body)?).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
        let answer = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, answer))
    }

    async fn declare(
        &self,
        source: &str,
        bytes: u64,
        as_owner: bool,
    ) -> Result<(StatusCode, Value), TestError> {
        let request = Request::post(DECLARE).header("content-type", "application/json");
        let body = Body::from(json!({ "source": source, "bytes": bytes }).to_string());
        self.send(request, body, as_owner).await
    }

    async fn state(&self, import: &str, as_owner: bool) -> Result<(StatusCode, Value), TestError> {
        let request = Request::get(format!("{DECLARE}/{import}/upload"));
        self.send(request, Body::empty(), as_owner).await
    }

    /// One part at `offset`; `declared` says the part's length in its
    /// `content-length`, else the server counts it as it arrives.
    async fn put(
        &self,
        import: &str,
        offset: u64,
        part: &[u8],
        declared: bool,
        as_owner: bool,
    ) -> Result<(StatusCode, Value), TestError> {
        let mut request = Request::put(format!("{DECLARE}/{import}/upload?offset={offset}"))
            .header("content-type", "application/octet-stream");
        if declared {
            request = request.header("content-length", part.len().to_string());
        }
        self.send(request, Body::from(part.to_vec()), as_owner)
            .await
    }

    fn job(&self, import: &str) -> Result<HostedImportJob, TestError> {
        let id = HostedImportId::parse(import).ok_or("the answer's id is no import id")?;
        self.vault
            .hosted_import(id)?
            .ok_or_else(|| format!("no job row for hosted import {import}").into())
    }
}

/// The declared upload's id, from the declare's answer.
fn import_of(answer: &Value) -> Result<String, TestError> {
    Ok(answer["import_id"]
        .as_str()
        .ok_or_else(|| format!("the declare answered no import_id: {answer}"))?
        .to_owned())
}

/// The upload's (offset, staged) from a route's answer.
fn standing(answer: &Value) -> (Option<u64>, Option<bool>) {
    (answer["offset"].as_u64(), answer["staged"].as_bool())
}

#[test]
fn an_upload_in_two_parts_resumes_after_a_restart_and_its_job_lands() {
    run_on_engine_stack("upload-resumes", async {
        let mut host = Host::new()?;
        let export = export_bytes()?;
        let total = u64::try_from(export.len())?;
        let (first, second) = export.split_at(export.len() / 2);
        let half = u64::try_from(first.len())?;

        let (status, answer) = host.declare("chatgpt", total, true).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "FAILBEFORE: the owner declares an upload: {answer}"
        );
        let import = import_of(&answer)?;
        assert_eq!(standing(&answer), (Some(0), Some(false)));
        assert_eq!(answer["declared_bytes"].as_u64(), Some(total));

        let (status, answer) = host.put(&import, 0, first, true, true).await?;
        assert_eq!(status, StatusCode::OK, "the first part: {answer}");
        assert_eq!(standing(&answer), (Some(half), Some(false)));
        assert_eq!(host.part_len(&import)?, half);
        assert!(!host.folder(&import).join("request.json").exists());

        // The server stops between the parts; the next one knows the
        // upload only by its folder.
        host.restart()?;
        let (status, answer) = host.state(&import, true).await?;
        assert_eq!(status, StatusCode::OK, "the upload's state: {answer}");
        assert_eq!(
            standing(&answer),
            (Some(half), Some(false)),
            "the restarted server answers the upload's offset"
        );
        let (status, answer) = host.put(&import, 0, first, true, true).await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a part at another offset is refused: {answer}"
        );
        assert!(answer.to_string().contains("upload_offset"), "{answer}");
        assert_eq!(host.part_len(&import)?, half, "and writes nothing");

        let (status, answer) = host.put(&import, half, second, true, true).await?;
        assert_eq!(status, StatusCode::OK, "the last part: {answer}");
        assert_eq!(
            standing(&answer),
            (Some(total), Some(true)),
            "the part that reaches the declared size stages the export"
        );
        let folder = host.folder(&import);
        assert!(!folder.join("export.part").exists());
        assert_eq!(
            std::fs::read(folder.join("export.json"))?,
            export,
            "the staged export is the bytes sent, in order"
        );
        assert!(folder.join("request.json").is_file());
        // A client whose last reply was lost sends the end again.
        let (status, answer) = host.put(&import, total, &[], true, true).await?;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(standing(&answer), (Some(total), Some(true)));

        pass(&host.vault, host.vault_dir(), None)?;
        let job = host.job(&import)?;
        assert_eq!(job.state, HostedImportState::Landed);
        assert_eq!((job.conversations, job.messages), (3, MESSAGES));
        assert_eq!(job.new, MESSAGES, "every message landed once");
        assert_eq!(job.staged_bytes, total);
        assert!(!folder.exists(), "the staging is removed once the job ends");
        Ok::<(), TestError>(())
    });
}

#[test]
fn a_part_past_the_declared_size_writes_nothing() {
    run_on_engine_stack("upload-past-declared", async {
        let host = Host::new()?;
        let export = export_bytes()?;
        let total = u64::try_from(export.len())?;
        let mut longer = export.clone();
        longer.push(b'\n');

        let (status, answer) = host.declare("chatgpt", total, true).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "FAILBEFORE: the owner declares an upload: {answer}"
        );
        let import = import_of(&answer)?;

        // One byte past the declared size: refused by its length, then as
        // it arrives.
        let (status, answer) = host.put(&import, 0, &longer, true, true).await?;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{answer}");
        let (status, answer) = host.put(&import, 0, &longer, false, true).await?;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{answer}");
        assert_eq!(host.part_len(&import)?, 0, "neither wrote a byte");

        let (status, answer) = host.put(&import, 0, &export[..10], true, true).await?;
        assert_eq!(status, StatusCode::OK, "{answer}");
        let (status, answer) = host.put(&import, 10, &longer[10..], false, true).await?;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{answer}");
        assert_eq!(
            host.part_len(&import)?,
            10,
            "the part past the size wrote nothing"
        );
        let (status, answer) = host.state(&import, true).await?;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(standing(&answer), (Some(10), Some(false)));

        // Nothing is staged: the worker makes no job.
        pass(&host.vault, host.vault_dir(), None)?;
        assert!(host.vault.hosted_imports()?.is_empty(), "no job was made");
        assert!(!host.folder(&import).join("request.json").exists());

        // A size the vault's disk has no room for past its floor, a size of
        // nothing and a source that is no export: refused, no folder made.
        let (status, answer) = host.declare("chatgpt", u64::MAX, true).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{answer}");
        assert!(answer.to_string().contains("disk_capacity"), "{answer}");
        let (status, answer) = host.declare("chatgpt", 0, true).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
        let (status, answer) = host.declare("claude_code", total, true).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
        assert_eq!(host.folders()?, 1, "only the first upload has a folder");

        // The upload goes on at its offset and lands whole.
        let (status, answer) = host.put(&import, 10, &export[10..], false, true).await?;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(standing(&answer), (Some(total), Some(true)));
        pass(&host.vault, host.vault_dir(), None)?;
        let job = host.job(&import)?;
        assert_eq!(job.state, HostedImportState::Landed);
        assert_eq!(job.new, MESSAGES);
        Ok::<(), TestError>(())
    });
}

#[test]
fn a_caller_without_the_owners_proof_is_refused_every_upload_route() {
    run_on_engine_stack("upload-owner-door", async {
        let host = Host::new()?;
        let export = export_bytes()?;
        let total = u64::try_from(export.len())?;

        let (status, answer) = host.declare("chatgpt", total, true).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "FAILBEFORE: the owner declares an upload: {answer}"
        );
        let import = import_of(&answer)?;
        let refused =
            |status: StatusCode| matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN);

        let (status, answer) = host.declare("chatgpt", total, false).await?;
        assert!(
            refused(status),
            "a declare with no credential: {status} {answer}"
        );
        let (status, answer) = host
            .send(
                Request::post(DECLARE)
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer not-a-slip"),
                Body::from(json!({ "source": "chatgpt", "bytes": total }).to_string()),
                false,
            )
            .await?;
        assert!(refused(status), "a declare with no slip: {status} {answer}");
        assert_eq!(host.folders()?, 1, "neither made a folder");

        let (status, answer) = host.state(&import, false).await?;
        assert!(
            refused(status),
            "a state read with no credential: {status} {answer}"
        );
        let (status, answer) = host.put(&import, 0, &export, true, false).await?;
        assert!(
            refused(status),
            "a part with no credential: {status} {answer}"
        );
        assert_eq!(host.part_len(&import)?, 0, "the part wrote nothing");
        assert!(!host.folder(&import).join("request.json").exists());
        Ok::<(), TestError>(())
    });
}
