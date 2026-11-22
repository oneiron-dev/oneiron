//! The artifact listener serves each vault at a host of its own, and each of
//! its apps at an origin of its own (APP-HOST = A; CROSS-ARCH-0024:467: "A
//! published app lives at `<app>--<name>.oneiron.page`: one origin per app,
//! one wildcard certificate"; CROSS-ARCH-0019:514 and :517: a person's shared
//! artifacts serve from `<name>.oneiron.page`, and "each vault serves its own
//! names"). A managed vault answers on its internal authority alone, which
//! its edge forwards to once it has checked the public name (FIX 6716).
//!
//! The rule lives in `src/api/artifacts/host.rs`: `<vault>.<domain>/<artifact>/…`
//! is that vault's `/a/<artifact>/…`, and `<app>--<vault>.<domain>/…` is its
//! `/a/<app>/…`. A host under a configured domain that names no vault here
//! answers exactly as a forbidden artifact does, and so does every refusal
//! from a known vault: the one artifact 404. Any other host keeps local `/a/`.
//!
//! Each promise holds on main, so each test's red proof is a seeded fault in
//! `host.rs` or `api/mod.rs` (Test rules v2, rule 5), named in the PR.
//!
//! `cargo test --locked -p oneiron-server --features oneiron/test-support,oneiron/test-hooks
//! --test artifact_vault_hosts`.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(
    clippy::disallowed_methods,
    reason = "the fixture commits a bundle with the git binary; the rule covers the server's crates"
)]

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::header::LOCATION;
use axum::http::{Request, StatusCode};
use oneiron::artifact_hosting::ArtifactServeTier;
use oneiron::{TimeRange, Vault, VaultConfig};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_artifact_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::Value;
use tower::ServiceExt;

const NOTES_PAGE: &str = "<h1>the notes app</h1>\n";
const LEDGER_PAGE: &str = "<h1>the ledger app</h1>\n";
const DIARY_PAGE: &str = "<h1>the private diary app</h1>\n";
/// The configured artifact domain (`oneiron.page` in the hosted service).
const DOMAIN: &str = "apps.example.test";
/// The label this server's vault answers to under [`DOMAIN`].
const VAULT_NAME: &str = "mina";
/// A managed vault's id: its name on the internal authority.
const VAULT_ID: &str = "0f3a9c2e7d41";
/// A vault id served nowhere here.
const OTHER_VAULT_ID: &str = "7b2e0c9d5a18";
/// The artifact port a request names in its `Host`; the router reads the
/// name alone.
const ARTIFACT_PORT: u16 = 49152;
/// A host outside every artifact domain and the internal authority: local
/// serving.
const LOCAL_HOST: &str = "127.0.0.1:49152";

fn git(repo: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("git starts");
    assert!(status.success(), "git {args:?} failed");
}

/// Commits `index.html` holding `page` to a fresh repository and publishes it
/// as the code bundle `name` at `tier`.
fn publish_bundle(vault: &Vault, name: &str, page: &str, tier: ArtifactServeTier) {
    let repo = tempfile::tempdir().expect("artifact repo");
    std::fs::write(repo.path().join("index.html"), page).expect("write bundle file");
    git(repo.path(), &["init"]);
    git(
        repo.path(),
        &["config", "user.email", "oneiron@example.test"],
    );
    git(repo.path(), &["config", "user.name", "Oneiron Test"]);
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-m", "bundle"]);
    let ingest = oneiron::codebase::RepoIngestConfig::new(repo.path(), ["index.html"])
        .expect("ingest config");
    let result = vault
        .ingest_local_repo_at_commit(name, &ingest, "HEAD", TimeRange { start: 10, end: 10 }, 10)
        .expect("ingest bundle");
    let body = vault
        .get_code_artifact(&result.code_artifact_id)
        .expect("read code artifact")
        .expect("code artifact exists")
        .with_class(oneiron::code_artifact::CodeArtifactClass::Artifact);
    vault
        .put_code_artifact(
            &result.code_artifact_id,
            &body,
            TimeRange { start: 10, end: 10 },
            10,
        )
        .expect("mark hostable");
    vault
        .publish_artifact_pointer_with_tier(
            name,
            oneiron::ArtifactPointerChannel::Published,
            &result.snapshot.fork_hash,
            tier,
        )
        .expect("publish bundle");
}

/// How the server names its vault on the artifact listener.
#[derive(Clone, Copy)]
enum Naming {
    /// A plain serve: the vault answers as [`VAULT_NAME`] under [`DOMAIN`].
    Domain,
    /// A managed vault: [`VAULT_ID`] on the internal authority. [`DOMAIN`]
    /// and [`VAULT_NAME`] stay configured, and the listener never reads them.
    Internal,
}

/// A vault holding the public apps `notes` and `ledger` and the private app
/// `diary`, served under an auth secret, with an artifact listener on
/// [`ARTIFACT_PORT`] named as `naming` says.
fn served(naming: Naming) -> (tempfile::TempDir, Arc<SyncServer>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    publish_bundle(&vault, "notes", NOTES_PAGE, ArtifactServeTier::Public);
    publish_bundle(&vault, "ledger", LEDGER_PAGE, ArtifactServeTier::Public);
    publish_bundle(&vault, "diary", DIARY_PAGE, ArtifactServeTier::Private);
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("artifact-vault-hosts".to_owned()),
            artifact_domains: vec![DOMAIN.to_owned()],
            artifact_vault_name: Some(VAULT_NAME.to_owned()),
            artifact_internal_vault_id: matches!(naming, Naming::Internal)
                .then(|| VAULT_ID.to_owned()),
            ..Default::default()
        },
    )
    .expect("a server")
    .with_artifact_listener(ARTIFACT_PORT);
    (dir, Arc::new(server))
}

/// One answer of the artifact listener.
struct Answer {
    status: StatusCode,
    location: Option<String>,
    body: String,
}

impl Answer {
    /// The error envelope without its per-request id, so two refusals compare
    /// by what they say. `None` when the body is no error envelope.
    fn stable_error(&self) -> Option<Value> {
        let mut body: Value = serde_json::from_str(&self.body).ok()?;
        body.get_mut("error")?.as_object_mut()?.remove("requestId");
        Some(body)
    }
}

/// `GET <path>` on the artifact listener under `Host: <host>`, with no
/// credential.
async fn get(server: &Arc<SyncServer>, host: &str, path: &str) -> Answer {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("host", host)
        .body(Body::empty())
        .expect("request");
    let response = build_artifact_app(Arc::clone(server))
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let location = response
        .headers()
        .get(LOCATION)
        .map(|value| value.to_str().expect("an ASCII location").to_owned());
    let bytes = to_bytes(response.into_body(), 1_048_576)
        .await
        .expect("response body");
    Answer {
        status,
        location,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// The one artifact 404, as local `/a/` answers it for an artifact this
/// vault does not hold: its status and its stable envelope.
async fn missing_artifact(server: &Arc<SyncServer>) -> (StatusCode, Option<Value>) {
    let answer = get(server, LOCAL_HOST, "/a/absent/_s/c/published/").await;
    assert_eq!(
        answer.status,
        StatusCode::NOT_FOUND,
        "the reference refusal: {}",
        answer.body
    );
    let error = answer.stable_error();
    assert!(
        error.is_some(),
        "the reference refusal is an error envelope: {}",
        answer.body
    );
    (answer.status, error)
}

/// Runs `case` on a runtime whose threads have the engine's stack.
fn on_engine_stack<F>(case: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    let thread = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(case());
        })
        .expect("engine-stack thread");
    if let Err(panic) = thread.join() {
        std::panic::resume_unwind(panic);
    }
}

/// CROSS-ARCH-0024:467 (APP-HOST = A): an app lives at
/// `<app>--<vault>.<domain>`, its root at `/`. The vault's own host serves
/// the same app by path, and local `/a/` keeps serving it. Each entry
/// redirect keeps the form of the host it answers on, so an app's links stay
/// on its own origin.
#[test]
fn an_app_answers_at_the_root_of_its_own_origin() {
    on_engine_stack(|| async {
        let (_dir, server) = served(Naming::Domain);
        let app_host = format!("notes--{VAULT_NAME}.{DOMAIN}");
        let entry = get(&server, &app_host, "/").await;
        assert_eq!(
            entry.status,
            StatusCode::PERMANENT_REDIRECT,
            "{app_host}/: {}",
            entry.body
        );
        assert_eq!(
            entry.location.as_deref(),
            Some("/_s/c/published/"),
            "the app origin's entry redirect stays at its root"
        );
        let page = get(&server, &app_host, "/_s/c/published/").await;
        assert_eq!(page.status, StatusCode::OK, "{app_host}: {}", page.body);
        assert!(
            page.body.contains(NOTES_PAGE),
            "the app's page at its own origin: {}",
            page.body
        );

        let vault_host = format!("{VAULT_NAME}.{DOMAIN}");
        let entry = get(&server, &vault_host, "/notes/").await;
        assert_eq!(
            entry.status,
            StatusCode::PERMANENT_REDIRECT,
            "{vault_host}/notes/: {}",
            entry.body
        );
        assert_eq!(
            entry.location.as_deref(),
            Some("/notes/_s/c/published/"),
            "the vault host's entry redirect keeps the artifact path"
        );
        let page = get(&server, &vault_host, "/notes/_s/c/published/").await;
        assert_eq!(page.status, StatusCode::OK, "{vault_host}: {}", page.body);
        assert!(
            page.body.contains(NOTES_PAGE),
            "the app's page on the vault host: {}",
            page.body
        );

        let entry = get(&server, LOCAL_HOST, "/a/notes/").await;
        assert_eq!(
            entry.location.as_deref(),
            Some("/a/notes/_s/c/published/"),
            "local serving keeps `/a/`: {}",
            entry.body
        );
        let page = get(&server, LOCAL_HOST, "/a/notes/_s/c/published/").await;
        assert_eq!(page.status, StatusCode::OK, "local /a/: {}", page.body);
        assert!(
            page.body.contains(NOTES_PAGE),
            "the app's page on local /a/: {}",
            page.body
        );
    });
}

/// CROSS-ARCH-0024:467: one origin per app. No path on an app's origin opens
/// another app of the same vault, and each app's origin serves that app.
#[test]
fn an_app_origin_opens_no_other_app() {
    on_engine_stack(|| async {
        let (_dir, server) = served(Naming::Domain);
        let notes_host = format!("notes--{VAULT_NAME}.{DOMAIN}");
        for path in [
            "/ledger/_s/c/published/",
            "/a/ledger/_s/c/published/",
            "/diary/_s/c/published/",
        ] {
            let answer = get(&server, &notes_host, path).await;
            assert!(
                !answer.body.contains(LEDGER_PAGE) && !answer.body.contains(DIARY_PAGE),
                "{notes_host}{path} opened another app: {}",
                answer.body
            );
            assert_eq!(
                answer.status,
                StatusCode::NOT_FOUND,
                "{notes_host}{path}: {}",
                answer.body
            );
        }
        let ledger_host = format!("ledger--{VAULT_NAME}.{DOMAIN}");
        let page = get(&server, &ledger_host, "/_s/c/published/").await;
        assert_eq!(page.status, StatusCode::OK, "{ledger_host}: {}", page.body);
        assert!(
            page.body.contains(LEDGER_PAGE) && !page.body.contains(NOTES_PAGE),
            "each app's origin serves that app: {}",
            page.body
        );
    });
}

/// `host.rs`, and CROSS-ARCH-0019:517 ("each vault serves its own names"): a
/// host under the artifact domain that names no vault served here answers
/// exactly as an artifact this vault does not hold: the one artifact 404. So
/// does this vault's private app read with no credential, at either host
/// form. No answer tells a vault that lives here from one that does not.
#[test]
fn a_host_that_names_no_vault_here_answers_the_one_artifact_404() {
    on_engine_stack(|| async {
        let (_dir, server) = served(Naming::Domain);
        let missing = missing_artifact(&server).await;
        let vault_host = format!("{VAULT_NAME}.{DOMAIN}");
        let cases = [
            // Another vault's name, and an app of another vault.
            (format!("other.{DOMAIN}"), "/notes/_s/c/published/"),
            (format!("notes--other.{DOMAIN}"), "/_s/c/published/"),
            // The bare domain, and a name of two labels.
            (DOMAIN.to_owned(), "/notes/_s/c/published/"),
            (format!("notes.{VAULT_NAME}.{DOMAIN}"), "/_s/c/published/"),
            // This vault's host with no artifact named, and an artifact it
            // does not hold.
            (vault_host.clone(), "/"),
            (vault_host.clone(), "/absent/_s/c/published/"),
            // This vault's private app, with no credential.
            (vault_host.clone(), "/diary/_s/c/published/"),
            (format!("diary--{VAULT_NAME}.{DOMAIN}"), "/_s/c/published/"),
        ];
        for (host, path) in cases {
            let answer = get(&server, &host, path).await;
            assert!(
                !answer.body.contains(NOTES_PAGE) && !answer.body.contains(DIARY_PAGE),
                "{host}{path} served an app: {}",
                answer.body
            );
            assert_eq!(
                (answer.status, answer.stable_error()),
                missing,
                "{host}{path}: {}",
                answer.body
            );
        }
    });
}

/// `host.rs`: every refusal from a vault served here reads as the one
/// artifact 404 at its host, whatever its cause. Local `/a/` refuses a
/// malformed selector with a 400 that names the field; at the vault's host
/// and at an app's origin the same request answers the one artifact 404, so
/// a refusal's cause never tells that the vault lives here.
#[test]
fn a_refusal_from_a_vault_served_here_reads_as_the_one_artifact_404() {
    on_engine_stack(|| async {
        let (_dir, server) = served(Naming::Domain);
        let missing = missing_artifact(&server).await;
        let local = get(&server, LOCAL_HOST, "/a/notes/?blobVersion=0").await;
        assert_eq!(
            local.status,
            StatusCode::BAD_REQUEST,
            "local /a/ names the refusal: {}",
            local.body
        );
        let vault_host = format!("{VAULT_NAME}.{DOMAIN}");
        let cases = [
            (vault_host.clone(), "/notes/?blobVersion=0"),
            (vault_host.clone(), "/notes/?channel=published&forkHash=00"),
            (format!("notes--{VAULT_NAME}.{DOMAIN}"), "/?blobVersion=0"),
        ];
        for (host, path) in cases {
            let answer = get(&server, &host, path).await;
            assert_eq!(
                (answer.status, answer.stable_error()),
                missing,
                "{host}{path}: {}",
                answer.body
            );
        }
    });
}

/// FIX 6716 (`host.rs`; `SyncServerConfig::artifact_internal_vault_id`): a
/// managed vault answers on its internal authority,
/// `<vault_id>.artifact.invalid/<artifact>/…` and
/// `<app>.<vault_id>.artifact.invalid/…`, which its edge forwards to once it
/// has checked the public name. It never reads a configured artifact domain,
/// so a public name the edge did not check reaches no app, and another vault
/// id answers the one artifact 404.
#[test]
fn a_managed_vault_answers_on_its_internal_authority_alone() {
    on_engine_stack(|| async {
        let (_dir, server) = served(Naming::Internal);
        for (host, path) in [
            (format!("notes--{VAULT_NAME}.{DOMAIN}"), "/_s/c/published/"),
            (format!("{VAULT_NAME}.{DOMAIN}"), "/notes/_s/c/published/"),
        ] {
            let answer = get(&server, &host, path).await;
            assert!(
                !answer.body.contains(NOTES_PAGE),
                "{host}{path}: a configured domain reached an app: {}",
                answer.body
            );
            assert_eq!(
                answer.status,
                StatusCode::NOT_FOUND,
                "{host}{path}: {}",
                answer.body
            );
        }

        let vault_host = format!("{VAULT_ID}.artifact.invalid");
        let page = get(&server, &vault_host, "/notes/_s/c/published/").await;
        assert_eq!(page.status, StatusCode::OK, "{vault_host}: {}", page.body);
        assert!(
            page.body.contains(NOTES_PAGE),
            "the app's page on the internal vault host: {}",
            page.body
        );
        let app_host = format!("notes.{VAULT_ID}.artifact.invalid");
        let entry = get(&server, &app_host, "/").await;
        assert_eq!(
            entry.location.as_deref(),
            Some("/_s/c/published/"),
            "the internal app host's entry redirect stays at its root: {}",
            entry.body
        );
        let page = get(&server, &app_host, "/_s/c/published/").await;
        assert_eq!(page.status, StatusCode::OK, "{app_host}: {}", page.body);
        assert!(
            page.body.contains(NOTES_PAGE),
            "the app's page on its internal app host: {}",
            page.body
        );

        let missing = missing_artifact(&server).await;
        for (host, path) in [
            (
                format!("{OTHER_VAULT_ID}.artifact.invalid"),
                "/notes/_s/c/published/",
            ),
            (
                format!("notes.{OTHER_VAULT_ID}.artifact.invalid"),
                "/_s/c/published/",
            ),
        ] {
            let answer = get(&server, &host, path).await;
            assert_eq!(
                (answer.status, answer.stable_error()),
                missing,
                "{host}{path}: {}",
                answer.body
            );
        }
    });
}
