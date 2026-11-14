//! A pinned public code bundle's documents revalidate on every load, so a
//! policy change reaches a browser that already holds them (ARCH-0050
//! #artifact-origin-open: "Pinned public code still caches for a year as
//! immutable ... A browser holding a fresh pre-fix copy can reuse it without
//! the new CSP"; #1490's follow-up: "Reconsider the one-year `immutable`
//! lifetime for active code documents"; census L4-26).
//!
//! A fork-hash URL serves only while a channel pins that hash, and its bytes
//! never change, so the bundle's other files keep the immutable year: a CSP
//! on a script or a style governs nothing. Its HTML pages, and an SVG opened
//! on its own, revalidate as a channel's do. The ETag makes each check a 304,
//! and the 304 carries the current CSP.
//!
//! Red at main: the pinned page reads `public, max-age=31536000, immutable`.
//! The script guard passes there too.
//!
//! `cargo test --locked -p oneiron-server --features oneiron/test-support,oneiron/test-hooks
//! --test artifact_pinned_document_cache`.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(
    clippy::disallowed_methods,
    reason = "the fixture commits a bundle with the git binary; the rule covers the server's crates"
)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, ETAG, IF_NONE_MATCH};
use axum::http::{HeaderMap, Request, StatusCode};
use oneiron::artifact_hosting::ArtifactServeTier;
use oneiron::{TimeRange, Vault, VaultConfig};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_artifact_app, config::SyncServerConfig, server::SyncServer,
};
use tower::ServiceExt;

/// What a channel sends, and now what a pinned document sends.
const REVALIDATE: &str = "no-cache, max-age=0, must-revalidate";
/// What every other file of a pinned public bundle keeps.
const IMMUTABLE_YEAR: &str = "public, max-age=31536000, immutable";

const PAGE: &str = "<h1>a pinned page</h1><script src=\"app.js\"></script>\n";
const SCRIPT: &str = "document.title = 'pinned';\n";
const IMAGE: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\"/>\n";

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

/// A server whose vault publishes `site` (a page, a script and an SVG image)
/// on the public tier, and the hex fork hash the published pointer pins.
struct Served {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    fork_hash: String,
}

fn served() -> Served {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");

    let repo = tempfile::tempdir().expect("artifact repo");
    let files = [
        ("index.html", PAGE),
        ("app.js", SCRIPT),
        ("logo.svg", IMAGE),
    ];
    for (name, text) in files {
        std::fs::write(repo.path().join(name), text).expect("write bundle file");
    }
    git(repo.path(), &["init"]);
    git(
        repo.path(),
        &["config", "user.email", "oneiron@example.test"],
    );
    git(repo.path(), &["config", "user.name", "Oneiron Test"]);
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-m", "bundle"]);
    let ingest = oneiron::codebase::RepoIngestConfig::new(repo.path(), files.map(|(name, _)| name))
        .expect("ingest config");
    let result = vault
        .ingest_local_repo_at_commit(
            "site",
            &ingest,
            "HEAD",
            TimeRange { start: 10, end: 10 },
            10,
        )
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
            "site",
            oneiron::ArtifactPointerChannel::Published,
            &result.snapshot.fork_hash,
            ArtifactServeTier::Public,
        )
        .expect("publish bundle");

    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("artifact-pinned-document-cache".to_owned()),
                ..Default::default()
            },
        )
        .expect("a server"),
    );
    Served {
        _dir: dir,
        server,
        fork_hash: oneiron::artifact_hex(&result.snapshot.fork_hash),
    }
}

impl Served {
    /// `GET /a/site/_s/f/<pinned hash>/<file>` on the artifact listener, with
    /// no credential and, when given, an `If-None-Match`: the status and the
    /// headers.
    async fn get(&self, file: &str, if_none_match: Option<&str>) -> (StatusCode, HeaderMap) {
        let mut request = Request::builder()
            .method("GET")
            .uri(format!("/a/site/_s/f/{}/{file}", self.fork_hash));
        if let Some(etag) = if_none_match {
            request = request.header(IF_NONE_MATCH, etag);
        }
        let response = build_artifact_app(Arc::clone(&self.server))
            .oneshot(request.body(Body::empty()).expect("request"))
            .await
            .expect("response");
        (response.status(), response.headers().clone())
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &axum::http::HeaderName) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
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

#[test]
fn a_pinned_document_revalidates() {
    on_engine_stack(|| async {
        let fx = served();
        let (status, headers) = fx.get("index.html", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header(&headers, &CACHE_CONTROL),
            REVALIDATE,
            "the pinned page"
        );
        let policy = header(&headers, &CONTENT_SECURITY_POLICY).to_owned();
        assert!(
            policy.contains("connect-src 'none'"),
            "the page carries the code CSP: {policy}"
        );
        let etag = header(&headers, &ETAG).to_owned();
        assert!(!etag.is_empty(), "the page has an ETag");

        let (status, headers) = fx.get("index.html", Some(&etag)).await;
        assert_eq!(status, StatusCode::NOT_MODIFIED, "the revalidation");
        assert_eq!(header(&headers, &CACHE_CONTROL), REVALIDATE, "the 304");
        assert_eq!(
            header(&headers, &CONTENT_SECURITY_POLICY),
            policy,
            "the 304 carries the current CSP"
        );
    });
}

#[test]
fn a_pinned_svg_image_revalidates() {
    on_engine_stack(|| async {
        let fx = served();
        let (status, headers) = fx.get("logo.svg", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header(&headers, &CACHE_CONTROL),
            REVALIDATE,
            "the pinned SVG"
        );
    });
}

#[test]
fn a_pinned_script_keeps_the_immutable_year() {
    on_engine_stack(|| async {
        let fx = served();
        let (status, headers) = fx.get("app.js", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header(&headers, &CACHE_CONTROL),
            IMMUTABLE_YEAR,
            "the pinned script"
        );
    });
}
