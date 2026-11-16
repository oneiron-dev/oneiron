//! A private published app serves its vault's owner alone (CROSS-ARCH-0019
//! #public-backend, PUBLIC-BACKEND = A, owner 2026-10-11: "An app's default
//! audience is `private`: the owner only. A sharing link or an invite widens
//! it"; census L10-35).
//!
//! `ArtifactServeTier::Private` is the default tier, and the artifact
//! listener refused it to every reader, the owner included, so no one could
//! open a private app. Now the owner's own request reads it: his full slip,
//! judged by the owner routes' own rule.
//!
//! Red at main: the owner's full slip reads 404. Guards (they pass there too):
//! no credential, the owner's narrowed slip (an identity alone is no owner
//! proof), another person's read slip and the unauthenticated dev mode each
//! read 404; a public app reads 200 with no credential.
//!
//! `cargo test --locked -p oneiron-server --features oneiron/test-support,oneiron/test-hooks
//! --test artifact_private_owner_read`.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(
    clippy::disallowed_methods,
    reason = "the fixture commits a bundle with the git binary; the rule covers the server's crates"
)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use oneiron::artifact_hosting::ArtifactServeTier;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, SlipCaveat, holder_proof};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_artifact_app, config::SyncServerConfig, server::SyncServer,
};
use tower::ServiceExt;

const PRIVATE_PAGE: &str = "<h1>the owner's private app</h1>\n";
const PUBLIC_PAGE: &str = "<h1>a public app</h1>\n";

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every credential here binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5B; 32])
}

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

/// A vault with a private app `private-app` and a public app `public-app`,
/// served under its auth secret (or, with `rooted` false, in the
/// unauthenticated dev mode), its host issuer and its owner.
struct Served {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    issuer: Option<HostSlipIssuer>,
    owner: EntityId,
}

fn served(rooted: bool) -> Served {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    // Both apps land before the vault is rooted, as the browser rows do.
    publish_bundle(
        &vault,
        "private-app",
        PRIVATE_PAGE,
        ArtifactServeTier::Private,
    );
    publish_bundle(&vault, "public-app", PUBLIC_PAGE, ArtifactServeTier::Public);
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: rooted.then(|| "artifact-private-owner-read".to_owned()),
                allow_unauthenticated: !rooted,
                ..Default::default()
            },
        )
        .expect("a server"),
    );
    let issuer = rooted.then(|| vault.bootstrap_host_slip_issuer().expect("host issuer"));
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    Served {
        _dir: dir,
        server,
        vault,
        issuer,
        owner,
    }
}

impl Served {
    fn issuer(&self) -> &HostSlipIssuer {
        self.issuer
            .as_ref()
            .expect("a rooted fixture holds its host issuer")
    }

    /// A slip this host mints `who` as a human, at the host root's own scope.
    fn slip_for(&self, who: EntityId) -> CapabilitySlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(self.issuer())
            .expect("the host root slip")
            .claims;
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = who.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = holder_key().verifying_key().to_bytes();
        self.vault
            .mint_capability_slip(self.issuer(), claims)
            .expect("a slip")
    }

    /// `who`'s slip narrowed by its holder to `read` and `write`: not owner
    /// grade.
    fn read_write_slip_for(&self, who: EntityId) -> CapabilitySlip {
        let mut slip = self.slip_for(who);
        let mut narrowed = Scope::top();
        narrowed.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        slip.attenuate(
            SlipCaveat {
                scope: Some(narrowed),
                ..Default::default()
            },
            &holder_key(),
        )
        .expect("the holder narrows its own slip");
        assert!(!slip.caveats.is_empty(), "the slip is caveated");
        slip
    }

    fn person(&self) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .expect("a live person");
        id
    }

    /// `GET /a/<app>/_s/c/published/` on the artifact listener, under
    /// `slip` with its holder's proof when one is given: the status and the
    /// body.
    async fn open(&self, app: &str, slip: Option<&CapabilitySlip>) -> (StatusCode, String) {
        let mut request = Request::builder()
            .method("GET")
            .uri(format!("/a/{app}/_s/c/published/"));
        if let Some(slip) = slip {
            let binding = holder_proof(slip, &holder_key(), self.vault.now_recorded_at())
                .expect("holder proof");
            request = request
                .header(
                    "Authorization",
                    format!("Bearer {}", slip.to_token().expect("token")),
                )
                .header("x-oneiron-binding", binding.to_string());
        }
        let response = build_artifact_app(Arc::clone(&self.server))
            .oneshot(request.body(Body::empty()).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576)
            .await
            .expect("response body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }
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
fn the_owner_opens_his_private_app() {
    on_engine_stack(|| async {
        let fx = served(true);
        let slip = fx.slip_for(fx.owner);
        let (status, body) = fx.open("private-app", Some(&slip)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains(PRIVATE_PAGE), "the private page: {body}");
    });
}

#[test]
fn a_request_with_no_credential_opens_no_private_app() {
    on_engine_stack(|| async {
        let fx = served(true);
        let (status, body) = fx.open("private-app", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    });
}

#[test]
fn the_owners_narrowed_slip_opens_no_private_app() {
    on_engine_stack(|| async {
        let fx = served(true);
        let slip = fx.read_write_slip_for(fx.owner);
        let (status, body) = fx.open("private-app", Some(&slip)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    });
}

#[test]
fn another_persons_read_slip_opens_no_private_app() {
    on_engine_stack(|| async {
        let fx = served(true);
        let other = fx.person();
        let slip = fx.read_write_slip_for(other);
        let (status, body) = fx.open("private-app", Some(&slip)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    });
}

#[test]
fn the_dev_mode_opens_no_private_app() {
    on_engine_stack(|| async {
        let fx = served(false);
        let (status, body) = fx.open("private-app", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    });
}

#[test]
fn a_public_app_opens_with_no_credential() {
    on_engine_stack(|| async {
        let fx = served(true);
        let (status, body) = fx.open("public-app", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains(PUBLIC_PAGE), "the public page: {body}");
    });
}
