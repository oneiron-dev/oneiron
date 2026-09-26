//! Authentication-gate tests for Git smart-HTTP.

use super::gate::{
    GIT_HTTP_CHALLENGE, ServiceRefusal, advertised_service, authenticate, remote_user, repo_name,
};
use super::routes::{GitService, git_http_routes};
use crate::auth::CoreScope;
use crate::auth::RevokedTokenJtis;
use crate::config::SyncServerConfig;
use crate::server::SyncServer;
use axum::body::Body;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::header::WWW_AUTHENTICATE;
use oneiron::origin::smart_http;
use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    struct NoRevocations;

    impl RevokedTokenJtis for NoRevocations {
        fn is_revoked(&self, _jti: &str) -> Result<bool, ()> {
            Ok(false)
        }
    }

    fn secret_config() -> SyncServerConfig {
        SyncServerConfig {
            auth_secret: Some("trust-root-secret".to_owned()),
            ..SyncServerConfig::default()
        }
    }

    fn hatch_config() -> SyncServerConfig {
        SyncServerConfig {
            auth_secret: None,
            allow_unauthenticated: true,
            ..SyncServerConfig::default()
        }
    }

    fn fixture(config: SyncServerConfig) -> (tempfile::TempDir, Arc<SyncServer>) {
        let dir = tempfile::tempdir().unwrap();
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
        let server = Arc::new(SyncServer::new(vault, config).unwrap());
        (dir, server)
    }
    fn bearer(server: &SyncServer, token: &str) -> HeaderMap {
        let request = axum::http::Request::builder()
            .header(AUTHORIZATION, token)
            .body(Body::empty())
            .unwrap();
        crate::test_credentials::bind_request(server, request)
            .headers()
            .clone()
    }
    /// A registered principal is an entity id, so the fixture mints one rather
    /// than inventing a spelling the grammar would reject.
    fn principal() -> String {
        oneiron::EntityId::now().to_hex()
    }

    fn scoped_token(config: &SyncServerConfig, scopes: &str, principal: Option<&str>) -> String {
        assert!(config.auth_secret.is_some());
        let claims = match principal {
            Some(principal_ref) => format!("scope={scopes};principal_ref={principal_ref}"),
            None => format!("scope={scopes}"),
        };
        format!("{}{claims}", crate::test_credentials::RECIPE_PREFIX)
    }

    #[test]
    fn git_smart_http_unauthenticated_info_refs_is_401() {
        let config = secret_config();
        let refused = authenticate(
            &HeaderMap::new(),
            &config,
            &NoRevocations,
            GitService::UploadPack,
        )
        .expect_err("unauthenticated info/refs is refused");
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            refused
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some(GIT_HTTP_CHALLENGE),
            "a stock client is told how to authenticate"
        );
    }

    #[test]
    fn git_http_read_scope_serves_upload_pack() {
        let config = secret_config();
        let (_dir, server) = fixture(config.clone());
        let token = scoped_token(&config, "core:read", None);
        let auth = authenticate(
            &bearer(&server, &token),
            &config,
            server.vault().as_ref(),
            GitService::UploadPack,
        )
        .expect("read scope serves a fetch");
        assert!(auth.has_scope(CoreScope::Read));
    }

    #[test]
    fn git_smart_http_receive_pack_without_registered_principal_ref_refused_even_on_loopback() {
        let config = secret_config();
        let (_dir, server) = fixture(config.clone());
        // A write-scoped bearer with no principal_ref: authenticated, but not a
        // registered actor. There is no loopback branch that could admit it,
        // because the gate never reads an address.
        let token = scoped_token(&config, "core:read,core:write", None);
        let refused = authenticate(
            &bearer(&server, &token),
            &config,
            server.vault().as_ref(),
            GitService::ReceivePack,
        )
        .expect_err("a push without a registered principal_ref is refused");
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn git_http_receive_pack_refuses_the_unauthenticated_dev_hatch() {
        let config = hatch_config();
        // The hatch identity carries every scope and no principal_ref. The
        // hatch itself is untouched: a fetch still passes.
        assert!(
            authenticate(
                &HeaderMap::new(),
                &config,
                &NoRevocations,
                GitService::UploadPack,
            )
            .is_ok(),
            "the dev hatch still serves reads"
        );
        assert!(
            authenticate(
                &HeaderMap::new(),
                &config,
                &NoRevocations,
                GitService::ReceivePack,
            )
            .is_err(),
            "the dev escape hatch can never admit a push"
        );
    }

    #[test]
    fn git_http_receive_pack_admits_a_registered_principal() {
        let config = secret_config();
        let (_dir, server) = fixture(config.clone());
        let pusher = principal();
        let token = scoped_token(&config, "core:read,core:write", Some(&pusher));
        let auth = authenticate(
            &bearer(&server, &token),
            &config,
            server.vault().as_ref(),
            GitService::ReceivePack,
        )
        .expect("a registered principal with write scope may push");
        assert_eq!(remote_user(&auth).as_deref(), Some(pusher.as_str()));
    }

    fn stock_git(root: &std::path::Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .current_dir(root)
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("stock Git starts");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn git_http_stock_git_authenticated_publication_roundtrip() {
        let dir = tempfile::tempdir().expect("vault");
        let vault = Arc::new(
            oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).expect("open vault"),
        );
        let config = secret_config();
        let pusher = principal();
        let token = scoped_token(&config, "core:read,core:write", Some(&pusher));
        let server = Arc::new(SyncServer::new(Arc::clone(&vault), config).expect("server"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let url = format!(
            "http://{}/git/demo.git",
            listener.local_addr().expect("address")
        );
        let headers = bearer(&server, &token);
        let token = headers[AUTHORIZATION]
            .to_str()
            .unwrap()
            .strip_prefix("Bearer ")
            .unwrap()
            .to_owned();
        let binding = format!(
            "http.extraHeader=X-Oneiron-Binding: {}",
            headers["x-oneiron-binding"].to_str().unwrap()
        );
        let routes = git_http_routes().with_state(server);
        let serving = tokio::spawn(async move {
            axum::serve(listener, routes).await.expect("serve");
        });
        let checked = tokio::task::spawn_blocking(move || {
            let source = tempfile::tempdir().expect("source");
            stock_git(source.path(), &["init", "--initial-branch=main"]);
            std::fs::write(
                source.path().join("README.md"),
                "public repository content\n",
            )
            .expect("readme");
            stock_git(source.path(), &["add", "README.md"]);
            stock_git(
                source.path(),
                &[
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-m",
                    "initial",
                ],
            );
            let oid = stock_git(source.path(), &["rev-parse", "HEAD"]);
            let root = smart_http::origin_serving_root(&vault).expect("serving root");
            stock_git(
                &root,
                &[
                    "clone",
                    "--bare",
                    source.path().to_str().expect("source path"),
                    "demo.git",
                ],
            );
            let repo_dir = root.join("demo.git");
            let auth = format!("http.extraHeader=Authorization: Bearer {token}");
            let unpublished = stock_git(
                source.path(),
                &["-c", &auth, "-c", &binding, "ls-remote", &url],
            );
            assert!(
                !unpublished.contains("refs/heads/main") && !unpublished.contains("\tHEAD"),
                "raw main and HEAD are not advertisement authority"
            );
            stock_git(&repo_dir, &["update-ref", "-d", "refs/heads/main"]);
            // No fixture attribution and no serve_with_provenance call. This is
            // CoreAuth -> run_serve -> serve -> landed door -> durable producer.
            stock_git(
                source.path(),
                &["-c", &auth, "-c", &binding, "push", &url, "refs/heads/main"],
            );
            let rows: Vec<_> = vault
                .origin_publication_ids(None)
                .expect("publication ids")
                .into_iter()
                .map(|id| {
                    vault
                        .origin_publication(id)
                        .expect("publication")
                        .expect("durable publication")
                })
                .collect();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].actor_id.to_hex(), pusher);
            assert_eq!(
                rows[0].status,
                oneiron::origin::publication::OriginPublicationStatus::Published
            );
            let evidence = vault
                .get_claim(&rows[0].provenance_claim_id)
                .expect("source")
                .expect("durable claim");
            assert_eq!(evidence.predicate, "repo.receive_pack_outcome");
            assert_eq!(
                evidence.lifecycle,
                oneiron::claim::ClaimLifecycleStatus::Active
            );
            let fields = evidence.value.as_map().expect("outcome fields");
            let field = |key: &str| {
                fields
                    .iter()
                    .find(|(name, _)| name.as_str() == Some(key))
                    .map(|(_, value)| value)
                    .expect("evidence field")
            };
            assert_eq!(field("actor_id").as_str(), Some(pusher.as_str()));
            assert_eq!(
                field("repo_id").as_str(),
                Some(rows[0].repo_id.to_hex().as_str())
            );
            assert_eq!(field("scan").as_str(), Some("clean"));
            let operation =
                oneiron::EntityId::from_hex(field("operation_id").as_str().expect("operation id"))
                    .expect("entity id");
            let admission = vault
                .get_claim(&operation)
                .expect("admission")
                .expect("durable admission");
            assert_eq!(admission.predicate, "repo.receive_pack_admission");
            let admission_fields = admission.value.as_map().expect("admission fields");
            assert!(admission_fields.contains(&(
                rmpv::Value::from("credential_presented"),
                rmpv::Value::from(false)
            )));
            assert!(admission_fields.contains(&(
                rmpv::Value::from("method"),
                rmpv::Value::from("bearer+registered-principal")
            )));
            let refs = stock_git(
                source.path(),
                &["-c", &auth, "-c", &binding, "ls-remote", &url],
            );
            assert!(refs.contains(&format!("{oid}\trefs/heads/main")));
            let clone = tempfile::tempdir().expect("client");
            stock_git(
                clone.path(),
                &["-c", &auth, "-c", &binding, "clone", &url, "checkout"],
            );
            assert_eq!(
                std::fs::read_to_string(clone.path().join("checkout/README.md")).expect("checkout"),
                "public repository content\n"
            );
            assert_eq!(
                vault
                    .origin_publication_ids(None)
                    .expect("publication ids")
                    .len(),
                1
            );

            // The server has not silently switched to the explicit no-op seam.
            std::fs::write(
                source.path().join("secret.txt"),
                "TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n",
            )
            .expect("scan fixture");
            stock_git(source.path(), &["add", "secret.txt"]);
            stock_git(
                source.path(),
                &[
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-m",
                    "refused scan fixture",
                ],
            );
            let refused = std::process::Command::new("git")
                .current_dir(source.path())
                .args(["-c", &auth, "-c", &binding, "push", &url, "refs/heads/main"])
                .env("GIT_TERMINAL_PROMPT", "0")
                .output()
                .expect("push starts");
            assert!(
                !refused.status.success(),
                "the landed scan refuses the secret fixture"
            );
            assert_eq!(stock_git(&repo_dir, &["rev-parse", "refs/heads/main"]), oid);
            assert_eq!(
                vault
                    .origin_publication_ids(None)
                    .expect("publication ids")
                    .len(),
                1
            );
        })
        .await;
        serving.abort();
        checked.expect("authenticated stock Git path");
    }

    #[tokio::test]
    async fn git_http_missing_push_auth_is_rejected_before_repository_or_git() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().expect("vault");
        let vault = Arc::new(
            oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).expect("vault"),
        );
        let config = secret_config();
        let no_principal = scoped_token(&config, "core:write", None);
        let server = Arc::new(SyncServer::new(vault, config).expect("server"));
        for (token, expected) in [
            (None, StatusCode::UNAUTHORIZED),
            (Some(no_principal), StatusCode::FORBIDDEN),
        ] {
            let mut request = axum::http::Request::builder()
                .method("POST")
                .uri("/git/missing.git/git-receive-pack");
            if let Some(token) = token {
                request = request.header(AUTHORIZATION, token);
            }
            let response = git_http_routes()
                .with_state(Arc::clone(&server))
                .oneshot(crate::test_credentials::bind_request(
                    &server,
                    request.body(Body::from("not a pack")).expect("request"),
                ))
                .await
                .expect("response");
            assert_eq!(
                response.status(),
                expected,
                "auth refuses before repository resolution"
            );
        }
    }

    #[test]
    fn git_http_read_only_bearer_cannot_reach_receive_pack() {
        let config = secret_config();
        let (_dir, server) = fixture(config.clone());
        let token = scoped_token(&config, "core:read", Some(&principal()));
        assert!(
            authenticate(
                &bearer(&server, &token),
                &config,
                server.vault().as_ref(),
                GitService::ReceivePack,
            )
            .is_err(),
            "a read scope never becomes a write scope"
        );
    }

    #[test]
    fn git_http_route_shapes_are_closed() {
        assert_eq!(repo_name("demo.git"), "demo");
        assert_eq!(repo_name("demo"), "demo");
        assert_eq!(
            advertised_service("service=git-upload-pack"),
            Ok(GitService::UploadPack)
        );
        assert_eq!(
            advertised_service("service=git-receive-pack&extra=1"),
            Ok(GitService::ReceivePack)
        );
        assert_eq!(
            advertised_service(""),
            Err(ServiceRefusal::Missing),
            "the dumb protocol is not served"
        );
        assert_eq!(
            advertised_service("service=git-daemon"),
            Err(ServiceRefusal::Unsupported)
        );
    }

    /// The gate and `git http-backend` must decide about the same service.
    ///
    /// The backend keeps the LAST `service=`; reading the first here would let
    /// a read-scoped bearer be authorized for `git-upload-pack` and then handed
    /// the `git-receive-pack` advertisement. Neither value wins: the request is
    /// refused before the gate runs.
    #[test]
    fn git_http_info_refs_refuses_a_query_that_names_two_services() {
        assert_eq!(
            advertised_service("service=git-upload-pack&service=git-receive-pack"),
            Err(ServiceRefusal::Ambiguous),
            "first-wins and last-wins cannot disagree if neither is used"
        );
        assert_eq!(
            advertised_service("service=git-receive-pack&service=git-upload-pack"),
            Err(ServiceRefusal::Ambiguous)
        );
        assert_eq!(
            advertised_service("service=git-upload-pack&service=git-upload-pack"),
            Err(ServiceRefusal::Ambiguous),
            "one service= parameter means one, even when the values agree"
        );
        assert_eq!(
            ServiceRefusal::Ambiguous.response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ServiceRefusal::Missing.response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ServiceRefusal::Unsupported.response().status(),
            StatusCode::FORBIDDEN
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lease_checkout_stock_git_push_authenticates_at_the_real_door_route() {
        use oneiron::checkout::lease::*;
        struct Facts;
        impl CheckoutFactSink for Facts {
            fn apply_checkout_fact(&mut self, _: CheckoutFactMutation) -> CheckoutResult<()> {
                Ok(())
            }
        }
        #[derive(Default)]
        struct Liveness(Option<CheckoutLivenessPulse>);
        impl CheckoutLiveness for Liveness {
            fn publish(&mut self, pulse: CheckoutLivenessPulse) -> CheckoutResult<()> {
                self.0 = Some(pulse);
                Ok(())
            }
            fn current(&self, _: CheckoutId) -> CheckoutResult<Option<CheckoutLivenessPulse>> {
                Ok(self.0.clone())
            }
            fn clear(&mut self, _: CheckoutId, _: u64) -> CheckoutResult<()> {
                self.0 = None;
                Ok(())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        // The claim and the real HTTP door must read the same clock. A wall
        // second sampled after the authority clock's first observation can be
        // one second ahead at a boundary, making a fresh lease look unissued.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let clock = oneiron::store::ports::ManualClock::new(now);
        let mut vault_config = oneiron::VaultConfig::device();
        vault_config.store_clock = clock.bundle();
        let vault = Arc::new(oneiron::Vault::open(dir.path(), vault_config).unwrap());
        let config = secret_config();
        let pusher = principal();
        let token = scoped_token(&config, "core:read,core:write", Some(&pusher));
        let server = Arc::new(SyncServer::new(Arc::clone(&vault), config).unwrap());
        let headers = bearer(&server, &token);
        let token = headers[AUTHORIZATION]
            .to_str()
            .unwrap()
            .strip_prefix("Bearer ")
            .unwrap()
            .to_owned();
        let binding = format!(
            "http.extraHeader=X-Oneiron-Binding: {}",
            headers["x-oneiron-binding"].to_str().unwrap()
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/git", listener.local_addr().unwrap());
        let serving = tokio::spawn(async move {
            axum::serve(listener, git_http_routes().with_state(server))
                .await
                .unwrap();
        });
        let checked = tokio::task::spawn_blocking(move || {
            let source = tempfile::tempdir().unwrap();
            stock_git(source.path(), &["init", "--initial-branch=main"]);
            std::fs::write(source.path().join("README.md"), "lease route\n").unwrap();
            stock_git(source.path(), &["add", "README.md"]);
            stock_git(
                source.path(),
                &[
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-m",
                    "initial",
                ],
            );
            let oid = stock_git(source.path(), &["rev-parse", "HEAD"]);
            let root = smart_http::origin_serving_root(&vault).unwrap();
            stock_git(
                &root,
                &[
                    "clone",
                    "--bare",
                    source.path().to_str().unwrap(),
                    "demo.git",
                ],
            );
            let repo_dir = root.join("demo.git");
            stock_git(&repo_dir, &["remote", "remove", "origin"]);
            let mut leases = CheckoutLeaseService::new(vault.as_ref(), Facts, Liveness::default());
            let grant = leases
                .claim(CheckoutClaimRequest {
                    checkout_id: CheckoutId::from_bytes(*oneiron::EntityId::now().as_bytes())
                        .unwrap(),
                    task_ref: oneiron::EntityId::now(),
                    repo_ref: oneiron::codebase::RepoRef::LocalFolder {
                        path: repo_dir.to_string_lossy().into_owned(),
                        commit: oid.clone(),
                    },
                    holder_ref: pusher.clone(),
                    task_class: CheckoutTaskClass::Build,
                    // The test proves admission and stale epoch, not expiry.
                    // Leave ample time for a busy CI host to finish the push.
                    ttl_secs: Some(24 * 60 * 60),
                    now,
                })
                .unwrap();
            let lease = leases.get(grant.checkout_id).unwrap().unwrap();
            let wire = oneiron::git_wire::GitWire::new(&vault)
                .unwrap()
                .with_checkout_door(&base)
                .unwrap();
            wire.materialize(&lease).unwrap();
            let tree = wire.checkout_worktree_path(&lease).unwrap();
            let url = stock_git(&tree, &["remote", "get-url", "origin"]);
            assert_eq!(
                url,
                format!(
                    "{base}/lease/{}.{}/demo.git",
                    grant.checkout_id, grant.epoch
                )
            );
            let unauthenticated = std::process::Command::new("git")
                .current_dir(&tree)
                .args(["push", "origin", "HEAD:refs/heads/lease"])
                .env("GIT_TERMINAL_PROMPT", "0")
                .output()
                .unwrap();
            assert!(!unauthenticated.status.success());
            // A lease never substitutes for the registered actor's signed bearer.
            let auth = format!("http.extraHeader=Authorization: Bearer {token}");
            stock_git(
                &tree,
                &[
                    "-c",
                    &auth,
                    "-c",
                    &binding,
                    "push",
                    "origin",
                    "HEAD:refs/heads/lease",
                ],
            );
            assert_eq!(
                stock_git(&repo_dir, &["rev-parse", "refs/heads/lease"]),
                oid
            );
            let ids = vault.origin_publication_ids(None).unwrap();
            assert_eq!(ids.len(), 1);
            let row = vault.origin_publication(ids[0]).unwrap().unwrap();
            let outcome = vault.get_claim(&row.provenance_claim_id).unwrap().unwrap();
            let fields = outcome.value.as_map().unwrap();
            let op = fields
                .iter()
                .find(|(key, _)| key.as_str() == Some("operation_id"))
                .unwrap()
                .1
                .as_str()
                .unwrap();
            let admission = vault
                .get_claim(&oneiron::EntityId::from_hex(op).unwrap())
                .unwrap()
                .unwrap();
            assert!(admission.value.as_map().unwrap().contains(&(
                rmpv::Value::from("method"),
                rmpv::Value::from("door-credential+registered-principal")
            )));
            assert!(!stock_git(&tree, &["config", "--list"]).contains(&token));
            leases
                .reclaim_idempotent(
                    grant.checkout_id,
                    principal(),
                    lease.lease_expires_at.unwrap() + 1,
                )
                .unwrap();
            let stale = std::process::Command::new("git")
                .current_dir(&tree)
                .args([
                    "-c",
                    &auth,
                    "-c",
                    &binding,
                    "push",
                    "origin",
                    "HEAD:refs/heads/stale",
                ])
                .env("GIT_TERMINAL_PROMPT", "0")
                .output()
                .unwrap();
            assert!(!stale.status.success());
        })
        .await;
        serving.abort();
        checked.unwrap();
    }
}
