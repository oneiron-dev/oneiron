//! Authentication-gate tests for Git smart-HTTP.

use super::gate::{
    GIT_HTTP_CHALLENGE, ServiceRefusal, advertised_service, authenticate, remote_user, repo_name,
};
use super::routes::{GitService, git_http_routes};
use crate::auth::CoreScope;
use crate::auth::RevokedTokenJtis;
use crate::auth::mint_core_token_v2;
use crate::config::SyncServerConfig;
use crate::server::SyncServer;
use axum::body::Body;
use axum::http::HeaderMap;
use axum::http::HeaderValue;
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

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let value = HeaderValue::from_str(&format!("Bearer {token}")).expect("bearer header");
        headers.insert(AUTHORIZATION, value);
        headers
    }

    /// A registered principal is an entity id, so the fixture mints one rather
    /// than inventing a spelling the grammar would reject.
    fn principal() -> String {
        oneiron::EntityId::now().to_hex()
    }

    fn scoped_token(config: &SyncServerConfig, scopes: &str, principal: Option<&str>) -> String {
        let secret = config
            .auth_secret
            .as_deref()
            .expect("fixture configures a trust root");
        let claims = match principal {
            Some(principal_ref) => format!("scope={scopes};principal_ref={principal_ref}"),
            None => format!("scope={scopes}"),
        };
        mint_core_token_v2(secret, &claims)
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
        let token = scoped_token(&config, "core:read", None);
        let auth = authenticate(
            &bearer(&token),
            &config,
            &NoRevocations,
            GitService::UploadPack,
        )
        .expect("read scope serves a fetch");
        assert!(auth.has_scope(CoreScope::Read));
    }

    #[test]
    fn git_smart_http_receive_pack_without_registered_principal_ref_refused_even_on_loopback() {
        let config = secret_config();
        // A write-scoped bearer with no principal_ref: authenticated, but not a
        // registered actor. There is no loopback branch that could admit it,
        // because the gate never reads an address.
        let token = scoped_token(&config, "core:read,core:write", None);
        let refused = authenticate(
            &bearer(&token),
            &config,
            &NoRevocations,
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
        let pusher = principal();
        let token = scoped_token(&config, "core:read,core:write", Some(&pusher));
        let auth = authenticate(
            &bearer(&token),
            &config,
            &NoRevocations,
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
            let unpublished = stock_git(source.path(), &["-c", &auth, "ls-remote", &url]);
            assert!(
                !unpublished.contains("refs/heads/main") && !unpublished.contains("\tHEAD"),
                "raw main and HEAD are not advertisement authority"
            );
            stock_git(&repo_dir, &["update-ref", "-d", "refs/heads/main"]);
            // No fixture attribution and no serve_with_provenance call. This is
            // CoreAuth -> run_serve -> serve -> landed door -> durable producer.
            stock_git(
                source.path(),
                &["-c", &auth, "push", &url, "refs/heads/main"],
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
            let refs = stock_git(source.path(), &["-c", &auth, "ls-remote", &url]);
            assert!(refs.contains(&format!("{oid}\trefs/heads/main")));
            let clone = tempfile::tempdir().expect("client");
            stock_git(clone.path(), &["-c", &auth, "clone", &url, "checkout"]);
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
                .args(["-c", &auth, "push", &url, "refs/heads/main"])
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
                request = request.header(AUTHORIZATION, format!("Bearer {token}"));
            }
            let response = git_http_routes()
                .with_state(Arc::clone(&server))
                .oneshot(request.body(Body::from("not a pack")).expect("request"))
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
        let token = scoped_token(&config, "core:read", Some(&principal()));
        assert!(
            authenticate(
                &bearer(&token),
                &config,
                &NoRevocations,
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
}
