use super::*;
use tower::ServiceExt;

#[test]
fn router_can_be_constructed_before_entering_a_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
    let server = Arc::new(crate::server::SyncServer::new(vault, Default::default()).unwrap());
    let router = crate::build_app(server);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let response = runtime.block_on(async {
        router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    });
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}
