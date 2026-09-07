use super::*;

#[cfg(unix)]
#[tokio::test]
async fn server_startup_refuses_held_writer_before_opening_lmdb() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _owner = oneiron::VaultWriterLease::acquire(dir.path()).expect("other owner");
    let config = ServeConfig {
        vault_path: dir.path().to_path_buf(),
        host: "127.0.0.1".to_owned(),
        port: 0,
        ..Default::default()
    };
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        serve_with_config(config),
    )
    .await
    .expect("lease refusal must not start serving")
    .expect_err("server cannot open another owner's vault");
    assert!(matches!(
        error.downcast_ref::<oneiron::Error>(),
        Some(oneiron::Error::ConcurrentWrite(
            oneiron::VAULT_WRITER_LEASE_HELD
        ))
    ));
    assert!(!dir.path().join("data.mdb").exists());
}
