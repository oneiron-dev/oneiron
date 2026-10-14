//! Unauthenticated mode (`--insecure-allow-unauthenticated` with no
//! `auth_secret`) admits a request with no credential as the owner, so
//! unmanaged serve refuses it on any listener but loopback (C2).
//!
//! Each start runs against a vault another owner already holds: a start that
//! clears the bind check stops at the writer lease instead of serving.

use super::*;

async fn start_against_held_vault(host: &str, auth_secret: Option<String>) -> anyhow::Error {
    let dir = tempfile::tempdir().expect("tempdir");
    let _owner = oneiron::VaultWriterLease::acquire(dir.path()).expect("other owner");
    let config = ServeConfig {
        vault_path: dir.path().to_path_buf(),
        host: host.to_owned(),
        port: 0,
        auth_secret,
        allow_unauthenticated: true,
        ..Default::default()
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        serve_with_config(config),
    )
    .await
    .expect("a held vault stops serve before it serves")
    .expect_err("a held vault stops serve")
}

fn reached_the_vault(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<oneiron::Error>(),
        Some(oneiron::Error::ConcurrentWrite(
            oneiron::VAULT_WRITER_LEASE_HELD
        ))
    )
}

#[tokio::test]
async fn unauthenticated_mode_refuses_a_network_listener_before_the_vault_opens() {
    // The product default host, the IPv6 wildcard and one LAN address.
    for host in ["0.0.0.0", "[::]", "192.0.2.10"] {
        let error = start_against_held_vault(host, None).await;
        assert!(
            !reached_the_vault(&error),
            "{host}: unauthenticated serve went on to open the vault"
        );
        assert!(
            error.to_string().contains("loopback"),
            "{host}: refusal must name the remedy: {error:#}"
        );
    }
}

#[tokio::test]
async fn loopback_or_a_secret_still_clears_the_bind_check() {
    let secret = blake3::hash(b"unauthenticated-bind-check")
        .to_hex()
        .to_string();
    for (host, auth_secret) in [
        ("127.0.0.1", None),
        ("[::1]", None),
        ("0.0.0.0", Some(secret)),
    ] {
        let error = start_against_held_vault(host, auth_secret).await;
        assert!(
            reached_the_vault(&error),
            "{host}: expected the held-vault refusal, got {error:#}"
        );
    }
}
