#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! CODE-MODE-LENDING-WORLD-PRIVACY = A (FIX CODE-MODE-LENDING-W9): a
//! connector's run sets no world's privacy, for either run author (caller
//! code and engine model), until a direct row exists. Native agent runs keep
//! the act (the engine's own dispatcher is unchanged).
//!
//! - `a_connectors_run_is_refused_world_privacy_for_both_authors`: a
//!   credential that binds `vault.worlds.privacy.set` and holds Write, for
//!   each author (the door's caller-code and engine-model constructors),
//!   has `admit_run_call(RunCall::Bridge(SelfEffect::WorldPrivacySet))`
//!   refused with code `mcp_world_privacy_refused` and reason code
//!   `world_privacy.set_by_holder_directly`. Red: drop the new `if` in
//!   `mcp_run_call_gate` (api/mcp_gateway/actor_dispatch/gates.rs); the
//!   call is then admitted past the privacy rule to the session gate.
//!
//! The door is driven through `test_doors::mcp_code_mode_verbs`, as the run's
//! guest drives it: no QuickJS host, model or guest starts. Each test runs on
//! the engine's multi-thread runtime (`on_engine_stack`): the door runs its
//! work on that runtime and waits for it, as the production guest does from
//! its own thread, which a current-thread test runtime would deadlock.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! mcp_world_privacy_refused`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use engine_stack::on_engine_stack;
use oneiron::code_run::SelfEffect;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::mcp_code_mode_verbs::{
    ProgramAuthor, admit_run_effect, register_credential,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    _dir: tempfile::TempDir,
    _vault: Arc<Vault>,
    server: Arc<SyncServer>,
}

fn fixture(secret: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    // The keystore goes in BEFORE the server: construction roots the vault.
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some(secret.into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    Fixture {
        _dir: dir,
        _vault: vault,
        server,
    }
}

/// A connector's run is refused the world's privacy for both authors, even
/// with the verb bound and Write held: the privacy rule refuses before the
/// session gate, not for a missing binding or grant.
#[test]
fn a_connectors_run_is_refused_world_privacy_for_both_authors() -> TestResult {
    on_engine_stack(connectors_run_refused_world_privacy)
}

async fn connectors_run_refused_world_privacy() -> TestResult {
    let fixture = fixture("world-privacy-refused");
    let writer = register_credential(
        &fixture.server,
        0xD1,
        &["read", "write"],
        Some(&["vault.worlds.privacy.set"]),
    )
    .await
    .expect("a write credential bound to the privacy row registers");
    let run = EntityId::now();
    for author in [ProgramAuthor::Caller, ProgramAuthor::EngineModel] {
        let refused = admit_run_effect(
            &fixture.server,
            &writer,
            run,
            SelfEffect::WorldPrivacySet,
            author,
        )
        .await
        .expect("the admission runs")
        .expect_err("a connector's run sets no world's privacy");
        assert_eq!(refused.code, "mcp_world_privacy_refused", "{author:?}");
        assert_eq!(
            refused.reason_codes,
            ["world_privacy.set_by_holder_directly"],
            "{author:?}"
        );
    }
    Ok(())
}
