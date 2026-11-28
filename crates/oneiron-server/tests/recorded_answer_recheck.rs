#![cfg(oneiron_test_support)]

//! T3 (FIX CODE-MODE-LENDING-W11). Red if the MCP door's recorded verb
//! admission (Part 2 item 2) is removed: the default trait method would
//! admit both the caller-refused verb and the unbound generated verb.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use engine_stack::on_engine_stack;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::mcp_code_mode_verbs::{
    ProgramAuthor, register_credential, verb_row,
};
use oneiron_server::test_doors::recorded_answer_recheck::admit_recorded_verb;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn a_recorded_verb_answer_meets_the_mcp_door_as_its_live_call_does() -> TestResult {
    on_engine_stack(check_recorded_admission)
}

async fn check_recorded_admission() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some("recorded-answer-recheck".into()),
            ..Default::default()
        },
    )?);
    let settings_only = register_credential(
        &server,
        0xC1,
        &["read", "write"],
        Some(&["vault.settings.list"]),
    )
    .await?;
    let with_recall =
        register_credential(&server, 0xC2, &["read", "write"], Some(&["vault.recall"])).await?;
    let run = EntityId::now();
    let settings = verb_row("vault.settings.list")?;
    let recall = verb_row("vault.recall")?;

    let refused = admit_recorded_verb(
        &server,
        &settings_only,
        run,
        settings,
        ProgramAuthor::Caller,
    )
    .await?
    .expect_err("the caller's own code is refused a bound settings row");
    assert_eq!(refused.code, "caller_code_refused");
    assert_eq!(refused.reason_codes, ["caller_code.credential_answer"]);
    admit_recorded_verb(
        &server,
        &settings_only,
        run,
        settings,
        ProgramAuthor::EngineModel,
    )
    .await?
    .expect("the engine's code is admitted on the same bound row");

    let refused = admit_recorded_verb(
        &server,
        &settings_only,
        run,
        recall,
        ProgramAuthor::EngineModel,
    )
    .await?
    .expect_err("the unbound generated row is refused");
    assert_eq!(refused.code, "mcp_verb_not_bound");
    admit_recorded_verb(
        &server,
        &with_recall,
        run,
        recall,
        ProgramAuthor::EngineModel,
    )
    .await?
    .expect("the generated row is admitted once bound");
    Ok(())
}
