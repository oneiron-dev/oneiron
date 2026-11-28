#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FIX CODE-MODE-LENDING-W8: a callable skill called over MCP runs its nested
//! calls behind the caller's own door, not the door of a run the engine's
//! model wrote. Its program is stored code, so it is lent nothing a direct
//! call by the same credential lacks.
//!
//! - `a_skill_called_over_mcp_is_refused_what_a_task_run_would_lend`: at the
//!   door `skill_execution_door` builds, a browser or desktop row (the host's
//!   guest), a row whose answer is a credential, a reader child, a summary
//!   job and a nested skill call are each refused as `caller_code_refused`,
//!   with the reason code naming what was refused. Red at the red pin (the
//!   skill door built as the engine model's, as on main): every call is
//!   admitted or refused for another reason.
//! - `a_skill_called_over_mcp_keeps_the_base_verbs`: the default view's base
//!   verbs stay open at that door. Green before and after the fix.
//! - `a_skill_called_over_mcp_admits_its_outer_call` (REVIEW-10594): the
//!   outer `self.skills.call`, which the caller made itself, is not refused
//!   as caller code (`admit_outer_skill_call`), while the same effect from
//!   the skill's body still is. Red at the red pin (the door's own
//!   `admit_outer_skill_call` removed, so the trait's default admits it as
//!   a run call): the outer call is refused `caller_code_refused`.
//!
//! The door is driven through `test_doors::mcp_code_mode_verbs`, as the
//! skill's runtime drives it: no QuickJS host, model or guest starts. Each
//! test runs on the engine's multi-thread runtime (`on_engine_stack`), as
//! `caller_code_admission.rs` does.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! skill_door_caller_author`.

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
    admit_outer_skill_call, admit_skill_run_effect, call_skill_verb, register_credential,
};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CALLER_CODE_REFUSED: &str = "caller_code_refused";

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

/// A callable skill called over MCP is refused what a task run's door would
/// lend.
#[test]
fn a_skill_called_over_mcp_is_refused_what_a_task_run_would_lend() -> TestResult {
    on_engine_stack(skill_door_lending)
}

async fn skill_door_lending() -> TestResult {
    let fixture = fixture("skill-door-lending");
    let writer = register_credential(&fixture.server, 0xD1, &["read", "write"], None)
        .await
        .expect("a write credential registers");
    let run = EntityId::now();
    for (verb, reason) in [
        ("self.browser.screenshot", "caller_code.host_guest"),
        ("self.desktop.screenshot", "caller_code.host_guest"),
        ("self.credential.attenuate", "caller_code.credential_answer"),
    ] {
        let refused = call_skill_verb(&fixture.server, &writer, run, verb, json!({}))
            .await
            .expect("the composed call runs")
            .expect_err("a skill's nested call is refused the row");
        assert_eq!(refused.code, CALLER_CODE_REFUSED, "{verb}");
        assert_eq!(refused.reason_codes, [reason], "{verb}");
    }
    for (effect, reason) in [
        (SelfEffect::ReaderSpawn, "caller_code.reader_child"),
        (SelfEffect::Summarize, "caller_code.summary_job"),
        (SelfEffect::SkillsCall, "caller_code.credential_answer"),
    ] {
        let refused = admit_skill_run_effect(&fixture.server, &writer, run, effect)
            .await
            .expect("the admission runs")
            .expect_err("a skill's nested run call is refused the effect");
        assert_eq!(refused.code, CALLER_CODE_REFUSED, "{effect:?}");
        assert_eq!(refused.reason_codes, [reason], "{effect:?}");
    }
    Ok(())
}

/// The base verbs of the default view stay open at a callable skill's door.
#[test]
fn a_skill_called_over_mcp_keeps_the_base_verbs() -> TestResult {
    on_engine_stack(skill_door_base_verbs)
}

async fn skill_door_base_verbs() -> TestResult {
    let fixture = fixture("skill-door-base");
    let writer = register_credential(&fixture.server, 0xD2, &["read", "write"], None)
        .await
        .expect("a write credential registers");
    let run = EntityId::now();
    for verb in ["vault.recall", "vault.get", "self.actor"] {
        // An empty input meets the row's own checks after the caller-code
        // check; any answer but that refusal shows the row is open.
        let answer = call_skill_verb(&fixture.server, &writer, run, verb, json!({})).await?;
        assert!(
            !matches!(&answer, Err(refused) if refused.code == CALLER_CODE_REFUSED),
            "a base verb is open to a skill's nested call: {verb} {answer:?}"
        );
    }
    Ok(())
}

/// The outer skill call a caller makes over MCP is its own direct call: the
/// skill door admits it past the caller-code refusals, while the same effect
/// from the skill's body stays refused (REVIEW-10594).
#[test]
fn a_skill_called_over_mcp_admits_its_outer_call() -> TestResult {
    on_engine_stack(skill_door_outer_call)
}

async fn skill_door_outer_call() -> TestResult {
    let fixture = fixture("skill-door-outer");
    let writer = register_credential(&fixture.server, 0xD3, &["read", "write"], None)
        .await
        .expect("a write credential registers");
    let run = EntityId::now();
    // Any answer but the caller-code refusal shows the call is the caller's.
    let outer = admit_outer_skill_call(&fixture.server, &writer, run).await?;
    assert!(
        !matches!(&outer, Err(refused) if refused.code == CALLER_CODE_REFUSED),
        "the outer skill call is the caller's own: {outer:?}"
    );
    let nested = admit_skill_run_effect(&fixture.server, &writer, run, SelfEffect::SkillsCall)
        .await?
        .expect_err("the body's own skill call is still refused");
    assert_eq!(nested.code, CALLER_CODE_REFUSED);
    assert_eq!(nested.reason_codes, ["caller_code.credential_answer"]);
    Ok(())
}
