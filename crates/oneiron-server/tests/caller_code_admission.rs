#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FIX EXECUTE-CALLER-CODE, PR B: a run whose program its caller wrote (the
//! coming MCP `execute`) gets the caller's own per-verb gates and nothing the
//! run would lend, and a run row of a shared effect needs its own binding.
//!
//! - A caller's own code is refused a browser or desktop row (the host's
//!   guest), a row whose answer is a credential or not yet shown to carry
//!   none (`"caller_code": "refused"`, or a run row's effect the door names),
//!   a reader child and a summary job (model work on the host's meter), all
//!   as `caller_code_refused` with a reason code naming what was refused. A
//!   program the engine's model wrote keeps them, as before. The base verbs
//!   of the default view stay open.
//! - A caller's own speech needs Write even in the run's own conversation;
//!   the engine's program speaks there under Read, as before.
//! - A credential bound to one row of the Fold effect admits that row alone
//!   (`admit_run_row`), and the effect itself when any of its rows is bound:
//!   before, only the effect's first row (`self.compact`) was checked.
//!
//! The door is driven through `test_doors::mcp_code_mode_verbs`, as the run's
//! guest drives it: no QuickJS host, model or guest starts.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! caller_code_admission`.

use std::sync::Arc;

use oneiron::code_run::SelfEffect;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::mcp_code_mode_verbs::{
    ProgramAuthor, admit_own_run_speech, admit_run_effect, admit_run_row, call_verb_written_by,
    register_credential,
};
use serde_json::json;

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

/// A caller's own code is refused what the run would lend; the engine's
/// program is not refused for that reason.
#[tokio::test]
async fn caller_code_is_refused_what_the_run_would_lend() {
    let fixture = fixture("caller-code-lending");
    let writer = register_credential(&fixture.server, 0xC1, &["read", "write"], None)
        .await
        .expect("a write credential registers");
    let run = EntityId::now();
    for (verb, reason) in [
        ("self.browser.screenshot", "caller_code.host_guest"),
        ("self.desktop.screenshot", "caller_code.host_guest"),
        ("self.credential.attenuate", "caller_code.credential_answer"),
        // Marked from the credential sweep: a slip, and a row whose answer
        // the sweep could not clear (refused until it is read).
        ("vault.guests.mint_slip", "caller_code.credential_answer"),
        ("vault.settings.list", "caller_code.credential_answer"),
    ] {
        let refused = call_verb_written_by(
            &fixture.server,
            &writer,
            run,
            verb,
            json!({}),
            ProgramAuthor::Caller,
        )
        .await
        .expect("the composed call runs")
        .expect_err("a caller's own code is refused the row");
        assert_eq!(refused.code, CALLER_CODE_REFUSED, "{verb}");
        assert_eq!(refused.reason_codes, [reason], "{verb}");
        let engine = call_verb_written_by(
            &fixture.server,
            &writer,
            run,
            verb,
            json!({}),
            ProgramAuthor::EngineModel,
        )
        .await
        .expect("the composed call runs");
        assert!(
            engine
                .as_ref()
                .err()
                .is_none_or(|refused| refused.code != CALLER_CODE_REFUSED),
            "the engine's program is not refused as caller code: {verb} {engine:?}"
        );
    }
    for (effect, reason) in [
        (SelfEffect::ReaderSpawn, "caller_code.reader_child"),
        (SelfEffect::Summarize, "caller_code.summary_job"),
    ] {
        let refused =
            admit_run_effect(&fixture.server, &writer, run, effect, ProgramAuthor::Caller)
                .await
                .expect("the admission runs")
                .expect_err("a caller's own code queues no model work on the host's meter");
        assert_eq!(refused.code, CALLER_CODE_REFUSED, "{effect:?}");
        assert_eq!(refused.reason_codes, [reason], "{effect:?}");
        admit_run_effect(
            &fixture.server,
            &writer,
            run,
            effect,
            ProgramAuthor::EngineModel,
        )
        .await
        .expect("the admission runs")
        .expect("the engine's program is admitted, as before");
    }
    // Run rows whose answer can carry a secret value: the run table has no
    // `caller_code` key, so the door names their effects.
    for effect in [
        SelfEffect::RepoSnapshotsRead,
        SelfEffect::RepoViewsRead,
        SelfEffect::SkillsCall,
        SelfEffect::ConnectorAnswer,
        SelfEffect::Leader,
    ] {
        let refused =
            admit_run_effect(&fixture.server, &writer, run, effect, ProgramAuthor::Caller)
                .await
                .expect("the admission runs")
                .expect_err("a caller's own code is refused the run row");
        assert_eq!(refused.code, CALLER_CODE_REFUSED, "{effect:?}");
        assert_eq!(
            refused.reason_codes,
            ["caller_code.credential_answer"],
            "{effect:?}"
        );
        let engine = admit_run_effect(
            &fixture.server,
            &writer,
            run,
            effect,
            ProgramAuthor::EngineModel,
        )
        .await
        .expect("the admission runs");
        assert!(
            engine
                .as_ref()
                .err()
                .is_none_or(|refused| refused.code != CALLER_CODE_REFUSED),
            "the engine's program is not refused as caller code: {effect:?} {engine:?}"
        );
    }
}

/// The base verbs of the default view stay open to a caller's own code:
/// whatever else a call meets, it is not refused as caller code.
#[tokio::test]
async fn caller_code_keeps_the_base_verbs() {
    let fixture = fixture("caller-code-base");
    let writer = register_credential(&fixture.server, 0xC4, &["read", "write"], None)
        .await
        .expect("a write credential registers");
    let run = EntityId::now();
    for verb in [
        "vault.recall",
        "vault.hydrate",
        "vault.remember",
        "vault.claims.retract",
        "vault.notes.create",
        "vault.writes.pending",
        "self.actor",
        "self.focus.refresh",
    ] {
        // An empty input meets the row's own checks after the caller-code
        // check; any answer but that refusal shows the row is open.
        let answer = call_verb_written_by(
            &fixture.server,
            &writer,
            run,
            verb,
            json!({}),
            ProgramAuthor::Caller,
        )
        .await;
        assert!(
            !matches!(&answer, Ok(Err(refused)) if refused.code == CALLER_CODE_REFUSED),
            "a base verb is open to caller code: {verb} {answer:?}"
        );
    }
}

/// A caller's own speech needs Write wherever it lands.
#[tokio::test]
async fn caller_code_speech_needs_write() {
    let fixture = fixture("caller-code-speech");
    let reader = register_credential(&fixture.server, 0xC2, &["read"], None)
        .await
        .expect("a read credential registers");
    let writer = register_credential(&fixture.server, 0xC3, &["read", "write"], None)
        .await
        .expect("a write credential registers");
    let run = EntityId::now();
    admit_own_run_speech(&fixture.server, &reader, run, ProgramAuthor::EngineModel)
        .await
        .expect("the admission runs")
        .expect("the engine's program speaks in its own run under Read, as before");
    let refused = admit_own_run_speech(&fixture.server, &reader, run, ProgramAuthor::Caller)
        .await
        .expect("the admission runs")
        .expect_err("a caller's own code writes no MESSAGE under Read");
    assert_ne!(
        refused.code, CALLER_CODE_REFUSED,
        "it is the grant's refusal"
    );
    admit_own_run_speech(&fixture.server, &writer, run, ProgramAuthor::Caller)
        .await
        .expect("the admission runs")
        .expect("a caller with Write speaks");
}

/// A run row of a shared effect needs its own binding.
#[tokio::test]
async fn a_shared_effect_row_needs_its_own_binding() {
    let fixture = fixture("caller-code-shared-effect");
    let compact_only = register_credential(
        &fixture.server,
        0xC4,
        &["read", "write"],
        Some(&["self.compact"]),
    )
    .await
    .expect("a credential bound to self.compact registers");
    let fold_only = register_credential(
        &fixture.server,
        0xC5,
        &["read", "write"],
        Some(&["self.fold"]),
    )
    .await
    .expect("a credential bound to self.fold registers");
    let run = EntityId::now();
    admit_run_row(&fixture.server, &compact_only, run, "self.compact")
        .await
        .expect("the admission runs")
        .expect("the bound row is admitted");
    for row in ["self.fold", "self.unfold", "self.folds"] {
        let refused = admit_run_row(&fixture.server, &compact_only, run, row)
            .await
            .expect("the admission runs")
            .expect_err("a row of the same effect that is not bound is refused");
        assert_eq!(refused.code, "mcp_verb_not_bound", "{row}");
    }
    // The effect is admitted when one of its rows is bound, whichever.
    for credential in [&compact_only, &fold_only] {
        admit_run_effect(
            &fixture.server,
            credential,
            run,
            SelfEffect::Fold,
            ProgramAuthor::EngineModel,
        )
        .await
        .expect("the admission runs")
        .expect("a credential bound to one Fold row admits the effect");
    }
}
