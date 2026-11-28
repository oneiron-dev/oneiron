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
//! - A caller's own speech needs Write even in the run's own conversation,
//!   and the row it is made through bound (`say`, or `self.think.aloud`).
//!   The engine's program needs Write there too (FIX CODE-MODE-LENDING-W7:
//!   no direct call writes a MESSAGE under Read); it needs no binding.
//! - A credential bound to one row of the Fold effect admits that row alone
//!   (`admit_run_row`), and the effect itself when any of its rows is bound:
//!   before, only the effect's first row (`self.compact`) was checked.
//! - The engine's program calls the `ai.*` media doors on its run's line,
//!   and the line only pays: a credential no Grant names the operation is
//!   refused as its direct call is, naming the Grant (FIX
//!   CODE-MODE-LENDING-W1; `media_call_on_run_line`).
//!
//! The door is driven through `test_doors::mcp_code_mode_verbs`, as the run's
//! guest drives it: no QuickJS host, model or guest starts. Each test runs on
//! the engine's multi-thread runtime (`on_engine_stack`): the door runs its
//! work on that runtime and waits for it, as the production guest does from
//! its own thread, which a current-thread test runtime would deadlock.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! caller_code_admission`.

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
    ProgramAuthor, admit_own_run_speech, admit_run_effect, admit_run_row, admit_run_speech_as,
    call_verb_written_by, media_call_on_run_line, register_credential,
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

/// A caller's own code is refused what the run would lend; the engine's
/// program is not refused for that reason.
#[test]
fn caller_code_is_refused_what_the_run_would_lend() -> TestResult {
    on_engine_stack(caller_code_lending)
}

async fn caller_code_lending() -> TestResult {
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
    Ok(())
}

/// The base verbs of the default view stay open to a caller's own code:
/// whatever else a call meets, it is not refused as caller code.
#[test]
fn caller_code_keeps_the_base_verbs() -> TestResult {
    on_engine_stack(caller_code_base_verbs)
}

async fn caller_code_base_verbs() -> TestResult {
    let fixture = fixture("caller-code-base");
    let writer = register_credential(&fixture.server, 0xC4, &["read", "write"], None)
        .await
        .expect("a write credential registers");
    let run = EntityId::now();
    for verb in [
        "vault.recall",
        "vault.hydrate",
        "vault.get",
        "vault.remember",
        "vault.claims.retract",
        "vault.notes.create",
        "vault.writes.pending",
        "self.actor",
        "self.focus.refresh",
    ] {
        // An empty input meets the row's own checks after the caller-code
        // check; the call runs, and any answer but that refusal shows the row
        // is open. A call that stops outside a refusal (an unknown row, a
        // credential that does not resolve) fails the test.
        let answer = call_verb_written_by(
            &fixture.server,
            &writer,
            run,
            verb,
            json!({}),
            ProgramAuthor::Caller,
        )
        .await?;
        assert!(
            !matches!(&answer, Err(refused) if refused.code == CALLER_CODE_REFUSED),
            "a base verb is open to caller code: {verb} {answer:?}"
        );
    }
    Ok(())
}

/// A caller's own speech needs Write wherever it lands, and so does the
/// engine's program's in its own run (FIX CODE-MODE-LENDING-W7). Red on
/// main: the engine's program spoke there under Read.
#[test]
fn caller_code_speech_needs_write() -> TestResult {
    on_engine_stack(caller_code_speech)
}

async fn caller_code_speech() -> TestResult {
    let fixture = fixture("caller-code-speech");
    let reader = register_credential(&fixture.server, 0xC2, &["read"], None)
        .await
        .expect("a read credential registers");
    let writer = register_credential(&fixture.server, 0xC3, &["read", "write"], None)
        .await
        .expect("a write credential registers");
    let run = EntityId::now();
    let refused = admit_own_run_speech(&fixture.server, &reader, run, ProgramAuthor::EngineModel)
        .await
        .expect("the admission runs")
        .expect_err("the engine's program writes no MESSAGE under Read either");
    assert_ne!(
        refused.code, CALLER_CODE_REFUSED,
        "it is the grant's refusal"
    );
    admit_own_run_speech(&fixture.server, &writer, run, ProgramAuthor::EngineModel)
        .await
        .expect("the admission runs")
        .expect("the engine's program speaks in its own run under Write");
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
    Ok(())
}

/// A caller's own speech needs the row it is made through bound, as a
/// direct call does (review of #10558: a connector bound to `vault.recall`
/// alone spoke through `self.think.aloud` and a plain `say`). The engine's
/// program speaks in its own run's conversation with no binding, as before.
#[test]
fn caller_code_speech_needs_its_row_bound() -> TestResult {
    on_engine_stack(caller_code_speech_binding)
}

async fn caller_code_speech_binding() -> TestResult {
    let fixture = fixture("caller-code-speech-binding");
    let recall_only = register_credential(
        &fixture.server,
        0xC6,
        &["read", "write"],
        Some(&["vault.recall"]),
    )
    .await?;
    let speaker = register_credential(
        &fixture.server,
        0xC7,
        &["read", "write"],
        Some(&["say", "self.think.aloud"]),
    )
    .await?;
    let run = EntityId::now();
    // A plain `say(text)` is `self.speak`, made through the `say` row;
    // `self.think.aloud` is a run row of its own.
    for effect in [SelfEffect::Speak, SelfEffect::ThinkAloud] {
        let refused = admit_run_speech_as(
            &fixture.server,
            &recall_only,
            run,
            effect,
            ProgramAuthor::Caller,
        )
        .await?
        .expect_err("a caller's speech through a row it is not bound to is refused");
        assert_eq!(refused.code, "mcp_verb_not_bound", "{effect:?}");
        admit_run_speech_as(
            &fixture.server,
            &speaker,
            run,
            effect,
            ProgramAuthor::Caller,
        )
        .await?
        .unwrap_or_else(|refused| {
            panic!("a caller bound to the row speaks: {effect:?} {refused:?}")
        });
    }
    admit_run_speech_as(
        &fixture.server,
        &recall_only,
        run,
        SelfEffect::Speak,
        ProgramAuthor::EngineModel,
    )
    .await?
    .unwrap_or_else(|refused| panic!("the engine's program speaks in its own run: {refused:?}"));
    Ok(())
}

/// A run row of a shared effect needs its own binding.
#[test]
fn a_shared_effect_row_needs_its_own_binding() -> TestResult {
    on_engine_stack(shared_effect_row_binding)
}

async fn shared_effect_row_binding() -> TestResult {
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
    Ok(())
}

/// The engine's program calls the `ai.*` media doors on its run's line, and
/// the line only pays (FIX CODE-MODE-LENDING-W1): a credential no Grant
/// names `ai.image` or `ai.video` is refused there as its direct call is,
/// naming the Grant it needs, at the call, the poll and the cancel. Red with
/// the media fix undone (the door is new, so main has no test target): the
/// line answered before the Grant check, so each call went on to the
/// fixture's absent model, and the poll and the cancel to the run's own
/// jobs, and none named the Grant.
#[test]
fn engine_program_media_on_its_line_needs_the_grant() -> TestResult {
    on_engine_stack(engine_program_media)
}

async fn engine_program_media() -> TestResult {
    let fixture = fixture("engine-program-media");
    let writer = register_credential(&fixture.server, 0xC8, &["read", "write"], None)
        .await
        .expect("a write credential registers");
    let run = EntityId::now();
    for (verb, input, grant) in [
        (
            "ai.image",
            json!({"prompt": "a heron lantern by the north gate"}),
            "grant_required.ai.image",
        ),
        (
            "ai.video",
            json!({"prompt": "the north gate at dusk"}),
            "grant_required.ai.video",
        ),
        (
            "ai.video.poll",
            json!({"job": "media-line-job"}),
            "grant_required.ai.video",
        ),
        (
            "ai.video.cancel",
            json!({"job": "media-line-job"}),
            "grant_required.ai.video",
        ),
    ] {
        let refused = media_call_on_run_line(&fixture.server, &writer, run, verb, input)
            .await
            .expect("the door call runs")
            .expect_err("a credential no Grant names is refused on the line");
        assert!(
            refused.reason_codes.iter().any(|code| code == grant),
            "{verb} names the Grant it needs: {refused:?}"
        );
    }
    Ok(())
}
