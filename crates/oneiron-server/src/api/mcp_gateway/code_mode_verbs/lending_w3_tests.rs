#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FIX CODE-MODE-LENDING-W3-STEP-VERDICT-UNBOUND and the Fill writer's payer
//! (CODE-MODE-LENDING-RUN-SPEND = A): a browser batch's routine `ai.verdict`
//! needs the connector's own binding, and an MCP run's field writer bills
//! only a payer it can name.
//!
//! - `a_step_verdict_without_an_ai_verdict_binding_is_refused`: a browser
//!   batch's step verdict over MCP, called with a credential that does not
//!   bind `ai.verdict`, is refused `mcp_verb_not_bound`, as a direct
//!   `tools/call` of it is. Red: the old `mcp_admit_step_verb` line in
//!   `execute_step_verdict` (dispatch/verb_call.rs), which admitted the
//!   scope alone. Needs `--cfg oneiron_test_support` for the run's host
//!   write origin, which only `oneiron::test_doors` stamps outside the
//!   engine.
//! - `a_field_writer_with_no_payer_refuses_for_an_mcp_run`: an MCP run's
//!   (`VerdictAsker::Connector`) field writer with no attached run answers
//!   `FieldWriteError::Refused`, naming that it has no payer and that a
//!   connector's run spends on no host meter. Red: the Connector arm back on
//!   `host_line`, which lends code mode's meter with no payer.
//!
//! Run: `cargo test --locked -p oneiron-server --lib
//! api::mcp_gateway::code_mode_verbs::lending_w3_tests` (the field-writer
//! test); with `RUSTFLAGS="--cfg oneiron_test_support"` prefixed for the
//! step-verdict test.

use std::collections::BTreeSet;
use std::sync::Arc;

#[cfg(oneiron_test_support)]
use super::dispatch::execute_step_verdict;
use super::*;
#[cfg(oneiron_test_support)]
use oneiron::llm::decision::Reversibility;
use oneiron_browser::{FieldWrite, FieldWriteError, FieldWriter};

use crate::mcp::{McpConnectorScope, McpResolvedActor};

/// A minimal server on a temporary vault, as `api::tests` builds one.
fn test_server() -> (tempfile::TempDir, Arc<crate::server::SyncServer>) {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("open vault"),
    );
    crate::test_credentials::install_fixture_keystore(&vault, b"");
    let server = Arc::new(
        crate::server::SyncServer::new(vault, crate::config::SyncServerConfig::default())
            .expect("sync server"),
    );
    (dir, server)
}

/// A call context for `actor_ref` bound to `bound_verbs` (`None` binds every
/// tool): the verdict admission judges the binding, the credential gate is
/// never reached on this path.
fn bound_context(
    actor_ref: oneiron::EntityId,
    bound_verbs: Option<BTreeSet<&'static str>>,
) -> McpCallContext {
    McpCallContext {
        actor: McpResolvedActor {
            auth: None,
            actor_ref,
            actor_class: oneiron::EdgeActorClass::Human,
            gate_actor_class: "human",
            gate_actor_ref: actor_ref.to_hex(),
            scope: McpConnectorScope::vault_wide(),
            stream_connection: oneiron::context_board::StreamConnectionId(
                "mcp-test:lending-w3".to_owned(),
            ),
            bound_verbs,
            subscription_ceiling: BTreeSet::new(),
        },
        mode: crate::mcp::McpSurfaceMode::ToolFirst,
        request_id: "lending-w3".to_owned(),
        landing: Ok(None),
        invocation: None,
        hook_ask: None,
        off_record_session: None,
        room_turn: None,
        drain: None,
        forwarded: None,
        client_surface: None,
        session_workspace: None,
        signing_request_transport: None,
    }
}

/// One routine step verdict's input, as the ladder asks it: a Choice over
/// the step's candidates through the same door the run's routine steps take.
#[cfg(oneiron_test_support)]
fn step_verdict_input() -> serde_json::Value {
    let request = oneiron::task_verb::sdk::AiVerdictRequest {
        question: "which candidate may the batch press?".to_owned(),
        contract: AnswerContract::Choice {
            options: vec!["submit".to_owned(), "cancel".to_owned()],
        },
        evidence: Vec::new(),
        state: Some(serde_json::json!({"field": "q"})),
        ceiling: None,
        reversibility: Reversibility::OutboundEffect,
        deadline_ms: None,
        routine: true,
        image: None,
        misses: 0,
        until_ms: None,
    };
    serde_json::to_value(&request).expect("a step verdict serializes")
}

/// A browser batch's step verdict over MCP is refused when the credential
/// does not bind `ai.verdict`, as a direct call is.
#[cfg(oneiron_test_support)]
#[tokio::test]
async fn a_step_verdict_without_an_ai_verdict_binding_is_refused() {
    let (_dir, server) = test_server();
    let actor_ref = oneiron::EntityId::now();
    let actor = bound_context(actor_ref, Some(BTreeSet::from(["vault.recall"])));
    let run = McpCodeRun {
        origin: oneiron::test_doors::host_write_origin::host_write_origin(actor_ref)
            .expect("a host write origin"),
        run_id: oneiron::EntityId::now(),
        author: RunAuthor::EngineModel,
    };
    let refused = execute_step_verdict(&server, &actor, step_verdict_input(), run)
        .await
        .expect_err("a step verdict without an ai.verdict binding is refused");
    let (code, _) = refused.code_and_message();
    assert_eq!(code, "mcp_verb_not_bound");
}

/// An MCP run's field writer with no payer refuses: it names that it has no
/// payer and that a connector's run spends on no host meter.
#[tokio::test]
async fn a_field_writer_with_no_payer_refuses_for_an_mcp_run() {
    let (_dir, server) = test_server();
    let runtime = tokio::runtime::Handle::current();
    let asker = VerdictAsker::Connector(bound_context(oneiron::EntityId::now(), None));
    let writer = RunFieldWriter::new(&server, &runtime, &asker, None);
    let ask = FieldWrite {
        instruction: Some("type the recipient's name".to_owned()),
        references: Vec::new(),
        enum_values: None,
        role: "textbox".to_owned(),
        name: "recipient".to_owned(),
        url: "https://example.invalid/compose".to_owned(),
        title: "compose".to_owned(),
        until_ms: None,
    };
    let refused = <RunFieldWriter as FieldWriter>::write(&writer, &ask)
        .expect_err("a field writer with no payer refuses");
    let FieldWriteError::Refused(message) = refused else {
        panic!("a missing payer is a refusal, not an outage: {refused:?}");
    };
    assert!(
        message.contains("has no payer"),
        "the refusal names the missing payer: {message}"
    );
    assert!(
        message.contains("spends on no host meter"),
        "the refusal names the unspent meter: {message}"
    );
}
