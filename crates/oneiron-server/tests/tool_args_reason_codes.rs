#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FIX CODE-MODE-DENIAL-REASONS: a refused verb call says what was wrong
//! with its arguments in stable reason codes, on a tool-first `tools/call`
//! and on a code-mode run's own call alike.
//!
//! The agent trial (Orchestrator NOTE 20:38, 26 Nov) saw 21 of its 58 run
//! calls refused as `tool_args_invalid` with `reason_codes: []`, so the
//! agent could not tell a wrong field from a missing one. Now an unknown
//! field answers `args.unknown_field`, a missing one `args.missing_field`
//! and `args.field.<name>` (the name the input's type declares), a value of
//! the wrong type `args.wrong_type`; the message stays as it was, and no code
//! repeats the caller's own text: neither a value nor an unknown key. A
//! run's guest gets the same codes beside its refusal
//! code (`McpCodeModeVerbs`, through the test door: no QuickJS host, model
//! or guest starts).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! tool_args_reason_codes`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use engine_stack::on_engine_stack;
use oneiron::authority::MachineRole;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::mcp_code_mode_verbs::{
    TestCredential, call_verb_with_input, credential_headers, register_credential,
};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MCP_PATH: &str = "/mcp/tool-first";
const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    app: Router,
}

impl Fixture {
    /// A rooted device vault behind the MCP gateway. The keystore goes in
    /// before the server, whose construction roots the vault.
    fn new(secret: &str) -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some(secret.into()),
                ..Default::default()
            },
        )?);
        let issuer = vault.load_host_slip_issuer()?;
        vault.ensure_host_root_slip(&issuer)?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        Ok(Self {
            _dir: dir,
            vault,
            app: build_app(Arc::clone(&server)),
            server,
        })
    }

    /// One JSON-RPC request to the tool-first endpoint as `credential`, with
    /// a fresh holder proof: the HTTP status and the reply.
    async fn rpc(
        &self,
        credential: &TestCredential,
        id: u64,
        method: &str,
        params: Value,
    ) -> TestResult<(u16, Value)> {
        let mut request = Request::post(MCP_PATH)
            .header("content-type", "application/json")
            .header("mcp-protocol-version", MCP_PROTOCOL_VERSION);
        for (name, value) in &credential_headers(&self.vault, credential)? {
            request = request.header(name, value);
        }
        let request = request.body(Body::from(
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string(),
        ))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let reply = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, reply))
    }

    /// `vault.get` as a tool-first call whose `spec` is `spec`.
    async fn get(
        &self,
        credential: &TestCredential,
        id: u64,
        version: &Value,
        spec: Value,
    ) -> TestResult<Value> {
        self.call_tool(
            credential,
            id,
            "vault.get",
            version,
            json!({ "spec": spec }),
        )
        .await
    }

    /// `tool` as a tool-first call whose inner `arguments` are `arguments`.
    async fn call_tool(
        &self,
        credential: &TestCredential,
        id: u64,
        tool: &str,
        version: &Value,
        arguments: Value,
    ) -> TestResult<Value> {
        let (status, reply) = self
            .rpc(
                credential,
                id,
                "tools/call",
                json!({
                    "name": tool,
                    "arguments": {
                        "schema_version": version,
                        "consent": {
                            "policy_ref": "policy:agent-session",
                            "purpose": "read one entity",
                        },
                        "arguments": arguments,
                    },
                }),
            )
            .await?;
        assert_eq!(status, 200, "a refusal is a 200 JSON-RPC error: {reply}");
        Ok(reply)
    }
}

/// The `schema_version` the tool-first endpoint's `tools/list` reply names
/// for `tool`.
fn schema_version(listed: &Value, tool: &str) -> TestResult<Value> {
    Ok(listed["result"]["tools"]
        .as_array()
        .ok_or("tools/list lists tools")?
        .iter()
        .find(|entry| entry["name"] == tool)
        .map(|entry| entry["inputSchema"]["properties"]["schema_version"]["const"].clone())
        .ok_or_else(|| format!("the tool-first endpoint lists {tool}"))?)
}

/// The refusal code and reason codes of a JSON-RPC error reply.
fn refusal(reply: &Value) -> (Value, Value) {
    (
        reply["error"]["data"]["error_code"].clone(),
        reply["error"]["data"]["reason_codes"].clone(),
    )
}

#[test]
fn a_tool_first_call_names_what_was_wrong_with_its_arguments() -> TestResult {
    on_engine_stack(tool_first_reason_codes)
}

async fn tool_first_reason_codes() -> TestResult {
    let fixture = Fixture::new("tool-args-reason-codes-tool-first")?;
    let reader = register_credential(&fixture.server, 0x51, &["read"], None).await?;
    let (status, listed) = fixture.rpc(&reader, 1, "tools/list", json!({})).await?;
    assert_eq!(status, 200, "{listed}");
    let version = schema_version(&listed, "vault.get")?;
    let entity = EntityId::now().to_hex();

    // The trial's own mistake: a field the verb does not take.
    let reply = fixture
        .get(
            &reader,
            2,
            &version,
            json!({ "entity_ref": entity, "id": "x" }),
        )
        .await?;
    assert_eq!(
        refusal(&reply),
        (json!("tool_args_invalid"), json!(["args.unknown_field"])),
        "an unknown field is refused as one: {reply}"
    );

    // The unknown key is the caller's own text: no code repeats it.
    let reply = fixture
        .get(
            &reader,
            5,
            &version,
            json!({ "entity_ref": entity, "synthetic_secret_123": true }),
        )
        .await?;
    assert_eq!(
        refusal(&reply),
        (json!("tool_args_invalid"), json!(["args.unknown_field"])),
        "{reply}"
    );
    assert!(
        !reply["error"]["data"]["reason_codes"]
            .to_string()
            .contains("synthetic_secret_123"),
        "no reason code repeats the caller's key: {reply}"
    );

    // A required field left out.
    let reply = fixture.get(&reader, 3, &version, json!({})).await?;
    assert_eq!(
        refusal(&reply),
        (
            json!("tool_args_invalid"),
            json!(["args.missing_field", "args.field.entity_ref"])
        ),
        "a missing field is named: {reply}"
    );

    // A value of the wrong type: the code names the kind, never the value.
    let reply = fixture
        .get(&reader, 4, &version, json!({ "entity_ref": 4242 }))
        .await?;
    assert_eq!(
        refusal(&reply),
        (json!("tool_args_invalid"), json!(["args.wrong_type"])),
        "a wrong type is named: {reply}"
    );
    assert!(
        !reply["error"]["data"]["reason_codes"]
            .to_string()
            .contains("4242"),
        "no reason code quotes the caller's value: {reply}"
    );

    // A host door decodes its input before its input check, so a wrong type
    // there is named too (review round 1 of #10553: the check refused it with
    // no reason). Every tool on the endpoint takes the one schema_version
    // vault.get lists (mcp::tests::endpoint_tool_schemas_are_closed_and_versioned).
    let reply = fixture
        .call_tool(
            &reader,
            6,
            "ai.options",
            &version,
            json!({ "spec": { "operation": 42 } }),
        )
        .await?;
    assert_eq!(
        refusal(&reply),
        (json!("tool_args_invalid"), json!(["args.wrong_type"])),
        "a host door names a wrong type: {reply}"
    );

    // A native read's request that does not decode is named the same way, on
    // the field it already named.
    let reply = fixture
        .call_tool(
            &reader,
            7,
            "memory.hydrate",
            &version,
            json!({ "request": { "ref": 42 } }),
        )
        .await?;
    assert_eq!(
        refusal(&reply),
        (json!("tool_args_invalid"), json!(["args.wrong_type"])),
        "a native request names a wrong type: {reply}"
    );
    assert_eq!(
        reply["error"]["data"]["field"], "arguments.request",
        "{reply}"
    );

    // A native read's request that decodes but fails the method's own check
    // is named too, on the field the check names (review round 2 of #10553:
    // it named none).
    let reply = fixture
        .call_tool(
            &reader,
            8,
            "memory.hydrate",
            &version,
            json!({ "request": { "ref": "bad" } }),
        )
        .await?;
    assert_eq!(
        refusal(&reply),
        (
            json!("tool_args_invalid"),
            json!(["args.invalid_field", "args.field.arguments.request.ref"])
        ),
        "a native check names the field it refused: {reply}"
    );
    assert_eq!(
        reply["error"]["data"]["field"], "arguments.request.ref",
        "{reply}"
    );
    Ok(())
}

/// A `tools/call` whose `_meta` names an invocation or a hook ask that is no
/// such handle, and a transport-only row's input of the wrong type, are
/// named in reason codes too (review round 2 of #10553: each refused with
/// none).
#[test]
fn call_meta_and_a_transport_row_name_what_was_wrong() -> TestResult {
    on_engine_stack(call_meta_and_transport_row_reason_codes)
}

async fn call_meta_and_transport_row_reason_codes() -> TestResult {
    let fixture = Fixture::new("tool-args-reason-codes-meta")?;
    let writer = register_credential(&fixture.server, 0x53, &["read", "write"], None).await?;
    let (status, listed) = fixture.rpc(&writer, 1, "tools/list", json!({})).await?;
    assert_eq!(status, 200, "{listed}");
    let version = schema_version(&listed, "vault.get")?;
    let get_with_meta = |meta: Value| {
        json!({
            "name": "vault.get",
            "_meta": meta,
            "arguments": {
                "schema_version": version,
                "consent": {
                    "policy_ref": "policy:agent-session",
                    "purpose": "read one entity",
                },
                "arguments": { "spec": { "entity_ref": EntityId::now().to_hex() } },
            },
        })
    };
    for (id, meta) in [
        (2, json!({ "oneiron/invocation": "bad" })),
        (3, json!({ "hook_ask": "bad" })),
    ] {
        let (status, reply) = fixture
            .rpc(&writer, id, "tools/call", get_with_meta(meta))
            .await?;
        assert_eq!(status, 200, "a refusal is a 200 JSON-RPC error: {reply}");
        assert_eq!(
            refusal(&reply),
            (
                json!("tool_args_invalid"),
                json!(["args.invalid_field", "args.field._meta"])
            ),
            "an invalid _meta value is named: {reply}"
        );
        assert_eq!(reply["error"]["data"]["field"], "_meta", "{reply}");
    }

    // The transport-only row decodes its typed input before its input
    // check, as a generated host door does.
    let reply = fixture
        .call_tool(
            &writer,
            4,
            "vault.imports.hook_transcript_part",
            &version,
            json!({
                "spec": {
                    "upload": "00000000000000000000000000000001",
                    "offset": 0,
                    "text": 42,
                },
            }),
        )
        .await?;
    assert_eq!(
        refusal(&reply),
        (json!("tool_args_invalid"), json!(["args.wrong_type"])),
        "a transport-only row names a wrong type: {reply}"
    );
    assert!(
        !reply["error"]["data"]["reason_codes"]
            .to_string()
            .contains("42"),
        "no reason code quotes the caller's value: {reply}"
    );
    Ok(())
}

/// A run's guest gets the same reason codes beside its refusal code.
#[test]
fn a_run_call_carries_its_reason_codes_to_the_guest() -> TestResult {
    on_engine_stack(run_call_reason_codes)
}

async fn run_call_reason_codes() -> TestResult {
    let fixture = Fixture::new("tool-args-reason-codes-run")?;
    let caller = register_credential(&fixture.server, 0x52, &["read", "write"], None).await?;
    let run = EntityId::now();
    let refused = call_verb_with_input(
        &fixture.server,
        &caller,
        run,
        "vault.get",
        json!({ "entity_ref": EntityId::now().to_hex(), "id": "x" }),
    )
    .await?
    .expect_err("an unknown field is refused");
    assert_eq!(refused.code, "tool_args_invalid");
    assert_eq!(
        refused.reason_codes,
        ["args.unknown_field"],
        "the guest learns which field was wrong"
    );
    let refused = call_verb_with_input(&fixture.server, &caller, run, "vault.get", json!({}))
        .await?
        .expect_err("a missing field is refused");
    assert_eq!(refused.code, "tool_args_invalid");
    assert_eq!(
        refused.reason_codes,
        ["args.missing_field", "args.field.entity_ref"],
        "the guest learns which field was missing"
    );
    Ok(())
}
