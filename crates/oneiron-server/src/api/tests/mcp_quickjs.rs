//! Production execute_code uses real JS through the vault-owned host and wire.
use super::*;
use oneiron::code_run::CodeRunDeterminism;
use oneiron::code_sandbox::{quickjs::QuickJsRuntimeFactory, wasmtime_runtime::ComponentBudget};
use oneiron::engine_executor::{EngineExecutorConfig, EngineExecutorLimits};
use oneiron::{
    BudgetLease, ContentPart, FinishReason, LlmBackend, LlmGenerateFuture, LlmMessage,
    LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult, LlmUsage, ModelId, ModelLocality,
    ModelTierRef,
};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;

struct Backend {
    scripts: Mutex<VecDeque<String>>,
}
impl LlmBackend for Backend {
    fn generate<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        let text = self
            .scripts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| "throw new Error('unexpected repeated provider call');".into());
        Box::pin(async move {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text { text }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
            })
        })
    }
    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        unimplemented!("this provider does not stream")
    }
}

fn factory() -> QuickJsRuntimeFactory {
    let directory = std::env::var_os("ONEIRON_QUICKJS_ARTIFACT_DIR").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/code-run-quickjs/artifacts")
        },
        PathBuf::from,
    );
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(directory.join("manifest.json")).expect("build the real QuickJS artifacts"),
    )
    .unwrap();
    let row = &manifest["artifacts"]["first-party"];
    let bytes = std::fs::read(directory.join(row["file"].as_str().unwrap())).unwrap();
    let text = row["sha256"].as_str().unwrap();
    let mut hash = [0; 32];
    for (i, byte) in hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
    }
    QuickJsRuntimeFactory::from_component(&bytes, hash, ComponentBudget::default()).unwrap()
}

#[tokio::test]
async fn quickjs_execute_code_wire_resumes_one_actor_run_without_repeated_writes() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let actor_id = seeded_test_entity_id(0x0024_6501);
    let subject = seeded_test_entity_id(0x0024_6502);
    let claim = seeded_test_entity_id(0x0024_6503);
    vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"quickjs subject",
        )
        .unwrap();
    let scripts = [
        format!(
            "const receipt = await self.memory.put_claim({{id:'{}', predicate:'profile.favorite_drink', subject:'{}', value:'sencha'}}); console.log(receipt.id);",
            claim.to_hex(),
            subject.to_hex()
        ),
        "finish('recorded');".into(),
    ];
    let provider = crate::mcp::McpQuickJsProvider::new(
        Arc::new(factory()),
        Arc::new(Backend {
            scripts: Mutex::new(scripts.into()),
        }),
        BudgetLease::for_test("quickjs-wire"),
        EngineExecutorConfig {
            run_id: seeded_test_entity_id(0x0024_6504),
            task: "template".into(),
            prompt_package_root: oneiron::prompt::workspace_prompt_package_root().unwrap(),
            model: ModelId::new("fixture/quickjs@v1").unwrap(),
            model_locality: ModelLocality::OnDevice,
            global_tier: ModelTierRef("fixture".into()),
            determinism: CodeRunDeterminism::new(1700000000000, [7; 32]),
            limits: EngineExecutorLimits {
                soft_steps: 1,
                hard_steps: 4,
            },
        },
    )
    .unwrap();
    let server = Arc::new(
        SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .unwrap()
        .with_mcp_quickjs_provider(provider),
    );
    let credential = "quickjs-wire-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_id,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    for path in ["/mcp", MCP_TOOL_FIRST_PATH] {
        let (_, listing) =
            route_json(server.clone(), mcp_list_request(path, credential, "list")).await;
        assert!(mcp_listed_tool_names(&listing).contains(&"execute_code"));
    }
    for (path, field) in [
        ("/api/core/discover", "feature_flags"),
        ("/api/health", "capabilities"),
    ] {
        let (status, body) = route_json(
            server.clone(),
            Request::builder().uri(path).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let capabilities = body[field]["capabilities"].as_array().unwrap();
        for token in [
            "mcp.tool.execute_code",
            "mcp.endpoint.primary.execute_code",
            "mcp.endpoint.tool_first.execute_code",
        ] {
            assert!(capabilities.contains(&json!(token)), "{path}: {body}");
        }
    }
    let args = mcp_merge_args(
        mcp_endpoint_envelope(actor_id, "write_memory"),
        json!({"run_ref":"quickjs-one", "task":"write one claim then finish"}),
    );
    let mut results = Vec::new();
    for request_id in ["first", "resume", "terminal-retry"] {
        let (_, body) = route_json(
            server.clone(),
            mcp_endpoint_call_request("/mcp", credential, request_id, "execute_code", args.clone()),
        )
        .await;
        assert!(body.get("error").is_none(), "{body}");
        results.push(body["result"]["structuredContent"].clone());
    }
    assert_eq!(results[0]["result"]["status"], "yielded");
    assert_eq!(results[1]["result"]["status"], "complete");
    assert_eq!(results[2]["steps_run"], 0);
    assert_eq!(results[0]["run_id"], results[1]["run_id"]);
    assert_eq!(results[1]["run_id"], results[2]["run_id"]);
    for result in &results {
        assert_eq!(result["bridge_calls"], 1);
    }
    let stored = vault.get_claim(&claim).unwrap().unwrap();
    assert_eq!(stored.source, Some(oneiron::ClaimSource::Generated));
    assert_eq!(stored.approval, oneiron::ClaimApprovalStatus::Proposed);
    let rmpv::Value::Map(evidence) = stored.evidence.unwrap() else {
        panic!("write must carry host evidence")
    };
    assert_eq!(
        evidence
            .iter()
            .find(|(key, _)| key.as_str() == Some("actor_entity_ref"))
            .map(|(_, value)| value),
        Some(&rmpv::Value::Binary(actor_id.as_bytes().to_vec()))
    );
    let changed = mcp_merge_args(args, json!({"task":"changed task"}));
    let (_, body) = route_json(
        server,
        mcp_endpoint_call_request("/mcp", credential, "changed", "execute_code", changed),
    )
    .await;
    assert_mcp_structured_error(&body, "code_run_failed");
}
