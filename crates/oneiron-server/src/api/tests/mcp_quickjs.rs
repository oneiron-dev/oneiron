//! Production execute_code uses real JS through the vault-owned host and wire.
use super::*;
use oneiron::code_run::CodeRunDeterminism;
use oneiron::code_sandbox::{quickjs::QuickJsRuntimeFactory, wasmtime_runtime::ComponentBudget};
use oneiron::engine_executor::{EngineExecutorConfig, EngineExecutorLimits};
use oneiron::llm::manifest::{MODEL_ROLES, ModelBinding, ModelManifest, ModelSlot};
use oneiron::llm::registry::{ModelRegistryRow, ModelWireFormat};
use oneiron::llm::seat::{ModelDescription, SeatCandidate, SeatJudge, SeatJudgment, SeatTask};
use oneiron::llm::{
    LlmCapability, LlmCatalogCost, LlmCatalogEntry, ModelTierRef as Tier, ReasoningEffort,
};
use oneiron::{
    BudgetLease, ContentPart, FinishReason, LlmBackend, LlmGenerateFuture, LlmMessage,
    LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult, LlmUsage, ModelId, ModelLocality,
    ModelTierRef,
};
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Backend {
    scripts: Mutex<VecDeque<String>>,
    requests: Mutex<Vec<LlmRequest>>,
}
struct Judge {
    model: ModelId,
    calls: AtomicUsize,
}
impl SeatJudge for Judge {
    fn judge(
        &self,
        task: &SeatTask,
        candidates: &[SeatCandidate],
    ) -> oneiron::Result<SeatJudgment> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        assert!(!task.task.is_empty());
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.model == self.model)
        );
        Ok(SeatJudgment {
            model: self.model.clone(),
            effort: None,
            why: "The owner's code-task description fits this run".into(),
        })
    }
}
impl LlmBackend for Backend {
    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        self.requests.lock().unwrap().push(request);
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

/// One server bound to the production QuickJS provider over a real component,
/// whose code-seat model answers with `scripts`, one per executor step.
struct CodeMode {
    server: Arc<SyncServer>,
    vault: Arc<oneiron::Vault>,
    backend: Arc<Backend>,
    judge: Arc<Judge>,
    seat_model: ModelId,
    _dir: tempfile::TempDir,
}

fn code_mode_server(scripts: Vec<String>) -> CodeMode {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let seat_model = ModelId::new("fixture/code-seat@v2").unwrap();
    let manifest = ModelManifest {
        version: 2,
        roles: MODEL_ROLES
            .into_iter()
            .map(|role| {
                (
                    role,
                    ModelBinding {
                        model: seat_model.clone(),
                        slot: ModelSlot::Llm,
                        tier: Tier("legacy".into()),
                        route_models: BTreeMap::new(),
                    },
                )
            })
            .collect(),
        routes: [ModelSlot::Llm, ModelSlot::Embedder, ModelSlot::Oneironer]
            .into_iter()
            .map(|slot| (slot, ModelLocality::OnDevice))
            .collect(),
        verdict: None,
        seat_policy: Some(oneiron::llm::seat::SeatPolicy {
            purpose_defaults: BTreeMap::from([(
                format!(
                    "other:{}",
                    oneiron::engine_executor::ENGINE_EXECUTOR_PURPOSE_NAME
                ),
                ReasoningEffort::High,
            )]),
            vault_ceiling: ReasoningEffort::High,
            ..oneiron::llm::seat::SeatPolicy::bundled().unwrap()
        }),
    };
    let approval = oneiron::llm::manifest::TeacherProbeApproval::for_scored_checkpoint(
        &manifest,
        &vault.teacher_probe_policy(None).unwrap(),
        1_000_000,
    )
    .unwrap();
    vault
        .set_model_manifest_with_teacher_approval(&manifest, &approval)
        .unwrap();
    vault
        .put_model_registry_row(&ModelRegistryRow {
            version: 1,
            wire: ModelWireFormat::Local,
            catalog: LlmCatalogEntry {
                model: seat_model.clone(),
                display_name: "Fixture seat".into(),
                locality: ModelLocality::OnDevice,
                context_window_tokens: 8192,
                max_output_tokens: Some(1024),
                cost: Some(LlmCatalogCost {
                    input_per_million: "1".into(),
                    output_per_million: "1".into(),
                    cache_read_per_million: None,
                    cache_write_per_million: None,
                }),
                capabilities: vec![LlmCapability::Reasoning],
                metadata: BTreeMap::new(),
            },
            scores: BTreeMap::new(),
            fetched_at: BTreeMap::new(),
        })
        .unwrap();
    vault
        .set_model_description(&ModelDescription {
            model: seat_model.clone(),
            facet: "code-task".into(),
            owner: Some("Code-mode task execution".into()),
            measured: None,
            benchmarks: None,
            vendor: None,
        })
        .unwrap();
    let judge = Arc::new(Judge {
        model: seat_model.clone(),
        calls: AtomicUsize::new(0),
    });
    let backend = Arc::new(Backend {
        scripts: Mutex::new(scripts.into()),
        requests: Mutex::new(Vec::new()),
    });
    let provider = crate::mcp::McpQuickJsProvider::new(
        Arc::new(factory()),
        backend.clone(),
        BudgetLease::for_test("quickjs-wire"),
        EngineExecutorConfig {
            run_id: seeded_test_entity_id(0x0024_6504),
            task: "template".into(),
            prompt_package_root: oneiron::prompt::workspace_test_prompt_package_root().unwrap(),
            model: ModelId::new("fixture/quickjs@v1").unwrap(),
            model_locality: ModelLocality::OnDevice,
            seat_effort: None,
            global_tier: ModelTierRef("fixture".into()),
            determinism: CodeRunDeterminism::new(1700000000000, [7; 32]),
            limits: EngineExecutorLimits {
                soft_steps: 1,
                hard_steps: 4,
            },
        },
    )
    .unwrap()
    .with_model_seat_router(judge.clone(), "code-task");
    let server = Arc::new(
        SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("secret".to_owned()),
                ..Default::default()
            },
        )
        .unwrap()
        .with_mcp_quickjs_provider(provider),
    );
    CodeMode {
        server,
        vault,
        backend,
        judge,
        seat_model,
        _dir: dir,
    }
}

#[tokio::test]
async fn quickjs_execute_code_wire_resumes_one_actor_run_without_repeated_writes() {
    let actor_id = seeded_test_entity_id(0x0024_6501);
    let subject = seeded_test_entity_id(0x0024_6502);
    let claim = seeded_test_entity_id(0x0024_6503);
    let scripts = vec![
        format!(
            "const receipt = await self.memory.put_claim({{id:'{}', predicate:'profile.favorite_drink', subject:'{}', value:'sencha'}}); console.log(receipt.id);",
            claim.to_hex(),
            subject.to_hex()
        ),
        "finish('recorded');".into(),
    ];
    let CodeMode {
        server,
        vault,
        backend,
        judge,
        seat_model,
        _dir,
    } = code_mode_server(scripts);
    vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"quickjs subject",
        )
        .unwrap();
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
            Request::builder()
                .uri(path)
                .header(AUTHORIZATION, owner_bearer())
                .body(Body::empty())
                .unwrap(),
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
    assert_eq!(judge.calls.load(Ordering::Relaxed), 1);
    assert_eq!(results[0]["model_choice"]["model"], seat_model.as_str());
    assert_eq!(results[0]["model_choice"]["effort"], "high");
    assert_eq!(results[0]["model_choice"]["reused"], false);
    assert_eq!(results[1]["model_choice"]["reused"], true);
    {
        let seen = backend.requests.lock().unwrap();
        assert_eq!(seen.len(), 2);
        for request in seen.iter() {
            assert_eq!(request.model, seat_model);
            assert_eq!(request.envelope.seat_effort, Some(ReasoningEffort::High));
        }
    }
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
    assert_mcp_structured_error(&body, "code_run_binding_failed");
}

const CODE_MODE_RECALL: &str = "const pack = await self.memory.recall({query: 'heron lantern', \
    effort: 'medium', scope: {}}); finish(JSON.stringify(pack));";

/// Witnesses one message through the tool list's generated `witness` tool.
async fn witness_through_tool_list(
    server: &Arc<SyncServer>,
    credential: &str,
    actor: oneiron::EntityId,
    text: &str,
) {
    let args = mcp_merge_args(
        mcp_endpoint_envelope(actor, "write_memory"),
        json!({"arguments": {"spec": {
            "conversation_ref": "41414141414141414141414141414141",
            "occurred_at": 1_767_225_600,
            "messages": [{"author": "user", "message_type": "text", "content": text, "is_visible": true, "order": 0}],
        }}}),
    );
    let (_, body) = route_json(
        server.clone(),
        mcp_endpoint_call_request(MCP_TOOL_FIRST_PATH, credential, "witness", "witness", args),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
}

/// Done means (ARCH-0028, OF-246/OF-227): through the shipped HTTP MCP wire, an
/// `execute_code` run calls `self.memory.recall({query, effort, scope})` and
/// reads back a phrase saved earlier in the same vault. Before this change the
/// method did not exist.
#[tokio::test]
async fn quickjs_code_mode_recall_reads_back_a_phrase_saved_in_the_vault() {
    let mode = code_mode_server(vec![CODE_MODE_RECALL.to_owned()]);
    let actor = seeded_test_entity_id(0x0024_6511);
    let credential = "quickjs-recall-credential";
    register_mcp_actor(
        &mode.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    witness_through_tool_list(
        &mode.server,
        credential,
        actor,
        "The heron lantern hangs by the north gate.",
    )
    .await;

    let args = mcp_merge_args(
        mcp_endpoint_envelope(actor, "read_memory"),
        json!({"run_ref": "quickjs-recall", "task": "recall the heron lantern"}),
    );
    let (_, body) = route_json(
        mode.server.clone(),
        mcp_endpoint_call_request("/mcp", credential, "recall", "execute_code", args),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    let structured = &body["result"]["structuredContent"];
    assert_eq!(structured["result"]["status"], "complete", "{structured}");
    // The recall's own output is the run's one bridge call, as recorded.
    let steps = structured["steps"].as_array().expect("steps");
    assert_eq!(steps.len(), 1, "{structured}");
    assert_eq!(steps[0]["effect"], "self.verbs.call");
    let recalled = steps[0]["outcome"]["output"]
        .as_str()
        .expect("recall output");
    assert!(
        recalled.contains("north gate"),
        "recall did not return the saved phrase: {recalled}"
    );
}

/// A connector narrowed to one world reaches no other world's memory through
/// recall, on the tool list or in code mode; and a connector bound to fewer
/// verbs cannot reach the rest through code mode. Code mode is a door onto the
/// same gate, never around it.
#[tokio::test]
async fn quickjs_code_mode_keeps_connector_narrowing() {
    let refused = "try { await self.memory.recall({query: 'heron lantern'}); finish('reached'); } \
        catch (error) { finish('refused ' + String(error)); }";
    let mode = code_mode_server(vec![refused.to_owned()]);
    let owner = seeded_test_entity_id(0x0024_6521);
    register_mcp_actor(
        &mode.server,
        "quickjs-owner",
        owner,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    witness_through_tool_list(
        &mode.server,
        "quickjs-owner",
        owner,
        "The heron lantern hangs by the north gate.",
    )
    .await;

    let narrowed = seeded_test_entity_id(0x0024_6522);
    let scope = crate::mcp::McpConnectorScope {
        world_ref: Some(seeded_test_entity_id(0x0024_6523)),
        facet_ref: None,
    };
    register_scoped_mcp_actor(&mode.server, "quickjs-world", narrowed, scope.clone()).await;
    let tool = mcp_merge_args(
        mcp_scoped_envelope(narrowed, "read_memory", &scope),
        json!({"arguments": {"spec": {"query": "heron lantern"}}}),
    );
    let code = mcp_merge_args(
        mcp_scoped_envelope(narrowed, "read_memory", &scope),
        json!({"run_ref": "quickjs-world", "task": "recall the heron lantern"}),
    );
    for request in [
        mcp_endpoint_call_request(MCP_TOOL_FIRST_PATH, "quickjs-world", "tool", "recall", tool),
        mcp_endpoint_call_request("/mcp", "quickjs-world", "code", "execute_code", code),
    ] {
        let body = mcp_refusal(&mode.server, request).await;
        assert_eq!(
            body["error"]["data"]["error_code"], "mcp_scope_refused",
            "{body}"
        );
        assert!(!body.to_string().contains("north gate"), "{body}");
    }
    assert!(
        mode.backend.requests.lock().unwrap().is_empty(),
        "a refused run reaches no model"
    );

    let bound = seeded_test_entity_id(0x0024_6524);
    register_bound_verb_mcp_actor(&mode.server, "quickjs-bound", bound, &["execute_code"]).await;
    let args = mcp_merge_args(
        mcp_endpoint_envelope(bound, "read_memory"),
        json!({"run_ref": "quickjs-bound", "task": "recall the heron lantern"}),
    );
    let (_, body) = route_json(
        mode.server.clone(),
        mcp_endpoint_call_request("/mcp", "quickjs-bound", "bound", "execute_code", args),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    let text = body["result"]["structuredContent"].to_string();
    assert!(
        text.contains("refused") && text.contains("mcp_verb_not_bound"),
        "{text}"
    );
    assert!(!text.contains("north gate"), "{text}");
}

/// Code mode applies the per-verb argument rules a `tools/call` of the verb
/// applies (review repro: an empty subscription set was refused on the tool
/// list but accepted from `self.memory.board.subscribe`).
#[tokio::test]
async fn quickjs_code_mode_applies_the_tool_argument_rules() {
    let script = "try { await self.memory.board.subscribe({scopes: []}); finish('reached'); } \
        catch (error) { finish('refused ' + String(error)); }";
    let mode = code_mode_server(vec![script.to_owned()]);
    let actor = seeded_test_entity_id(0x0024_6531);
    register_mcp_actor(
        &mode.server,
        "quickjs-args",
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let args = mcp_merge_args(
        mcp_endpoint_envelope(actor, "read_board"),
        json!({"run_ref": "quickjs-args", "task": "subscribe to nothing"}),
    );
    let (_, body) = route_json(
        mode.server.clone(),
        mcp_endpoint_call_request("/mcp", "quickjs-args", "args", "execute_code", args),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    let steps = body["result"]["structuredContent"]["steps"].to_string();
    assert!(
        steps.contains("self.verbs.call") && steps.contains("tool_args_invalid"),
        "{steps}"
    );
}
