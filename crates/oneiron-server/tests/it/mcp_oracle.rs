//! Context Board forward test oracle — MCP surface + packaging arms, epic
//! ONE-1692, relocated from the engine crate by the ONE-1797 split so these
//! arms live in the crate that can legally link the MCP implementation.
//!
//! Contract-level red tests derived from the ticket acceptance criteria
//! (ONE-1704 / ONE-1705) and the ratified design
//! `oneiron-v1/design/out/08b-Context-Board-extension.md` (16/16, 2026-07-15).
//!
//! Shape of every test:
//! * `#[ignore = "armed by ONE-XXXX"]` — dormant until its ticket lands.
//! * An `arm_*` seam function whose body is `unimplemented!()`. Its doc
//!   comment is the fixture spec. The ARMING ticket replaces the seam body
//!   (and may freely adapt the seam signature), then removes the `#[ignore]`.
//! * Asserts are the contract: exact counts and equalities, never `any()`.
//!   Arming NEVER weakens, loosens, or removes an assert.
//!
//! Observation structs are contract shapes, not API proposals — every field
//! is asserted by at least one test.

// Contract shapes are constructed only once their arming ticket lands.
#![allow(dead_code)]

// ════════════════════════════════════════════════════════════════════════
// CB-X — MCP surface + packaging (ONE-1704 MCP 2-tool · ONE-1705 skill/CLI/
//        thin client)
// ════════════════════════════════════════════════════════════════════════
mod cb_x {
    /// Tool-first variant generation observations.
    struct GeneratedToolVariant {
        /// The fixture verb table, sorted.
        verb_table: Vec<String>,
        /// Generated tool names, sorted (F17: set-equality with the verb
        /// table — 7 duplicates of one verb must fail).
        generated_tool_names: Vec<String>,
        /// Hand-written (non-generated) tools in the variant (must be none).
        hand_written_tools: usize,
    }

    /// ONE-1704 fixture: the verb table is the engine's EXPORTED
    /// the agent verb catalog, read straight off the
    /// constants; generate the tool-first variant from it.
    fn arm_generated_tool_variant() -> GeneratedToolVariant {
        let mut verb_table = oneiron_server::mcp::exported_verb_rows()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        verb_table.sort();

        let surface =
            oneiron_server::mcp::registered_surface(oneiron_server::mcp::McpSurfaceMode::ToolFirst);
        let mut generated_tool_names = surface
            .tool_names()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        generated_tool_names.sort();

        // Every registered tool on this endpoint is a projection of one
        // exported row; a hand-written one would be a tool whose name is not
        // in the exported table.
        let hand_written_tools = surface
            .tools()
            .iter()
            .filter(|tool| !matches!(tool, oneiron_server::mcp::McpEndpointTool::Verb(_)))
            .count();

        GeneratedToolVariant {
            verb_table,
            generated_tool_names,
            hand_written_tools,
        }
    }

    /// ONE-1704 · 08b §6: the tool-first variant is GENERATED from the verb
    /// table — the generated tool-name set equals the verb table exactly
    /// (one tool per verb, distinct), nothing hand-rolled.
    #[test]
    fn tool_first_variant_is_generated_one_tool_per_verb() {
        let variant = arm_generated_tool_variant();
        // The census is REGENERATED from the exported constants rather than
        // restated: the MCP projection of the board, tasks and rooms verbs,
        // and `MEMORY_VERBS`, sorted.
        let mut expected = oneiron::task_verb::sdk::AgentVerb::ALL
            .iter()
            .filter(|verb| verb.is_mcp())
            .map(|verb| verb.as_str())
            .chain(oneiron::code_run::vault_read::MEMORY_VERBS.iter().copied())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        expected.sort();
        // 24 since ARCH-0067's 2026-09-22 amendment folded `tasks.check` and
        // `tasks.expand` into the one `describe` row; 28 since ONE-2563 added
        // `rooms.render`, `rooms.find`, `rooms.get` and `rooms.trunk`.
        assert_eq!(expected.len(), 28);
        assert_eq!(variant.verb_table, expected);
        assert_eq!(variant.generated_tool_names, expected);
        assert_eq!(variant.hand_written_tools, 0);
    }
}

// ════════════════════════════════════════════════════════════════════════
// ONE-1704 fixtures
//
// Both arms drive SHIPPED code: the setup assembly the gateway calls, and the
// engine dispatcher `execute_code` projects onto. Nothing here re-implements a
// surface it is meant to observe.
// ════════════════════════════════════════════════════════════════════════

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron::code_run::{
    CODE_RUN_RNG_SEED_LEN, CodeRunDeterminism, SelfCall, SelfFixtureEffectCall,
    SelfMemorySearchCall,
};
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorStatus, JsCodeModeHost,
    JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
};
use oneiron::registry::ENTITY_TYPE_MACHINE;
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EntityId, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, ModelLocality, ModelTierRef, TimeRange, Vault, VaultConfig,
};
use oneiron_server::mcp::{
    McpCodeExecutionHost, McpCodeExecutionRequest, McpCodeModeProvider, McpConnectorScope,
    McpEngineNativeCodeHost, McpResolvedActor, mcp_code_run_id,
};

fn oracle_vault_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.max_readers = 32;
    config
}

fn oracle_id(counter: u128) -> EntityId {
    let mut bytes = counter.to_be_bytes();
    bytes[0] = 0x17;
    EntityId::from_bytes(bytes).expect("seeded oracle id should be valid")
}

// ════════════════════════════════════════════════════════════════════════
// ONE-1704 M2 — the INJECTED execute_code host SEAM
//
// The core crate ships no production `JsCodeModeRuntime`, so the provider is a
// fixture and the ADAPTER under observation is the shipped one: it constructs
// `HostSelfDispatcher`/`GatedActorWrite` and enters the sandbox/REPL through
// `EngineNativeExecutor`. Nothing here re-dispatches calls of its own.
//
// These arms observe the SEAM, not the wire. A server that binds no verified
// runtime registers `execute_code` on no endpoint and refuses a direct call with
// `code_host_unbound`, so nothing below is reachable from a client on an
// unconfigured server; the host is entered here directly, with a fixture
// provider this test supplies. The production provider binding and the engine's
// settlement door are covered separately, not by these seam arms.
// ════════════════════════════════════════════════════════════════════════

/// What the fixture sandbox/REPL runtime actually observed.
#[derive(Default)]
struct OracleRuntimeWitness {
    /// Times the executor ENTERED the runtime.
    entered: AtomicUsize,
    /// `self.*` calls the runtime pushed through the host bridge.
    host_calls: AtomicUsize,
}

/// A fixture backend that always answers with the same plain-JS step.
struct OracleCodeBackend;

impl LlmBackend for OracleCodeBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: "const found = await self.memory.search(\"board\");".to_owned(),
                    }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
            })
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        unimplemented!("the oracle fixture never streams")
    }
}

/// The fixture guest component. Reaching it proves the gateway path entered a
/// RUNTIME; its `self.*` calls prove that runtime entered `HostSelfDispatcher`.
struct OracleCodeRuntime {
    witness: Arc<OracleRuntimeWitness>,
}

impl JsCodeModeRuntime for OracleCodeRuntime {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> oneiron::Result<JsCodeModeStepOutcome> {
        self.witness.entered.fetch_add(1, Ordering::SeqCst);
        host.dispatch_self(SelfCall::MemorySearch(SelfMemorySearchCall::new(
            "board", 4,
        )))?;
        self.witness.host_calls.fetch_add(1, Ordering::SeqCst);
        host.dispatch_self(SelfCall::OutboundFixture(SelfFixtureEffectCall::new(
            "oracle outbound effect",
        )))?;
        self.witness.host_calls.fetch_add(1, Ordering::SeqCst);
        Ok(JsCodeModeStepOutcome::pending(
            "parked on an outbound effect",
        ))
    }
}

struct OracleCodeProvider {
    backend: OracleCodeBackend,
    lease: BudgetLease,
    witness: Arc<OracleRuntimeWitness>,
}

impl McpCodeModeProvider for OracleCodeProvider {
    fn backend(&self) -> &dyn LlmBackend {
        &self.backend
    }

    fn lease(&self) -> &BudgetLease {
        &self.lease
    }

    fn runtime(&self) -> Box<dyn JsCodeModeRuntime + Send> {
        Box::new(OracleCodeRuntime {
            witness: Arc::clone(&self.witness),
        })
    }

    fn executor_config(&self, run_id: EntityId, task: &str) -> EngineExecutorConfig {
        EngineExecutorConfig {
            run_id,
            task: task.to_owned(),
            // ONE-1929: the executor wire teaching comes from the DEPLOYED
            // prompt package, so every run input must carry its root.
            prompt_package_root: oneiron::prompt::workspace_test_prompt_package_root()
                .expect("workspace test prompt package"),
            model: ModelId::new("fixture/executor@v1").expect("fixture model id"),
            model_locality: ModelLocality::OnDevice,
            seat_effort: None,
            global_tier: ModelTierRef("fixture-tier".to_owned()),
            determinism: CodeRunDeterminism::new(1_000, [7; CODE_RUN_RNG_SEED_LEN]),
            limits: EngineExecutorLimits::default(),
        }
    }
}

/// What ONE durable run through the injected host produced, plus the re-entry
/// that proves the wait is PERSISTED rather than ephemeral.
///
/// Persistence is all it proves: re-entry returns the same stored terminal
/// marker without running another step. Settling a wait and continuing past it
/// is an engine door this release does not have, and no arm here claims one.
struct InjectedHostRun {
    runtime_entries: usize,
    host_dispatched_calls: usize,
    persisted_bridge_calls: usize,
    status: EngineExecutorStatus,
    resumed_status: EngineExecutorStatus,
    resumed_steps_run: u32,
    run_id: EntityId,
}

fn oracle_resolved_actor(actor_ref: EntityId) -> McpResolvedActor {
    // The injected host is a trusted embedding seam, not network admission.
    // Resolve its actor through the public registry; no read proof is forged.
    let mut registry = oneiron_server::mcp::McpConnectorActorRegistry::new(
        oneiron_server::mcp::McpCredentialHashKey::from_bytes([0x41; 32]),
    );
    registry
        .register(
            "oracle-injected-host",
            oneiron_server::mcp::McpConnectorActorRecord::new(
                actor_ref,
                EdgeActorClass::Agent,
                McpConnectorScope::vault_wide(),
            ),
        )
        .expect("register actor");
    registry
        .resolve("oracle-injected-host", 1, |class, id| {
            class == "agent" && id == actor_ref.to_hex()
        })
        .expect("resolve registered actor")
}

/// Runs `execute_code` twice under ONE run handle through the SHIPPED injected
/// host adapter.
async fn injected_host_execute_code() -> InjectedHostRun {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Arc::new(Vault::open(dir.path(), oracle_vault_config()).expect("vault opens"));
    let actor_ref = oracle_id(0x01);
    vault
        .put_entity(
            &actor_ref,
            ENTITY_TYPE_MACHINE,
            TimeRange { start: 1, end: 1 },
            1,
            b"mcp oracle connector actor",
        )
        .expect("actor entity lands");

    let resolved = oracle_resolved_actor(actor_ref);
    let witness = Arc::new(OracleRuntimeWitness::default());
    let provider = Arc::new(OracleCodeProvider {
        backend: OracleCodeBackend,
        lease: BudgetLease::for_test("mcp-oracle-execute-code"),
        witness: Arc::clone(&witness),
    });
    let host = McpEngineNativeCodeHost::new(provider);

    let run_ref = "oracle-run";
    let run_id = mcp_code_run_id(run_ref, &resolved);
    let task = "search the board, then park an outbound effect";

    let first = host
        .execute(McpCodeExecutionRequest {
            vault: Arc::clone(&vault),
            actor: &resolved,
            run_ref,
            task,
            run_id,
        })
        .await
        .expect("the durable run enters");
    // The SAME handle re-enters the SAME persisted run rather than starting a
    // second one. That is persistence, not settlement: the stored wait comes
    // back unchanged because nothing in this release can settle it.
    let resumed = host
        .execute(McpCodeExecutionRequest {
            vault: Arc::clone(&vault),
            actor: &resolved,
            run_ref,
            task,
            run_id,
        })
        .await
        .expect("the persisted run re-enters");

    InjectedHostRun {
        runtime_entries: witness.entered.load(Ordering::SeqCst),
        host_dispatched_calls: witness.host_calls.load(Ordering::SeqCst),
        persisted_bridge_calls: first.replay_record.bridge_calls.len(),
        status: first.status,
        resumed_status: resumed.status,
        resumed_steps_run: resumed.steps_run,
        run_id,
    }
}

/// ONE-1704 M2: the INJECTED host's runtime is entered, that runtime reaches
/// `HostSelfDispatcher`, and a `Waiting` result is PERSISTED behind a derived
/// run handle that re-entering returns unchanged.
#[tokio::test]
async fn execute_code_enters_injected_host_runtime() {
    let run = injected_host_execute_code().await;

    // The gateway's substrate is a RUNTIME, entered once, and every `self.*`
    // call it made landed on the host bridge and in the durable replay log.
    assert_eq!(run.runtime_entries, 1);
    assert_eq!(run.host_dispatched_calls, 2);
    assert_eq!(
        run.persisted_bridge_calls, 2,
        "every bridge call is recorded by the engine, not by this test"
    );

    // A parked effect is a typed durable wait, never flattened into an error.
    let EngineExecutorStatus::Waiting(waiting) = &run.status else {
        panic!("a parked effect must stay Waiting, got {:?}", run.status);
    };
    assert_eq!(waiting.effect.as_str(), "self.fixture.outbound");

    // Persistence: the same handle re-enters the SAME stored run and returns
    // the SAME wait id without running another step. An ephemeral, per-call
    // wait id could not do this. It is not a settlement door, and this release
    // publishes no advancement claim built on it.
    assert_eq!(run.resumed_steps_run, 0);
    let EngineExecutorStatus::Waiting(resumed) = &run.resumed_status else {
        panic!(
            "re-entering the handle must return the persisted wait, got {:?}",
            run.resumed_status
        );
    };
    assert_eq!(waiting.wait_id, resumed.wait_id);
    assert_eq!(waiting.reason, resumed.reason);
    assert_eq!(run.run_id.to_hex().len(), 32);
}
