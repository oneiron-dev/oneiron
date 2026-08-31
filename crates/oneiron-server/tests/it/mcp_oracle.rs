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
    /// Primary MCP surface observations.
    struct McpPrimarySurface {
        /// Tool names on the PRIMARY surface, sorted.
        tools: Vec<String>,
        /// True iff setup_oneiron() returns a board keyframe.
        setup_returns_board_keyframe: bool,
        /// True iff setup_oneiron() returns the typed verb grammar.
        setup_returns_verb_grammar: bool,
        /// True iff setup_oneiron() returns the instructions payload
        /// (ticket AC: "board keyframe + verb grammar + instructions
        /// payload" — F17 setup half).
        setup_returns_instructions: bool,
        /// True iff execute_code() reaches the code-mode REPL/self.oneiron.
        execute_code_reaches_repl: bool,
    }

    /// ONE-1704 fixture: enumerate the primary MCP surface and call both
    /// tools once against a small vault.
    fn arm_mcp_primary_surface() -> McpPrimarySurface {
        let surface =
            oneiron_server::mcp::registered_surface(oneiron_server::mcp::McpSurfaceMode::Primary);
        let mut tools = surface
            .tool_names()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        tools.sort();

        // setup_oneiron: the shipped assembly, over the same section producers
        // the gateway renders from.
        let payload = super::setup_payload_over_a_small_vault();
        let value = payload.to_value();
        let setup_returns_board_keyframe = !payload.board.text.is_empty()
            && value["board"]["keyframe"].is_string()
            && value["board"]["render"]["floor_exceeds_cap"].is_boolean();
        let setup_returns_verb_grammar = !payload.verb_grammar.is_empty()
            && value["verb_grammar"]["verbs"]
                .as_array()
                .is_some_and(|verbs| verbs.len() == payload.verb_grammar.len());
        let setup_returns_instructions = value["instructions"]
            .as_str()
            .is_some_and(|text| !text.trim().is_empty());

        McpPrimarySurface {
            tools,
            setup_returns_board_keyframe,
            setup_returns_verb_grammar,
            setup_returns_instructions,
            execute_code_reaches_repl: super::execute_code_reaches_the_gated_repl(),
        }
    }

    /// ONE-1704 · 08b §6 (r3v2): the PRIMARY MCP surface is exactly two
    /// tools — setup_oneiron() and execute_code(); setup returns all three
    /// payload parts.
    #[test]
    fn mcp_primary_surface_is_exactly_two_tools() {
        let surface = arm_mcp_primary_surface();
        assert_eq!(surface.tools.len(), 2);
        assert_eq!(surface.tools, ["execute_code", "setup_oneiron"]);
        assert!(surface.setup_returns_board_keyframe);
        assert!(surface.setup_returns_verb_grammar);
        assert!(surface.setup_returns_instructions);
        assert!(surface.execute_code_reaches_repl);
    }

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
    /// `BOARD_VERBS ∪ TASKS_VERBS` (four plus five), read straight off the
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
        // restated: `BOARD_VERBS` (four) plus `TASKS_VERBS` (five), sorted.
        let mut expected = oneiron::board_verb::BOARD_VERBS
            .iter()
            .chain(oneiron::task_verb::TASKS_VERBS.iter())
            .map(|verb| (*verb).to_owned())
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(expected.len(), 9);
        assert_eq!(variant.verb_table, expected);
        assert_eq!(variant.generated_tool_names, expected);
        assert_eq!(variant.hand_written_tools, 0);
    }

    /// Packaging-ladder observations.
    struct PackagingLadder {
        /// Self-routing lanes the agent skill opens with.
        skill_lanes: usize,
        lane_code_mode_repl: bool,
        lane_thin_client: bool,
        lane_curl_cli: bool,
        lane_tool_first_mcp: bool,
        /// True iff a fat autogen SDK ships anywhere (must not).
        fat_autogen_sdk_shipped: bool,
        /// Distinct thin-client artifacts shipped (ticket: "ONE thin
        /// hand-rolled typed client … SAME artifact" — must be exactly 1;
        /// three independent clients must fail; F18).
        distinct_thin_client_artifacts: usize,
        /// Consumers importing THAT SAME artifact (code-mode inject, native
        /// app, npm-capable BYOA).
        consumers_importing_same_artifact: usize,
        /// True iff the thin client passes raw responses through
        /// (ticket AC: "raw-response passthrough").
        thin_client_raw_response_passthrough: bool,
        /// True iff the thin client is an autogenerated artifact (ticket:
        /// hand-rolled — must be false).
        thin_client_autogenerated: bool,
    }

    /// ONE-1705 fixture: inspect the shipped packaging artifacts — skill
    /// routing tree, thin CLI, thin typed client manifest + its consumer
    /// import table.
    fn arm_packaging_ladder() -> PackagingLadder {
        unimplemented!("armed by ONE-1705: skill + thin CLI + ONE thin typed client")
    }

    /// ONE-1705 · 08b §6 (r3v2): choose-your-own-adventure skill with four
    /// lanes; ONE hand-rolled thin client (raw-response passthrough) — the
    /// SAME artifact imported by three consumers; fat SDK never.
    #[test]
    #[ignore = "armed by ONE-1705"]
    fn packaging_ladder_four_lanes_one_thin_client_no_fat_sdk() {
        let ladder = arm_packaging_ladder();
        assert_eq!(ladder.skill_lanes, 4);
        assert!(ladder.lane_code_mode_repl);
        assert!(ladder.lane_thin_client);
        assert!(ladder.lane_curl_cli);
        assert!(ladder.lane_tool_first_mcp);
        assert!(!ladder.fat_autogen_sdk_shipped);
        assert_eq!(ladder.distinct_thin_client_artifacts, 1);
        assert_eq!(ladder.consumers_importing_same_artifact, 3);
        assert!(ladder.thin_client_raw_response_passthrough);
        assert!(!ladder.thin_client_autogenerated);
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
use oneiron::context_board::{
    BoardBlockHeader, BoardBudgetRequest, StreamConnectionId, SubscriptionScope,
    assemble_task_agent_sections, render_agents_section, render_tasks_section,
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
    MCP_BOARD_BUDGET_TOK, McpCodeExecutionHost, McpCodeExecutionRequest, McpCodeModeProvider,
    McpConnectorScope, McpEngineNativeCodeHost, McpResolvedActor, McpSetupPayload,
    generated_verb_tools, mcp_code_run_id, mcp_setup_payload, mcp_verb_board_section,
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

/// The EXACT `setup_oneiron` assembly the gateway runs, over a small board:
/// the pinned VERBS section plus the engine's own TASKS/AGENTS producers.
fn setup_payload_over_a_small_vault() -> McpSetupPayload {
    let verbs = generated_verb_tools().expect("exported verb rows project onto tools");
    let verb_section = mcp_verb_board_section(&verbs).expect("VERBS section is valid");
    let tasks = render_tasks_section(&[], &[]);
    let agents = render_agents_section(&[], &[]);
    let [tasks_section, agents_section] =
        assemble_task_agent_sections(&tasks, &agents).expect("board sections assemble");
    let header = BoardBlockHeader {
        epoch: 47,
        scope: "VaultWide".to_owned(),
    };
    mcp_setup_payload(
        &header,
        &[verb_section, tasks_section, agents_section],
        BoardBudgetRequest {
            harness_default_tok: MCP_BOARD_BUDGET_TOK,
            caller_limit_tok: None,
            explicit_override_tok: None,
        },
    )
    .expect("setup payload assembles")
}

// ════════════════════════════════════════════════════════════════════════
// ONE-1704 M2 — the INJECTED execute_code host
//
// The core crate ships no production `JsCodeModeRuntime`, so the provider is a
// fixture and the ADAPTER under observation is the shipped one: it constructs
// `HostSelfDispatcher`/`GatedActorWrite` and enters the sandbox/REPL through
// `EngineNativeExecutor`. Nothing here re-dispatches calls of its own.
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
        host.dispatch_self(SelfCall::MemorySearch(SelfMemorySearchCall::new("board", 4)))?;
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
            model: ModelId::new("fixture/executor@v1").expect("fixture model id"),
            model_locality: ModelLocality::OnDevice,
            global_tier: ModelTierRef("fixture-tier".to_owned()),
            determinism: CodeRunDeterminism::new(1_000, [7; CODE_RUN_RNG_SEED_LEN]),
            limits: EngineExecutorLimits::default(),
        }
    }
}

/// What ONE durable run through the injected host produced, plus the re-entry
/// that proves the wait is persisted rather than ephemeral.
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
    McpResolvedActor {
        actor_ref,
        actor_class: EdgeActorClass::Agent,
        gate_actor_class: EdgeActorClass::Agent.gate_actor_class(),
        gate_actor_ref: actor_ref.to_hex(),
        scope: McpConnectorScope::vault_wide(),
        stream_connection: StreamConnectionId("mcp-connector:oracle".to_owned()),
        bound_verbs: None,
        subscription_ceiling: SubscriptionScope::ALL.into_iter().collect(),
    }
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
    // The SAME handle re-enters the SAME persisted run: this is the resume
    // door, not a second run.
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

/// True iff `execute_code` reaches the code-mode REPL through the injected
/// host — the runtime AND `HostSelfDispatcher` — and iff a parked effect comes
/// back as a typed, PERSISTED durable wait rather than an error.
fn execute_code_reaches_the_gated_repl() -> bool {
    let reactor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("oracle reactor builds");
    let run = reactor.block_on(injected_host_execute_code());
    run.runtime_entries == 1
        && run.host_dispatched_calls == 2
        && run.persisted_bridge_calls == 2
        && matches!(run.status, EngineExecutorStatus::Waiting(_))
        && run.resumed_steps_run == 0
}

/// ONE-1704 M2: `execute_code` enters the INJECTED host's runtime, that runtime
/// reaches `HostSelfDispatcher`, and a `Waiting` result is persisted behind a
/// derived run handle that re-entering actually resumes.
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

    // The resume door: the same handle re-enters the SAME persisted run and
    // returns the SAME wait id without running another step. An ephemeral,
    // per-call wait id could not do this.
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
