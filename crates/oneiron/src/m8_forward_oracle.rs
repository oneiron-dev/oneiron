//! M8 forward test oracle — authored by the path opener (ONE-1685) for the
//! M8-A / M8-B remainder tickets. CONTRACT-level red tests, each behind
//! `#[ignore = "armed by ONE-XXXX"]`.
//!
//! Arming protocol (owner path-opener pattern): the arming ticket removes
//! the `#[ignore]`, adapts SIGNATURES (including replacing the
//! `unimplemented!()` ARMING-SEAM helpers below with the real engine
//! surfaces), and NEVER weakens an assert. Count-asserts throughout —
//! never `any()`.
//!
//! Seam classes used here, thinnest-first:
//! * real shipped surfaces whose current behavior is measurably wrong
//!   (e.g. the argument-blind grant scope, the unfenced summary write);
//! * local ARMING-SEAM stubs where the surface does not exist at all
//!   (external-MCP door, intent ledger) — they compile, and panic red the
//!   moment the test is armed, so the contract can never silently rot.
//!
//! Armed-ticket-owned axes (no contract-level oracle is expressible today;
//! proving each is the ARMING ticket's job, not a stub test's):
//! * ONE-1687: creation-time SYNC suppression of a fenced summary — the
//!   sync queue has no per-entity write feed to count yet;
//! * ONE-1690: the stdio child's OS sandbox (env/FD/fs allowlist);
//! * ONE-1690: destination TLS-verify + the human-shown resolved endpoint;
//! * ONE-1690: identity-PIN (deferred by the ticket itself — a
//!   registry-rebind needs a compromised host, outside the gate's threat
//!   model).

use std::collections::BTreeSet;
use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope, encode_agent_definition};
use crate::anchored_annotation::{Anchor, Locator, ThreadState};
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::config::VaultConfig;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::off_record::OffRecordBackendClass;
use crate::outbound_consent::{
    DataClass, FrozenMcpPayload, OutboundBindingAuthority, OutboundResultSender,
    OutboundTransportResult, RawOutboundResult, ScopedMcpCall as EngineScopedMcpCall,
    ScopedMcpCallContext, evaluate_scoped_mcp_calls as evaluate_engine_scoped_mcp_calls,
    execute_scoped_mcp_outbound_call,
};
use crate::outbound_grant::{ScopedMcpGrantMintIntent, StandingOutboundGrantScope};
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, OutboundSendOutcome, OutboundToolDescriptor,
};
use crate::pipeline::{DreamerWorkingSetBudget, DreamerWorkingSetCursor};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
use crate::temporal::TimeRange;
use crate::test_util::open_test_vault_with;
use crate::write_envelope::WriteActor;

fn open_vault() -> (tempfile::TempDir, Vault) {
    open_test_vault_with(VaultConfig::device())
}

fn t(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn empty_map_body() -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &Value::Map(Vec::new())).expect("encode empty map");
    body
}

fn person_actor(vault: &Vault, seed: u8, class: EdgeActorClass) -> WriteActor {
    let id = EntityId::from_bytes([seed; 16]).expect("actor id");
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, t(1), 1, b"oracle actor")
        .expect("put actor");
    WriteActor::new(id, class)
}

// ═══════════════════════════════════════════════════════════════════════
// ONE-1687 — [RT-05] per-agent compaction
// ═══════════════════════════════════════════════════════════════════════

fn minimal_agent_definition() -> AgentDefinition {
    AgentDefinition::new(
        "oracle-compaction-agent",
        "M8 oracle fixture",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::Imported,
        1.0,
        false,
        true,
        Value::Map(Vec::new()),
    )
}

/// The profile facts RT-05 pins. Field NAMES stay armer-owned — these are
/// accessor stubs over the seam, not literal record keys.
struct MemoryProfileFacts {
    /// The context-window token budget, LIFTED from `context_pack`.
    window_token_budget: u64,
    /// Dreamer ALWAYS owns MEMORY consolidation (the moat) — never the
    /// execution owner.
    dreamer_owns_memory_consolidation: bool,
    /// Ownership discriminant: first-party code mode vs a BYOA harness —
    /// whoever OWNS execution self-compacts its own window, and only that
    /// owner (never double-compacted).
    window_owner_is_first_party: bool,
    /// The pluggable cheap compaction backend named in the profile.
    compaction_backend: String,
    /// Frontier tiers are banned as compaction backends (cheap by design).
    compaction_backend_is_frontier_tier: bool,
}

/// ARMING SEAM (ONE-1687): read the memory profile off the agent
/// definition record through its accessors.
fn memory_profile_facts(_vault: &Vault, _def: &AgentDefinition) -> MemoryProfileFacts {
    unimplemented!(
        "ONE-1687 arming seam: AgentDefinition.memoryProfile accessors \
         (window budget + compaction ownership + compaction_backend)"
    )
}

/// ARMING SEAM (ONE-1687): the `context_pack` token budget the profile's
/// window budget is LIFTED from — read from the config store, so the
/// equality assert below is a real cross-read, not an echo of the profile.
fn context_pack_window_token_budget(_vault: &Vault) -> u64 {
    unimplemented!("ONE-1687 arming seam: the lifted context_pack token budget")
}

/// RT-05: the consolidation-vs-compaction ownership split is observable
/// per agent — `context_pack`'s token budget and the compaction ownership
/// (Dreamer always owns MEMORY consolidation; the execution owner
/// self-compacts its own WINDOW, never double-compacted) lift onto
/// `AgentDefinition.memoryProfile`, with the pluggable cheap
/// `compaction_backend` named inside it.
#[test]
#[ignore = "armed by ONE-1687"]
fn one_1687_memory_profile_rides_the_agent_definition_record() {
    let (_dir, vault) = open_vault();
    let definition = minimal_agent_definition();
    let body = encode_agent_definition(&definition).expect("encode agent def");
    let value = rmpv::decode::read_value(&mut Cursor::new(&body[..])).expect("decode body");
    let Value::Map(entries) = value else {
        panic!("agent definition body must be a MessagePack map");
    };
    let memory_profile_keys = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some("memory_profile"))
        .count();
    assert_eq!(
        memory_profile_keys, 1,
        "the AgentDefinition record carries exactly one memory_profile \
         (window budget + compaction ownership + compaction_backend)"
    );

    // The NAMED components (C17/G4): a dummy "memory_profile" key cannot
    // pass — the budget must be nonzero AND equal the context_pack config
    // it lifts from, both ownership discriminants must be observable, and
    // the backend must be a named non-frontier model.
    let facts = memory_profile_facts(&vault, &definition);
    assert_ne!(facts.window_token_budget, 0, "a real window budget");
    assert_eq!(
        facts.window_token_budget,
        context_pack_window_token_budget(&vault),
        "LIFTED from context_pack: equal to the config it came from"
    );
    assert!(
        facts.dreamer_owns_memory_consolidation,
        "MEMORY consolidation is the Dreamer's, always"
    );
    assert!(
        facts.window_owner_is_first_party,
        "this fixture is first-party code mode; a BYOA harness flips the discriminant"
    );
    assert!(
        !facts.compaction_backend.is_empty(),
        "the cheap compaction backend is NAMED in the profile"
    );
    assert!(
        !facts.compaction_backend_is_frontier_tier,
        "compaction is cheap by design — never a frontier tier"
    );
}

/// Read-path probe (mirrors the wave-1 fence tests' `surfaced_turns`):
/// SUMMARY ids the retrieval pipeline surfaces in the fixture window.
fn surfaced_summary_ids(vault: &Vault) -> Vec<EntityId> {
    vault
        .query()
        .search_temporal(150, 260, 16)
        .filter_types(&[ENTITY_TYPE_SUMMARY])
        .limit(16)
        .run()
        .expect("pipeline run")
        .into_iter()
        .map(|scored| scored.id)
        .collect()
}

/// Index-path probe (mirrors the wave-1 fence tests'
/// `dreamer_working_set_turns`): SUMMARY ids the dreamer working set
/// admits in the fixture window.
fn working_set_summary_ids(vault: &Vault) -> Vec<EntityId> {
    vault
        .query()
        .search_temporal(150, 260, 16)
        .filter_types(&[ENTITY_TYPE_SUMMARY])
        .run_dreamer_working_set(
            DreamerWorkingSetCursor::start(),
            DreamerWorkingSetBudget::new(16),
            16,
        )
        .expect("dreamer working set")
        .rows
        .into_iter()
        .map(|scored| scored.id)
        .collect()
}

/// RT-05 HARDENING (H-S3): a SUMMARY compacted from a FENCED (off-record)
/// window is fenced AT CREATION — live quarantine (suppressed from read /
/// index; creation-time SYNC suppression is armed-ticket-owned, see the
/// module doc) while the session is still open — not merely swept at
/// close. The quarantine is asserted through the REAL wave-1 fence
/// surfaces, with an unfenced control summary proving each probe is live.
#[test]
#[ignore = "armed by ONE-1687"]
fn one_1687_summary_compacted_from_a_fenced_window_is_fenced_at_creation() {
    let (_dir, vault) = open_vault();
    vault
        .enter_off_record_session("oracle-1687", OffRecordBackendClass::Local)
        .expect("enter off-record");

    let turn = EntityId::now();
    vault
        .put_entity(&turn, ENTITY_TYPE_TURN, t(100), 100, &empty_map_body())
        .expect("put fenced turn");
    vault
        .tag_turn_off_record("oracle-1687", &turn)
        .expect("tag turn");
    assert!(
        vault.is_turn_off_record_fenced(&turn).expect("fence read"),
        "scenario sanity: the compaction window IS fenced"
    );

    // The compaction write: a SUMMARY derived from the fenced window.
    let summary = EntityId::now();
    vault
        .batch()
        .put(
            &summary,
            ENTITY_TYPE_SUMMARY,
            t(200),
            200,
            &empty_map_body(),
        )
        .edge(&summary, EdgeKind::DerivedFrom, &turn, 1.0)
        .commit()
        .expect("compaction summary write");
    // Control: an ordinary summary in the same window, NOT derived from
    // the fenced turn — it must keep surfacing everywhere.
    let control = EntityId::now();
    vault
        .put_entity(
            &control,
            ENTITY_TYPE_SUMMARY,
            t(210),
            210,
            &empty_map_body(),
        )
        .expect("put control summary");

    // CONTRACT: fenced the moment it exists — the session is still OPEN,
    // so delete-at-close cannot be what protects it.
    assert!(
        vault
            .is_turn_off_record_fenced(&summary)
            .expect("fence read"),
        "a summary compacted from a fenced window must be fenced AT CREATION"
    );

    // LIVE quarantine, not just the bit: the read path returns 0 rows for
    // the quarantined summary while the control surfaces (probe is live).
    let surfaced = surfaced_summary_ids(&vault);
    assert_eq!(
        surfaced.iter().filter(|id| **id == summary).count(),
        0,
        "read path returns 0 rows for the quarantined summary"
    );
    assert_eq!(
        surfaced.iter().filter(|id| **id == control).count(),
        1,
        "the unfenced control summary surfaces — the read probe is not vacuous"
    );

    // Index / working-set surface: same shape, same counts.
    let working_set = working_set_summary_ids(&vault);
    assert_eq!(
        working_set.iter().filter(|id| **id == summary).count(),
        0,
        "the dreamer working set admits 0 rows for the quarantined summary"
    );
    assert_eq!(
        working_set.iter().filter(|id| **id == control).count(),
        1,
        "the unfenced control summary is admitted — the index probe is not vacuous"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// ONE-1689 — [RT-08] collaborative-doc / RLM layer
// ═══════════════════════════════════════════════════════════════════════

/// Puts a versioned office artifact so annotation threads can open on it
/// with today's API (mirrors `anchored_annotation::tests::put_workbook`).
fn put_workbook(vault: &Vault, actor: WriteActor, at: u64) -> EntityId {
    let artifact_id = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact_id,
            &BlobArtifactBody::new(
                "plan.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ),
            t(at),
            at,
        )
        .expect("put workbook");
    vault
        .append_blob_artifact_version(
            &artifact_id,
            b"workbook bytes v1",
            &BlobVersionProvenance::UserUpload,
            actor,
            t(at),
            at,
        )
        .expect("append v1");
    artifact_id
}

fn xlsx_anchor(artifact_id: EntityId, version: u64) -> Anchor {
    Anchor::new(
        artifact_id,
        version,
        Locator::xlsx("Sheet1", "B2").expect("xlsx locator"),
    )
}

/// ARMING SEAM (ONE-1689): wire an anchored thread to an ARCH-0006a
/// conversation-DAG node (fork/HEAD mechanics stay armer-owned — the
/// WIRING is the contract this oracle pins).
fn wire_thread_to_conversation_dag_node(
    _vault: &Vault,
    _artifact: &EntityId,
    _thread_id: &EntityId,
    _node: &EntityId,
) {
    unimplemented!("ONE-1689 arming seam: OF-368 ↔ conversation-DAG composition (wire)")
}

/// ARMING SEAM (ONE-1689): resolve the conversation-DAG node an anchored
/// thread is wired to.
fn thread_conversation_dag_node(
    _vault: &Vault,
    _artifact: &EntityId,
    _thread_id: &EntityId,
) -> EntityId {
    unimplemented!("ONE-1689 arming seam: OF-368 ↔ conversation-DAG composition (resolve)")
}

/// RT-08: branching opens an ANCHORED thread on the built
/// anchored_annotation ARTIFACT and WIRES it to an ARCH-0006a
/// conversation-DAG node — the OF-368 ↔ conversation-DAG composition. The
/// DAG node is the wiring target, never the anchoring surface (documents
/// anchor threads; conversations fork from them).
#[test]
#[ignore = "armed by ONE-1689"]
fn one_1689_annotation_thread_anchors_to_a_conversation_dag_node() {
    let (_dir, vault) = open_vault();
    let human = person_actor(&vault, 0x31, EdgeActorClass::Human);
    let artifact = put_workbook(&vault, human, 100);

    // The conversation-DAG node this branch forks from.
    let node = EntityId::now();
    vault
        .put_entity(&node, ENTITY_TYPE_TURN, t(150), 150, &empty_map_body())
        .expect("put conversation-DAG node");

    let thread = vault
        .open_annotation_thread(
            &xlsx_anchor(artifact, 1),
            human,
            "fork the plan here",
            t(200),
            200,
        )
        .expect("open thread on the artifact");
    assert_eq!(
        vault
            .annotation_threads_for_artifact(&artifact)
            .expect("threads on the artifact")
            .len(),
        1,
        "exactly one thread anchored on the artifact"
    );

    wire_thread_to_conversation_dag_node(&vault, &artifact, &thread.thread_id, &node);
    assert_eq!(
        thread_conversation_dag_node(&vault, &artifact, &thread.thread_id),
        node,
        "the thread's node linkage resolves to the wired conversation node"
    );
}

/// ARMING SEAM (ONE-1689): the ticket's exact intermediate state. The
/// arming ticket adds the variant (open → agent-replied → resolved) and
/// replaces this stub with it.
fn agent_replied_thread_state() -> ThreadState {
    unimplemented!("ONE-1689 arming seam: the agent-replied variant between Open and Resolved")
}

/// RT-08: the per-thread state machine is open → agent-replied → resolved.
/// An agent reply must advance the thread BEYOND `Open` without resolving
/// it — this pins the intermediate state's existence and entry without
/// naming the variant (signatures are the arming ticket's).
#[test]
#[ignore = "armed by ONE-1689"]
fn one_1689_agent_reply_advances_the_thread_state_beyond_open() {
    let (_dir, vault) = open_vault();
    let human = person_actor(&vault, 0x32, EdgeActorClass::Human);
    let agent = person_actor(&vault, 0x33, EdgeActorClass::Agent);
    let artifact = put_workbook(&vault, human, 100);

    let thread = vault
        .open_annotation_thread(
            &xlsx_anchor(artifact, 1),
            human,
            "please check B2",
            t(300),
            300,
        )
        .expect("open thread");
    assert_eq!(thread.state, ThreadState::Open);

    vault
        .add_annotation_comment(
            &artifact,
            &thread.thread_id,
            agent,
            "checked — the formula is fixed",
            t(400),
            400,
        )
        .expect("agent reply");

    let replied = vault
        .get_annotation_thread(&artifact, &thread.thread_id)
        .expect("read thread")
        .expect("thread exists");
    assert_ne!(
        replied.state,
        ThreadState::Open,
        "an agent reply must advance open → agent-replied"
    );
    assert_ne!(
        replied.state,
        ThreadState::Resolved,
        "an agent reply alone must NOT resolve — resolution stays human"
    );
    assert_eq!(
        replied.state,
        agent_replied_thread_state(),
        "the EXACT ticket state machine: open → agent-replied → resolved, \
         not any third state that happens to be neither Open nor Resolved"
    );

    let resolved = vault
        .set_annotation_thread_state(
            &artifact,
            &thread.thread_id,
            ThreadState::Resolved,
            human,
            t(500),
            500,
        )
        .expect("resolve");
    assert_eq!(resolved.state, ThreadState::Resolved);
}

/// RT-08: threads progress CONCURRENTLY, per-thread — the agent answers
/// thread A while the human still types in thread B; there is no one
/// global handoff. Linear chat is the degenerate case.
#[test]
#[ignore = "armed by ONE-1689"]
fn one_1689_threads_progress_per_thread_not_one_global_handoff() {
    let (_dir, vault) = open_vault();
    let human = person_actor(&vault, 0x34, EdgeActorClass::Human);
    let agent = person_actor(&vault, 0x35, EdgeActorClass::Agent);
    let artifact = put_workbook(&vault, human, 100);

    let thread_a = vault
        .open_annotation_thread(&xlsx_anchor(artifact, 1), human, "thread A", t(300), 300)
        .expect("open thread A");
    let thread_b = vault
        .open_annotation_thread(&xlsx_anchor(artifact, 1), human, "thread B", t(310), 310)
        .expect("open thread B");
    assert_eq!(
        vault
            .annotation_threads_for_artifact(&artifact)
            .expect("threads")
            .len(),
        2
    );

    vault
        .add_annotation_comment(
            &artifact,
            &thread_a.thread_id,
            agent,
            "answering A",
            t(400),
            400,
        )
        .expect("agent answers A");

    let a = vault
        .get_annotation_thread(&artifact, &thread_a.thread_id)
        .expect("read A")
        .expect("A exists");
    let b = vault
        .get_annotation_thread(&artifact, &thread_b.thread_id)
        .expect("read B")
        .expect("B exists");
    assert_ne!(a.state, ThreadState::Open, "A advanced by the agent reply");
    assert_eq!(
        a.state,
        agent_replied_thread_state(),
        "A sits in the exact agent-replied state"
    );
    assert_eq!(
        b.state,
        ThreadState::Open,
        "B untouched — no global handoff"
    );

    // B still accepts the human's typing while A sits agent-replied.
    vault
        .add_annotation_comment(
            &artifact,
            &thread_b.thread_id,
            human,
            "still typing in B",
            t(410),
            410,
        )
        .expect("human keeps typing in B");
    // Durable, not return-value: B re-read from the store stays Open.
    let b_after = vault
        .get_annotation_thread(&artifact, &thread_b.thread_id)
        .expect("re-read B")
        .expect("B exists");
    assert_eq!(
        b_after.state,
        ThreadState::Open,
        "the human's comment leaves B open in the STORE — per-thread progress only"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// ONE-1690 — [RT-09] external MCP via rmcp (SECURITY)
// ═══════════════════════════════════════════════════════════════════════

/// RT-09: the standing grant covering `self.mcp` calls is payload-aware —
/// it carries the (server, tool, data-class) axis. A scope WITHOUT that
/// axis must not cover an effectful MCP call. Red today: the shipped
/// channel scope matches on channel string + send-verb alone
/// (argument-blind `matches_effect`), which is exactly the verified hole.
#[test]
fn one_1690_argument_blind_scopes_must_not_cover_mcp_calls() {
    let scope = StandingOutboundGrantScope::Channel {
        channel: "mcp:calendar".to_owned(),
    };
    let covers = scope.matches_effect("send", "mcp:calendar", None, None);
    assert!(
        !covers,
        "an argument-blind grant scope must not cover an effectful MCP call — \
         the (server, tool, data-class) axis is required for auto-fire"
    );
}

/// The ticket's grant axes (ONE-1690): (server, tool, data-class) scope
/// plus the endpoint allowlist the human saw at grant time.
struct ScopedMcpGrant {
    server: &'static str,
    tool: &'static str,
    /// Highest data class the grant covers ("public" < "personal" < "secret").
    data_class_ceiling: &'static str,
    endpoint_allowlist: &'static [&'static str],
}

/// One `self.mcp` call as the automated per-call check sees it.
struct ScopedMcpCall {
    server: &'static str,
    tool: &'static str,
    payload_data_class: &'static str,
    resolved_endpoint: &'static str,
}

/// Per-batch verdict of the payload-aware scoped-grant check.
struct ScopedMcpVerdict {
    auto_fired: usize,
    human_escalations: usize,
}

/// ARMING SEAM (ONE-1690): evaluate `calls` against the standing SCOPED
/// grant — the payload-aware AUTOMATED per-call check (endpoint allowlist
/// + tool + data-class ceiling).
fn evaluate_scoped_mcp_calls(
    _vault: &Vault,
    grant: &ScopedMcpGrant,
    calls: &[ScopedMcpCall],
) -> ScopedMcpVerdict {
    let endpoint_allowlist = grant
        .endpoint_allowlist
        .iter()
        .map(|endpoint| (*endpoint).to_owned())
        .collect::<Vec<_>>();
    let scope = StandingOutboundGrantScope::ScopedMcp {
        server: grant.server.to_owned(),
        tool: grant.tool.to_owned(),
        data_class_ceiling: DataClass::parse(grant.data_class_ceiling),
        endpoint_allowlist,
    };
    let grant = scope.scoped_mcp_grant().expect("scoped fixture grant");
    let calls = calls
        .iter()
        .map(|call| EngineScopedMcpCall {
            server: call.server,
            tool: call.tool,
            payload_data_class: DataClass::parse(call.payload_data_class),
            resolved_endpoint: call.resolved_endpoint,
        })
        .collect::<Vec<_>>();
    let verdict = evaluate_engine_scoped_mcp_calls(grant, &calls);
    ScopedMcpVerdict {
        auto_fired: verdict.auto_fired,
        human_escalations: verdict.human_escalations,
    }
}

/// RT-09: a call INSIDE scope auto-fires with no human in the loop (auto
/// mode intact); a SCOPE-EXCEED — an off-allowlist endpoint or a payload
/// above the data-class ceiling — NEVER fires and escalates to a human.
/// The ticket states no escalation coalescing, so the escalation count is
/// pinned only as ≥ 1 (armer policy); the fire count is exactly 0.
#[test]
fn one_1690_in_scope_auto_fires_and_scope_exceeds_escalate_without_firing() {
    let (_dir, vault) = open_vault();
    let grant = ScopedMcpGrant {
        server: "files",
        tool: "read_file",
        data_class_ceiling: "personal",
        endpoint_allowlist: &["https://files.internal.example"],
    };
    let in_scope_call = || ScopedMcpCall {
        server: "files",
        tool: "read_file",
        payload_data_class: "personal",
        resolved_endpoint: "https://files.internal.example",
    };

    let in_scope = evaluate_scoped_mcp_calls(
        &vault,
        &grant,
        &[in_scope_call(), in_scope_call(), in_scope_call()],
    );
    assert_eq!(in_scope.auto_fired, 3, "inside scope every call auto-fires");
    assert_eq!(
        in_scope.human_escalations, 0,
        "inside scope there is NO human in the loop"
    );

    let off_allowlist = evaluate_scoped_mcp_calls(
        &vault,
        &grant,
        &[ScopedMcpCall {
            resolved_endpoint: "https://exfil.example",
            ..in_scope_call()
        }],
    );
    assert_eq!(
        off_allowlist.auto_fired, 0,
        "an off-allowlist endpoint never auto-fires"
    );
    assert!(
        off_allowlist.human_escalations >= 1,
        "an off-allowlist endpoint escalates to a human"
    );

    let secret_over_ceiling = evaluate_scoped_mcp_calls(
        &vault,
        &grant,
        &[ScopedMcpCall {
            payload_data_class: "secret",
            ..in_scope_call()
        }],
    );
    assert_eq!(
        secret_over_ceiling.auto_fired, 0,
        "a secret-tier payload under a personal ceiling never auto-fires"
    );
    assert!(
        secret_over_ceiling.human_escalations >= 1,
        "the data-class exceed escalates to a human"
    );

    let wrong_server = evaluate_scoped_mcp_calls(
        &vault,
        &grant,
        &[ScopedMcpCall {
            server: "calendar",
            ..in_scope_call()
        }],
    );
    assert_eq!(
        wrong_server.auto_fired, 0,
        "a grant for another server never auto-fires"
    );
    assert!(
        wrong_server.human_escalations >= 1,
        "a wrong-server call escalates to a human"
    );

    let wrong_tool = evaluate_scoped_mcp_calls(
        &vault,
        &grant,
        &[ScopedMcpCall {
            tool: "write_file",
            ..in_scope_call()
        }],
    );
    assert_eq!(
        wrong_tool.auto_fired, 0,
        "a grant for another tool never auto-fires"
    );
    assert!(
        wrong_tool.human_escalations >= 1,
        "a wrong-tool call escalates to a human"
    );
}

/// Byte-level trace of one consented effectful send.
struct EffectfulSendTrace {
    /// Effectful wire sends the drive performed — must be 1, or every
    /// other assert here is vacuous.
    effectful_sends: usize,
    /// Buffer FREEZE (serialization) events: exactly one, shared by check
    /// and send. A second event is the re-serialize TOCTOU sneaking back.
    freeze_events: usize,
    checked_bytes: Vec<u8>,
    sent_bytes: Vec<u8>,
    /// Scrubbable result fields the fixture seeded (body/error/stderr/URL).
    scrubbable_result_fields: usize,
    /// How many of those the fence actually scrubbed.
    scrubbed_result_fields: usize,
}

/// ARMING SEAM (ONE-1690): drive one effectful `self.mcp` call whose
/// result carries EXACTLY four scrubbable fields (body, error, stderr,
/// URL) and report the frozen-buffer + scrub trace.
#[derive(Default)]
struct OracleMcpResultSender {
    sent_bytes: Vec<Vec<u8>>,
}

impl OutboundResultSender for OracleMcpResultSender {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundTransportResult {
        self.sent_bytes.push(call.payload().to_vec());
        OutboundTransportResult {
            outcome: OutboundSendOutcome::Acked,
            raw_result: RawOutboundResult::new(
                Some(b"provider body".to_vec()),
                Some("provider error".to_owned()),
                Some(b"provider stderr".to_vec()),
                Some("https://provider.example/result".to_owned()),
            ),
        }
    }
}

fn trace_effectful_mcp_send(vault: &Vault) -> EffectfulSendTrace {
    let grant_id = EntityId::from_bytes([0x90; 16]).expect("grant id");
    let grant = vault
        .mint_scoped_mcp_outbound_grant(
            &grant_id,
            &ScopedMcpGrantMintIntent {
                principal_ref: "principal:oracle".to_owned(),
                origin_component_id: "consent:oracle".to_owned(),
                origin_action_id: "grant:oracle".to_owned(),
                origin_receipt_ref: Some("gate:oracle".to_owned()),
                server: "files".to_owned(),
                tool: "read_file".to_owned(),
                data_class_ceiling: DataClass::Personal,
                endpoint_allowlist: vec!["https://files.internal.example".to_owned()],
            },
            10,
        )
        .expect("mint oracle scoped grant");
    vault
        .register_connector_key(
            &EntityId::from_bytes([0x92; 16]).expect("connector key id"),
            crate::ConnectorKeyRecord::active(
                crate::gate::scoped_mcp_credential_connector_key("files", &grant_id),
                None,
                vec![crate::EffectorBudget::sends(
                    100,
                    crate::EffectorBudgetWindow::Calendar {
                        period: crate::CalendarPeriod::Day,
                        tz: None,
                    },
                    crate::EffectorBudgetOnExhaust::Refuse,
                )],
                10,
            ),
        )
        .expect("register active scoped connector key");
    let authority = OutboundBindingAuthority::for_vault(vault).expect("binding authority");
    let payload = b"{\"path\":\"calendar.txt\"}".to_vec();
    let mut sender = OracleMcpResultSender::default();
    let result = execute_scoped_mcp_outbound_call(
        vault,
        &authority,
        grant_id,
        &grant,
        &grant.principal_ref,
        OutboundToolDescriptor {
            read_only_hint: Some(false),
            idempotency_supported_hint: Some(true),
        },
        crate::attempt_queue::AttemptId::from_bytes(&[0x91; 16]).expect("attempt id"),
        1,
        ScopedMcpCallContext {
            server: "files".to_owned(),
            tool: "read_file".to_owned(),
            payload_data_class: DataClass::Personal,
            resolved_endpoint: "https://files.internal.example".to_owned(),
        },
        FrozenMcpPayload::new(payload),
        11,
        &mut sender,
    )
    .expect("effectful scoped send");
    EffectfulSendTrace {
        effectful_sends: result.effectful_sends,
        freeze_events: result.freeze_events,
        checked_bytes: result.checked_bytes().to_vec(),
        sent_bytes: sender.sent_bytes.into_iter().next().unwrap_or_default(),
        scrubbable_result_fields: result.scrubbable_result_fields,
        scrubbed_result_fields: result.scrubbed_result_fields,
    }
}

/// RT-09 R2: for EFFECTFUL calls the checked bytes ARE the sent bytes —
/// one frozen immutable buffer, ONE freeze event, no re-serialize between
/// check and send (no TOCTOU) — and every seeded result field is scrubbed,
/// not just headers. Non-vacuous by construction: the trace must show the
/// send happened and the buffer carries real bytes.
#[test]
fn one_1690_checked_bytes_equal_sent_bytes_and_results_are_fully_scrubbed() {
    let (_dir, vault) = open_vault();
    let trace = trace_effectful_mcp_send(&vault);
    assert_eq!(
        trace.effectful_sends, 1,
        "exactly one effectful send occurred — the trace is not vacuous"
    );
    assert_eq!(
        trace.freeze_events, 1,
        "ONE freeze: check and send share one serialization, never two"
    );
    assert!(
        !trace.sent_bytes.is_empty(),
        "the frozen buffer carries real bytes"
    );
    assert_eq!(
        trace.checked_bytes, trace.sent_bytes,
        "consent must bind the exact frozen bytes the wire carries"
    );
    assert_eq!(
        trace.scrubbable_result_fields, 4,
        "the fixture seeds exactly body, error, stderr, URL"
    );
    assert_eq!(
        trace.scrubbed_result_fields, 4,
        "ALL four result fields are scrubbed — zero escape"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// ONE-1691 — [RT-11] outbound INTENT ledger (SECURITY)
// ═══════════════════════════════════════════════════════════════════════

/// One durable intent row, RE-READ from the store after the drive — never
/// echoed from the driver's in-memory state.
struct IntentRow {
    id: String,
    server: String,
    tool: String,
    payload_hash: String,
    state: String,
    idempotency_key: String,
}

/// Ledger + transport observation for one driven effectful MCP call.
struct IntentLedgerTrace {
    /// Ordered observation log: `(event kind, idempotency key)` in the
    /// order events were OBSERVED. Kinds pinned by the asserts:
    /// "intent_journaled", "wire_send".
    events: Vec<(String, String)>,
    /// Intent rows observed durably BEFORE the send.
    rows_before_send: Vec<IntentRow>,
    /// Intent rows RE-READ from the store after the ack (or recovery).
    rows_after: Vec<IntentRow>,
    /// Idempotency key carried by each wire send, in order.
    transport_send_keys: Vec<String>,
    /// Server-side effects actually applied (the exactly-once observable).
    effects_applied: usize,
}

/// ARMING SEAM (ONE-1691): drive one EFFECTFUL `self.mcp` call
/// (send/post/charge/book class). With `crash_before_ack` the process
/// "crashes" after the wire send but before the DONE journal write, then
/// runs crash-recovery.
fn drive_effectful_mcp_call(_vault: &Vault, _crash_before_ack: bool) -> IntentLedgerTrace {
    unimplemented!(
        "ONE-1691 arming seam: durable INTENT{{id, server, tool, \
         payload_hash, state}} written BEFORE the rmcp send; DONE on ack; \
         crash-recovery walks PENDING rows"
    )
}

/// Trace of one READ-ONLY `self.mcp` call.
struct ReadOnlyCallTrace {
    /// Read-only calls the drive actually performed — 1, or the zero-rows
    /// assert below is vacuous.
    read_only_calls: usize,
    /// Intent-ledger rows those calls wrote.
    intent_rows: usize,
}

/// ARMING SEAM (ONE-1691): drive one READ-ONLY `self.mcp` call
/// (search/read/fetch class) and report the call + ledger trace.
fn drive_read_only_mcp_call(_vault: &Vault) -> ReadOnlyCallTrace {
    unimplemented!("ONE-1691 arming seam: read-only calls bypass the ledger")
}

/// Trace of one effectful call against a tool with NO idempotency support,
/// driven into an ambiguous (unacked) outcome.
struct AtMostOnceTrace {
    /// Ambiguous acks the fixture induced — 1, or the test is vacuous.
    ambiguous_acks: usize,
    wire_sends: usize,
    /// Automatic re-sends attempted after the ambiguity.
    auto_resends: usize,
    human_escalations: usize,
    /// Disposition the escalation carried to the human.
    escalated_disposition: Option<String>,
}

/// ARMING SEAM (ONE-1691): drive an effectful call against a tool with NO
/// idempotency support, inducing exactly one ambiguous (unacked) outcome.
fn drive_effectful_call_without_idempotency_support(_vault: &Vault) -> AtMostOnceTrace {
    unimplemented!("ONE-1691 arming seam: no-idempotency tools degrade to at-most-once")
}

/// Recovery/retry observation for a crash BEFORE the PENDING journal write.
struct CrashBeforeJournalTrace {
    /// Intent rows recovery found (the crash preceded the journal write).
    rows_after_recovery: usize,
    /// Wire sends RECOVERY performed on its own.
    recovery_wire_sends: usize,
    /// Wire sends the caller's explicit retry performed.
    retry_wire_sends: usize,
    /// Intent rows after the retry settled.
    rows_after_retry: usize,
}

/// ARMING SEAM (ONE-1691): "crash" BEFORE the durable PENDING write, run
/// crash-recovery, then let the caller retry the call.
fn drive_crash_before_intent_journal(_vault: &Vault) -> CrashBeforeJournalTrace {
    unimplemented!(
        "ONE-1691 arming seam: no journal row means recovery has nothing \
         to re-send; the caller's retry journals + sends exactly once"
    )
}

/// RT-11: the durable INTENT row (state PENDING, idempotency key already
/// minted) exists BEFORE the send — proven by OBSERVED event order, not a
/// self-reported flag — carries {id, server, tool, payload_hash, state},
/// and the ack flips it to DONE in the STORE (re-read, not returned). The
/// ledger doubles as the outbound audit receipt.
#[test]
#[ignore = "armed by ONE-1691"]
fn one_1691_intent_is_pending_before_send_and_done_on_ack() {
    let (_dir, vault) = open_vault();
    let trace = drive_effectful_mcp_call(&vault, false);

    assert_eq!(trace.rows_before_send.len(), 1, "exactly one intent row");
    let intent = &trace.rows_before_send[0];
    assert_eq!(
        intent.state, "pending",
        "the intent is journaled PENDING before the wire send"
    );
    let populated = [
        &intent.id,
        &intent.server,
        &intent.tool,
        &intent.payload_hash,
        &intent.state,
    ]
    .iter()
    .filter(|field| !field.is_empty())
    .count();
    assert_eq!(
        populated, 5,
        "the row carries id, server, tool, payload_hash, state — all populated"
    );

    assert_eq!(trace.transport_send_keys.len(), 1, "exactly one wire send");
    assert_eq!(
        intent.idempotency_key, trace.transport_send_keys[0],
        "the wire send carries the journaled idempotency key"
    );

    // ORDER is observed, not self-reported: exactly one journal event and
    // one send event, and the journal precedes the send in the trace.
    let journal_events = trace
        .events
        .iter()
        .filter(|(kind, _)| kind == "intent_journaled")
        .count();
    let send_events = trace
        .events
        .iter()
        .filter(|(kind, _)| kind == "wire_send")
        .count();
    assert_eq!(journal_events, 1);
    assert_eq!(send_events, 1);
    let journal_pos = trace
        .events
        .iter()
        .position(|(kind, _)| kind == "intent_journaled")
        .expect("journal event present");
    let send_pos = trace
        .events
        .iter()
        .position(|(kind, _)| kind == "wire_send")
        .expect("send event present");
    assert!(
        journal_pos < send_pos,
        "the intent-row write is OBSERVED before the wire send"
    );

    assert_eq!(trace.rows_after.len(), 1);
    assert_eq!(
        trace.rows_after[0].state, "done",
        "the RE-READ row shows the ack flipped PENDING → DONE"
    );
    assert_eq!(
        trace.rows_after[0].id, intent.id,
        "same durable row settled — not a second one"
    );
    assert_eq!(trace.effects_applied, 1);
}

/// RT-11: crash-recovery re-sends a PENDING intent with the SAME
/// idempotency key, so the server dedups — a crash-before-journal or an
/// identical-bytes replay cannot double-fire. Exactly-once is observable.
#[test]
#[ignore = "armed by ONE-1691"]
fn one_1691_crash_recovery_replays_with_the_same_key_exactly_once() {
    let (_dir, vault) = open_vault();
    let trace = drive_effectful_mcp_call(&vault, true);

    assert_eq!(
        trace.transport_send_keys.len(),
        2,
        "recovery re-sends the PENDING intent (crashed send + replay)"
    );
    let distinct_keys: BTreeSet<&String> = trace.transport_send_keys.iter().collect();
    assert_eq!(
        distinct_keys.len(),
        1,
        "the replay rides the SAME idempotency key — server-side dedupe"
    );
    assert_eq!(
        trace.effects_applied, 1,
        "exactly-once observable under simulated crash"
    );
    assert_eq!(trace.rows_after.len(), 1);
    assert_eq!(
        trace.rows_after[0].state, "done",
        "recovery settles the RE-READ row"
    );
}

/// RT-11: read-only calls (search/read/fetch) are replay-safe and carry
/// NO ledger machinery. Non-vacuous: the trace proves one read-only call
/// really ran.
#[test]
#[ignore = "armed by ONE-1691"]
fn one_1691_read_only_calls_are_unledgered() {
    let (_dir, vault) = open_vault();
    let trace = drive_read_only_mcp_call(&vault);
    assert_eq!(
        trace.read_only_calls, 1,
        "exactly one read-only call was performed — the zero below is earned"
    );
    assert_eq!(
        trace.intent_rows, 0,
        "read-only MCP calls write zero intent rows"
    );
}

/// RT-11: a tool with no idempotency support degrades to AT-MOST-ONCE —
/// exactly one induced ambiguous ack, exactly one wire send, ZERO
/// automatic re-sends, and exactly one human escalation carrying the
/// may-not-have-sent disposition.
#[test]
#[ignore = "armed by ONE-1691"]
fn one_1691_no_idempotency_support_degrades_to_at_most_once() {
    let (_dir, vault) = open_vault();
    let trace = drive_effectful_call_without_idempotency_support(&vault);
    assert_eq!(
        trace.ambiguous_acks, 1,
        "the fixture induced exactly one ambiguous ack — non-vacuous"
    );
    assert_eq!(
        trace.wire_sends, 1,
        "NO auto re-send on ambiguity — at-most-once"
    );
    assert_eq!(trace.auto_resends, 0, "zero automatic re-sends");
    assert_eq!(
        trace.human_escalations, 1,
        "the ambiguity escalates to a human exactly once"
    );
    assert_eq!(
        trace.escalated_disposition.as_deref(),
        Some("may not have sent"),
        "the escalation carries the may-not-have-sent disposition"
    );
}

/// RT-11 (G7): a crash BEFORE the PENDING journal write leaves recovery
/// with zero rows — recovery must send NOTHING on its own (the intent was
/// never durable; re-sending would forge one). The caller's retry then
/// produces exactly one send and one row.
#[test]
#[ignore = "armed by ONE-1691"]
fn one_1691_crash_before_journal_recovers_to_zero_sends_and_retry_sends_once() {
    let (_dir, vault) = open_vault();
    let trace = drive_crash_before_intent_journal(&vault);
    assert_eq!(
        trace.rows_after_recovery, 0,
        "no intent row survived the pre-journal crash"
    );
    assert_eq!(
        trace.recovery_wire_sends, 0,
        "recovery never sends without a durable intent"
    );
    assert_eq!(
        trace.retry_wire_sends, 1,
        "the caller's retry sends exactly once"
    );
    assert_eq!(trace.rows_after_retry, 1, "and journals exactly one row");
}
