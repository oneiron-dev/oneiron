//! Context Board forward test oracle — epic ONE-1692, opened by ONE-1693 (CB-01).
//!
//! Contract-level red tests for all four Context Board clusters, derived from
//! the ticket acceptance criteria (ONE-1694..ONE-1711) and the ratified design
//! `oneiron-v1/design/out/08b-Context-Board-extension.md` (16/16, 2026-07-15),
//! which extends `08-Memory-Board-design.md` (the board surface is renamed
//! Context Board; the Eiri v4 activated-memories tier keeps its names).
//!
//! Shape of every test:
//! * `#[ignore = "armed by ONE-XXXX"]` — dormant until its ticket lands.
//! * An `arm_*` seam function whose body is `unimplemented!()`. Its doc
//!   comment is the fixture spec. The ARMING ticket replaces the seam body
//!   (and may freely adapt the seam signature or move the test to the owning
//!   crate), then removes the `#[ignore]`.
//! * Asserts are the contract: exact counts and equalities, never `any()`.
//!   Arming NEVER weakens, loosens, or removes an assert.
//!
//! Observation structs are contract shapes, not API proposals — every field
//! is asserted by at least one test.

// Contract shapes are constructed only once their arming ticket lands.
#![allow(dead_code)]

// ════════════════════════════════════════════════════════════════════════
// CB-A — AGENTS section + delegation (ONE-1697 renderer · ONE-1698 preset/
//        kill · ONE-1709 team-lead · ONE-1710 peer-answer trust)
// ════════════════════════════════════════════════════════════════════════
mod cb_a {
    /// One rendered AGENTS-section row.
    struct AgentRow {
        /// Actor handle (children: run/agent id; peers: connection-keyed).
        id: String,
        /// "child" or "peer".
        lane: String,
        /// Exact rendered text of the row.
        line: String,
        /// Harness label carried on peer rows (a label, never the identity).
        harness_label: Option<String>,
    }

    struct AgentsSectionRender {
        rows: Vec<AgentRow>,
    }

    /// ONE-1697 fixture: children `child_a` + `child_b` (running, M8 driver
    /// state) + 2 peer connections of the SAME vendor/harness ("claude-code")
    /// registered under two different config dirs whose owner-assigned actor
    /// handles are `cc-main` and `cc-second` (08b §4.2 multi-instance law);
    /// render the AGENTS section collapsed.
    fn arm_render_agents_section() -> AgentsSectionRender {
        use oneiron::context_board::{ChildAgentPresence, PeerPresence};
        use oneiron::run_tree::{RunTreeNode, RunTreeStatus, RunTreeTimestamps};

        let node = RunTreeNode {
            attempt_id: "child_a".to_owned(),
            run_id: None,
            parent_id: None,
            worker_kind: oneiron::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
            agent_id: None,
            status: RunTreeStatus::Running,
            timestamps: RunTreeTimestamps {
                created_at: 1,
                updated_at: 1,
            },
            failure: None,
            events: Vec::new(),
            children: Vec::new(),
        };
        let children = [
            ChildAgentPresence::from_run_tree_node(&node)
                .expect("running driver node must produce child presence"),
            ChildAgentPresence {
                id: "child_b".to_owned(),
                status: RunTreeStatus::Running,
                label: None,
                role: "worker".to_owned(),
            },
        ];
        let peers = [
            PeerPresence {
                actor_handle: "cc-main".to_owned(),
                harness_label: "claude-code".to_owned(),
                last_seen: Some(1),
            },
            PeerPresence {
                actor_handle: "cc-second".to_owned(),
                harness_label: "claude-code".to_owned(),
                last_seen: Some(2),
            },
        ];

        let section = oneiron::context_board::render_agents_section(&children, &peers);
        let rows = section
            .rows
            .into_iter()
            .map(|row| AgentRow {
                id: row.id,
                lane: row.lane.as_str().to_string(),
                line: row.line,
                harness_label: row.harness_label,
            })
            .collect();
        AgentsSectionRender { rows }
    }

    /// ONE-1697 · 08b §4.1–4.2: one-line rows; children from driver state;
    /// peer identity keys on the CONNECTION (config dir), never the vendor —
    /// two same-vendor connections are two named actors (`cc-main` /
    /// `cc-second`); harness is a row label with an exact value (F9).
    #[test]
    fn agents_section_renders_children_and_connection_keyed_peers() {
        let section = arm_render_agents_section();
        assert_eq!(section.rows.len(), 4);
        let one_liners = section
            .rows
            .iter()
            .filter(|r| r.line.lines().count() == 1)
            .count();
        assert_eq!(one_liners, 4);
        let mut child_ids: Vec<&str> = section
            .rows
            .iter()
            .filter(|r| r.lane == "child")
            .map(|r| r.id.as_str())
            .collect();
        child_ids.sort_unstable();
        assert_eq!(child_ids, ["child_a", "child_b"]);
        let peers: Vec<&AgentRow> = section.rows.iter().filter(|r| r.lane == "peer").collect();
        assert_eq!(peers.len(), 2);
        let mut peer_ids: Vec<&str> = peers.iter().map(|r| r.id.as_str()).collect();
        peer_ids.sort_unstable();
        assert_eq!(peer_ids, ["cc-main", "cc-second"]);
        let exact_labels = peers
            .iter()
            .filter(|r| r.harness_label.as_deref() == Some("claude-code"))
            .count();
        assert_eq!(exact_labels, 2);
    }

    /// Outcome of a zero-config spawn.
    struct DefaultPresetSpawn {
        spawned_children: usize,
        /// Logical id the spawn RESOLVED to, read back off the stored row the
        /// dispatch named (engine-observed output, never a caller-side flag —
        /// G6 vacuous-pass hazard).
        resolved_logical_id: String,
        /// Logical id the engine registers as its default base agent.
        system_default_logical_id: String,
    }

    /// ONE-1698 fixture: call `agents.spawn` with NO agent definition and a
    /// plain task prompt; observe the RESOLVED logical id of the spawned child
    /// and, separately, the registered system-default base logical id.
    fn arm_zero_config_spawn() -> DefaultPresetSpawn {
        use oneiron::agent_dispatch::{
            AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DEFAULT_BASE_LOGICAL_ID,
        };
        use oneiron::dreamer_runner::{
            DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload,
        };
        use oneiron::{AttemptQueue, Vault, VaultConfig};

        let dir = tempfile::tempdir().expect("temp dir");
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Vault::open(dir.path(), config).expect("open vault");
        let dispatcher = AgentDispatcher::new(&vault);
        let AgentDispatchOutcome::Dispatched(status) = dispatcher
            .dispatch_default_base(None, None, None, 1)
            .expect("zero-config dispatch")
        else {
            panic!("expected one fresh spawn");
        };
        let AgentDispatchTarget::Custom(resolved_id) = status.input.target;
        let resolved_logical_id = vault
            .get_agent_definition(&resolved_id)
            .expect("read the resolved row")
            .expect("the resolved row exists")
            .logical_id
            .expect("a seeded row carries a logical id");
        let spawned_children = AttemptQueue::new(&vault)
            .list()
            .expect("observe dispatch attempts")
            .into_iter()
            .filter(|attempt| {
                attempt.kind == DREAMER_RUNNER_ATTEMPT_KIND
                    && decode_dreamer_attempt_payload(&attempt.payload).is_ok_and(|payload| {
                        payload.attempt_type == oneiron::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE
                    })
            })
            .count();

        DefaultPresetSpawn {
            spawned_children,
            resolved_logical_id,
            system_default_logical_id: DEFAULT_BASE_LOGICAL_ID.to_owned(),
        }
    }

    /// ONE-1698 · 08b §4.1 (r8): one generic default base agent — spawn works
    /// with zero definition; the spawned child resolves to THAT seeded row.
    #[test]
    fn spawn_with_zero_definition_uses_default_base_preset() {
        let spawn = arm_zero_config_spawn();
        assert_eq!(spawn.spawned_children, 1);
        assert!(!spawn.system_default_logical_id.is_empty());
        assert_eq!(spawn.resolved_logical_id, spawn.system_default_logical_id);
    }

    /// Kill-authority matrix over one spawn tree.
    struct KillMatrix {
        /// Spawner kills its own spawn → effects.
        spawner_kill_effects: usize,
        /// Spawner kills its own spawn OF A DIFFERENT CLASS → effects.
        cross_class_spawner_kill_effects: usize,
        /// Non-spawner kill attempts that took effect (must fail closed).
        non_spawner_kill_effects: usize,
        /// Non-spawner kill attempts surfaced as proposals.
        non_spawner_kill_proposals: usize,
    }

    /// ONE-1698 fixture: agent A spawns X (same class) and Y (different
    /// class); A kills X and Y; unrelated agent B attempts to kill a third
    /// spawn of A's.
    fn arm_kill_matrix() -> KillMatrix {
        use oneiron::agent_dispatch::{
            AgentDispatchOutcome, AgentDispatchStatus, AgentDispatchTarget, AgentDispatcher,
            DispatchAgent, KillOutcome,
        };
        use oneiron::{
            AgentCeiling, AgentDefinition, AgentScope, AttemptQueue, AttemptState,
            ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EntityId, TimeRange, Vault,
            VaultConfig,
        };

        fn dispatched(outcome: AgentDispatchOutcome) -> AgentDispatchStatus {
            let AgentDispatchOutcome::Dispatched(status) = outcome else {
                panic!("expected fresh dispatch");
            };
            status
        }

        let dir = tempfile::tempdir().expect("temp dir");
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Vault::open(dir.path(), config).expect("open vault");
        let custom_id = EntityId::from_bytes([0x61; 16]).expect("custom agent id");
        vault
            .put_agent_definition(
                &custom_id,
                &AgentDefinition::new(
                    "custom",
                    "custom dispatch fixture",
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
                    ClaimSource::UserStated,
                    1.0,
                    false,
                    true,
                    rmpv::Value::Map(vec![(
                        rmpv::Value::from("fixture"),
                        rmpv::Value::from("custom"),
                    )]),
                    None,
                    true,
                    None,
                ),
                TimeRange { start: 1, end: 1 },
                1,
            )
            .expect("store custom definition");

        // The seeded roster is data: a logical id resolves to its stored row.
        let seeded = |logical_id: &str| {
            let (id, _) = vault
                .get_seeded_agent_definition_by_logical_id(logical_id)
                .expect("resolve seeded row")
                .expect("seeded row exists");
            AgentDispatchTarget::Custom(id)
        };

        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched(
            dispatcher
                .dispatch_default_base(None, None, None, 2)
                .expect("dispatch spawner A"),
        );
        let non_spawner = dispatched(
            dispatcher
                .dispatch_default_base(None, None, None, 3)
                .expect("dispatch non-spawner B"),
        );
        let spawn = |target, now| {
            dispatched(
                dispatcher
                    .dispatch(DispatchAgent {
                        target,
                        parent_attempt: Some(spawner.attempt.id),
                        dedupe_key: None,
                        run_id: None,
                        now,
                    })
                    .expect("dispatch child"),
            )
        };
        let system_child = spawn(seeded("sys.scout"), 4);
        let custom_child = spawn(AgentDispatchTarget::Custom(custom_id), 5);
        let proposed_child = spawn(seeded("sys.creative"), 6);

        dispatcher
            .kill_spawn(&system_child.attempt.id, &spawner.attempt.id, 7)
            .expect("spawner kills system child");
        dispatcher
            .kill_spawn(&custom_child.attempt.id, &spawner.attempt.id, 8)
            .expect("spawner kills custom child");
        let non_spawner_outcome = dispatcher
            .kill_spawn(&proposed_child.attempt.id, &non_spawner.attempt.id, 9)
            .expect("non-spawner kill proposes");
        let non_spawner_kill_proposals =
            usize::from(matches!(non_spawner_outcome, KillOutcome::Proposed(_)));
        let queue = AttemptQueue::new(&vault);
        let observed_state = |id| {
            queue
                .get(id)
                .expect("read child")
                .expect("child exists")
                .state
        };
        let spawner_kill_effects =
            usize::from(observed_state(system_child.attempt.id) == AttemptState::Cancelled);
        let cross_class_spawner_kill_effects =
            usize::from(observed_state(custom_child.attempt.id) == AttemptState::Cancelled);
        let non_spawner_kill_effects =
            usize::from(observed_state(proposed_child.attempt.id) == AttemptState::Cancelled);

        assert_eq!(
            observed_state(proposed_child.attempt.id),
            AttemptState::Queued
        );

        KillMatrix {
            spawner_kill_effects,
            cross_class_spawner_kill_effects,
            non_spawner_kill_effects,
            non_spawner_kill_proposals,
        }
    }

    /// ONE-1698 · 08b §4.1 (owner r1): the spawner kills its own spawns,
    /// regardless of class; others' kill fails closed into a proposal.
    #[test]
    fn spawner_kills_own_spawns_non_spawner_fails_closed() {
        let matrix = arm_kill_matrix();
        assert_eq!(matrix.spawner_kill_effects, 1);
        assert_eq!(matrix.cross_class_spawner_kill_effects, 1);
        assert_eq!(matrix.non_spawner_kill_effects, 0);
        assert_eq!(matrix.non_spawner_kill_proposals, 1);
    }

    /// Team-lead preset delegation observations (RLM level 2).
    struct TeamLeadDelegation {
        /// True iff the team-lead SYSTEM preset is available next to the
        /// default base preset.
        preset_available: bool,
        /// Subtasks the lead created from the received TASK.
        subtasks_created: usize,
        /// Workers the lead spawned (depth 1 under the lead).
        workers_spawned: usize,
        /// True iff every depth-1 worker ceiling ⊆ the lead's ceiling.
        child_ceilings_within_parent: bool,
        /// True iff every depth-2 spawn ceiling ⊆ its spawner's ceiling.
        grandchild_ceilings_within_child: bool,
        /// Delegation grants that ended up WIDER than the granting agent's
        /// authority (must be none — attenuation, never amplification).
        wider_grants_effected: usize,
        /// Worker results the lead COLLECTED (ticket flow: … → collects).
        results_collected: usize,
        /// Reports the lead delivered on the originating TASK (→ reports).
        reports_delivered: usize,
    }

    /// ONE-1709 fixture: team-lead preset receives one TASK, plans, creates
    /// 2 subtasks, spawns 2 workers, collects both worker results, and
    /// reports once on the originating TASK; one worker spawns a depth-2
    /// helper REQUESTING a ceiling wider than its own.
    fn arm_team_lead_delegation() -> TeamLeadDelegation {
        unimplemented!("armed by ONE-1709: team-lead system preset, recursive attenuation")
    }

    /// ONE-1709 · 08b §4.5 (r13): team-lead composes existing primitives —
    /// "receives TASK → plans → tasks.create subtasks → agents.spawn workers
    /// → collects → reports" (full flow, F22); ceiling attenuation holds
    /// recursively — child ⊆ parent at every depth, wider requests clamp.
    #[test]
    #[ignore = "armed by ONE-1709"]
    fn team_lead_recursive_delegation_ceilings_attenuate() {
        let lead = arm_team_lead_delegation();
        assert!(lead.preset_available);
        assert_eq!(lead.subtasks_created, 2);
        assert_eq!(lead.workers_spawned, 2);
        assert!(lead.child_ceilings_within_parent);
        assert!(lead.grandchild_ceilings_within_child);
        assert_eq!(lead.wider_grants_effected, 0);
        assert_eq!(lead.results_collected, 2);
        assert_eq!(lead.reports_delivered, 1);
    }

    /// ask(lead, panel-spec) fusion-shape observations.
    struct LeadPanelRun {
        /// Panel members the lead ran.
        panel_members: usize,
        /// Members that could observe another member's answer before
        /// submitting their own (must be none — BLIND panel).
        members_with_cross_visibility: usize,
        /// Judge passes over the member answers.
        judge_passes: usize,
        /// Synthesized final answers delivered to the asker.
        syntheses_delivered: usize,
    }

    /// ONE-1709 fixture: `ask(lead, panel-spec)` with a 3-member panel spec;
    /// the lead runs the panel in code-mode.
    fn arm_lead_panel_run() -> LeadPanelRun {
        unimplemented!("armed by ONE-1709: ask lead panel-spec, blind panel + judge + synthesis")
    }

    /// ONE-1709 · 08b §4.5 (r13) · ticket AC: "Fan-out via lead: `ask(lead,
    /// panel-spec)` → lead runs blind panel + judge + synthesis in
    /// code-mode" (G4/F22 — the fusion shape as a preset).
    #[test]
    #[ignore = "armed by ONE-1709"]
    fn ask_lead_panel_spec_runs_blind_panel_judge_synthesis() {
        let panel = arm_lead_panel_run();
        assert_eq!(panel.panel_members, 3);
        assert_eq!(panel.members_with_cross_visibility, 0);
        assert_eq!(panel.judge_passes, 1);
        assert_eq!(panel.syntheses_delivered, 1);
    }

    /// Landing + consolidation observations for one peer answer.
    struct PeerAnswerLanding {
        /// Turns stored for the answer (storage never gated).
        stored_turns: usize,
        /// Human gate prompts raised by STORAGE of the answer.
        storage_gate_prompts: usize,
        /// Claims the Dreamer derived from the answer.
        derived_claims: usize,
        /// Of those, claims carrying source = tool_output.
        claims_with_source_tool_output: usize,
        /// Of those, claims carrying a confidence value.
        claims_with_confidence: usize,
        /// Answer-turn hops present in the provenance chain (required kind).
        chain_answer_turn_hops: usize,
        /// Consult-task hops present in the provenance chain (required kind).
        chain_consult_task_hops: usize,
        /// Total provenance chain length. 08b r15 requires the CHAIN, not a
        /// fixed length — richer conforming chains (e.g. + actor-signature
        /// hop) must pass (F23 canon correction).
        provenance_chain_len: usize,
    }

    /// ONE-1710 fixture: a peer answers one consult; the Dreamer
    /// consolidates the answer into exactly one derived claim.
    fn arm_peer_answer_landing() -> PeerAnswerLanding {
        unimplemented!("armed by ONE-1710: peer-answer trust = provenance, not friction")
    }

    /// ONE-1710 · 08b §7.5 (r15): storage is never gated; derived claims
    /// carry source:tool_output + confidence + a provenance chain containing
    /// the answer-turn and consult-task hops (r15 names the chain, not a
    /// length — floor assert, richer chains conform).
    #[test]
    #[ignore = "armed by ONE-1710"]
    fn peer_answer_lands_ungated_with_full_provenance_chain() {
        let landing = arm_peer_answer_landing();
        assert_eq!(landing.stored_turns, 1);
        assert_eq!(landing.storage_gate_prompts, 0);
        assert_eq!(landing.derived_claims, 1);
        assert_eq!(landing.claims_with_source_tool_output, 1);
        assert_eq!(landing.claims_with_confidence, 1);
        assert_eq!(landing.chain_answer_turn_hops, 1);
        assert_eq!(landing.chain_consult_task_hops, 1);
        assert!(landing.provenance_chain_len >= 2);
    }

    /// Label-forgery lineage-check observations.
    struct LabelForgeryAttempt {
        /// Write paths exposed to the agent, enumerated by the fixture —
        /// the FULL exposed surface, not a sample (F24).
        exposed_agent_write_paths: usize,
        /// Count of paths through which the restamp was actually attempted
        /// (must cover every exposed agent write path — F24).
        write_paths_attempted: usize,
        /// Lineage-check rejections (must equal the attempted paths).
        lineage_check_rejections: usize,
        /// Claims labeled `generated` whose lineage says tool_output.
        forged_label_claims_stored: usize,
    }

    /// ONE-1710 fixture: attempt to re-stamp a tool_output-sourced claim as
    /// `generated` (source-label forgery) via EVERY write path exposed to
    /// the agent — each exposed path is one counted attempt.
    fn arm_label_forgery_attempt() -> LabelForgeryAttempt {
        unimplemented!("armed by ONE-1710: label-forgery lineage check (dashboard-v2 finding)")
    }

    /// ONE-1710 · 08b r15 KEPT invariant: re-stamping tool_output→generated
    /// is structurally impossible — the lineage check rejects the forgery on
    /// EVERY exposed write path, not just one.
    #[test]
    #[ignore = "armed by ONE-1710"]
    fn label_forgery_lineage_check_rejects_restamped_source() {
        let forgery = arm_label_forgery_attempt();
        assert!(forgery.exposed_agent_write_paths >= 1);
        assert_eq!(
            forgery.write_paths_attempted,
            forgery.exposed_agent_write_paths
        );
        assert_eq!(
            forgery.lineage_check_rejections,
            forgery.write_paths_attempted
        );
        assert_eq!(forgery.forged_label_claims_stored, 0);
    }

    /// Trust-surface observations after a conflicting peer answer.
    struct TrustSurfaces {
        /// Approval-queue entries anywhere in the flow (ratified: none).
        approval_queue_entries: usize,
        /// Human digest entries for the landing.
        human_digest_entries: usize,
        /// conflict.open surfacings for the contradiction.
        conflict_open_surfacings: usize,
        /// Writes needed to correct the wrong note (one supersede).
        correction_writes: usize,
        /// True iff read-time resolution ranks the HIGHER-confidence claim
        /// above the contradicting lower-confidence peer claim (ticket:
        /// "read-time confidence weighting" — F24 confidence half).
        higher_confidence_ranked_first_at_read: bool,
    }

    /// ONE-1710 fixture: a peer answer contradicting an existing first-party
    /// note lands (at lower confidence than the note) and is consolidated;
    /// read back the contradicted fact; then the owner corrects it.
    fn arm_trust_surfaces() -> TrustSurfaces {
        unimplemented!("armed by ONE-1710: NO approval queues; supersession + conflict.open")
    }

    /// ONE-1710 · 08b r15: NO approval queues — digest only; wrong-note
    /// protection is supersession + conflict.open + read-time confidence
    /// weighting; one-write correctable.
    #[test]
    #[ignore = "armed by ONE-1710"]
    fn no_approval_queues_digest_and_supersession_only() {
        let surfaces = arm_trust_surfaces();
        assert_eq!(surfaces.approval_queue_entries, 0);
        assert_eq!(surfaces.human_digest_entries, 1);
        assert_eq!(surfaces.conflict_open_surfacings, 1);
        assert_eq!(surfaces.correction_writes, 1);
        assert!(surfaces.higher_confidence_ranked_first_at_read);
    }
}

// ════════════════════════════════════════════════════════════════════════
// CB-X — agent run status registry mints (ONE-1711)
// ════════════════════════════════════════════════════════════════════════
mod cb_x {
    /// AgentRunStatus contract observations.
    struct AgentRunStatusContract {
        /// The status states, in contract order.
        states: Vec<String>,
        /// Illegal transitions attempted by the fixture: spawned→archived,
        /// spawned→delivered, working→spawned, delivered→working,
        /// archived→working (F25 matrix).
        illegal_transitions_attempted: usize,
        /// Of those, rejected by the contract (must be all).
        illegal_transitions_rejected: usize,
        /// Of those, accepted (must be none).
        illegal_transitions_accepted: usize,
    }

    /// ONE-1711 fixture: enumerate the AgentRunStatus contract and attempt
    /// FIVE illegal transitions: spawned→archived, spawned→delivered,
    /// working→spawned, delivered→working, archived→working.
    fn arm_agent_run_status_contract() -> AgentRunStatusContract {
        unimplemented!("armed by ONE-1711: AgentRunStatus contract shape")
    }

    /// ONE-1711 · 08b registry: AgentRunStatus is exactly spawned → working
    /// → needs_input → delivered → archived; every out-of-order jump in the
    /// fixture matrix rejects.
    #[test]
    #[ignore = "armed by ONE-1711"]
    fn agent_run_status_contract_is_five_states_in_order() {
        let contract = arm_agent_run_status_contract();
        assert_eq!(contract.states.len(), 5);
        assert_eq!(
            contract.states,
            ["spawned", "working", "needs_input", "delivered", "archived"]
        );
        assert_eq!(contract.illegal_transitions_attempted, 5);
        assert_eq!(contract.illegal_transitions_rejected, 5);
        assert_eq!(contract.illegal_transitions_accepted, 0);
    }

    /// needs_input round-trip observations (EF-049 lineage → OF twin).
    struct NeedsInputRoundTrip {
        /// Runs sitting in needs_input after the agent asks.
        runs_in_needs_input_after_ask: usize,
        /// Runs resumed to working after the owner supplies input.
        resumed_to_working_after_input: usize,
        /// Runs reaching delivered after the resume.
        delivered_after_resume: usize,
    }

    /// ONE-1711 fixture: a run asks for input (→ needs_input), the owner
    /// answers, the run resumes and delivers.
    fn arm_needs_input_round_trip() -> NeedsInputRoundTrip {
        unimplemented!("armed by ONE-1711: needs_input round-trip (EF-049 lineage, OF twin)")
    }

    /// ONE-1711 · 08b §4.4 + registry: the needs_input round-trip — ask,
    /// owner input, resume to working, deliver.
    #[test]
    #[ignore = "armed by ONE-1711"]
    fn needs_input_round_trip_resumes_and_delivers() {
        let round_trip = arm_needs_input_round_trip();
        assert_eq!(round_trip.runs_in_needs_input_after_ask, 1);
        assert_eq!(round_trip.resumed_to_working_after_input, 1);
        assert_eq!(round_trip.delivered_after_resume, 1);
    }
}
