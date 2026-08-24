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
        use oneiron::agent_run_status::AgentRunStatus;
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
                status: AgentRunStatus::Working,
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
        use oneiron::agent_dispatch::{
            AgentDispatchOutcome, AgentDispatchStatus, AgentDispatchTarget, AgentDispatcher,
            AgentSpawnContext, DEFAULT_BASE_LOGICAL_ID, DispatchAgent,
        };
        use oneiron::run_tree::{RunTreeAdapter, RunTreeNode};
        use oneiron::{
            AgentCeiling, ContextSpec, EntityId, TaskAssignee, TaskCreateSpec, TaskResultInput,
            TaskRouteOutcome, TaskTerminalDisposition,
        };

        fn find<'a>(nodes: &'a [RunTreeNode], attempt_id: &str) -> Option<&'a RunTreeNode> {
            nodes.iter().find_map(|node| {
                if node.attempt_id == attempt_id {
                    Some(node)
                } else {
                    find(&node.children, attempt_id)
                }
            })
        }

        let fixture = super::lead_fixture::LeadFixture::open();
        let vault = &fixture.vault;

        // The seeded lead is DATA: a `sys.*` logical id resolving to a stored
        // row, available next to the generic default base.
        let (lead_ref, lead_definition) = vault
            .get_seeded_agent_definition_by_logical_id(super::TEAM_LEAD_LOGICAL_ID)
            .expect("seeded roster resolves")
            .expect("the team lead row is seeded");
        let preset_available = vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
            .expect("seeded roster resolves")
            .is_some();
        assert_eq!(lead_definition.ceiling, AgentCeiling::Auto);
        fixture.assert_lead_create_is_owner_granted(lead_ref);

        // 1. A TASK addressed to the lead routes through ONE-1700's ordinary
        //    agent-definition assignee lane — no lead-specific scheduler.
        let receipt = fixture.create_owned_task(
            lead_ref,
            TaskCreateSpec::new(
                rmpv::Value::Nil,
                Some("ship the release".to_owned()),
                None,
                Some(super::LEAD_NOW),
            )
            .with_assignee(TaskAssignee::AgentDef {
                agent_def_ref: lead_ref,
            }),
        );
        let originating_task = receipt.task_ref.expect("the originating task is minted");
        let Some(TaskRouteOutcome::AgentDispatch {
            attempt_ref: lead_attempt,
            agent_def_ref,
        }) = receipt.route
        else {
            panic!("an agent-definition assignee routes to an agent dispatch");
        };
        assert_eq!(agent_def_ref, lead_ref);

        // Everything below is what the LEAD does in code mode, over the same
        // primitives any agent has: tasks.create, agents.spawn, results.
        let lead_facade = fixture.agent_facade(lead_ref);
        let dispatcher = AgentDispatcher::new(vault);
        let run_id = fixture.run_id_of(lead_attempt);

        // 2. Plan → two typed subtasks the lead owns, and is therefore the
        //    execution writer for.
        let subtasks: Vec<EntityId> = ["draft the notes", "cut the tag"]
            .into_iter()
            .map(|label| {
                fixture
                    .create_owned_task(
                        lead_ref,
                        TaskCreateSpec::new(
                            rmpv::Value::Nil,
                            Some(label.to_owned()),
                            None,
                            Some(super::LEAD_NOW),
                        )
                        .with_assignee(TaskAssignee::Dreamer),
                    )
                    .task_ref
                    .expect("the subtask is minted")
            })
            .collect();
        let subtasks_created = subtasks.len();

        // 3. Spawn → two workers, each under the lead, on the lead's run.
        //    The workers' rows are NARROWER than the lead's, so nothing needs
        //    clamping at depth 1 and the seeded row dispatches as-is.
        let spawn = |target: EntityId, parent, now| -> AgentDispatchStatus {
            let AgentDispatchOutcome::Dispatched(status) = dispatcher
                .dispatch_with_context(
                    DispatchAgent {
                        target: AgentDispatchTarget::Custom(target),
                        parent_attempt: Some(parent),
                        dedupe_key: None,
                        run_id: run_id.clone(),
                        now,
                    },
                    // Delegation narrows: the workers see nothing of the
                    // lead's memory or chat, only their own briefing.
                    AgentSpawnContext::default()
                        .with_context_spec(ContextSpec::excluded().with_briefing("do one subtask")),
                )
                .expect("the lead spawns a worker")
            else {
                panic!("expected a fresh spawn");
            };
            status
        };
        let workers = [
            spawn(fixture.worker_a, lead_attempt, super::LEAD_NOW + 1),
            spawn(fixture.worker_b, lead_attempt, super::LEAD_NOW + 2),
        ];
        let workers_spawned = workers.len();

        // 4. Depth 2: worker A asks for a helper row WIDER than its own.
        assert_eq!(
            vault
                .get_agent_definition(&fixture.helper_auto)
                .expect("read the helper row")
                .expect("the helper row exists")
                .ceiling,
            AgentCeiling::Auto,
            "the depth-2 request must be genuinely wider, or the clamp is vacuous"
        );
        let helper = spawn(
            fixture.helper_auto,
            workers[0].attempt.id,
            super::LEAD_NOW + 3,
        );

        // Effective ceilings come from the row each dispatch NAMED, read back
        // live — never from the frozen payload snapshot, which carries none.
        let effective = |status: &AgentDispatchStatus| {
            let AgentDispatchTarget::Custom(id) = status.input.target;
            vault
                .get_agent_definition(&id)
                .expect("read the dispatched row")
                .expect("the dispatched row exists")
                .ceiling
        };
        let lead_ceiling = lead_definition.ceiling;
        let child_ceilings_within_parent = workers
            .iter()
            .all(|worker| !effective(worker).widens_beyond(lead_ceiling));
        let grandchild_ceilings_within_child =
            !effective(&helper).widens_beyond(effective(&workers[0]));
        let wider_grants_effected =
            usize::from(
                workers
                    .iter()
                    .any(|worker| effective(worker).widens_beyond(lead_ceiling)),
            ) + usize::from(effective(&helper).widens_beyond(effective(&workers[0])));
        // The wider request was ATTENUATED, not honoured: the dispatch names a
        // run-scoped fork of the helper row, not the wide source row.
        assert_ne!(
            helper.input.target,
            AgentDispatchTarget::Custom(fixture.helper_auto)
        );
        assert_eq!(effective(&helper), AgentCeiling::Proposed);

        // 5. Collect → each worker's durable result lands on its subtask.
        for (index, subtask) in subtasks.iter().enumerate() {
            let result_ref = fixture.result_turn(0xB0 + u8::try_from(index).expect("small index"));
            lead_facade
                .land_task_result(
                    *subtask,
                    &TaskResultInput {
                        result_ref,
                        disposition: TaskTerminalDisposition::Completed,
                        finished_at: super::LEAD_NOW + 10,
                    },
                )
                .expect("the lead collects a worker result");
        }
        let results_collected = subtasks
            .iter()
            .filter(|subtask| fixture.terminal_result_ref(**subtask).is_some())
            .count();

        // 6. Report → exactly once, on the originating TASK.
        lead_facade
            .land_task_result(
                originating_task,
                &TaskResultInput {
                    result_ref: fixture.result_turn(0xB9),
                    disposition: TaskTerminalDisposition::Completed,
                    finished_at: super::LEAD_NOW + 20,
                },
            )
            .expect("the lead reports on the originating task");
        let reports_delivered =
            usize::from(fixture.terminal_result_ref(originating_task).is_some());
        // A second report is refused: one delivered report, not two.
        assert!(
            lead_facade
                .land_task_result(
                    originating_task,
                    &TaskResultInput {
                        result_ref: fixture.result_turn(0xBA),
                        disposition: TaskTerminalDisposition::Completed,
                        finished_at: super::LEAD_NOW + 21,
                    },
                )
                .is_err()
        );

        // Whole-tree observability: ONE existing run tree, correct parent ids
        // at every level — no second "team tree" store.
        let tree = RunTreeAdapter::new(vault)
            .read()
            .expect("render the run tree");
        let lead_hex = fixture.attempt_hex(lead_attempt);
        let lead_node = find(&tree.roots, &lead_hex).expect("the lead is a run-tree root");
        assert_eq!(lead_node.parent_id, None);
        assert_eq!(
            lead_node.agent_id.as_deref(),
            Some(super::TEAM_LEAD_LOGICAL_ID)
        );
        assert_eq!(lead_node.children.len(), 2);
        let worker_a_node = find(
            &lead_node.children,
            &fixture.attempt_hex(workers[0].attempt.id),
        )
        .expect("worker A hangs off the lead");
        assert_eq!(worker_a_node.parent_id.as_deref(), Some(lead_hex.as_str()));
        let helper_node = find(
            &worker_a_node.children,
            &fixture.attempt_hex(helper.attempt.id),
        )
        .expect("the depth-2 helper hangs off worker A");
        assert_eq!(
            helper_node.parent_id.as_deref(),
            Some(fixture.attempt_hex(workers[0].attempt.id).as_str())
        );
        // Every attempt in the branch carries the lead's run id.
        let branch_runs: Vec<Option<String>> = [lead_node, worker_a_node, helper_node]
            .iter()
            .map(|node| node.run_id.clone())
            .collect();
        assert_eq!(branch_runs.iter().filter(|id| **id == run_id).count(), 3);
        // Depth decrements at every level and is persisted, not merely counted.
        assert_eq!(fixture.persisted_depth(lead_attempt), Some(8));
        assert_eq!(fixture.persisted_depth(workers[0].attempt.id), Some(7));
        assert_eq!(fixture.persisted_depth(helper.attempt.id), Some(6));

        TeamLeadDelegation {
            preset_available,
            subtasks_created,
            workers_spawned,
            child_ceilings_within_parent,
            grandchild_ceilings_within_child,
            wider_grants_effected,
            results_collected,
            reports_delivered,
        }
    }

    /// ONE-1709 · 08b §4.5 (r13): team-lead composes existing primitives —
    /// "receives TASK → plans → tasks.create subtasks → agents.spawn workers
    /// → collects → reports" (full flow, F22); ceiling attenuation holds
    /// recursively — child ⊆ parent at every depth, wider requests clamp.
    #[test]
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
        use oneiron::{
            ConsultPayloadRef, ConsultResultInput, ConsultResultKind, ContextSpec, EntityId,
            LeadPanelSpec, PanelJudgeSpec, PanelMemberSpec, PanelResultInputs, PanelSynthesisSpec,
            TaskAssignee, TaskCreateSpec, TaskKind, TaskTtl, load_lead_panel_spec,
            persist_lead_panel_spec, plan_lead_panel_tasks,
        };

        let fixture = super::lead_fixture::LeadFixture::open();
        let vault = &fixture.vault;
        let (lead_ref, _) = vault
            .get_seeded_agent_definition_by_logical_id(super::TEAM_LEAD_LOGICAL_ID)
            .expect("seeded roster resolves")
            .expect("the team lead row is seeded");
        fixture.assert_lead_create_is_owner_granted(lead_ref);

        // The panel spec is a TYPED SPEC ENTITY. Member instructions, the judge
        // rubric, and the synthesis instructions live here and nowhere else.
        let members: Vec<EntityId> = (0..3)
            .map(|index| fixture.person(0xC0 + index, "panelist"))
            .collect();
        let judge_actor = fixture.person(0xC5, "judge");
        let synthesis_actor = fixture.person(0xC6, "synthesist");
        let spec = LeadPanelSpec {
            members: members
                .iter()
                .enumerate()
                .map(|(index, actor_ref)| PanelMemberSpec {
                    responder: TaskAssignee::Peer {
                        actor_ref: *actor_ref,
                    },
                    instructions: format!("{index}: answer without seeing anyone else"),
                    context_spec: ContextSpec::excluded(),
                })
                .collect(),
            judge: PanelJudgeSpec {
                responder: TaskAssignee::Peer {
                    actor_ref: judge_actor,
                },
                rubric: super::PANEL_JUDGE_RUBRIC.to_owned(),
                context_spec: ContextSpec::excluded(),
            },
            synthesis: PanelSynthesisSpec {
                responder: TaskAssignee::Peer {
                    actor_ref: synthesis_actor,
                },
                instructions: super::PANEL_SYNTHESIS_INSTRUCTIONS.to_owned(),
                context_spec: ContextSpec::excluded(),
            },
        };
        let question_ref = ConsultPayloadRef::Turn(fixture.question_turn());
        let spec_ref =
            persist_lead_panel_spec(vault, &spec, super::LEAD_NOW).expect("persist the panel spec");
        let correlation_ref = fixture.question_turn();

        // `ask(lead, panel-spec)`: ONE task addressed at the seeded lead row.
        //
        // It rides the STANDARD lane, not the consult lane: ONE-1699's
        // validator admits `TaskKind::Consult` only with a `TaskAssignee::Peer`
        // responder, and addressing an agent-definition row is exactly what
        // `TaskAssignee::AgentDef` is for. ONE-1709 consumes that validator
        // read-only, so the ask carries REF STRINGS ONLY — never the question
        // text, never the panel spec inline.
        let ask_receipt = fixture.create_owned_task(
            lead_ref,
            TaskCreateSpec::new(
                rmpv::Value::Map(vec![
                    (
                        rmpv::Value::from("question_ref"),
                        rmpv::Value::from(question_ref.short_ref()),
                    ),
                    (
                        rmpv::Value::from("panel_spec_ref"),
                        rmpv::Value::from(spec_ref.short_ref()),
                    ),
                ]),
                Some("ask the lead".to_owned()),
                None,
                Some(super::LEAD_NOW),
            )
            .with_assignee(TaskAssignee::AgentDef {
                agent_def_ref: lead_ref,
            }),
        );
        let ask_task = ask_receipt.task_ref.expect("the ask task is minted");

        // The lead loads the referenced spec and plans typed task INPUTS. The
        // planner allocates no entity id; `tasks.create` mints every one.
        let loaded = load_lead_panel_spec(vault, spec_ref).expect("the lead loads the spec");
        assert_eq!(loaded, spec);
        let plan = plan_lead_panel_tasks(question_ref, spec_ref, correlation_ref, &loaded)
            .expect("the lead plans the panel");
        let lead_facade = fixture.agent_facade(lead_ref);
        let ttl = TaskTtl::at(super::LEAD_NOW + 3_600);

        // Each panel TASK is minted the same way the delegation arm mints the
        // lead's subtasks — through the granted owner, OWNED by the lead — for
        // the reason `assert_lead_create_is_owner_granted` pins: the seeded row
        // is not self-authorizing, so the lead's own create parks.
        let mint = |input: &oneiron::LeadPanelTaskInputSpec, now: u64| -> EntityId {
            fixture
                .create_owned_task(
                    lead_ref,
                    TaskCreateSpec::new(rmpv::Value::Nil, None, None, Some(now))
                        .with_kind(TaskKind::Consult)
                        .with_consult(input.consult.clone())
                        .with_assignee(input.responder)
                        .with_ttl(ttl),
                )
                .task_ref
                .expect("the panel task is minted")
        };

        // Members run FIRST and alone: none is mintable with a sibling result,
        // because none has one to carry.
        let member_tasks: Vec<EntityId> = plan
            .member_tasks
            .iter()
            .map(|input| {
                assert_eq!(input.result_inputs, PanelResultInputs::None);
                mint(input, super::LEAD_NOW)
            })
            .collect();
        let panel_members = member_tasks.len();

        // Each member answers on its own task. Its answer is a durable turn.
        let member_results: Vec<EntityId> = member_tasks
            .iter()
            .enumerate()
            .map(|(index, task_ref)| {
                let result_ref =
                    fixture.result_turn(0xD0 + u8::try_from(index).expect("small index"));
                fixture
                    .peer_facade(members[index])
                    .land_consult_result(
                        *task_ref,
                        &ConsultResultInput {
                            kind: ConsultResultKind::Answer {
                                result_ref,
                                evidence_refs: vec![ConsultPayloadRef::Turn(result_ref)],
                            },
                            completed_at: super::LEAD_NOW + 10,
                        },
                    )
                    .expect("a panel member answers");
                result_ref
            })
            .collect();

        // BLINDNESS, checked against the persisted rows: no member task's body
        // carries any other member's answer, in any encoding.
        let members_with_cross_visibility = member_tasks
            .iter()
            .enumerate()
            .filter(|(index, task_ref)| {
                member_results
                    .iter()
                    .enumerate()
                    .any(|(other, result_ref)| {
                        other != *index && fixture.body_mentions(**task_ref, result_ref.as_bytes())
                    })
            })
            .count();

        // REF-ONLY: the free-form question, member instructions, and judge
        // rubric exist only in the referenced entities.
        for task_ref in &member_tasks {
            for text in [
                super::PANEL_QUESTION_TEXT,
                super::PANEL_JUDGE_RUBRIC,
                super::PANEL_SYNTHESIS_INSTRUCTIONS,
            ] {
                assert!(
                    !fixture.body_mentions(*task_ref, text.as_bytes()),
                    "free-form panel text must not ride a TASK payload"
                );
            }
        }

        // The judge task becomes mintable only now that every member result
        // ref exists, and it runs exactly once over all of them.
        assert_eq!(
            plan.judge_task.result_inputs,
            PanelResultInputs::AllMemberResults
        );
        assert_eq!(member_results.len(), panel_members);
        let judge_task = mint(&plan.judge_task, super::LEAD_NOW + 11);
        let judge_result = fixture.result_turn(0xD8);
        fixture
            .peer_facade(judge_actor)
            .land_consult_result(
                judge_task,
                &ConsultResultInput {
                    kind: ConsultResultKind::Answer {
                        result_ref: judge_result,
                        evidence_refs: member_results
                            .iter()
                            .map(|result| ConsultPayloadRef::Turn(*result))
                            .collect(),
                    },
                    completed_at: super::LEAD_NOW + 20,
                },
            )
            .expect("the judge ranks the answers");
        let judge_passes = usize::from(fixture.terminal_result_ref(judge_task).is_some());

        // Synthesis receives the judge's result plus the members', and one
        // final answer reaches the asker on the originating ask TASK.
        assert_eq!(
            plan.synthesis_task.result_inputs,
            PanelResultInputs::AllMemberAndJudgeResults
        );
        let synthesis_task = mint(&plan.synthesis_task, super::LEAD_NOW + 21);
        let synthesis_result = fixture.result_turn(0xD9);
        fixture
            .peer_facade(synthesis_actor)
            .land_consult_result(
                synthesis_task,
                &ConsultResultInput {
                    kind: ConsultResultKind::Answer {
                        result_ref: synthesis_result,
                        evidence_refs: member_results
                            .iter()
                            .chain(std::iter::once(&judge_result))
                            .map(|result| ConsultPayloadRef::Turn(*result))
                            .collect(),
                    },
                    completed_at: super::LEAD_NOW + 30,
                },
            )
            .expect("the synthesist writes the final answer");
        lead_facade
            .land_task_result(
                ask_task,
                &oneiron::TaskResultInput {
                    result_ref: synthesis_result,
                    disposition: oneiron::TaskTerminalDisposition::Completed,
                    finished_at: super::LEAD_NOW + 31,
                },
            )
            .expect("the lead delivers one synthesis to the asker");
        let syntheses_delivered =
            usize::from(fixture.terminal_result_ref(ask_task) == Some(synthesis_result));

        LeadPanelRun {
            panel_members,
            members_with_cross_visibility,
            judge_passes,
            syntheses_delivered,
        }
    }

    /// ONE-1709 · 08b §4.5 (r13) · ticket AC: "Fan-out via lead: `ask(lead,
    /// panel-spec)` → lead runs blind panel + judge + synthesis in
    /// code-mode" (G4/F22 — the fusion shape as a preset).
    #[test]
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
        use oneiron::ClaimSource;
        use oneiron::dreamer_consolidation::ConsolidationProvenanceHopKind;

        let fixture = super::peer_fixture::PeerFixture::open();
        // §1 order: the answer TURN and the consult TASK result land FIRST,
        // through the ordinary ledger doors, before any consolidation
        // decision exists to make.
        let answer = fixture.land_peer_answer("ACME");
        let stored_turns = usize::from(fixture.entity_exists(answer.answer_turn_ref));
        let storage_gate_prompts = fixture.pending_gate_consents();

        let (outcome, _) = fixture.consolidate_peer_answer(&answer, "ACME", 0.7, None);
        let derived_claims = outcome.landed.len();

        let bodies: Vec<_> = outcome.landed.iter().map(|id| fixture.claim(*id)).collect();
        let claims_with_source_tool_output = bodies
            .iter()
            .filter(|body| body.source == Some(ClaimSource::ToolOutput))
            .count();
        let claims_with_confidence = bodies
            .iter()
            .filter(|body| body.confidence.is_finite() && body.confidence > 0.0)
            .count();

        let chains: Vec<_> = bodies
            .iter()
            .map(super::peer_fixture::stored_chain)
            .collect();
        let chain_answer_turn_hops = chains
            .iter()
            .flatten()
            .filter(|hop| hop.kind == ConsolidationProvenanceHopKind::AnswerTurn)
            .count();
        let chain_consult_task_hops = chains
            .iter()
            .flatten()
            .filter(|hop| hop.kind == ConsolidationProvenanceHopKind::ConsultTask)
            .count();
        let provenance_chain_len = chains.iter().map(Vec::len).sum();

        PeerAnswerLanding {
            stored_turns,
            storage_gate_prompts,
            derived_claims,
            claims_with_source_tool_output,
            claims_with_confidence,
            chain_answer_turn_hops,
            chain_consult_task_hops,
            provenance_chain_len,
        }
    }

    /// ONE-1710 · 08b §7.5 (r15): storage is never gated; derived claims
    /// carry source:tool_output + confidence + a provenance chain containing
    /// the answer-turn and consult-task hops (r15 names the chain, not a
    /// length — floor assert, richer chains conform).
    #[test]
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
        let fixture = super::peer_fixture::PeerFixture::open();
        let attempts = fixture.attempt_forgery_through_every_exposed_write_path();

        LabelForgeryAttempt {
            exposed_agent_write_paths: super::peer_fixture::EXPOSED_AGENT_CLAIM_WRITE_PATHS,
            write_paths_attempted: attempts.len(),
            lineage_check_rejections: attempts
                .iter()
                .filter(|attempt| attempt.rejected_for_lineage)
                .count(),
            forged_label_claims_stored: attempts
                .iter()
                .filter(|attempt| fixture.entity_exists(attempt.claim_id))
                .count(),
        }
    }

    /// ONE-1710 · 08b r15 KEPT invariant: re-stamping tool_output→generated
    /// is structurally impossible — the lineage check rejects the forgery on
    /// EVERY exposed write path, not just one.
    #[test]
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
        let fixture = super::peer_fixture::PeerFixture::open();

        // A first-party note the owner already trusts, at HIGH confidence.
        let note = fixture.owner_note("Globex", 0.9);

        // The peer answers the same question differently, at LOWER
        // confidence. Storage is ungated and consolidation lands the claim.
        let answer = fixture.land_peer_answer("ACME");
        let (outcome, candidate) = fixture.consolidate_peer_answer(&answer, "ACME", 0.4, None);
        let peer_claim = *outcome
            .landed
            .first()
            .expect("the peer answer lands as one claim");

        // Wrong-note protection is the EXISTING conflict machinery: one open
        // conflict over the contradicted identity, both claims still
        // legible, and one informational digest line.
        let (conflict_open_surfacings, conflict_open_ref) =
            fixture.detect_open_conflict(&candidate, note.claim_id);
        let human_digest_entries = fixture.surface_digest(&answer, peer_claim, conflict_open_ref);

        // Read-time confidence weighting ranks the higher-confidence head
        // first WHILE the contradiction stands.
        let ranked = fixture.read_ranked_heads();
        let higher_confidence_ranked_first_at_read = ranked.first() == Some(&note.claim_id);

        // One superseding write corrects the wrong note.
        let correction = fixture.correct_with_supersession(&answer, peer_claim, "Globex", 0.9);

        TrustSurfaces {
            approval_queue_entries: fixture.pending_gate_consents(),
            human_digest_entries,
            conflict_open_surfacings,
            correction_writes: correction,
            higher_confidence_ranked_first_at_read,
        }
    }

    /// ONE-1710 · 08b r15: NO approval queues — digest only; wrong-note
    /// protection is supersession + conflict.open + read-time confidence
    /// weighting; one-write correctable.
    #[test]
    fn no_approval_queues_digest_and_supersession_only() {
        let surfaces = arm_trust_surfaces();
        assert_eq!(surfaces.approval_queue_entries, 0);
        assert_eq!(surfaces.human_digest_entries, 1);
        assert_eq!(surfaces.conflict_open_surfacings, 1);
        assert_eq!(surfaces.correction_writes, 1);
        assert!(surfaces.higher_confidence_ranked_first_at_read);
    }
}

/// Local ONE-1710 fixture support. Deliberately NOT in `cb_oracle_common`:
/// that surface is frozen additive-only, and the exhaustive exposed-write-path
/// enumeration below is specific to this ticket.
mod peer_fixture {
    use oneiron::claim::{ClaimBody, ClaimSubject};
    use oneiron::config::VaultConfig;
    use oneiron::dreamer_consolidation::{
        ConsolidationProvenanceHop, ConsolidationProvenanceHopKind, PeerAnswerLineage,
        PeerTrustDigestLine, PeerTrustDigestSink, PriorHead, conflict_open_marker_id,
        decode_consolidation_evidence, detect_conflicts, evidence_chain_source,
        peer_answer_provenance_chain, surface_peer_answer_digest,
    };
    use oneiron::edge::EdgeActorClass;
    use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
    use oneiron::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
    use oneiron::{
        AttemptId, ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, DreamerRunContext,
        EntityId, PromotionCandidate, PromotionOutcome, TaskAssignee, TaskCreateSpec,
        TaskResultInput, TaskTerminalDisposition, TimeRange, Vault, promote_consolidated_claims,
    };
    use rmpv::Value;

    const PEER_NOW: u64 = 1_800_000_100;
    /// The ONE actor a fresh vault's DEFAULT policy manifest grants an
    /// `agent`-class Auto ceiling (the first-party connection). The Dreamer
    /// writes as this connection; installing a wider owner manifest is a
    /// control-plane write with no public door, so the fixture uses the
    /// permission the shipped default already carries.
    const OWNER_BYTES: [u8; 16] = [0xE1; 16];
    /// The consolidated fact under test. `profile.` is one of the default
    /// manifest's normal-criticality prefixes.
    const PEER_PREDICATE: &str = "profile.employer";

    /// The FULL set of claim-write doors an agent can reach (F24): the
    /// targeted `Vault::put_claim`, both public batch builders, and the
    /// lexical-hint batch put. Reserved-namespace and replication doors are
    /// crate-private/engine-only and are covered by the same chokepoint.
    pub(crate) const EXPOSED_AGENT_CLAIM_WRITE_PATHS: usize = 4;

    pub(crate) struct PeerFixture {
        _dir: tempfile::TempDir,
        pub(crate) vault: Vault,
        owner: EntityId,
        peer: EntityId,
        subject: EntityId,
        attempt: AttemptId,
    }

    /// One landed peer answer: the stored refs the provenance chain binds.
    pub(crate) struct LandedPeerAnswer {
        pub(crate) answer_turn_ref: EntityId,
        pub(crate) consult_task_ref: EntityId,
    }

    pub(crate) struct OwnerNote {
        pub(crate) claim_id: EntityId,
    }

    pub(crate) struct ForgeryAttempt {
        pub(crate) claim_id: EntityId,
        pub(crate) rejected_for_lineage: bool,
    }

    #[derive(Default)]
    struct CountingDigestSink {
        lines: Vec<PeerTrustDigestLine>,
    }

    impl PeerTrustDigestSink for CountingDigestSink {
        fn push(&mut self, line: PeerTrustDigestLine) -> oneiron::Result<()> {
            self.lines.push(line);
            Ok(())
        }
    }

    impl PeerFixture {
        pub(crate) fn open() -> Self {
            let dir = tempfile::tempdir().expect("temporary vault directory");
            let mut config = VaultConfig::device();
            config.map_size = 32 * 1024 * 1024;
            config.dimensions = 4;
            config.embedding_model = None;
            let vault = Vault::open(dir.path(), config).expect("open the fixture vault");

            let owner = EntityId::from_bytes(OWNER_BYTES).expect("owner id");
            let peer = EntityId::from_bytes([0xC3; 16]).expect("peer actor id");
            let subject = EntityId::from_bytes([0xC4; 16]).expect("subject id");
            for (id, label) in [(owner, "owner"), (peer, "peer"), (subject, "subject")] {
                put_entity(&vault, id, ENTITY_TYPE_PERSON, label.as_bytes());
            }

            Self {
                _dir: dir,
                vault,
                owner,
                peer,
                subject,
                attempt: AttemptId::now(),
            }
        }

        fn run(&self) -> DreamerRunContext {
            DreamerRunContext {
                run_id: "cb-b-1710".to_owned(),
                attempt_id: self.attempt,
                agent_actor: WriteActor::new(self.owner, EdgeActorClass::Agent),
                now_ms: PEER_NOW,
            }
        }

        pub(crate) fn entity_exists(&self, id: EntityId) -> bool {
            self.vault.get(&id).expect("read the entity").is_some()
        }

        pub(crate) fn claim(&self, id: EntityId) -> ClaimBody {
            self.vault
                .get_claim(&id)
                .expect("read the claim")
                .expect("the claim exists")
        }

        /// Human-prompt rows anywhere in the vault: the approval queue the
        /// ratified design says must never appear on this path.
        pub(crate) fn pending_gate_consents(&self) -> usize {
            self.vault
                .pending_gate_consents(1_000)
                .expect("read pending gate consents")
                .len()
        }

        /// §1: persist the answer TURN, then the consult TASK result that
        /// binds back to it. Neither write is a claim-approval act.
        pub(crate) fn land_peer_answer(&self, answer_text: &str) -> LandedPeerAnswer {
            let answer_turn_ref = EntityId::from_bytes([0xC5; 16]).expect("answer turn id");
            put_entity(
                &self.vault,
                answer_turn_ref,
                ENTITY_TYPE_TURN,
                turn_body(answer_text).as_slice(),
            );

            let mut spec = TaskCreateSpec::new(
                Value::Map(vec![(Value::from("ask"), Value::from("who employs them?"))]),
                Some("consult".to_owned()),
                Some(self.owner),
                Some(PEER_NOW),
            );
            spec.assignee = Some(TaskAssignee::Peer {
                actor_ref: self.peer,
            });
            let consult_task_ref = self
                .vault
                .memory_facade(self.owner, EdgeActorClass::Agent)
                .tasks_create(&spec)
                .expect("the granted owner mints the consult task")
                .task_ref
                .expect("a granted create returns its task ref");

            // The ANSWERING peer settles its own task with the durable
            // answer as the result ref — the read-only back-link the
            // provenance chain validates against.
            self.vault
                .memory_facade(self.peer, EdgeActorClass::Agent)
                .land_task_result(
                    consult_task_ref,
                    &TaskResultInput {
                        result_ref: answer_turn_ref,
                        disposition: TaskTerminalDisposition::Completed,
                        finished_at: PEER_NOW + 1,
                    },
                )
                .expect("the peer lands its answer");

            LandedPeerAnswer {
                answer_turn_ref,
                consult_task_ref,
            }
        }

        fn lineage(&self, answer: &LandedPeerAnswer) -> PeerAnswerLineage {
            PeerAnswerLineage {
                answer_turn_ref: answer.answer_turn_ref,
                consult_task_ref: answer.consult_task_ref,
                peer_actor_ref: self.peer,
                result_artifact_ref: None,
            }
        }

        pub(crate) fn peer_candidate(
            &self,
            answer: &LandedPeerAnswer,
            value: &str,
            confidence: f32,
            supersedes: Option<EntityId>,
        ) -> PromotionCandidate {
            let chain = peer_answer_provenance_chain(&self.vault, self.lineage(answer))
                .expect("the peer answer binds back to its consult task");
            let evidence_turn_refs = vec![answer.answer_turn_ref];
            let evidence_meet =
                evidence_chain_source(&self.vault, &chain, &evidence_turn_refs).expect("meet");

            PromotionCandidate {
                claim_id: EntityId::now(),
                candidate: ClaimCandidate::new(
                    PEER_PREDICATE,
                    ClaimSubject::Entity(self.subject),
                    Value::from(value),
                    confidence,
                )
                // The default manifest's tool_output auto permit is banded at
                // `public`; the consolidated fact is stamped accordingly.
                .with_scope(Value::Map(vec![(
                    Value::from("sensitivity"),
                    Value::from("public"),
                )])),
                evidence_turn_refs,
                provenance_chain: chain,
                supersedes,
                evidence_meet,
                occurred: TimeRange {
                    start: PEER_NOW,
                    end: PEER_NOW,
                },
                learned_at: PEER_NOW,
            }
        }

        pub(crate) fn consolidate_peer_answer(
            &self,
            answer: &LandedPeerAnswer,
            value: &str,
            confidence: f32,
            supersedes: Option<EntityId>,
        ) -> (PromotionOutcome, PromotionCandidate) {
            let candidate = self.peer_candidate(answer, value, confidence, supersedes);
            let outcome =
                promote_consolidated_claims(&self.vault, &self.run(), vec![candidate.clone()])
                    .expect("promotion runs");
            assert!(
                outcome.rejected.is_empty(),
                "peer consolidation must not be rejected: {:?}",
                outcome.rejected
            );
            assert!(
                outcome.pended.is_empty(),
                "ONE-1710: there is no approval lane to pend into"
            );
            (outcome, candidate)
        }

        /// One owner-authored first-party note, written through the ordinary
        /// public claim door.
        pub(crate) fn owner_note(&self, value: &str, confidence: f32) -> OwnerNote {
            let claim_id = EntityId::from_bytes([0xC6; 16]).expect("note id");
            let envelope = WriteEnvelope::new(
                WriteActor::new(self.owner, EdgeActorClass::Human),
                ClaimSource::UserStated,
                WriteProvenance::new(Value::from("cb-b-1710-owner-note")).expect("provenance"),
                // The owner's own note takes direct effect: `user_stated`
                // needs no explicit auto permit, and the default manifest
                // already grants the human class Auto. Requesting anything
                // narrower would mint the very approval row this arm counts.
                ClaimApprovalStatus::Auto,
            );
            self.vault
                .batch()
                .claim_candidate(
                    &claim_id,
                    ClaimCandidate::new(
                        PEER_PREDICATE,
                        ClaimSubject::Entity(self.subject),
                        Value::from(value),
                        confidence,
                    ),
                    &envelope,
                    TimeRange {
                        start: PEER_NOW - 10,
                        end: PEER_NOW - 10,
                    },
                    PEER_NOW - 10,
                )
                .commit()
                .expect("the owner's own note lands");
            OwnerNote { claim_id }
        }

        /// Routes the contradiction through the EXISTING consolidation
        /// conflict path and returns `(surfacings, marker)` — no peer-specific
        /// review state is minted.
        pub(crate) fn detect_open_conflict(
            &self,
            candidate: &PromotionCandidate,
            note: EntityId,
        ) -> (usize, Option<EntityId>) {
            let prior = PriorHead {
                claim_id: note,
                body: self.claim(note),
            };
            let conflicts = detect_conflicts(std::slice::from_ref(candidate), &[prior])
                .expect("conflict detection runs");
            let marker = conflicts
                .first()
                .map(|conflict| conflict_open_marker_id(conflict, self.attempt));
            (conflicts.len(), marker)
        }

        pub(crate) fn surface_digest(
            &self,
            answer: &LandedPeerAnswer,
            claim_ref: EntityId,
            conflict_open_ref: Option<EntityId>,
        ) -> usize {
            let mut sink = CountingDigestSink::default();
            surface_peer_answer_digest(
                &mut sink,
                PeerTrustDigestLine {
                    consult_task_ref: answer.consult_task_ref,
                    answer_turn_ref: answer.answer_turn_ref,
                    claim_ref,
                    conflict_open_ref,
                },
            )
            .expect("the digest line is informational and always accepted");
            sink.lines.len()
        }

        /// Read-time resolution over the contradicted fact: the surfaceable
        /// active heads, ordered by the ordinary confidence weighting.
        pub(crate) fn read_ranked_heads(&self) -> Vec<EntityId> {
            let mut heads: Vec<(EntityId, f32)> = self
                .vault
                .claims_for_subject(&self.subject)
                .expect("read the subject's claims")
                .into_iter()
                .filter_map(|id| {
                    let body = self.claim(id);
                    let surfaceable = matches!(
                        body.approval,
                        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
                    ) && body.lifecycle == ClaimLifecycleStatus::Active
                        && !body.stale
                        && body.predicate == PEER_PREDICATE;
                    surfaceable.then_some((id, body.confidence))
                })
                .collect();
            heads.sort_by(|left, right| {
                right
                    .1
                    .partial_cmp(&left.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            heads.into_iter().map(|(id, _)| id).collect()
        }

        /// ONE superseding write corrects the wrong note.
        pub(crate) fn correct_with_supersession(
            &self,
            answer: &LandedPeerAnswer,
            wrong: EntityId,
            value: &str,
            confidence: f32,
        ) -> usize {
            let (outcome, _) = self.consolidate_peer_answer(answer, value, confidence, Some(wrong));
            assert_eq!(
                self.claim(wrong).lifecycle,
                ClaimLifecycleStatus::Superseded,
                "the wrong note is superseded, never deleted"
            );
            outcome.landed.len()
        }

        /// Attempts the SAME tool_output-lineage → generated restamp through
        /// every claim-write door an agent can reach. Each attempt is
        /// counted, and each must be refused by the central lineage check.
        pub(crate) fn attempt_forgery_through_every_exposed_write_path(
            &self,
        ) -> Vec<ForgeryAttempt> {
            let envelope = WriteEnvelope::new(
                WriteActor::new(self.owner, EdgeActorClass::Agent),
                // The forged label: first-person generated.
                ClaimSource::Generated,
                WriteProvenance::new(Value::from("cb-b-1710-forgery")).expect("provenance"),
                ClaimApprovalStatus::Proposed,
            );
            let occurred = TimeRange {
                start: PEER_NOW,
                end: PEER_NOW,
            };
            let forged_candidate = |seed: u8| {
                (
                    EntityId::from_bytes([seed; 16]).expect("forged claim id"),
                    ClaimCandidate::new(
                        PEER_PREDICATE,
                        ClaimSubject::Entity(self.subject),
                        Value::from("forged"),
                        0.9,
                    )
                    // ... over a lineage that says tool_output.
                    .with_scope(tool_output_lineage_scope()),
                )
            };

            let mut attempts = Vec::new();

            // 1. The targeted public claim door.
            let put_claim_id = EntityId::from_bytes([0xA8; 16]).expect("forged claim id");
            let mut body = ClaimBody::new(
                PEER_PREDICATE,
                ClaimSubject::Entity(self.subject),
                Value::from("forged"),
                0.9,
                ClaimApprovalStatus::Proposed,
                ClaimLifecycleStatus::Active,
            );
            body.source = Some(ClaimSource::Generated);
            body.scope = Some(tool_output_lineage_scope());
            attempts.push(ForgeryAttempt {
                claim_id: put_claim_id,
                rejected_for_lineage: is_lineage_rejection(
                    self.vault
                        .put_claim(&put_claim_id, &body, occurred, PEER_NOW)
                        .err(),
                ),
            });

            // 2. The public batch builder.
            let (batch_id, candidate) = forged_candidate(0xA9);
            attempts.push(ForgeryAttempt {
                claim_id: batch_id,
                rejected_for_lineage: is_lineage_rejection(
                    self.vault
                        .batch()
                        .claim_candidate(&batch_id, candidate, &envelope, occurred, PEER_NOW)
                        .commit()
                        .err(),
                ),
            });

            // 3. The transaction-composable batch builder.
            let (txn_id, candidate) = forged_candidate(0xAA);
            attempts.push(ForgeryAttempt {
                claim_id: txn_id,
                rejected_for_lineage: is_lineage_rejection(
                    self.vault
                        .with_write_txn(|wtxn| {
                            self.vault
                                .batch_in()
                                .claim_candidate(&txn_id, candidate, &envelope, occurred, PEER_NOW)
                                .apply(wtxn)
                        })
                        .err(),
                ),
            });

            // 4. The lexical-hint batch put.
            let (hint_id, candidate) = forged_candidate(0xAB);
            attempts.push(ForgeryAttempt {
                claim_id: hint_id,
                rejected_for_lineage: is_lineage_rejection(
                    self.vault
                        .batch()
                        .claim_candidate_with_lexical_hints(
                            &hint_id,
                            candidate,
                            &envelope,
                            occurred,
                            PEER_NOW,
                            &["employer"],
                        )
                        .commit()
                        .err(),
                ),
            });

            assert_eq!(
                attempts.len(),
                EXPOSED_AGENT_CLAIM_WRITE_PATHS,
                "every exposed agent write path is attempted, not a sample"
            );
            attempts
        }
    }

    /// The engine-owned taint stamp a forger has to carry to be believed —
    /// and the exact key the central validator reads.
    fn tool_output_lineage_scope() -> Value {
        Value::Map(vec![
            (
                Value::from("evidence_taint"),
                Value::from(ClaimSource::ToolOutput.as_str()),
            ),
            (Value::from("sensitivity"), Value::from("public")),
        ])
    }

    fn is_lineage_rejection(error: Option<oneiron::Error>) -> bool {
        error.is_some_and(|error| {
            error
                .to_string()
                .contains("claim source widens beyond evidence lineage")
        })
    }

    /// The typed chain read back off a landed claim's structured evidence.
    pub(crate) fn stored_chain(body: &ClaimBody) -> Vec<ConsolidationProvenanceHop> {
        let Some(Value::Map(evidence)) = &body.evidence else {
            panic!("a promoted claim carries the envelope evidence map");
        };
        let candidate_evidence = evidence
            .iter()
            .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
            .map(|(_, value)| value)
            .expect("candidate_evidence entry");
        decode_consolidation_evidence(candidate_evidence)
            .expect("the evidence envelope decodes")
            .expect("a consolidation claim carries the typed envelope")
            .chain
    }

    fn turn_body(text: &str) -> Vec<u8> {
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &Value::Map(vec![
                (Value::from("txt"), Value::from(text)),
                (Value::from("spkr"), Value::from("agent")),
            ]),
        )
        .expect("encode the turn body");
        body
    }

    fn put_entity(vault: &Vault, id: EntityId, entity_type: u8, body: &[u8]) {
        vault
            .put_entity(
                &id,
                entity_type,
                TimeRange {
                    start: PEER_NOW,
                    end: PEER_NOW,
                },
                PEER_NOW,
                body,
            )
            .expect("store the fixture entity");
    }

    /// Unused-kind tripwire: the hop vocabulary is a contract, so a kind that
    /// stops being constructible anywhere must fail loudly here.
    #[allow(dead_code)]
    const HOP_KINDS: [ConsolidationProvenanceHopKind; 4] = [
        ConsolidationProvenanceHopKind::AnswerTurn,
        ConsolidationProvenanceHopKind::ConsultTask,
        ConsolidationProvenanceHopKind::PeerActor,
        ConsolidationProvenanceHopKind::ResultArtifact,
    ];
}

/// The seeded team lead's stable logical id — a DATA lookup key, not an enum.
const TEAM_LEAD_LOGICAL_ID: &str = "sys.team_lead";
const LEAD_NOW: u64 = 1_800_000_000;
const PANEL_QUESTION_TEXT: &str = "which release note wording lands best?";
const PANEL_JUDGE_RUBRIC: &str = "rank the answers by clarity, then by accuracy";
const PANEL_SYNTHESIS_INSTRUCTIONS: &str = "merge the ranked answers into one reply";

/// Local ONE-1709 fixture support. Deliberately NOT in `cb_oracle_common`:
/// that surface is frozen additive-only, and nothing here is shared.
mod lead_fixture {
    use oneiron::agent_dispatch::{AGENT_DISPATCH_ATTEMPT_TYPE, decode_agent_dispatch_input};
    use oneiron::config::VaultConfig;
    use oneiron::dreamer_runner::decode_dreamer_attempt_payload;
    use oneiron::edge::EdgeActorClass;
    use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
    use oneiron::{
        AgentCeiling, AgentDefinition, AgentScope, AttemptId, AttemptQueue, ClaimApprovalStatus,
        ClaimLifecycleStatus, ClaimSource, EntityId, MemoryFacade, TaskCreateReceipt,
        TaskCreateSpec, TimeRange, Vault,
    };
    use rmpv::Value;

    /// The first-party actor the default policy manifest grants an Auto
    /// ceiling, so the ASKER's creates take direct effect.
    const OWNER_BYTES: [u8; 16] = [0xE1; 16];

    pub(crate) struct LeadFixture {
        _dir: tempfile::TempDir,
        pub(crate) vault: Vault,
        pub(crate) owner: EntityId,
        /// A worker row narrower than the lead: Proposed under an Auto lead.
        pub(crate) worker_a: EntityId,
        pub(crate) worker_b: EntityId,
        /// A helper row WIDER than a Proposed worker — the clamp's live target.
        pub(crate) helper_auto: EntityId,
    }

    impl LeadFixture {
        pub(crate) fn open() -> Self {
            let dir = tempfile::tempdir().expect("temporary vault directory");
            let mut config = VaultConfig::device();
            config.map_size = 32 * 1024 * 1024;
            config.dimensions = 4;
            config.embedding_model = None;
            let vault = Vault::open(dir.path(), config).expect("open the fixture vault");
            let owner = EntityId::from_bytes(OWNER_BYTES).expect("owner id");
            put_entity(&vault, owner, ENTITY_TYPE_PERSON, b"owner");

            let worker_a = put_row(&vault, 0xE5, "worker.a", AgentCeiling::Proposed);
            let worker_b = put_row(&vault, 0xE6, "worker.b", AgentCeiling::Proposed);
            let helper_auto = put_row(&vault, 0xE7, "helper.wide", AgentCeiling::Auto);

            Self {
                _dir: dir,
                vault,
                owner,
                worker_a,
                worker_b,
                helper_auto,
            }
        }

        pub(crate) fn owner_facade(&self) -> MemoryFacade<'_> {
            self.vault.memory_facade(self.owner, EdgeActorClass::Agent)
        }

        pub(crate) fn agent_facade(&self, agent_def_ref: EntityId) -> MemoryFacade<'_> {
            self.vault
                .memory_facade(agent_def_ref, EdgeActorClass::Agent)
        }

        pub(crate) fn peer_facade(&self, actor_ref: EntityId) -> MemoryFacade<'_> {
            self.vault.memory_facade(actor_ref, EdgeActorClass::Agent)
        }

        /// Pins WHY every TASK below is minted through the owner facade with
        /// `owner_ref = lead`, rather than by the lead actor itself.
        ///
        /// A seeded agent-definition row is not self-authorizing: its effective
        /// create ceiling is `definition ∧ manifest`, and a fresh vault's
        /// default manifest grants `agent`-class Auto to exactly one actor ref
        /// — the first-party connector. Installing an owner manifest that
        /// grants the lead row Auto is a control-plane write with NO public
        /// door, and ONE-1709 deliberately opens none. So the lead's own
        /// `tasks.create` PARKS, which this asserts rather than hides. Task
        /// OWNERSHIP still lands on the lead, so the lead remains the execution
        /// writer that collects the results and delivers the report — and the
        /// behaviour under test (attenuation, depth, projection, panel refs) is
        /// independent of which actor minted the row.
        pub(crate) fn assert_lead_create_is_owner_granted(&self, lead_ref: EntityId) {
            let parked = self
                .agent_facade(lead_ref)
                .tasks_create(&TaskCreateSpec::new(
                    Value::Nil,
                    Some("ungranted".to_owned()),
                    None,
                    Some(super::LEAD_NOW),
                ))
                .expect("an ungranted create parks rather than failing");
            assert_eq!(parked.approval, ClaimApprovalStatus::Proposed);
            assert!(!parked.effected);
            assert_eq!(parked.task_ref, None);
        }

        /// Mints one TASK as the granted owner, OWNED by `owner_ref`.
        pub(crate) fn create_owned_task(
            &self,
            owner_ref: EntityId,
            mut spec: TaskCreateSpec,
        ) -> TaskCreateReceipt {
            spec.owner_ref = Some(owner_ref);
            self.owner_facade()
                .tasks_create(&spec)
                .expect("the granted owner mints the task")
        }

        pub(crate) fn person(&self, seed: u8, label: &str) -> EntityId {
            let id = EntityId::from_bytes([seed; 16]).expect("person id");
            put_entity(&self.vault, id, ENTITY_TYPE_PERSON, label.as_bytes());
            id
        }

        /// The durable TURN carrying the panel's free-form question. The TASK
        /// payload only ever names it.
        pub(crate) fn question_turn(&self) -> EntityId {
            let id = EntityId::from_bytes([0xCF; 16]).expect("question turn id");
            put_entity(
                &self.vault,
                id,
                ENTITY_TYPE_TURN,
                turn_body(super::PANEL_QUESTION_TEXT).as_slice(),
            );
            id
        }

        /// A durable result artifact. A `result_ref` exists only once its work
        /// is done, which is what makes "after settlement" structural.
        pub(crate) fn result_turn(&self, seed: u8) -> EntityId {
            let id = EntityId::from_bytes([seed; 16]).expect("result turn id");
            put_entity(
                &self.vault,
                id,
                ENTITY_TYPE_TURN,
                turn_body("result").as_slice(),
            );
            id
        }

        pub(crate) fn attempt_hex(&self, attempt: AttemptId) -> String {
            attempt
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        }

        pub(crate) fn run_id_of(&self, attempt: AttemptId) -> Option<String> {
            AttemptQueue::new(&self.vault)
                .get(attempt)
                .expect("read the attempt")
                .expect("the attempt exists")
                .run_id
        }

        pub(crate) fn persisted_depth(&self, attempt: AttemptId) -> Option<u8> {
            let record = AttemptQueue::new(&self.vault)
                .get(attempt)
                .expect("read the attempt")
                .expect("the attempt exists");
            let payload =
                decode_dreamer_attempt_payload(&record.payload).expect("decode the payload");
            assert_eq!(payload.attempt_type, AGENT_DISPATCH_ATTEMPT_TYPE);
            decode_agent_dispatch_input(&payload.input)
                .expect("decode the dispatch input")
                .depth_remaining
        }

        /// The settled `result_ref` on a TASK, read off the persisted body.
        pub(crate) fn terminal_result_ref(&self, task_ref: EntityId) -> Option<EntityId> {
            let body = self
                .vault
                .get(&task_ref)
                .expect("read the task body")
                .expect("the task exists");
            let mut cursor = body.as_slice();
            let value = rmpv::decode::read_value(&mut cursor).expect("decode the task body");
            let state = map_get(&value, "state")?;
            let terminal = map_get(state, "terminal")?;
            let result = map_get(terminal, "result_ref")?;
            EntityId::from_hex(result.as_str()?).ok()
        }

        /// Whether a TASK's persisted body mentions `needle` in ANY encoding —
        /// raw bytes or lower-case hex. Blindness and ref-only are structural
        /// claims about the stored row, not about the caller's intent.
        pub(crate) fn body_mentions(&self, task_ref: EntityId, needle: &[u8]) -> bool {
            let body = self
                .vault
                .get(&task_ref)
                .expect("read the task body")
                .expect("the task exists");
            let hex: String = needle.iter().map(|byte| format!("{byte:02x}")).collect();
            contains(&body, needle) || contains(&body, hex.as_bytes())
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    fn map_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
        let Value::Map(entries) = value else {
            return None;
        };
        entries
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .map(|(_, found)| found)
    }

    fn turn_body(text: &str) -> Vec<u8> {
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &Value::Map(vec![(Value::from("txt"), Value::from(text))]),
        )
        .expect("encode the turn body");
        body
    }

    fn put_entity(vault: &Vault, id: EntityId, entity_type: u8, body: &[u8]) {
        vault
            .put_entity(
                &id,
                entity_type,
                TimeRange {
                    start: super::LEAD_NOW,
                    end: super::LEAD_NOW,
                },
                super::LEAD_NOW,
                body,
            )
            .expect("store the fixture entity");
    }

    /// An ordinary user-authored AGENT_DEF row at the requested ceiling.
    fn put_row(vault: &Vault, seed: u8, agent_id: &str, ceiling: AgentCeiling) -> EntityId {
        let id = EntityId::from_bytes([seed; 16]).expect("agent definition id");
        vault
            .put_agent_definition(
                &id,
                &AgentDefinition::new(
                    agent_id,
                    "cb oracle worker fixture",
                    "1",
                    None,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    None,
                    AgentScope::All,
                    ceiling,
                    None,
                    ClaimApprovalStatus::Approved,
                    ClaimLifecycleStatus::Active,
                    ClaimSource::UserStated,
                    1.0,
                    false,
                    true,
                    Value::Map(vec![(Value::from("fixture"), Value::from(agent_id))]),
                    None,
                    true,
                    None,
                ),
                TimeRange {
                    start: super::LEAD_NOW,
                    end: super::LEAD_NOW,
                },
                super::LEAD_NOW,
            )
            .expect("store the worker row");
        id
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
        use oneiron::agent_run_status::{AgentRunStatus, validate_agent_run_status_transition};
        let states = AgentRunStatus::RATIFIED_FLOW
            .iter()
            .map(|status| status.as_str().to_owned())
            .collect();
        let attempts = [
            (AgentRunStatus::Spawned, AgentRunStatus::Archived),
            (AgentRunStatus::Spawned, AgentRunStatus::Delivered),
            (AgentRunStatus::Working, AgentRunStatus::Spawned),
            (AgentRunStatus::Delivered, AgentRunStatus::Working),
            (AgentRunStatus::Archived, AgentRunStatus::Working),
        ];
        let rejected = attempts
            .iter()
            .filter(|(from, to)| validate_agent_run_status_transition(*from, *to).is_err())
            .count();
        AgentRunStatusContract {
            states,
            illegal_transitions_attempted: attempts.len(),
            illegal_transitions_rejected: rejected,
            illegal_transitions_accepted: attempts.len() - rejected,
        }
    }

    /// ONE-1711 · 08b registry: AgentRunStatus is exactly spawned → working
    /// → needs_input → delivered → archived; every out-of-order jump in the
    /// fixture matrix rejects.
    #[test]
    fn agent_run_status_contract_is_five_states_in_order() {
        use oneiron::agent_run_status::{
            AgentRunStatus, ExecutorTerminalCause, project_abandoned_terminal,
            project_agent_run_status, validate_agent_run_status_transition,
        };

        let contract = arm_agent_run_status_contract();
        assert_eq!(contract.states.len(), 5);
        assert_eq!(
            contract.states,
            ["spawned", "working", "needs_input", "delivered", "archived"]
        );
        assert_eq!(contract.illegal_transitions_attempted, 5);
        assert_eq!(contract.illegal_transitions_rejected, 5);
        assert_eq!(contract.illegal_transitions_accepted, 0);

        assert_eq!(
            AgentRunStatus::TERMINAL,
            [
                AgentRunStatus::Archived,
                AgentRunStatus::Failed,
                AgentRunStatus::Abandoned,
            ]
        );
        for status in AgentRunStatus::TERMINAL {
            assert!(status.is_terminal());
        }
        for status in [
            AgentRunStatus::Spawned,
            AgentRunStatus::Working,
            AgentRunStatus::NeedsInput,
            AgentRunStatus::Delivered,
        ] {
            assert!(!status.is_terminal());
        }
        assert!(
            validate_agent_run_status_transition(
                AgentRunStatus::Delivered,
                AgentRunStatus::Archived
            )
            .is_ok()
        );
        assert!(
            validate_agent_run_status_transition(AgentRunStatus::Failed, AgentRunStatus::Working)
                .is_err()
        );
        assert!(
            validate_agent_run_status_transition(
                AgentRunStatus::Abandoned,
                AgentRunStatus::Working
            )
            .is_err()
        );
        assert_eq!(
            project_agent_run_status(oneiron::run_tree::RunTreeStatus::Failed),
            AgentRunStatus::Failed
        );
        assert_eq!(
            project_agent_run_status(oneiron::run_tree::RunTreeStatus::Cancelled),
            AgentRunStatus::Failed
        );
        assert_eq!(
            project_abandoned_terminal(ExecutorTerminalCause::LeaseReclaimed),
            Some(AgentRunStatus::Abandoned)
        );
        assert_eq!(
            project_abandoned_terminal(ExecutorTerminalCause::NeverAnswered),
            Some(AgentRunStatus::Abandoned)
        );
        assert_eq!(
            project_abandoned_terminal(ExecutorTerminalCause::ExecutionFailed),
            None
        );
        assert_eq!(
            project_abandoned_terminal(ExecutorTerminalCause::Cancelled),
            None
        );
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
        use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
        use oneiron::agent_run_status::{AgentRunStatus, project_agent_run_status};
        use oneiron::context_board::{ChildAgentPresence, render_agents_section};
        use oneiron::dreamer_runner::{DreamerRunnerStore, ParkDreamerAttempt};
        use oneiron::llm::{
            DurableStepContext, consume_trap_signal, open_trap, register_wait,
            trap_for_durable_wait, trap_park_owner,
        };
        use oneiron::{
            AttemptQueue, EdgeActorClass, EntityId, SelfDurableWait, SelfDurableWaitReason,
            SelfEffect, Vault, VaultConfig, WriteActor,
        };

        let dir = tempfile::tempdir().expect("temp dir");
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Vault::open(dir.path(), config).expect("open vault");
        let dispatcher = AgentDispatcher::new(&vault);
        let AgentDispatchOutcome::Dispatched(status) = dispatcher
            .dispatch_default_base(None, None, None, 1)
            .expect("dispatch")
        else {
            panic!("expected fresh dispatch")
        };
        let attempt_id = status.attempt.id;
        let step_hash = [0x71u8; 32];
        let subject = EntityId::from_bytes([0x42; 16]).expect("subject");
        vault
            .put_entity(
                &subject,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"agent subject",
            )
            .expect("subject entity");
        let wait = SelfDurableWait {
            wait_id: subject,
            effect: SelfEffect::AskHuman,
            reason: SelfDurableWaitReason::HumanInput,
            prompt: Some("decide".to_owned()),
        };
        let ctx = DurableStepContext {
            vault: &vault,
            attempt_id,
            run_id: Some("agent-run".to_owned()),
            envelope_actor: WriteActor::new(subject, EdgeActorClass::Agent),
            subject,
            deadline: None,
            now_ms: 1,
        };
        let trap = open_trap(
            &vault,
            &ctx,
            trap_for_durable_wait(&wait, step_hash),
            step_hash,
            "human response",
        )
        .expect("open trap");
        let queue = AttemptQueue::new(&vault);
        queue
            .claim(oneiron::attempt_queue::ClaimAttempt {
                lease_owner: "agent-worker".to_owned(),
                now: 2,
            })
            .expect("claim dispatched attempt");
        let runner = DreamerRunnerStore::new(&vault);
        runner
            .park_attempt(ParkDreamerAttempt {
                attempt_id,
                reason: "human response".to_owned(),
                park_owner: trap_park_owner(&trap.trap_claim_id),
                now: 1,
            })
            .expect("park");
        register_wait(&vault, &trap, 1).expect("register wait");
        let is_parked = runner
            .parked_attempt(attempt_id)
            .expect("parked observation")
            .is_some();
        assert!(is_parked);
        let record = AttemptQueue::new(&vault)
            .get(attempt_id)
            .expect("read attempt")
            .expect("attempt exists");
        let node = oneiron::run_tree::render_run_tree(vec![record])
            .expect("render tree")
            .roots
            .remove(0);
        let presence = ChildAgentPresence::from_run_tree_node_with_park(&node, is_parked)
            .expect("parked child presence");
        let waiting = render_agents_section(&[presence], &[]);
        let runs_in_needs_input_after_ask = waiting
            .rows
            .iter()
            .filter(|row| row.line.ends_with(AgentRunStatus::NeedsInput.as_str()))
            .count();
        let signal = oneiron::llm::send_trap_signal(&vault, &trap.trap_claim_id, step_hash, 2)
            .expect("send signal");
        let _ = signal;
        consume_trap_signal(&vault, &runner, &trap, 3).expect("consume signal");
        let is_parked = runner
            .parked_attempt(attempt_id)
            .expect("parked observation")
            .is_some();
        assert!(!is_parked);
        let record = AttemptQueue::new(&vault)
            .get(attempt_id)
            .expect("read resumed attempt")
            .expect("resumed attempt");
        let node = oneiron::run_tree::render_run_tree(vec![record])
            .expect("render resumed tree")
            .roots
            .remove(0);
        let presence = ChildAgentPresence::from_run_tree_node_with_park(&node, is_parked)
            .expect("working child presence");
        let resumed = render_agents_section(&[presence], &[]);
        let resumed_to_working_after_input = resumed
            .rows
            .iter()
            .filter(|row| row.line.ends_with(AgentRunStatus::Working.as_str()))
            .count();
        let completed_record = AttemptQueue::new(&vault)
            .get(attempt_id)
            .expect("read completion attempt")
            .expect("completion attempt");
        AttemptQueue::new(&vault)
            .complete(oneiron::attempt_queue::CompleteAttempt {
                id: attempt_id,
                lease_owner: "agent-worker".to_owned(),
                attempt_count: completed_record.attempt_count,
                now: 4,
            })
            .expect("complete resumed attempt");
        let record = AttemptQueue::new(&vault)
            .get(attempt_id)
            .expect("read completed attempt")
            .expect("completed attempt");
        assert_eq!(
            record.state,
            oneiron::attempt_queue::AttemptState::Completed
        );
        let node = oneiron::run_tree::render_run_tree(vec![record])
            .expect("render completed tree")
            .roots
            .remove(0);
        assert_eq!(node.status, oneiron::run_tree::RunTreeStatus::Completed);
        let delivered_after_resume =
            usize::from(project_agent_run_status(node.status) == AgentRunStatus::Delivered);
        NeedsInputRoundTrip {
            runs_in_needs_input_after_ask,
            resumed_to_working_after_input,
            delivered_after_resume,
        }
    }

    /// ONE-1711 · 08b §4.4 + registry: the needs_input round-trip — ask,
    /// owner input, resume to working, deliver.
    #[test]
    fn needs_input_round_trip_resumes_and_delivers() {
        let round_trip = arm_needs_input_round_trip();
        assert_eq!(round_trip.runs_in_needs_input_after_ask, 1);
        assert_eq!(round_trip.resumed_to_working_after_input, 1);
        assert_eq!(round_trip.delivered_after_resume, 1);
    }
}
