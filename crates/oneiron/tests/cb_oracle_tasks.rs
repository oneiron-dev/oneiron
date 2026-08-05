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
// CB-T — TASKS section (ONE-1694 renderer · ONE-1695 task_ref/fold-up ·
//        ONE-1696 tasks.* verbs)
// ════════════════════════════════════════════════════════════════════════
mod cb_t {
    /// One rendered TASKS-section row, decomposed for assertion.
    struct TasksRow {
        /// Stable id of the intent task or bare job (`tk_*` / `jb_*`).
        id: String,
        /// Exact rendered text of the row.
        line: String,
        /// One of: running / scheduled / queued / done / failed.
        status: String,
        /// True for a TASK-entity intent row, false for a bare system job.
        is_intent: bool,
        /// Realizing jobs folded under this intent row (0 for bare jobs).
        folded_job_count: usize,
    }

    struct TasksSectionRender {
        rows: Vec<TasksRow>,
    }

    /// ONE-1694 fixture: TASK entities `tk_a` (running, 2 realizing jobs),
    /// `tk_b` (scheduled, no jobs), `tk_q` (queued, no jobs), `tk_d` (done,
    /// no jobs) + bare system job `jb_c` (running), read via the SURF-005
    /// observe API; render the TASKS section, collapsed.
    fn arm_render_tasks_section() -> TasksSectionRender {
        use oneiron::context_board::{
            JobPresence, TaskBoardStatus, TaskIntentPresence, render_tasks_section,
        };
        use oneiron::run_tree::{RunTreeNode, RunTreeStatus, RunTreeTimestamps};

        let observed_running_job = |id: &str| RunTreeNode {
            attempt_id: id.to_owned(),
            run_id: None,
            parent_id: None,
            worker_kind: "sync".to_owned(),
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
        let realizing_nodes = [observed_running_job("jb_1"), observed_running_job("jb_2")];
        let realizing_jobs: Vec<JobPresence> = realizing_nodes
            .iter()
            .map(|node| {
                JobPresence::from_run_tree_node(node)
                    .expect("running observed job must reach the board")
            })
            .collect();

        let intent = |id: &str, status: TaskBoardStatus| TaskIntentPresence {
            id: id.to_owned(),
            status,
            label: None,
            acked: false,
            realizing_jobs: Vec::new(),
        };
        let mut tk_a = intent("tk_a", TaskBoardStatus::Running);
        tk_a.realizing_jobs = realizing_jobs;
        let intents = [
            tk_a,
            intent("tk_b", TaskBoardStatus::Scheduled),
            intent("tk_q", TaskBoardStatus::Queued),
            intent("tk_d", TaskBoardStatus::Done),
        ];
        let bare_node = observed_running_job("jb_c");
        let bare_jobs = [JobPresence::from_run_tree_node(&bare_node)
            .expect("running observed bare job must reach the board")];

        let section = render_tasks_section(&intents, &bare_jobs);
        TasksSectionRender {
            rows: section
                .rows
                .into_iter()
                .map(|row| TasksRow {
                    id: row.id,
                    line: row.line,
                    status: row.status.as_str().to_owned(),
                    is_intent: row.is_intent,
                    folded_job_count: row.folded_job_count,
                })
                .collect(),
        }
    }

    /// ONE-1694 · 08b §3 · owner render law: one-line rows; intent rows fold
    /// realizing jobs under themselves; bare system jobs render as-is.
    /// Ticket AC verbatim: "Status axis: running / scheduled / queued /
    /// done / failed" — every state in the fixture is asserted by row
    /// identity (F6/G5), failed is owned by the failed-lane test below.
    #[test]
    fn tasks_section_renders_one_line_rows_over_intent_and_bare_jobs() {
        let section = arm_render_tasks_section();
        assert_eq!(section.rows.len(), 5);
        let one_liners = section
            .rows
            .iter()
            .filter(|r| r.line.lines().count() == 1)
            .count();
        assert_eq!(one_liners, 5);
        assert_eq!(section.rows.iter().filter(|r| r.is_intent).count(), 4);
        for row in &section.rows {
            assert_eq!(
                row.line
                    .split_whitespace()
                    .filter(|token| *token == row.status)
                    .count(),
                1
            );
        }
        for (id, status) in [("tk_b", "scheduled"), ("tk_q", "queued"), ("tk_d", "done")] {
            let row = section
                .rows
                .iter()
                .find(|r| r.id == id)
                .unwrap_or_else(|| panic!("{id} row rendered"));
            assert_eq!(row.status, status);
            assert!(row.is_intent);
            assert_eq!(row.folded_job_count, 0);
        }
        let tk_a = section
            .rows
            .iter()
            .find(|r| r.id == "tk_a")
            .expect("tk_a row");
        assert_eq!(tk_a.status, "running");
        assert!(tk_a.is_intent);
        assert_eq!(tk_a.folded_job_count, 2);
        assert_eq!(
            tk_a.line
                .split_whitespace()
                .filter(|token| *token == "running")
                .count(),
            1
        );
        assert_eq!(
            tk_a.line
                .split_whitespace()
                .filter(|token| *token == "jobs=2")
                .count(),
            1
        );
        let jb_c = section
            .rows
            .iter()
            .find(|r| r.id == "jb_c")
            .expect("jb_c row");
        assert_eq!(jb_c.status, "running");
        assert!(!jb_c.is_intent);
        assert_eq!(jb_c.folded_job_count, 0);
        assert_eq!(
            jb_c.line
                .split_whitespace()
                .filter(|token| *token == "running")
                .count(),
            1
        );
    }

    /// ONE-1694 fixture: two FAILED tasks — `tk_failed_unacked` (never acked)
    /// and `tk_failed_acked` (acked via `tasks.ack`); render the TASKS
    /// section and return only its failed-lane rows.
    fn arm_render_failed_lane() -> TasksSectionRender {
        use oneiron::context_board::{
            TaskBoardStatus, TaskIntentPresence, failed_lane, render_tasks_section,
        };

        let failed = |id: &str, acked: bool| TaskIntentPresence {
            id: id.to_owned(),
            status: TaskBoardStatus::Failed,
            label: None,
            acked,
            realizing_jobs: Vec::new(),
        };
        let section = render_tasks_section(
            &[
                failed("tk_failed_unacked", false),
                failed("tk_failed_acked", true),
            ],
            &[],
        );
        TasksSectionRender {
            rows: failed_lane(&section)
                .into_iter()
                .map(|row| TasksRow {
                    id: row.id.clone(),
                    line: row.line.clone(),
                    status: row.status.as_str().to_owned(),
                    is_intent: row.is_intent,
                    folded_job_count: row.folded_job_count,
                })
                .collect(),
        }
    }

    /// ONE-1694 · 08b §3: failed rows stay surfaced until acked; an acked
    /// failed row leaves the lane.
    #[test]
    fn failed_rows_stay_surfaced_until_acked() {
        let lane = arm_render_failed_lane();
        assert_eq!(lane.rows.len(), 1);
        assert_eq!(lane.rows[0].id, "tk_failed_unacked");
        assert_eq!(lane.rows[0].status, "failed");
    }

    /// Rendered lines after `board.expand tasks.tk_a`.
    struct ExpandedTask {
        lines: Vec<String>,
    }

    /// ONE-1694 fixture: `tk_a` (running, 2 realizing jobs `jb_1`/`jb_2`);
    /// apply `board.expand tasks.tk_a` and return the expanded rendering.
    fn arm_expand_task_with_two_jobs() -> ExpandedTask {
        use oneiron::context_board::{
            JobPresence, TaskBoardStatus, TaskIntentPresence, expand_task,
        };

        let job = |id: &str| JobPresence {
            id: id.to_owned(),
            kind: "sync".to_owned(),
            status: TaskBoardStatus::Running,
        };
        let tk_a = TaskIntentPresence {
            id: "tk_a".to_owned(),
            status: TaskBoardStatus::Running,
            label: None,
            acked: false,
            realizing_jobs: vec![job("jb_1"), job("jb_2")],
        };
        ExpandedTask {
            lines: expand_task(&tk_a),
        }
    }

    /// ONE-1694 · 08b §3 · owner render law: expand unfolds the realizing
    /// jobs UNDER the intent row — exact rows and order: the `tk_a` intent
    /// line first, then `jb_1`, then `jb_2` (G7).
    #[test]
    fn expand_unfolds_realizing_jobs_under_intent_row() {
        let expanded = arm_expand_task_with_two_jobs();
        assert_eq!(expanded.lines.len(), 3);
        assert!(expanded.lines[0].contains("tk_a"));
        assert!(expanded.lines[1].contains("jb_1"));
        assert!(expanded.lines[2].contains("jb_2"));
        assert_eq!(
            expanded.lines[1]
                .split_whitespace()
                .filter(|token| *token == "running")
                .count(),
            1
        );
        assert_eq!(
            expanded.lines[2]
                .split_whitespace()
                .filter(|token| *token == "running")
                .count(),
            1
        );
        let job_lines = expanded.lines.iter().filter(|l| l.contains("jb_")).count();
        assert_eq!(job_lines, 2);
    }

    /// Observed task status under three fold-up sub-fixtures (same task,
    /// two realizing jobs each time).
    struct FoldUpOutcomes {
        /// Jobs {done, running} → task status.
        status_one_running: String,
        /// Jobs {done, done} → task status.
        status_all_done: String,
        /// Jobs {done, failed} → task status.
        status_one_failed: String,
    }

    /// ONE-1695 fixture: one TASK entity with 2 realizing jobs; drive the
    /// jobs through the three terminal mixes and observe the folded status.
    fn arm_job_status_fold_up() -> FoldUpOutcomes {
        use oneiron::context_board::{JobPresence, TaskBoardStatus, fold_up_status};

        let fold = |statuses: [TaskBoardStatus; 2]| {
            let jobs = statuses.map(|status| JobPresence {
                id: "job".to_owned(),
                kind: "sync".to_owned(),
                status,
            });
            fold_up_status(&jobs)
                .expect("two realizing jobs must fold to one status")
                .as_str()
                .to_owned()
        };

        FoldUpOutcomes {
            status_one_running: fold([TaskBoardStatus::Done, TaskBoardStatus::Running]),
            status_all_done: fold([TaskBoardStatus::Done, TaskBoardStatus::Done]),
            status_one_failed: fold([TaskBoardStatus::Done, TaskBoardStatus::Failed]),
        }
    }

    /// ONE-1695 · 08b §3/§9: job statuses fold up into the owning task's
    /// board status.
    #[test]
    fn job_statuses_fold_up_to_owning_task_status() {
        let fold = arm_job_status_fold_up();
        assert_eq!(fold.status_one_running, "running");
        assert_eq!(fold.status_all_done, "done");
        assert_eq!(fold.status_one_failed, "failed");
    }

    /// Storage-layer separation counts for one intent task + one realizing job.
    struct TaskJobStorageSplit {
        /// TASK entities present in the sync export (CRDT-synced intent).
        synced_task_entities: usize,
        /// JobQueue rows present in the sync export (must stay node-local).
        synced_job_rows: usize,
        /// Local jobs carrying a `task_ref` backlink to the owning task.
        local_jobs_with_task_ref: usize,
        /// The `task_ref` VALUE carried by the realizing job (must name the
        /// OWNING task, not merely any task — F7).
        job_task_ref: String,
        /// The owning TASK entity's real id (hex) the fixture stored it under;
        /// the job's backlink must equal THIS, proving linkage to the real owner.
        owning_task_hex: String,
    }

    /// ONE-1695 fixture: `tasks`-layer TASK entity `tk_owner` realized by one
    /// JobQueue job carrying `task_ref`; produce a sync export and count both
    /// layers; observe the job's stored `task_ref` value.
    #[cfg(feature = "sync")]
    fn arm_task_job_storage_split() -> TaskJobStorageSplit {
        use loro::{ExportMode, LoroDoc};
        use oneiron::attempt_queue::{AttemptQueue, EnqueueAttempt};
        use oneiron::habit::TaskRole;
        use oneiron::registry::ENTITY_TYPE_TASK;
        use oneiron::sync::schema::create_window_doc;
        use oneiron::sync::types::WindowKey;
        use oneiron::sync::window::reverse_rematerialize;
        use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
        use rmpv::Value;

        let temp = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open(temp.path(), VaultConfig::device()).expect("open fixture vault");
        let task_id = EntityId::from_bytes([0x74; 16]).expect("task id from 16 bytes");
        let learned_at = 1_772_400_000;
        // ENTITY_TYPE_TASK bodies are validated as a `{ "role": <byte> }` map; the
        // node-local backlink lives on the job below, not in this entity body.
        let mut task_body = Vec::new();
        rmpv::encode::write_value(
            &mut task_body,
            &Value::Map(vec![(
                Value::from("role"),
                Value::from(TaskRole::Task.role_byte()),
            )]),
        )
        .expect("encode owning task body");
        vault
            .put_entity(
                &task_id,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                &task_body,
            )
            .expect("store owning task entity");

        // Bind the job's backlink to the OWNING task's real id (not an unrelated
        // literal), so the fixture proves the job links to its actual owner.
        let owning_task_hex = task_id.to_hex();
        let queue = AttemptQueue::new(&vault);
        queue
            .enqueue_with_task_ref(
                EnqueueAttempt {
                    kind: "sync".to_owned(),
                    payload: b"local-job".to_vec(),
                    dedupe_key: None,
                    run_id: None,
                    now: learned_at,
                },
                Some(owning_task_hex.clone()),
            )
            .expect("enqueue realizing job");

        let window_key = WindowKey::new("2026-03");
        let sync_doc = create_window_doc("test-user", &window_key);
        reverse_rematerialize(&vault, &sync_doc, &window_key)
            .expect("mirror local entities into sync document");
        let snapshot = sync_doc
            .export(ExportMode::Snapshot)
            .expect("export sync snapshot");
        // Node-local proof: the job row never enters the sync export. Scan for the
        // job's unique payload — NOT its task_ref, which equals the owning task's
        // id and so legitimately appears as the synced entity id.
        let job_payload: &[u8] = b"local-job";
        assert!(
            !snapshot
                .windows(job_payload.len())
                .any(|window| window == job_payload),
            "node-local job row leaked into the sync export",
        );
        let exported_doc = LoroDoc::from_snapshot(&snapshot).expect("read sync snapshot");

        let exported_entities = exported_doc.get_map("entities");
        let synced_task_entities = vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("list local task entities")
            .iter()
            .filter(|id| exported_entities.get(id.to_hex().as_str()).is_some())
            .count();
        let mut synced_job_rows = 0;
        exported_doc
            .get_map("attempt_records")
            .for_each(|_, _| synced_job_rows += 1);

        let local_jobs = queue.list().expect("list local jobs");
        let local_jobs_with_task_ref = local_jobs
            .iter()
            .filter(|job| job.task_ref.is_some())
            .count();
        let job_task_ref = local_jobs
            .first()
            .and_then(|job| job.task_ref.clone())
            .expect("realizing job carries owning task backlink");

        TaskJobStorageSplit {
            synced_task_entities,
            synced_job_rows,
            local_jobs_with_task_ref,
            job_task_ref,
            owning_task_hex,
        }
    }

    /// ONE-1695 · 08b §3: consolidation at the interface, never at storage —
    /// the TASK entity syncs, the lease-bearing job does not; the link is the
    /// `task_ref` backlink on the job, pointing at its OWNER (ticket: "jobs
    /// carry `task_ref`, and job statuses fold up into the owning task").
    #[cfg(feature = "sync")]
    #[test]
    fn task_syncs_job_stays_node_local_linked_by_task_ref() {
        let split = arm_task_job_storage_split();
        assert_eq!(split.synced_task_entities, 1);
        assert_eq!(split.synced_job_rows, 0);
        assert_eq!(split.local_jobs_with_task_ref, 1);
        assert_eq!(
            split.job_task_ref, split.owning_task_hex,
            "job backlink must name the owning task's real id"
        );
    }

    /// The agent-facing tasks verb surface after one `tasks.create` call.
    struct TasksVerbSurface {
        /// Full agent-visible tasks verb family, sorted.
        verbs: Vec<String>,
        /// TASK entities minted by the one `tasks.create(spec)` call.
        create_minted_task_entities: usize,
        /// Agent-visible verbs that touch the JobQueue directly.
        agent_visible_jobqueue_verbs: usize,
    }

    /// ONE-1696 fixture: enumerate the agent-visible tasks verb family, then
    /// issue one own-agent `tasks.create(spec)` inside the allowed-set.
    fn arm_tasks_verb_surface() -> TasksVerbSurface {
        use oneiron::config::VaultConfig;
        use oneiron::edge::EdgeActorClass;
        use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
        use oneiron::{EntityId, TASKS_VERBS, TaskCreateSpec, TasksVerb, TimeRange, Vault};

        let temp = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open(temp.path(), VaultConfig::default()).expect("open fixture vault");
        let actor = EntityId::from_bytes([0xE1; 16]).expect("own agent id");
        vault
            .put_entity(
                &actor,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"own-agent",
            )
            .expect("store own agent");
        let before = vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("list task entities before create")
            .len();
        let created = vault
            .memory_facade(actor, EdgeActorClass::Agent)
            .tasks_create(&TaskCreateSpec {
                spec: rmpv::Value::from("oracle-task"),
                label: None,
                owner_ref: None,
                now: Some(120),
            })
            .expect("own tasks.create effects");
        assert_eq!(usize::from(created.effected), 1);
        let after = vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("list task entities after create")
            .len();
        let verbs: Vec<String> = TasksVerb::ALL
            .map(TasksVerb::as_str)
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(verbs, TASKS_VERBS);
        let agent_visible_jobqueue_verbs = verbs
            .iter()
            .filter(|verb| {
                verb.contains("queue") || verb.contains("claim") || verb.contains("lease")
            })
            .count();

        TasksVerbSurface {
            verbs,
            create_minted_task_entities: after - before,
            agent_visible_jobqueue_verbs,
        }
    }

    /// ONE-1696 · 08b §3 (r9): the family is exactly create/check/expand/
    /// ack/cancel; `tasks.create` mints a TASK entity and the ENGINE decides
    /// realizing jobs — the agent never touches the JobQueue.
    #[test]
    fn tasks_verb_family_is_exactly_five_and_never_exposes_jobqueue() {
        let surface = arm_tasks_verb_surface();
        assert_eq!(surface.verbs.len(), 5);
        assert_eq!(
            surface.verbs,
            [
                "tasks.ack",
                "tasks.cancel",
                "tasks.check",
                "tasks.create",
                "tasks.expand"
            ]
        );
        assert_eq!(surface.create_minted_task_entities, 1);
        assert_eq!(surface.agent_visible_jobqueue_verbs, 0);
    }

    /// Foreign-create + own-burst authority observations.
    struct CreateAuthorityOutcome {
        /// Foreign-agent `tasks.create` calls that mutated state directly
        /// (must be none — propose-only).
        foreign_create_direct_effects: usize,
        /// Foreign-agent `tasks.create` calls surfaced as proposals.
        foreign_create_proposals: usize,
        /// Per-actor create rate limit the fixture configured (per window).
        configured_rate_limit: usize,
        /// Own-agent creates attempted inside one window.
        burst_creates_attempted: usize,
        /// Burst creates that took direct effect (must equal the limit).
        burst_creates_effected: usize,
        /// Burst overflow falling closed to proposals.
        burst_overflow_proposals: usize,
    }

    /// ONE-1696 fixture: a FOREIGN agent issues one `tasks.create`; then an
    /// OWN agent, with the per-actor create rate limit configured to 10 per
    /// window, issues 12 creates inside one window.
    fn arm_create_authority() -> CreateAuthorityOutcome {
        use oneiron::config::VaultConfig;
        use oneiron::edge::EdgeActorClass;
        use oneiron::registry::ENTITY_TYPE_PERSON;
        use oneiron::{EntityId, TaskCreateRateLimit, TaskCreateSpec, TimeRange, Vault};

        let temp = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open(temp.path(), VaultConfig::default()).expect("open fixture vault");
        let own = EntityId::from_bytes([0xE1; 16]).expect("own agent id");
        let foreign = EntityId::from_bytes([0xE2; 16]).expect("foreign agent id");
        for actor in [own, foreign] {
            vault
                .put_entity(
                    &actor,
                    ENTITY_TYPE_PERSON,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"agent",
                )
                .expect("store agent");
        }
        let configured_rate_limit = 10;
        let rate_limit = TaskCreateRateLimit {
            limit: configured_rate_limit,
            window_seconds: 60,
        };
        let spec = TaskCreateSpec {
            spec: rmpv::Value::from("oracle-task"),
            label: None,
            owner_ref: None,
            now: Some(120),
        };
        let foreign_create = vault
            .memory_facade(foreign, EdgeActorClass::Agent)
            .tasks_create_with_rate_limit(&spec, rate_limit)
            .expect("foreign tasks.create proposes");
        let burst_creates_attempted = 12;
        let own_facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let mut burst = Vec::new();
        for _ in 0..burst_creates_attempted {
            burst.push(
                own_facade
                    .tasks_create_with_rate_limit(&spec, rate_limit)
                    .expect("own burst create"),
            );
        }

        CreateAuthorityOutcome {
            foreign_create_direct_effects: usize::from(foreign_create.effected),
            foreign_create_proposals: usize::from(foreign_create.proposal_ref.is_some()),
            configured_rate_limit,
            burst_creates_attempted,
            burst_creates_effected: burst.iter().filter(|result| result.effected).count(),
            burst_overflow_proposals: burst
                .iter()
                .filter(|result| result.proposal_ref.is_some())
                .count(),
        }
    }

    /// ONE-1696 AC verbatim: "`tasks.create(spec)` — … Own-agent: free in
    /// allowed-set, rate-limited; foreign: propose-only" (F8/G2). Burst
    /// overflow fails closed to Proposed (08 §4 own-agent lane).
    #[test]
    fn foreign_tasks_create_is_propose_only_own_burst_fails_closed() {
        let outcome = arm_create_authority();
        assert_eq!(outcome.foreign_create_direct_effects, 0);
        assert_eq!(outcome.foreign_create_proposals, 1);
        assert_eq!(outcome.configured_rate_limit, 10);
        assert_eq!(outcome.burst_creates_attempted, 12);
        assert_eq!(
            outcome.burst_creates_effected,
            outcome.configured_rate_limit
        );
        assert_eq!(outcome.burst_overflow_proposals, 2);
    }

    /// Cancel semantics across the auto-approval ladder.
    struct CancelLadderOutcome {
        /// Ladder modes available on `tasks.cancel`, sorted.
        ladder_modes: Vec<String>,
        /// Mode in effect with no explicit policy set.
        default_mode: String,
        /// Gate decisions recorded for the own-task cancel (gate presence).
        gate_decisions_for_own_cancel: usize,
        /// Own-task Gate decisions whose recorded outcome is Allow.
        allow_gate_decisions_for_own_cancel: usize,
        /// Own-task cancels that took effect.
        own_cancel_effects: usize,
        /// Foreign-task cancels that took effect (must fail closed).
        foreign_cancel_effects: usize,
        /// Foreign-task cancels surfaced as proposals instead.
        foreign_cancel_proposals: usize,
    }

    /// ONE-1696 fixture: agent A owns `tk_own`; agent B owns `tk_other`.
    /// A cancels `tk_own` under the default ladder mode, then A attempts to
    /// cancel `tk_other`.
    fn arm_cancel_ladder() -> CancelLadderOutcome {
        use oneiron::config::VaultConfig;
        use oneiron::edge::EdgeActorClass;
        use oneiron::registry::ENTITY_TYPE_PERSON;
        use oneiron::{
            DEFAULT_TASK_CANCEL_MODE, EntityId, GrantMintIntent, GrantMintIntentScope,
            TaskCancelMode, TaskCancelTarget, TaskCreateSpec, TimeRange, Vault,
        };

        let temp = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open(temp.path(), VaultConfig::default()).expect("open fixture vault");
        let agent_a = EntityId::from_bytes([0xE1; 16]).expect("agent A id");
        let agent_b = EntityId::from_bytes([0xE2; 16]).expect("agent B id");
        for actor in [agent_a, agent_b] {
            vault
                .put_entity(
                    &actor,
                    ENTITY_TYPE_PERSON,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"agent",
                )
                .expect("store agent");
        }
        let facade = vault.memory_facade(agent_a, EdgeActorClass::Agent);
        let own = facade
            .tasks_create(&TaskCreateSpec {
                spec: rmpv::Value::from("own-task"),
                label: None,
                owner_ref: None,
                now: Some(120),
            })
            .expect("create own task");
        let other = facade
            .tasks_create(&TaskCreateSpec {
                spec: rmpv::Value::from("other-task"),
                label: None,
                owner_ref: Some(agent_b),
                now: Some(120),
            })
            .expect("create other-owned task");
        let cancel_grant_ref = EntityId::from_bytes([0xD1; 16]).expect("cancel grant id");
        vault
            .mint_standing_outbound_grant(
                &cancel_grant_ref,
                &GrantMintIntent {
                    principal_ref: agent_a.to_hex(),
                    origin_component_id: "tasks".to_owned(),
                    origin_action_id: "cancel".to_owned(),
                    origin_receipt_ref: None,
                    scope: GrantMintIntentScope::VerbClass {
                        verb_class: "tasks.cancel".to_owned(),
                    },
                },
                120,
            )
            .expect("mint cancel grant");
        let own_cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(own.task_ref.expect("own task ref")))
            .expect("cancel own task");
        let foreign_cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(
                other.task_ref.expect("other task ref"),
            ))
            .expect("propose foreign task cancel");
        let own_gate_decision_ref = own_cancel.gate_decision_ref.as_deref();
        let decisions = vault.gate_decisions(512).expect("gate decisions");

        CancelLadderOutcome {
            ladder_modes: TaskCancelMode::ALL
                .map(TaskCancelMode::as_str)
                .into_iter()
                .map(str::to_owned)
                .collect(),
            default_mode: DEFAULT_TASK_CANCEL_MODE.as_str().to_owned(),
            gate_decisions_for_own_cancel: decisions
                .iter()
                .filter(|decision| {
                    own_gate_decision_ref
                        == Some(format!("gate:{}", decision.decision_id.to_hex()).as_str())
                })
                .count(),
            allow_gate_decisions_for_own_cancel: decisions
                .iter()
                .filter(|decision| {
                    own_gate_decision_ref
                        == Some(format!("gate:{}", decision.decision_id.to_hex()).as_str())
                        && decision.outcome == "allow"
                })
                .count(),
            own_cancel_effects: usize::from(own_cancel.effected),
            foreign_cancel_effects: usize::from(foreign_cancel.effected),
            foreign_cancel_proposals: usize::from(foreign_cancel.proposal_ref.is_some()),
        }
    }

    /// ONE-1696 · 08b §3 (r5v2): cancel rides the auto-approval ladder
    /// manual/full-access/auto with AUTO as default; it passes THROUGH the
    /// gate (decision recorded); own tasks + own spawns cancel directly,
    /// others' cancel surfaces as a proposal.
    #[test]
    fn tasks_cancel_rides_auto_approval_ladder_with_auto_default() {
        let outcome = arm_cancel_ladder();
        assert_eq!(outcome.ladder_modes.len(), 3);
        assert_eq!(outcome.ladder_modes, ["auto", "full-access", "manual"]);
        assert_eq!(outcome.default_mode, "auto");
        assert_eq!(outcome.gate_decisions_for_own_cancel, 1);
        assert_eq!(outcome.allow_gate_decisions_for_own_cancel, 1);
        assert_eq!(outcome.own_cancel_effects, 1);
        assert_eq!(outcome.foreign_cancel_effects, 0);
        assert_eq!(outcome.foreign_cancel_proposals, 1);
    }
}

// ════════════════════════════════════════════════════════════════════════
// CB-A — TASK delegation lanes (ONE-1699 consult · ONE-1700 BYOA executor ·
//        ONE-1708 human tasks)
// ════════════════════════════════════════════════════════════════════════
mod cb_a {
    /// Shape of one consult addressed to one peer.
    struct ConsultShape {
        /// TASK entities minted for the consult.
        consult_task_entities: usize,
        /// Of those, entities present in the sync export (must reach the
        /// peer's board wherever it connects).
        synced_consult_entities: usize,
        /// Node-local JobQueue realizations minted for the consult.
        consult_job_realizations: usize,
        /// The assignee actor handle on the consult entity.
        assignee: String,
        /// `cl_*`/`tn_*` ref entries carried in the payload.
        payload_ref_entries: usize,
        /// Raw content dumps carried in the payload.
        payload_raw_dumps: usize,
        /// Credential entries carried in the payload.
        payload_credential_entries: usize,
    }

    /// ONE-1699 fixture: `agents.consult` to peer actor `cc-second` with a
    /// question referencing exactly 2 entities (one `cl_*`, one `tn_*`).
    fn arm_consult_shape() -> ConsultShape {
        unimplemented!("armed by ONE-1699: consult TASK kind — synced, assignee-addressed")
    }

    /// ONE-1699 · 08b §4.2: consult is a CRDT-synced TASK ENTITY, not a job;
    /// assignee-addressed; payload carries refs, never creds, never dumps.
    #[test]
    #[ignore = "armed by ONE-1699"]
    fn consult_is_synced_assignee_addressed_task_entity() {
        let consult = arm_consult_shape();
        assert_eq!(consult.consult_task_entities, 1);
        assert_eq!(consult.synced_consult_entities, 1);
        assert_eq!(consult.consult_job_realizations, 0);
        assert_eq!(consult.assignee, "cc-second");
        assert_eq!(consult.payload_ref_entries, 2);
        assert_eq!(consult.payload_raw_dumps, 0);
        assert_eq!(consult.payload_credential_entries, 0);
    }

    /// Observable outcome of a consult passing its TTL unanswered.
    struct ConsultTtlOutcome {
        /// Rows for the consult in the asker's board FAILED lane.
        asker_failed_lane_rows: usize,
        /// True iff the row is marked expired (TTL cause visible).
        row_marked_expired: bool,
        /// ARCH-0046 human digest lines minted for the expiry.
        human_digest_lines: usize,
        /// True iff the digest line carries a recovery suggestion.
        digest_has_recovery_suggestion: bool,
    }

    /// ONE-1699 fixture: consult to an offline peer with a short TTL; let the
    /// deadline pass with no answer.
    fn arm_consult_ttl_expiry() -> ConsultTtlOutcome {
        unimplemented!("armed by ONE-1699: consult TTL expiry (r14)")
    }

    /// ONE-1699 · 08b r14: unanswered past deadline → failed/expired on the
    /// asker's board + a human digest line with a recovery suggestion.
    #[test]
    #[ignore = "armed by ONE-1699"]
    fn consult_ttl_expiry_is_observable_on_board_and_digest() {
        let outcome = arm_consult_ttl_expiry();
        assert_eq!(outcome.asker_failed_lane_rows, 1);
        assert!(outcome.row_marked_expired);
        assert_eq!(outcome.human_digest_lines, 1);
        assert!(outcome.digest_has_recovery_suggestion);
    }

    /// One landed fan-out answer.
    struct FanOutAnswer {
        /// Peer actor that produced this answer.
        assignee: String,
        /// True iff the answer carries evidence refs.
        has_evidence: bool,
        /// True iff the peer abstained (with a reason).
        abstained_with_reason: bool,
    }

    /// Fan-out consult outcome over N peers.
    struct ConsultFanOut {
        consult_tasks_minted: usize,
        distinct_assignees: usize,
        /// Answers landed on the asker's board, one per peer.
        answers: Vec<FanOutAnswer>,
        /// Consults blocked by any DEFAULT budget (must be none — ONE-1699
        /// comment 2026-07-15: "NO default budget on consults"; metering +
        /// estimate-then-approve + per-peer caps ride ES-06/ES-08, not CB).
        consults_blocked_by_default_budget: usize,
    }

    /// ONE-1699 fixture: fan out one question to 3 peers with NO budget
    /// configured; 2 answer with evidence refs, 1 abstains with a reason
    /// (the ask() contract).
    fn arm_consult_fan_out() -> ConsultFanOut {
        unimplemented!("armed by ONE-1699: fan-out = N consult tasks; ask() evidence/abstention")
    }

    /// ONE-1699 · 08b §4.2: fan-out to N peers is exactly N consult tasks;
    /// answers land on the asker's board and each answer is EXACTLY one of
    /// evidence-backed or abstention (F10 partition); no default budget
    /// blocks a consult.
    #[test]
    #[ignore = "armed by ONE-1699"]
    fn fan_out_to_three_peers_is_three_consult_tasks() {
        let fan = arm_consult_fan_out();
        assert_eq!(fan.consult_tasks_minted, 3);
        assert_eq!(fan.distinct_assignees, 3);
        assert_eq!(fan.answers.len(), 3);
        let mut answer_assignees: Vec<&str> =
            fan.answers.iter().map(|a| a.assignee.as_str()).collect();
        answer_assignees.sort_unstable();
        answer_assignees.dedup();
        assert_eq!(answer_assignees.len(), 3);
        let exactly_one_of_two = fan
            .answers
            .iter()
            .filter(|a| a.has_evidence != a.abstained_with_reason)
            .count();
        assert_eq!(exactly_one_of_two, 3);
        assert_eq!(fan.answers.iter().filter(|a| a.has_evidence).count(), 2);
        assert_eq!(
            fan.answers
                .iter()
                .filter(|a| a.abstained_with_reason)
                .count(),
            1
        );
        assert_eq!(fan.consults_blocked_by_default_budget, 0);
    }

    /// Routing observations for the three assignee lanes.
    struct AssigneeRouting {
        /// assignee=dreamer routed to Oneiron inference (LlmBackend seam).
        dreamer_routed_to_llm_backend: bool,
        /// assignee=agent-def routed to an in-process M8 spawn.
        agent_def_routed_in_process: bool,
        /// assignee=peer actor routed to the BYOA transport (synced entity).
        peer_routed_to_byoa_transport: bool,
        /// Distinct execution lanes exercised.
        lanes_exercised: usize,
    }

    /// ONE-1700 fixture: three TASKs, one per assignee kind {dreamer,
    /// agent-def, peer actor}; observe which execution lane realizes each.
    fn arm_assignee_routing() -> AssigneeRouting {
        unimplemented!("armed by ONE-1700: TASK.assignee routing {{dreamer/agent-def/peer}}")
    }

    /// ONE-1700 · 08b §4.3 (r10): TASK `assignee` is the routing field over
    /// exactly three pluggable execution lanes.
    #[test]
    #[ignore = "armed by ONE-1700"]
    fn task_assignee_routes_across_three_execution_lanes() {
        let routing = arm_assignee_routing();
        assert!(routing.dreamer_routed_to_llm_backend);
        assert!(routing.agent_def_routed_in_process);
        assert!(routing.peer_routed_to_byoa_transport);
        assert_eq!(routing.lanes_exercised, 3);
    }

    /// Durable-delegation observations across an engine restart.
    struct DurableDelegation {
        suspended_steps_before_restart: usize,
        suspended_steps_after_restart: usize,
        resumed_after_result_landed: usize,
        workflows_lost: usize,
    }

    /// ONE-1700 fixture: a workflow step emits a TASK assigned to a BYOA
    /// actor and suspends via C9 wait-for-signal; restart the engine; then
    /// land the peer's result.
    fn arm_durable_delegation_across_restart() -> DurableDelegation {
        unimplemented!("armed by ONE-1700: C9 bitemporal wait-for-signal delegation")
    }

    /// ONE-1700 · 08b §4.3: delegation suspends durably on the EXISTING C9
    /// bitemporal wait-for-signal and survives restart; resume fires when
    /// the result lands.
    #[test]
    #[ignore = "armed by ONE-1700"]
    fn byoa_delegation_wait_for_signal_survives_restart() {
        let durable = arm_durable_delegation_across_restart();
        assert_eq!(durable.suspended_steps_before_restart, 1);
        assert_eq!(durable.suspended_steps_after_restart, 1);
        assert_eq!(durable.resumed_after_result_landed, 1);
        assert_eq!(durable.workflows_lost, 0);
    }

    /// Human-assigned task observations.
    struct HumanTaskOutcome {
        /// JobQueue realizations minted for the human task (must be none).
        jobs_realized: usize,
        /// Dreamer follow-up machinery engagements (track/remind/digest/escalate).
        dreamer_followups_engaged: usize,
        /// Rows the task contributes to the (one) TASKS section.
        tasks_section_rows: usize,
        /// True iff the one-line row shows the human assignee.
        row_shows_human_assignee: bool,
        /// Plugin packs installed in the fixture vault (must be none — the
        /// NATIVE path is engine-level, "no pack needed"; F21).
        plugin_packs_installed: usize,
    }

    /// ONE-1708 fixture: `tasks.create` with assignee = a NATIVE human actor
    /// (vault member reachable via a connected channel) in a vault with ZERO
    /// plugin packs installed; render the board.
    fn arm_human_task() -> HumanTaskOutcome {
        unimplemented!("armed by ONE-1708: human tasks — no job realization, Dreamer follow-up")
    }

    /// ONE-1708 · 08b §4.4 (r12): assignee=human → NO job realization;
    /// Dreamer follow-up machinery instead; renders in the same TASKS
    /// section with the assignee column telling the story. Ticket AC:
    /// NATIVE humans are "Engine-level, no pack needed".
    #[test]
    #[ignore = "armed by ONE-1708"]
    fn human_assigned_task_realizes_no_jobs_and_engages_followup() {
        let human = arm_human_task();
        assert_eq!(human.jobs_realized, 0);
        assert_eq!(human.dreamer_followups_engaged, 1);
        assert_eq!(human.tasks_section_rows, 1);
        assert!(human.row_shows_human_assignee);
        assert_eq!(human.plugin_packs_installed, 0);
    }

    /// Wait-for-human-signal observations.
    struct HumanSignalResume {
        suspended_steps: usize,
        resumed_on_human_response: usize,
        resumed_before_response: usize,
    }

    /// ONE-1708 fixture: a workflow step assigned to a person suspends via
    /// C9; the person responds through their channel/app.
    fn arm_wait_for_human_signal() -> HumanSignalResume {
        unimplemented!("armed by ONE-1708: wait-for-human-signal resume")
    }

    /// ONE-1708 · 08b §4.4: durable workflows wait on humans exactly as on
    /// agents — suspend, then resume on the human's response, never before.
    #[test]
    #[ignore = "armed by ONE-1708"]
    fn workflow_waits_for_human_signal_and_resumes_on_response() {
        let resume = arm_wait_for_human_signal();
        assert_eq!(resume.suspended_steps, 1);
        assert_eq!(resume.resumed_on_human_response, 1);
        assert_eq!(resume.resumed_before_response, 0);
    }
}
