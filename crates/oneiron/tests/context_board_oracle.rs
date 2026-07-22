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
    /// The whole engine-rendered Context Board block as one string.
    struct BoardBlockRender {
        text: String,
    }

    /// ONE-1694 fixture: any non-empty board (1 world, 1 pinned memory,
    /// 1 running task) rendered in RESIDENT mode. Returns the full block.
    fn arm_render_board_block() -> BoardBlockRender {
        use oneiron::context_board::{
            BoardBlockHeader, BoardSection, TaskBoardStatus, TaskIntentPresence,
            render_board_block, render_tasks_section,
        };

        let running_task = TaskIntentPresence {
            id: "tk_a".to_owned(),
            status: TaskBoardStatus::Running,
            label: None,
            acked: false,
            realizing_jobs: Vec::new(),
        };
        let tasks = render_tasks_section(&[running_task], &[]);
        let sections = [
            BoardSection {
                name: "WORLDS".to_owned(),
                rows: vec!["wd_1 active".to_owned()],
            },
            BoardSection {
                name: "MEMORIES".to_owned(),
                rows: vec!["cl_1 pinned".to_owned()],
            },
            BoardSection {
                name: "TASKS".to_owned(),
                rows: tasks.rows.iter().map(|row| row.line.clone()).collect(),
            },
        ];
        let header = BoardBlockHeader {
            epoch: 47,
            scope: "WorldSet(wd_1)".to_owned(),
        };
        BoardBlockRender {
            text: render_board_block(&header, &sections),
        }
    }

    /// ONE-1694 · 08b §0/§1 (r1) · CB-01 contract: the board render tag is
    /// `[CONTEXT_BOARD …]`, never `[MEMORY_BOARD …]`. Token-boundary exact:
    /// a tag like `[CONTEXT_BOARD_EVIL …]` must NOT satisfy this test, and
    /// the check must fail closed on malformed renders (no slice panics).
    #[test]
    fn board_block_opens_with_context_board_render_tag() {
        let render = arm_render_board_block();
        let first_line = render.text.lines().next().expect("block has a first line");
        assert!(
            first_line
                .strip_prefix("[CONTEXT_BOARD ")
                .and_then(|rest| rest.strip_suffix(']'))
                .is_some(),
            "opening tag must be a complete [CONTEXT_BOARD …] line"
        );
        assert_eq!(render.text.matches("[CONTEXT_BOARD ").count(), 1);
        assert_eq!(render.text.matches("[/CONTEXT_BOARD]").count(), 1);
        assert_eq!(render.text.matches("MEMORY_BOARD").count(), 0);
    }

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
// CB-A — AGENTS section + delegation (ONE-1697 renderer · ONE-1698 preset/
//        kill · ONE-1699 consult · ONE-1700 BYOA executor · ONE-1708 human
//        tasks · ONE-1709 team-lead · ONE-1710 peer-answer trust)
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
        /// Preset id the spawn RESOLVED to (engine-observed output, never a
        /// caller-side flag — G6 vacuous-pass hazard).
        resolved_preset_id: String,
        /// Preset id the engine registers as its system DEFAULT base preset.
        system_default_preset_id: String,
    }

    /// ONE-1698 fixture: call `agents.spawn` with NO agent definition and a
    /// plain task prompt; observe the RESOLVED preset id of the spawned child
    /// and, separately, the registered system-default base preset id.
    fn arm_zero_config_spawn() -> DefaultPresetSpawn {
        use oneiron::agent_def::SystemAgentPreset;
        use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher};
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
        let AgentDispatchTarget::System(resolved) = status.input.target else {
            panic!("default dispatch must resolve to a system preset");
        };
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
            resolved_preset_id: resolved.preset_id().to_owned(),
            system_default_preset_id: SystemAgentPreset::default_base().preset_id().to_owned(),
        }
    }

    /// ONE-1698 · 08b §4.1 (r8): one generic default base preset — spawn
    /// works with zero definition; the spawned child resolves to THAT preset.
    #[test]
    fn spawn_with_zero_definition_uses_default_base_preset() {
        let spawn = arm_zero_config_spawn();
        assert_eq!(spawn.spawned_children, 1);
        assert!(!spawn.system_default_preset_id.is_empty());
        assert_eq!(spawn.resolved_preset_id, spawn.system_default_preset_id);
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
        use oneiron::agent_def::SystemAgentPreset;
        use oneiron::agent_dispatch::{
            AgentDispatchOutcome, AgentDispatchStatus, AgentDispatchTarget, AgentDispatcher,
            DispatchAgent, KillOutcome,
        };
        use oneiron::{AttemptQueue, AttemptState, EntityId, TimeRange, Vault, VaultConfig};

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
            .fork_system_agent(
                &custom_id,
                SystemAgentPreset::Keeper,
                "custom",
                TimeRange { start: 1, end: 1 },
                1,
            )
            .expect("store custom definition");

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
        let system_child = spawn(AgentDispatchTarget::System(SystemAgentPreset::Scout), 4);
        let custom_child = spawn(AgentDispatchTarget::Custom(custom_id), 5);
        let proposed_child = spawn(AgentDispatchTarget::System(SystemAgentPreset::Creative), 6);

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
// CB-S — STREAM delivery (ONE-1701 epoch frames · ONE-1702 subscriptions/
//        coalescing · ONE-1703 wake adapters)
// ════════════════════════════════════════════════════════════════════════
mod cb_s {
    /// Epoch keyframe/delta application observations.
    struct EpochStream {
        /// Epoch carried by the initial keyframe.
        keyframe_epoch: u64,
        /// Deltas applied when the delta epoch matched the current state.
        deltas_applied_on_matching_epoch: usize,
        /// Deltas applied when the delta epoch was stale (must be none).
        deltas_applied_on_stale_epoch: usize,
        /// State epoch after receiving keyframes 47 then 48.
        state_epoch_after_two_keyframes: u64,
        /// State epoch after a LATE stale keyframe arrives (48 delivered,
        /// then 47 arrives late) — latest EPOCH wins, not latest arrival
        /// (F12: an arrival-order receiver must fail here).
        state_epoch_after_late_stale_keyframe: u64,
        /// Verbs referencing an id present only in the agent's stale frame
        /// that were accepted against that stale frame (must be none).
        stale_frame_verb_acceptances: usize,
        /// The same stale-frame verb attempts, validated against CURRENT
        /// state and rejected (ticket AC: "verbs validate against current
        /// state, not the frame the agent last saw" — G3).
        stale_frame_verb_rejections: usize,
    }

    /// ONE-1701 fixture: STREAM connection receives keyframe(epoch=47), one
    /// delta stamped 47, one delta stamped 46, then keyframe(epoch=48),
    /// then a LATE keyframe stamped 47; finally the agent — still holding
    /// the epoch-47 frame — issues one verb on an id present only in that
    /// stale frame.
    fn arm_epoch_stream() -> EpochStream {
        unimplemented!("armed by ONE-1701: epoch-numbered keyframe/delta frames")
    }

    /// ONE-1701 · 08b §2 (r7) + §7.5: a delta applies only on a matching
    /// epoch; latest-EPOCH-wins across keyframes regardless of arrival
    /// order; verbs validate against current state, never a stale frame.
    #[test]
    #[ignore = "armed by ONE-1701"]
    fn stream_delta_applies_only_on_matching_epoch_latest_wins() {
        let stream = arm_epoch_stream();
        assert_eq!(stream.keyframe_epoch, 47);
        assert_eq!(stream.deltas_applied_on_matching_epoch, 1);
        assert_eq!(stream.deltas_applied_on_stale_epoch, 0);
        assert_eq!(stream.state_epoch_after_two_keyframes, 48);
        assert_eq!(stream.state_epoch_after_late_stale_keyframe, 48);
        assert_eq!(stream.stale_frame_verb_acceptances, 0);
        assert_eq!(stream.stale_frame_verb_rejections, 1);
    }

    /// Compaction-recovery observations.
    struct CompactionRecovery {
        /// Rows in the full keyframe returned by board.refresh.
        refresh_keyframe_rows: usize,
        /// True iff the refresh keyframe's epoch advanced past the
        /// pre-compaction epoch.
        refresh_epoch_advanced: bool,
        /// Pre-compaction deltas accepted after the refresh (must be none).
        stale_deltas_applied_after_refresh: usize,
    }

    /// ONE-1701 fixture: board with 3 rows; the foreign harness compacts its
    /// window; the agent calls `board.refresh`; a pre-compaction delta then
    /// arrives late.
    fn arm_compaction_recovery() -> CompactionRecovery {
        unimplemented!("armed by ONE-1701: board.refresh reset-on-compaction recovery")
    }

    /// ONE-1701 · 08b §2: `board.refresh` after compaction re-keys the agent
    /// with a full keyframe; stale frames cannot re-enter.
    #[test]
    #[ignore = "armed by ONE-1701"]
    fn board_refresh_recovers_full_keyframe_after_compaction() {
        let recovery = arm_compaction_recovery();
        assert_eq!(recovery.refresh_keyframe_rows, 3);
        assert!(recovery.refresh_epoch_advanced);
        assert_eq!(recovery.stale_deltas_applied_after_refresh, 0);
    }

    /// One routed event: fixture event id → delivery class.
    struct RoutedEvent {
        /// Fixture event id.
        event: String,
        /// "wake" / "carrier" / "on-demand".
        class: String,
    }

    /// Event-class routing observations.
    struct EventRouting {
        /// Per-event routing for the six fixture events (F13: exact pairs,
        /// aggregates alone would let classes swap invisibly).
        routed: Vec<RoutedEvent>,
        /// Events pushed NOW via the wake adapter.
        wake_pushed: usize,
        /// Events queued to piggyback the next tool response.
        carrier_queued: usize,
        /// ON-DEMAND events pushed (must be none).
        on_demand_pushed: usize,
        /// ON-DEMAND events carried (must be none — refresh/expand only).
        on_demand_carried: usize,
    }

    /// ONE-1702 fixture: emit exactly these six events on one STREAM
    /// connection: `consult-arrived`, `own-task-failed` (wake class),
    /// `own-task-done`, `child-done` (carrier class), `memories-changed`,
    /// `presence-changed` (on-demand class).
    fn arm_event_routing() -> EventRouting {
        unimplemented!("armed by ONE-1702: WAKE/CARRIER/ON-DEMAND event classes")
    }

    /// ONE-1702 · 08b §7.5 (r16): consult arrived + task failed push now;
    /// completions piggyback; memories/presence/counts are never pushed —
    /// asserted per event id, not by aggregate.
    #[test]
    #[ignore = "armed by ONE-1702"]
    fn event_classes_route_wake_carrier_on_demand() {
        let routing = arm_event_routing();
        assert_eq!(routing.routed.len(), 6);
        let class_of = |event: &str| {
            routing
                .routed
                .iter()
                .find(|e| e.event == event)
                .unwrap_or_else(|| panic!("event {event} was routed"))
                .class
                .clone()
        };
        assert_eq!(class_of("consult-arrived"), "wake");
        assert_eq!(class_of("own-task-failed"), "wake");
        assert_eq!(class_of("own-task-done"), "carrier");
        assert_eq!(class_of("child-done"), "carrier");
        assert_eq!(class_of("memories-changed"), "on-demand");
        assert_eq!(class_of("presence-changed"), "on-demand");
        assert_eq!(routing.wake_pushed, 2);
        assert_eq!(routing.carrier_queued, 2);
        assert_eq!(routing.on_demand_pushed, 0);
        assert_eq!(routing.on_demand_carried, 0);
    }

    /// Carrier-coalescing observations for one task key.
    struct CarrierCoalescing {
        /// Carrier lines for `tk_12` in the next tool response.
        lines_for_task: usize,
        /// True iff the surviving line reflects the FINAL status (done).
        final_line_reflects_done: bool,
        /// Intermediate deltas superseded within the key.
        superseded_intermediate_deltas: usize,
    }

    /// ONE-1702 fixture: task `tk_12` flips queued→running→done between two
    /// tool calls on one STREAM connection; inspect the next tool response's
    /// carrier payload.
    fn arm_carrier_coalescing() -> CarrierCoalescing {
        unimplemented!("armed by ONE-1702: carrier coalescing — deltas supersede within key")
    }

    /// ONE-1702 · 08b §7.5: queued→running→done coalesces to ONE line
    /// ("done · ran …"); deltas supersede within the key.
    #[test]
    #[ignore = "armed by ONE-1702"]
    fn carrier_deltas_coalesce_to_one_line_per_key() {
        let coalescing = arm_carrier_coalescing();
        assert_eq!(coalescing.lines_for_task, 1);
        assert!(coalescing.final_line_reflects_done);
        assert_eq!(coalescing.superseded_intermediate_deltas, 2);
    }

    /// Subscription-default observations for a fresh connection.
    struct SubscriptionDefaults {
        /// Subscription classes in the STREAM default set.
        stream_default_classes: usize,
        includes_my_tasks: bool,
        includes_my_children: bool,
        includes_consults_to_me: bool,
        /// True iff RESIDENT mode defaults to everything (budget polices).
        resident_default_is_everything: bool,
        /// True iff subscribe/unsubscribe are agent-free read-scope verbs.
        subscribe_verbs_agent_free: bool,
        /// Subscriptions accepted OUTSIDE the allowed-set (must be none).
        subscriptions_outside_allowed_set: usize,
    }

    /// Per-connection subscription isolation + unsubscribe observations.
    struct SubscriptionIsolation {
        /// Classes on connection A after it unsubscribes its children class.
        conn_a_classes_after_unsubscribe: usize,
        /// Classes on untouched connection B, observed at the same moment
        /// (must still hold the full default — no cross-connection leak).
        conn_b_classes: usize,
        /// True iff connection A still holds the my-children class after the
        /// unsubscribe (must be false — that is the class it removed).
        conn_a_includes_my_children_after_unsubscribe: bool,
        /// True iff untouched connection B still holds the my-children class
        /// (must be true — no cross-connection leak).
        conn_b_includes_my_children: bool,
        /// Gate/consent prompts raised by the unsubscribe (agent-free verb).
        unsubscribe_gate_prompts: usize,
    }

    /// ONE-1702 fixture: two STREAM connections A and B, both on default
    /// subscriptions; A unsubscribes its my-children class; B is untouched.
    fn arm_subscription_isolation() -> SubscriptionIsolation {
        unimplemented!("armed by ONE-1702: per-connection subscription state + unsubscribe")
    }

    /// ONE-1702 AC verbatim: "Per-connection subscription state" and
    /// "subscribe/unsubscribe = agent-free read-scope verbs" (F14) — one
    /// connection's unsubscribe never leaks to another, and unsubscribing
    /// raises no gate.
    #[test]
    #[ignore = "armed by ONE-1702"]
    fn subscriptions_are_per_connection_and_unsubscribe_is_agent_free() {
        let isolation = arm_subscription_isolation();
        assert_eq!(isolation.conn_a_classes_after_unsubscribe, 2);
        assert_eq!(isolation.conn_b_classes, 3);
        assert!(!isolation.conn_a_includes_my_children_after_unsubscribe);
        assert!(isolation.conn_b_includes_my_children);
        assert_eq!(isolation.unsubscribe_gate_prompts, 0);
    }

    /// ONE-1702 fixture: open a fresh STREAM connection and a fresh RESIDENT
    /// assembly; enumerate subscription state; attempt one subscribe to a
    /// scope outside the connection's allowed-set.
    fn arm_subscription_defaults() -> SubscriptionDefaults {
        unimplemented!("armed by ONE-1702: per-connection subscriptions + defaults")
    }

    /// ONE-1702 · 08b §7.5 (r16): STREAM default = {my tasks · my children ·
    /// consults to me}; RESIDENT default = everything; subscribe verbs are
    /// agent-free and bounded by the allowed-set.
    #[test]
    #[ignore = "armed by ONE-1702"]
    fn stream_defaults_to_own_scope_subscriptions_bounded_by_allowed_set() {
        let defaults = arm_subscription_defaults();
        assert_eq!(defaults.stream_default_classes, 3);
        assert!(defaults.includes_my_tasks);
        assert!(defaults.includes_my_children);
        assert!(defaults.includes_consults_to_me);
        assert!(defaults.resident_default_is_everything);
        assert!(defaults.subscribe_verbs_agent_free);
        assert_eq!(defaults.subscriptions_outside_allowed_set, 0);
    }

    /// Wake-mint injection-floor observations.
    struct WakeMintFloor {
        /// Wakes minted from the agent's OWN task events.
        own_task_event_wakes: usize,
        /// Foreign-content attempts to reach event emission.
        foreign_content_wake_attempts: usize,
        /// Wakes minted from foreign content (must be none).
        foreign_content_wakes_minted: usize,
        /// Event-EMISSION verbs present on the verb surface reachable from
        /// foreign content (must be none — the exclusion is structural, at
        /// the verb surface, not a downstream mint filter; F15).
        emission_verbs_reachable_from_foreign_content: usize,
    }

    /// ONE-1702 fixture: one own-task FAILED event; one foreign-authored
    /// content item crafted to look wake-worthy attempts the same path;
    /// enumerate the verb surface reachable from foreign content.
    fn arm_wake_mint_floor() -> WakeMintFloor {
        unimplemented!("armed by ONE-1702: wake-class mintable from own-task events only")
    }

    /// ONE-1702 AC verbatim: "wake-class mintable from own-task events only
    /// — foreign content has no verb reaching event emission" — asserted at
    /// the verb surface AND at the mint outcome.
    #[test]
    #[ignore = "armed by ONE-1702"]
    fn wake_class_mintable_from_own_task_events_only() {
        let floor = arm_wake_mint_floor();
        assert_eq!(floor.own_task_event_wakes, 1);
        assert_eq!(floor.foreign_content_wake_attempts, 1);
        assert_eq!(floor.foreign_content_wakes_minted, 0);
        assert_eq!(floor.emission_verbs_reachable_from_foreign_content, 0);
    }

    /// Wake-adapter install + delivery observations.
    struct WakeAdapterInstall {
        /// Adapter installs performed (ONE for the hook-capable instance;
        /// the weak-hook instance gets NO adapter — it lands on the
        /// fallback layer of the 08b §5 r4v2 ladder; F16 canon correction).
        adapter_installs: usize,
        /// Distinct actor keys the TWO instances registered under
        /// (config-dir keying makes them two actors regardless of lane).
        distinct_actor_keys: usize,
        /// True iff the undelivered message stayed persisted in the vault
        /// mailbox until delivery (durable transport layer).
        mailbox_persisted_until_delivery: bool,
        /// Deliveries via a harness adapter (layer 2).
        deliveries_via_adapter: usize,
        /// Deliveries via the hard fallback (layer 3).
        deliveries_via_fallback: usize,
        /// True iff the hook-capable instance's wake was delivered through
        /// its installed adapter (layer 2 — the instance that owns the one
        /// adapter install).
        hook_capable_delivered_via_adapter: bool,
        /// True iff the weak-hook instance's wake was delivered through the
        /// hard fallback (layer 3 — it has no adapter to use).
        weak_hook_delivered_via_fallback: bool,
    }

    /// ONE-1703 fixture: two instances of the SAME harness under different
    /// config dirs — one with lifecycle hooks (gets the adapter install),
    /// one weak-hook (no adapter; fallback lane); send one wake to each.
    fn arm_wake_adapter_install() -> WakeAdapterInstall {
        unimplemented!("armed by ONE-1703: per-INSTANCE wake adapters + 3-layer delivery")
    }

    /// ONE-1703 · 08b §5 (r4v2): adapters install PER INSTANCE (config-dir
    /// keyed); the vault mailbox is the durable transport; "weak-hook CLIs
    /// land lower on the delivery ladder" — so the conforming shape here is
    /// exactly 1 adapter install + 1 adapter delivery + 1 fallback delivery
    /// across 2 distinct actor keys.
    #[test]
    #[ignore = "armed by ONE-1703"]
    fn wake_adapters_install_per_instance_over_durable_mailbox() {
        let install = arm_wake_adapter_install();
        assert_eq!(install.adapter_installs, 1);
        assert_eq!(install.distinct_actor_keys, 2);
        assert!(install.mailbox_persisted_until_delivery);
        assert_eq!(install.deliveries_via_adapter, 1);
        assert_eq!(install.deliveries_via_fallback, 1);
        assert!(install.hook_capable_delivered_via_adapter);
        assert!(install.weak_hook_delivered_via_fallback);
    }
}

// ════════════════════════════════════════════════════════════════════════
// CB-X — surfaces, plugins, registry (ONE-1704 MCP 2-tool · ONE-1705
//        skill/CLI/thin client · ONE-1706 plugin sections · ONE-1707
//        plugin suggestions · ONE-1711 registry mints)
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
        unimplemented!("armed by ONE-1704: 2-tool MCP surface")
    }

    /// ONE-1704 · 08b §6 (r3v2): the PRIMARY MCP surface is exactly two
    /// tools — setup_oneiron() and execute_code(); setup returns all three
    /// payload parts.
    #[test]
    #[ignore = "armed by ONE-1704"]
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

    /// ONE-1704 fixture: a verb table of exactly these seven verbs —
    /// board.expand, board.refresh, tasks.ack, tasks.cancel, tasks.check,
    /// tasks.create, tasks.expand; generate the tool-first variant from it.
    fn arm_generated_tool_variant() -> GeneratedToolVariant {
        unimplemented!("armed by ONE-1704: tool-first variant generated from the verb table")
    }

    /// ONE-1704 · 08b §6: the tool-first variant is GENERATED from the verb
    /// table — the generated tool-name set equals the verb table exactly
    /// (one tool per verb, distinct), nothing hand-rolled.
    #[test]
    #[ignore = "armed by ONE-1704"]
    fn tool_first_variant_is_generated_one_tool_per_verb() {
        let variant = arm_generated_tool_variant();
        let expected = [
            "board.expand",
            "board.refresh",
            "tasks.ack",
            "tasks.cancel",
            "tasks.check",
            "tasks.create",
            "tasks.expand",
        ];
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

    /// Plugin-section admission observations.
    struct PluginSectionAdmission {
        /// Core sections before any plugin (WORLDS/MEMORIES/TASKS/AGENTS).
        sections_before: usize,
        /// Sections after one gated, consented, schema-valid manifest admit.
        sections_after_gated_admit: usize,
        /// Invalid manifests attempted — one per missing recipe component:
        /// missing state family, missing verbs, missing authority, missing
        /// budget (F19 matrix; the §2 recipe as schema).
        invalid_manifests_attempted: usize,
        /// Rejections among those (every component is load-bearing).
        invalid_manifest_rejections: usize,
        /// Sections admitted from ANY invalid manifest (must be none).
        invalid_manifest_admissions: usize,
        /// Gate TRIGGERS initiated by conversation ("install X plugin" —
        /// ticket AC: "conversation can INITIATE an install … triggers the
        /// gate").
        conversation_initiated_gate_triggers: usize,
        /// Sections registered directly by words with NO gate (must be
        /// none — words never register a section).
        words_only_direct_registrations: usize,
        /// Sections after the words-only attempt (unchanged).
        sections_after_words_only_attempt: usize,
        /// Owner consent records written by the gated admit.
        gate_consent_records: usize,
    }

    /// ONE-1706 fixture: 4 core sections; conversation says "install the CRM
    /// plugin" (initiates the gate); the gated admit with owner consent and
    /// a schema-valid typed manifest lands the CRM section; then attempt
    /// FOUR invalid manifests, each missing exactly one recipe component
    /// (state family / verbs / authority / budget), and one words-only
    /// registration with no gate.
    fn arm_plugin_section_admission() -> PluginSectionAdmission {
        unimplemented!("armed by ONE-1706: section manifest schema + plugin-gate admission")
    }

    /// ONE-1706 · 08b §7 (r6v2): every section enters through the gated
    /// plugin path (consent + typed manifest, each recipe component
    /// validated); conversation initiates, the gate registers; words never
    /// register a section directly — the 08 no-parser keystone.
    #[test]
    #[ignore = "armed by ONE-1706"]
    fn plugin_sections_enter_only_through_gated_typed_manifest() {
        let admission = arm_plugin_section_admission();
        assert_eq!(admission.sections_before, 4);
        assert_eq!(admission.sections_after_gated_admit, 5);
        assert_eq!(admission.invalid_manifests_attempted, 4);
        assert_eq!(admission.invalid_manifest_rejections, 4);
        assert_eq!(admission.invalid_manifest_admissions, 0);
        assert_eq!(admission.conversation_initiated_gate_triggers, 1);
        assert_eq!(admission.words_only_direct_registrations, 0);
        assert_eq!(admission.sections_after_words_only_attempt, 5);
        assert_eq!(admission.gate_consent_records, 1);
    }

    /// Plugin-section lifecycle observations.
    struct PluginSectionLifecycle {
        sections_with_plugin: usize,
        sections_after_remove: usize,
        /// Verbs of the removed section still reachable (must be none).
        orphan_verbs_after_remove: usize,
    }

    /// ONE-1706 fixture: with the CRM section admitted (5 sections), remove
    /// the plugin; enumerate sections + reachable verbs.
    fn arm_plugin_section_lifecycle() -> PluginSectionLifecycle {
        unimplemented!("armed by ONE-1706: sections appear/disappear with plugin lifecycle")
    }

    /// ONE-1706 · 08b §7: sections appear/disappear with the plugin
    /// lifecycle; removal leaves no orphan verbs.
    #[test]
    #[ignore = "armed by ONE-1706"]
    fn plugin_section_disappears_with_plugin_lifecycle() {
        let lifecycle = arm_plugin_section_lifecycle();
        assert_eq!(lifecycle.sections_with_plugin, 5);
        assert_eq!(lifecycle.sections_after_remove, 4);
        assert_eq!(lifecycle.orphan_verbs_after_remove, 0);
    }

    /// Renderer fuzz-coverage observations.
    struct RendererFuzzCoverage {
        /// Sections registered (core + plugin-admitted).
        total_sections: usize,
        /// Sections the fuzz harness exercises.
        sections_under_fuzz: usize,
        /// Hostile claim values that altered board STRUCTURE (must be none).
        structure_altering_escapes: usize,
        /// Structure line count rendering a hostile-delimiter value.
        hostile_value_structure_lines: usize,
        /// Structure line count rendering a benign value (same fixture).
        clean_value_structure_lines: usize,
        /// State mutations caused by RENDERING hostile text that contains
        /// verb-like lines (e.g. a claim value reading "tasks.cancel tk_x")
        /// — must be none: the render is OUTPUT-only, no code path parses
        /// context text back into state (08b §0 no-parser keystone; F5).
        state_mutations_from_render_path: usize,
    }

    /// ONE-1706 fixture: 5 sections (4 core + 1 admitted); fuzz the renderer
    /// with claim values containing board delimiters (`[/CONTEXT_BOARD]`,
    /// fake section headers, control bytes, verb-like lines such as
    /// "tasks.cancel tk_x") and a benign twin value; snapshot typed state
    /// before/after each render.
    fn arm_renderer_fuzz_coverage() -> RendererFuzzCoverage {
        unimplemented!("armed by ONE-1706: renderer fuzz over ALL sections")
    }

    /// ONE-1706 · 08b §7 + 08 §5 (owner ruling): no claim value can alter
    /// board structure; the fuzz test covers every section, core and
    /// plugin-admitted alike; rendering NEVER mutates state (one-way,
    /// no-parser keystone — 08b §0).
    #[test]
    #[ignore = "armed by ONE-1706"]
    fn renderer_fuzz_covers_all_sections_no_structural_escape() {
        let fuzz = arm_renderer_fuzz_coverage();
        assert_eq!(fuzz.total_sections, 5);
        assert_eq!(fuzz.sections_under_fuzz, 5);
        assert_eq!(fuzz.structure_altering_escapes, 0);
        assert_eq!(
            fuzz.hostile_value_structure_lines,
            fuzz.clean_value_structure_lines
        );
        assert_eq!(fuzz.state_mutations_from_render_path, 0);
    }

    /// Plugin-suggestion flow observations.
    struct PluginSuggestionFlow {
        /// Proposal rows surfaced on the board (agent-visible).
        board_proposal_rows: usize,
        /// Proposals surfaced on the app surface (owner-visible).
        app_surface_proposals: usize,
        /// Installs performed via the plugin gate after owner accept.
        installs_via_gate_on_accept: usize,
        /// Installs that bypassed the gate (must be none).
        installs_bypassing_gate: usize,
        /// Suggestions surfaced with the knob OFF (must be none).
        suggestions_with_knob_off: usize,
        /// Re-surfacings of the same suggestion in the next digest window
        /// (digest-not-nag: must be none).
        nag_repeats: usize,
        /// Observed knob value on a FRESH, untouched configuration — ticket
        /// AC: "Disableable knob, default ON" (F20: a product defaulting
        /// OFF and toggling ON for the fixture must fail).
        knob_on_in_fresh_config: bool,
    }

    /// ONE-1707 fixture: observe the suggestion knob on a FRESH config
    /// before any toggle; Dreamer notices a hand-tracked-contacts pattern
    /// and suggests the CRM pack; owner accepts; rerun with the knob
    /// explicitly OFF; then check the next digest window for repeats.
    fn arm_plugin_suggestion_flow() -> PluginSuggestionFlow {
        unimplemented!("armed by ONE-1707: Dreamer proactive-help x pack catalog")
    }

    /// ONE-1707 · 08b §7 (r11): suggestion = proposal row on board + app;
    /// accept = the gated install; knob disableable, DEFAULT ON on a fresh
    /// config; digest-not-nag.
    #[test]
    #[ignore = "armed by ONE-1707"]
    fn plugin_suggestion_is_gated_proposal_knob_off_silences() {
        let flow = arm_plugin_suggestion_flow();
        assert!(flow.knob_on_in_fresh_config);
        assert_eq!(flow.board_proposal_rows, 1);
        assert_eq!(flow.app_surface_proposals, 1);
        assert_eq!(flow.installs_via_gate_on_accept, 1);
        assert_eq!(flow.installs_bypassing_gate, 0);
        assert_eq!(flow.suggestions_with_knob_off, 0);
        assert_eq!(flow.nag_repeats, 0);
    }

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
