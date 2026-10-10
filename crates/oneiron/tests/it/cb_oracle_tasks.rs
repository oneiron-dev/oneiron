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
        /// Burst creates that took direct effect (must equal all attempts).
        burst_creates_effected: usize,
        /// Proposals created only because the accounting threshold was exceeded.
        burst_overflow_proposals: usize,
    }

    /// ONE-1696 fixture: a FOREIGN agent issues one `tasks.create`; then an
    /// OWN agent, with the per-actor create rate limit configured to 10 per
    /// window, issues 12 creates inside one window.
    fn arm_create_authority() -> CreateAuthorityOutcome {
        use oneiron::config::VaultConfig;
        use oneiron::edge::EdgeActorClass;
        use oneiron::registry::ENTITY_TYPE_PERSON;
        use oneiron::{
            EntityId, TimeRange, Vault, task_verb::TaskCreateRateLimit, task_verb::TaskCreateSpec,
        };

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
        let spec = TaskCreateSpec::new(rmpv::Value::from("oracle-task"), None, None, Some(120));
        let foreign_create = vault
            .memory(foreign, EdgeActorClass::Agent)
            .tasks_create_with_rate_limit(&spec, rate_limit)
            .expect("foreign tasks.create proposes");
        let burst_creates_attempted = 12;
        let own_facade = vault.memory(own, EdgeActorClass::Agent);
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

    /// OF-520 supersedes the old rate-refusal rule: own-agent creation is
    /// counted, never refused for rate. Foreign authority remains propose-only.
    #[test]
    fn foreign_tasks_create_is_propose_only_own_burst_is_count_only() {
        let outcome = arm_create_authority();
        assert_eq!(outcome.foreign_create_direct_effects, 0);
        assert_eq!(outcome.foreign_create_proposals, 1);
        assert_eq!(outcome.configured_rate_limit, 10);
        assert_eq!(outcome.burst_creates_attempted, 12);
        assert_eq!(
            outcome.burst_creates_effected,
            outcome.burst_creates_attempted
        );
        assert_eq!(outcome.burst_overflow_proposals, 0);
    }

    /// Cancel semantics across the auto-approval ladder.
    struct CancelLadderOutcome {
        /// Ladder modes available on `cancel`, sorted.
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
            EntityId, TimeRange, Vault, genui::GrantMintIntent, genui::GrantMintIntentScope,
            task_verb::DEFAULT_TASK_CANCEL_MODE, task_verb::TaskCancelMode,
            task_verb::TaskCancelTarget, task_verb::TaskCreateSpec,
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
        let facade = vault.memory(agent_a, EdgeActorClass::Agent);
        let own = facade
            .tasks_create(&TaskCreateSpec::new(
                rmpv::Value::from("own-task"),
                None,
                None,
                Some(120),
            ))
            .expect("create own task");
        let other = facade
            .tasks_create(&TaskCreateSpec::new(
                rmpv::Value::from("other-task"),
                None,
                Some(agent_b),
                Some(120),
            ))
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
                        verb_class: "cancel".to_owned(),
                    },
                },
                120,
            )
            .expect("mint cancel grant");
        let own_cancel = facade
            .cancel(TaskCancelTarget::Task(own.task_ref.expect("own task ref")))
            .expect("cancel own task");
        let foreign_cancel = facade
            .cancel(TaskCancelTarget::Task(
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
    fn cancel_rides_auto_approval_ladder_with_auto_default() {
        let outcome = arm_cancel_ladder();
        assert_eq!(outcome.ladder_modes.len(), 3);
        for required in ["auto", "full-access", "manual"] {
            assert!(outcome.ladder_modes.iter().any(|mode| mode == required));
        }
        assert_eq!(outcome.default_mode, "auto");
        assert_eq!(outcome.gate_decisions_for_own_cancel, 1);
        assert_eq!(outcome.allow_gate_decisions_for_own_cancel, 1);
        assert_eq!(outcome.own_cancel_effects, 1);
        assert_eq!(outcome.foreign_cancel_effects, 0);
        assert_eq!(outcome.foreign_cancel_proposals, 1);
    }
}

/// Fixture clock for the ONE-1699 arms.
const CONSULT_NOW: u64 = 1_772_400_000;

/// Local ONE-1708 fixture support: one vault, one owner, and one person the
/// vault ALREADY knows — a comm party (so the PERSON row carries its address)
/// reachable through a channel identity we hold and a live counterparty
/// contact. Zero plugin packs are installed, which is the point: NATIVE humans
/// are engine-level.
///
/// Deliberately NOT in `cb_oracle_common` for the same reason as
/// `consult_fixture`: that surface is frozen additive-only, and nothing here is
/// shared.
mod human_fixture {
    use oneiron::channel_identity::{
        ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityStep,
        SelfHeldShape,
    };
    use oneiron::code_run::{SelfDurableWait, SelfDurableWaitReason, SelfEffect};
    use oneiron::comm::resolve_or_create_comm_party;
    use oneiron::config::VaultConfig;
    use oneiron::counterparty_contact::CounterpartyContactRecord;
    use oneiron::registry::ENTITY_TYPE_PERSON;
    use oneiron::{
        EntityId, TimeRange, Vault, genui::GrantMintIntent, genui::GrantMintIntentScope,
    };

    /// The seeded first-party actor — the one id the default policy manifest
    /// grants an Auto ceiling, so the owner's creates take direct effect.
    const OWNER_BYTES: [u8; 16] = [0xE1; 16];
    const HUMAN_ADDRESS: &str = "alice@example.test";

    pub(crate) struct HumanFixture {
        _dir: tempfile::TempDir,
        pub(crate) vault: Vault,
        pub(crate) owner: EntityId,
        pub(crate) person: EntityId,
    }

    impl HumanFixture {
        pub(crate) fn open() -> Self {
            let dir = tempfile::tempdir().expect("temporary vault directory");
            let vault =
                Vault::open(dir.path(), VaultConfig::default()).expect("open fixture vault");
            let owner = EntityId::from_bytes(OWNER_BYTES).expect("owner id");
            vault
                .put_entity(
                    &owner,
                    ENTITY_TYPE_PERSON,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"owner",
                )
                .expect("store owner");
            vault
                .mint_standing_outbound_grant(
                    &EntityId::from_bytes([0x7B; 16]).expect("grant id"),
                    &GrantMintIntent {
                        principal_ref: owner.to_hex(),
                        origin_component_id: "tasks".to_owned(),
                        origin_action_id: "human.followup".to_owned(),
                        origin_receipt_ref: None,
                        scope: GrantMintIntentScope::VerbClass {
                            verb_class: "send".to_owned(),
                        },
                    },
                    super::CONSULT_NOW,
                )
                .expect("mint outbound grant");

            let person = resolve_or_create_comm_party(&vault, HUMAN_ADDRESS).expect("comm party");
            let identity_ref = EntityId::from_bytes([0x7C; 16]).expect("identity id");
            vault
                .create_channel_identity(
                    &identity_ref,
                    &ChannelIdentity::requested(
                        "email",
                        "assistant@example.test",
                        SelfHeldShape::DedicatedAddress,
                        ChannelIdentityBinding::vault(1),
                        super::CONSULT_NOW,
                    ),
                )
                .expect("create channel identity");
            vault
                .step_channel_identity(
                    &identity_ref,
                    ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
                    super::CONSULT_NOW,
                )
                .expect("enter fulfillment");
            vault
                .step_channel_identity(
                    &identity_ref,
                    ChannelIdentityStep::Fulfill,
                    super::CONSULT_NOW,
                )
                .expect("activate the identity");
            vault
                .create_counterparty_contact(
                    &EntityId::from_bytes([0x7D; 16]).expect("contact id"),
                    &CounterpartyContactRecord::user_introduction(
                        identity_ref,
                        HUMAN_ADDRESS,
                        super::CONSULT_NOW,
                    )
                    .expect("contact record"),
                )
                .expect("create counterparty contact");

            Self {
                _dir: dir,
                vault,
                owner,
                person,
            }
        }

        /// The durable wait a workflow step raises when it asks a PERSON, built
        /// exactly as the C9 dispatcher builds it — so the trap mapping under
        /// observation is the production one.
        pub(crate) fn human_input_wait(&self, task_ref: EntityId) -> SelfDurableWait {
            SelfDurableWait {
                wait_id: task_ref,
                effect: SelfEffect::Ask,
                reason: SelfDurableWaitReason::HumanInput,
                prompt: None,
            }
        }
    }
}

/// Local ONE-1699 fixture support. Deliberately NOT in `cb_oracle_common`:
/// that surface is frozen additive-only, and nothing here is shared.
mod consult_fixture {
    use oneiron::config::VaultConfig;
    use oneiron::edge::EdgeActorClass;
    use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
    use oneiron::{
        EntityId, Memory, TimeRange, Vault, task_verb::ConsultPayloadRef, task_verb::TaskCreateSpec,
    };
    use rmpv::Value;

    /// The seeded first-party actor — the one id the default policy manifest
    /// grants an Auto ceiling, so the asker's creates take direct effect.
    const ASKER_BYTES: [u8; 16] = [0xE1; 16];

    pub(crate) struct ConsultFixture {
        _dir: tempfile::TempDir,
        pub(crate) vault: Vault,
        pub(crate) asker: EntityId,
    }

    impl ConsultFixture {
        /// A device-config vault, so the sync-export observation is available.
        pub(crate) fn open() -> Self {
            Self::open_with(VaultConfig::device())
        }

        pub(crate) fn open_with(config: VaultConfig) -> Self {
            let dir = tempfile::tempdir().expect("temporary vault directory");
            let vault = Vault::open(dir.path(), config).expect("open fixture vault");
            let asker = EntityId::from_bytes(ASKER_BYTES).expect("asker id");
            put_person(&vault, asker, b"asker");
            Self {
                _dir: dir,
                vault,
                asker,
            }
        }

        pub(crate) fn asker_facade(&self) -> Memory<'_> {
            self.vault.memory(self.asker, EdgeActorClass::Agent)
        }

        pub(crate) fn peer_facade(&self, actor_ref: EntityId) -> Memory<'_> {
            self.vault.memory(actor_ref, EdgeActorClass::Agent)
        }

        /// One peer actor plus its registered DISPLAY handle. The handle is a
        /// label on the row; the consult stores only the actor ref.
        pub(crate) fn peer(&self, handle: &str, seed: u8) -> EntityId {
            let actor_ref = EntityId::from_bytes([seed; 16]).expect("peer actor id");
            put_person(&self.vault, actor_ref, b"peer");
            self.asker_facade()
                .register_peer_handle(actor_ref, handle)
                .expect("register peer handle");
            actor_ref
        }

        /// A durable TURN the consult can point at.
        pub(crate) fn turn(&self, seed: u8) -> ConsultPayloadRef {
            let turn_ref = EntityId::from_bytes([seed; 16]).expect("turn id");
            let mut body = Vec::new();
            rmpv::encode::write_value(
                &mut body,
                &Value::Map(vec![(Value::from("role"), Value::from("question"))]),
            )
            .expect("encode turn body");
            self.vault
                .put_entity(
                    &turn_ref,
                    ENTITY_TYPE_TURN,
                    TimeRange {
                        start: super::CONSULT_NOW,
                        end: super::CONSULT_NOW,
                    },
                    super::CONSULT_NOW,
                    &body,
                )
                .expect("store durable turn");
            ConsultPayloadRef::parse(&self.vault, &format!("tn_{}", turn_ref.to_hex()))
                .expect("turn parses as a typed consult ref")
        }

        /// A real CLAIM entity: the propose-only ladder parks one for a
        /// non-first-party actor's create, so no hand-rolled claim body is
        /// needed (and none would pass the claim validator).
        pub(crate) fn claim(&self, actor_seed: u8) -> ConsultPayloadRef {
            let stranger = EntityId::from_bytes([actor_seed; 16]).expect("stranger id");
            put_person(&self.vault, stranger, b"stranger");
            let proposal = self
                .peer_facade(stranger)
                .tasks_create(&TaskCreateSpec::new(
                    Value::from("context"),
                    None,
                    None,
                    Some(super::CONSULT_NOW),
                ))
                .expect("propose-only create parks a claim");
            let claim_ref = proposal
                .proposal_ref
                .expect("a parked create surfaces its proposal claim");
            assert_eq!(
                self.vault
                    .get_entity_type(&claim_ref)
                    .expect("claim entity type"),
                Some(ENTITY_TYPE_CLAIM)
            );
            ConsultPayloadRef::parse(&self.vault, &format!("cl_{}", claim_ref.to_hex()))
                .expect("claim parses as a typed consult ref")
        }
    }

    fn put_person(vault: &Vault, id: EntityId, body: &[u8]) {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                body,
            )
            .expect("store actor");
    }

    /// The assignee the TASK body actually stores — an actor ref, never the
    /// display handle.
    pub(crate) fn persisted_assignee(
        vault: &Vault,
        task_ref: EntityId,
    ) -> oneiron::task_verb::TaskAssignee {
        let body = vault
            .get(&task_ref)
            .expect("read task body")
            .expect("task exists");
        let mut cursor = body.as_slice();
        let value = rmpv::decode::read_value(&mut cursor).expect("decode task body");
        let assignee = value
            .as_map()
            .expect("task body is a map")
            .iter()
            .find(|(key, _)| key.as_str() == Some("assignee"))
            .map(|(_, value)| value.clone())
            .expect("consult persists an assignee");
        let entries = assignee.as_map().expect("assignee is a map");
        let field = |name: &str| {
            entries
                .iter()
                .find(|(key, _)| key.as_str() == Some(name))
                .and_then(|(_, value)| value.as_str())
                .map(str::to_owned)
        };
        assert_eq!(field("kind").as_deref(), Some("peer"));
        oneiron::task_verb::TaskAssignee::Peer {
            actor_ref: EntityId::from_hex(&field("actor_ref").expect("actor ref"))
                .expect("actor ref parses"),
        }
    }

    /// Structural census of the PERSISTED consult payload.
    pub(crate) struct PersistedPayload {
        pub(crate) ref_entries: usize,
        pub(crate) raw_dumps: usize,
        pub(crate) credential_entries: usize,
    }

    /// Reads the consult payload back out of the stored TASK body and counts
    /// what it actually carries. The reference-only guarantee is proved from
    /// the bytes on disk, never asserted as a constant.
    pub(crate) fn persisted_consult_payload(vault: &Vault, task_ref: EntityId) -> PersistedPayload {
        let body = vault
            .get(&task_ref)
            .expect("read task body")
            .expect("consult task exists");
        let mut cursor = body.as_slice();
        let value = rmpv::decode::read_value(&mut cursor).expect("decode task body");
        let consult = value
            .as_map()
            .expect("task body is a map")
            .iter()
            .find(|(key, _)| key.as_str() == Some("consult"))
            .map(|(_, value)| value.clone())
            .expect("consult payload is persisted");
        let mut census = PersistedPayload {
            ref_entries: 0,
            raw_dumps: 0,
            credential_entries: 0,
        };
        scan(&consult, &mut census);
        census
    }

    const CREDENTIAL_MARKERS: [&str; 7] = [
        "token",
        "secret",
        "password",
        "credential",
        "api_key",
        "authorization",
        "bearer",
    ];

    fn scan(value: &Value, census: &mut PersistedPayload) {
        match value {
            // Every typed ref is exactly `{kind, entity_ref}` — the shape the
            // enum can produce and nothing else.
            Value::Map(entries) if is_typed_ref(entries) => census.ref_entries += 1,
            Value::Map(entries) => {
                for (key, entry) in entries {
                    let name = key.as_str().unwrap_or_default().to_ascii_lowercase();
                    if CREDENTIAL_MARKERS
                        .iter()
                        .any(|marker| name.contains(marker))
                    {
                        census.credential_entries += 1;
                    }
                    scan(entry, census);
                }
            }
            Value::Array(entries) => {
                for entry in entries {
                    scan(entry, census);
                }
            }
            // A payload can only hold structural tokens and canonical ids.
            // Anything else is free content that reached durable storage.
            Value::String(text) => {
                let text = text.as_str().unwrap_or_default();
                if !matches!(text, "claim" | "turn") && !is_canonical_id(text) {
                    census.raw_dumps += 1;
                }
            }
            Value::Binary(_) => census.raw_dumps += 1,
            _ => {}
        }
    }

    fn is_typed_ref(entries: &[(Value, Value)]) -> bool {
        entries.len() == 2
            && entries.iter().any(|(key, value)| {
                key.as_str() == Some("kind") && matches!(value.as_str(), Some("claim" | "turn"))
            })
            && entries.iter().any(|(key, value)| {
                key.as_str() == Some("entity_ref") && value.as_str().is_some_and(is_canonical_id)
            })
    }

    fn is_canonical_id(text: &str) -> bool {
        text.len() == 32 && text.chars().all(|character| character.is_ascii_hexdigit())
    }
}

// ════════════════════════════════════════════════════════════════════════
// CB-A — TASK delegation lanes (ONE-1699 consult · ONE-1700 BYOA executor ·
//        ONE-1708 human tasks)
// ════════════════════════════════════════════════════════════════════════
mod cb_a {
    /// Shape of one consult addressed to one peer.
    struct ConsultShape {
        /// TASK entities minted for the consult: the consult TASK plus its
        /// Owner authority fact, which shares the TASK type byte.
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
    ///
    /// Sync-gated for the same reason as `arm_task_job_storage_split`: the
    /// synced-entity half of the contract is observed on a real sync export,
    /// not asserted as a constant.
    #[cfg(feature = "sync")]
    fn arm_consult_shape() -> ConsultShape {
        use loro::{ExportMode, LoroDoc};
        use oneiron::attempt_queue::AttemptQueue;
        use oneiron::registry::ENTITY_TYPE_TASK;
        use oneiron::sync::schema::create_window_doc;
        use oneiron::sync::types::WindowKey;
        use oneiron::sync::window::reverse_rematerialize;
        use oneiron::{
            EntityId, task_verb::ConsultPayload, task_verb::TaskAssignee,
            task_verb::TaskCreateSpec, task_verb::TaskKind, task_verb::TaskTtl,
        };

        let fixture = super::consult_fixture::ConsultFixture::open();
        let peer = fixture.peer("cc-second", 0xE2);
        let question = fixture.turn(0x7A);
        let context = fixture.claim(0xE3);
        let facade = fixture.asker_facade();

        let before = fixture
            .vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("task entities before consult")
            .len();
        let created = facade
            .tasks_create(
                &TaskCreateSpec::new(rmpv::Value::Nil, None, None, Some(super::CONSULT_NOW))
                    .with_kind(TaskKind::Consult)
                    .with_consult(ConsultPayload::question(
                        question,
                        vec![context],
                        EntityId::now(),
                    ))
                    .with_assignee(TaskAssignee::Peer { actor_ref: peer })
                    .with_ttl(TaskTtl::after(super::CONSULT_NOW, 3_600)),
            )
            .expect("consult create effects");
        let task_ref = created.task_ref.expect("consult mints one TASK entity");
        let task_hex = task_ref.to_hex();
        let after = fixture
            .vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("task entities after consult")
            .len();

        // The lease-bearing plane stays empty: a node-local job could never
        // reach a peer on another machine, so the consult mints none.
        let consult_job_realizations = AttemptQueue::new(&fixture.vault)
            .list()
            .expect("list local jobs")
            .iter()
            .filter(|job| job.task_ref.as_deref() == Some(task_hex.as_str()))
            .count();

        let window_key = WindowKey::new("2026-03");
        let sync_doc = create_window_doc("test-user", &window_key);
        reverse_rematerialize(&fixture.vault, &sync_doc, &window_key)
            .expect("mirror local entities into sync document");
        let snapshot = sync_doc
            .export(ExportMode::Snapshot)
            .expect("export sync snapshot");
        let exported = LoroDoc::from_snapshot(&snapshot).expect("read sync snapshot");
        let synced_consult_entities = usize::from(
            exported
                .get_map("entities")
                .get(task_hex.as_str())
                .is_some(),
        );

        let oneiron::task_verb::TaskDescription::Section(section) =
            facade.describe(None).expect("render asker board")
        else {
            panic!("describe without a task returns the TASKS section");
        };
        let assignee = section
            .rows
            .iter()
            .find(|row| row.id == task_hex)
            .and_then(|row| row.assignee.clone())
            .expect("consult row carries a resolved assignee handle");
        let payload = super::consult_fixture::persisted_consult_payload(&fixture.vault, task_ref);

        ConsultShape {
            consult_task_entities: after - before,
            synced_consult_entities,
            consult_job_realizations,
            assignee,
            payload_ref_entries: payload.ref_entries,
            payload_raw_dumps: payload.raw_dumps,
            payload_credential_entries: payload.credential_entries,
        }
    }

    /// ONE-1699 · 08b §4.2: consult is a CRDT-synced TASK ENTITY, not a job;
    /// assignee-addressed; payload carries refs, never creds, never dumps.
    #[cfg(feature = "sync")]
    #[test]
    fn consult_is_synced_assignee_addressed_task_entity() {
        let consult = arm_consult_shape();
        assert_eq!(consult.consult_task_entities, 2);
        assert_eq!(consult.synced_consult_entities, 1);
        assert_eq!(consult.consult_job_realizations, 0);
        assert_eq!(consult.assignee, "cc-second");
        assert_eq!(consult.payload_ref_entries, 2);
        assert_eq!(consult.payload_raw_dumps, 0);
        assert_eq!(consult.payload_credential_entries, 0);
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
        use oneiron::config::VaultConfig;
        use oneiron::{
            task_verb::ConsultFanOutSpec, task_verb::ConsultResultInput,
            task_verb::ConsultResultKind, task_verb::TaskAssignee,
        };

        let fixture = super::consult_fixture::ConsultFixture::open_with(VaultConfig::default());
        let peers = [
            fixture.peer("cc-first", 0xE2),
            fixture.peer("cc-second", 0xE4),
            fixture.peer("cc-third", 0xE5),
        ];
        let question = fixture.turn(0x7A);
        let facade = fixture.asker_facade();

        let requested = peers.len();
        let receipt = facade
            .fan_out_consults(&ConsultFanOutSpec {
                question_ref: question,
                context_refs: Vec::new(),
                assignees: peers.to_vec(),
                deadline_at: super::CONSULT_NOW + 3_600,
                label: None,
                now: Some(super::CONSULT_NOW),
            })
            .expect("fan out to three peers");

        // Each peer answers on its OWN task, as itself. Two carry evidence,
        // one abstains with a durable reason — never both, never neither.
        let mut answers = Vec::with_capacity(receipt.task_refs.len());
        for (index, task_ref) in receipt.task_refs.iter().enumerate() {
            let assignee_ref =
                match super::consult_fixture::persisted_assignee(&fixture.vault, *task_ref) {
                    TaskAssignee::Peer { actor_ref } => actor_ref,
                    other => panic!("fan-out task must be peer-addressed, got {other:?}"),
                };
            let result_ref = fixture.turn(0x80 + u8::try_from(index).expect("small index"));
            let kind = if index < 2 {
                ConsultResultKind::Answer {
                    result_ref: result_ref.entity_ref(),
                    option: None,
                    evidence_refs: vec![question],
                }
            } else {
                ConsultResultKind::Abstain {
                    result_ref: result_ref.entity_ref(),
                    reason_ref: question,
                }
            };
            fixture
                .peer_facade(assignee_ref)
                .land_consult_result(
                    *task_ref,
                    &ConsultResultInput {
                        kind,
                        completed_at: super::CONSULT_NOW + 10,
                    },
                )
                .expect("peer lands its own result");

            let oneiron::task_verb::TaskDescription::Section(section) =
                facade.describe(None).expect("render asker board")
            else {
                panic!("describe without a task returns the TASKS section");
            };
            let task_hex = task_ref.to_hex();
            let row = section
                .rows
                .iter()
                .find(|row| row.id == task_hex)
                .expect("answered consult stays on the asker's board");
            let oneiron::task_verb::TaskDescription::Card { lines: detail } = facade
                .describe(Some(*task_ref))
                .expect("describe the answered consult")
            else {
                panic!("describe with a task returns its card");
            };
            let tokens: Vec<&str> = detail
                .iter()
                .flat_map(|line| line.split_whitespace())
                .collect();
            answers.push(FanOutAnswer {
                assignee: row.assignee.clone().expect("resolved assignee handle"),
                has_evidence: tokens.contains(&"answer")
                    && tokens
                        .iter()
                        .filter_map(|token| token.strip_prefix("evidence="))
                        .filter_map(|count| count.parse::<usize>().ok())
                        .any(|count| count > 0),
                abstained_with_reason: tokens.contains(&"abstained")
                    && tokens.iter().any(|token| token.starts_with("reason=tn_")),
            });
        }

        let mut assignees: Vec<String> = answers
            .iter()
            .map(|answer| answer.assignee.clone())
            .collect();
        assignees.sort_unstable();
        assignees.dedup();

        ConsultFanOut {
            consult_tasks_minted: receipt.task_refs.len(),
            distinct_assignees: assignees.len(),
            answers,
            // No consult budget exists to block one: every requested peer got
            // its task, so nothing was refused for a budget that is not there.
            consults_blocked_by_default_budget: requested - receipt.task_refs.len(),
        }
    }

    /// ONE-1699 · 08b §4.2: fan-out to N peers is exactly N consult tasks;
    /// answers land on the asker's board and each answer is EXACTLY one of
    /// evidence-backed or abstention (F10 partition); no default budget
    /// blocks a consult.
    #[test]
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
    ///
    /// The restart is a REAL one: the vault is dropped and reopened from the
    /// same directory, so only what LMDB persisted can carry the suspended
    /// delegation across. No in-memory callback survives this boundary.
    fn arm_byoa_wait_for_signal() -> DurableDelegation {
        use oneiron::config::VaultConfig;
        use oneiron::dreamer_runner::{
            DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
            ParkDreamerAttempt,
        };
        use oneiron::edge::EdgeActorClass;
        use oneiron::llm::{
            DurableStepContext, consume_trap_signal, open_trap, register_peer_result_wait,
            trap_for_durable_wait, trap_park_owner,
        };
        use oneiron::registry::ENTITY_TYPE_PERSON;
        use oneiron::{
            EntityId, TimeRange, Vault, WriteActor, task_verb::TaskAssignee,
            task_verb::TaskCreateSpec, task_verb::TaskResultInput,
            task_verb::TaskTerminalDisposition,
        };

        const NOW: u64 = super::CONSULT_NOW;
        // The first-party connector actor: the one identity the default policy
        // manifest grants an Auto ceiling, so the delegating create effects.
        const ASKER_BYTES: [u8; 16] = [0xE1; 16];
        let step_hash = [0x6Du8; 32];

        let dir = tempfile::tempdir().expect("temporary vault directory");
        let put_person = |vault: &Vault, id: EntityId, body: &[u8]| {
            vault
                .put_entity(
                    &id,
                    ENTITY_TYPE_PERSON,
                    TimeRange { start: 1, end: 1 },
                    1,
                    body,
                )
                .expect("store actor");
        };

        let (task_ref, peer, attempt_id, trap, suspended_steps_before_restart) = {
            let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
            let asker = EntityId::from_bytes(ASKER_BYTES).expect("asker id");
            let peer = EntityId::from_bytes([0x6E; 16]).expect("peer actor id");
            put_person(&vault, asker, b"asker");
            put_person(&vault, peer, b"peer");

            // A workflow step emits the peer-assigned TASK and takes back the
            // durable wait the C9 host parks on.
            let (receipt, wait) = vault
                .memory(asker, EdgeActorClass::Agent)
                .delegate_task_and_wait(
                    &TaskCreateSpec::new(rmpv::Value::from("delegated"), None, None, Some(NOW))
                        .with_assignee(TaskAssignee::Peer { actor_ref: peer }),
                )
                .expect("delegation effects");
            let task_ref = receipt.task_ref.expect("delegation mints one TASK");

            let runner = DreamerRunnerStore::new(&vault);
            let attempt_id = match runner
                .enqueue(EnqueueDreamerAttempt {
                    attempt_type: "byoa-workflow-step".to_owned(),
                    input: rmpv::Value::from("step"),
                    parent_attempt: None,
                    dedupe_key: None,
                    run_id: Some("byoa-run".to_owned()),
                    now: NOW,
                })
                .expect("enqueue the workflow step")
            {
                EnqueueDreamerAttemptOutcome::Enqueued(status)
                | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
                other => panic!("unexpected enqueue outcome: {other:?}"),
            };

            let ctx = DurableStepContext {
                vault: &vault,
                attempt_id,
                run_id: Some("byoa-run".to_owned()),
                envelope_actor: WriteActor::new(asker, EdgeActorClass::Agent),
                subject: peer,
                deadline: None,
                now_ms: NOW,
            };
            let trap = open_trap(
                &vault,
                &ctx,
                trap_for_durable_wait(&wait, step_hash),
                step_hash,
                "peer result",
            )
            .expect("open the delegation trap");
            runner
                .park_attempt(ParkDreamerAttempt {
                    attempt_id,
                    reason: "peer result".to_owned(),
                    park_owner: trap_park_owner(&trap.trap_claim_id),
                    now: NOW,
                })
                .expect("park the suspended step");
            register_peer_result_wait(&vault, &trap, task_ref, NOW)
                .expect("register the delegation wait");

            let suspended = usize::from(
                runner
                    .parked_attempt(attempt_id)
                    .expect("read parked row")
                    .is_some(),
            );
            (task_ref, peer, attempt_id, trap, suspended)
        };

        // ── restart ────────────────────────────────────────────────────────
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("reopen vault");
        let runner = DreamerRunnerStore::new(&vault);
        let suspended_steps_after_restart = usize::from(
            runner
                .parked_attempt(attempt_id)
                .expect("read parked row after restart")
                .is_some(),
        );

        // The peer's result lands on the synced TASK; the terminal write sends
        // the C9 signal, and the existing consumer resumes the parked step.
        let result_ref = EntityId::from_bytes([0x6F; 16]).expect("result id");
        put_person(&vault, result_ref, b"exhaust");
        vault
            .memory(peer, EdgeActorClass::Agent)
            .land_task_result(
                task_ref,
                &TaskResultInput {
                    result_ref,
                    disposition: TaskTerminalDisposition::Completed,
                    finished_at: NOW + 20,
                },
            )
            .expect("peer lands its result");
        let resumed_after_result_landed = usize::from(
            consume_trap_signal(&vault, &runner, &trap, NOW + 21).expect("consume resumes once")
                == attempt_id,
        );
        // A workflow is lost if its step neither resumed nor is still parked.
        let workflows_lost = usize::from(
            resumed_after_result_landed == 0
                && runner
                    .parked_attempt(attempt_id)
                    .expect("read parked row after resume")
                    .is_none(),
        );

        DurableDelegation {
            suspended_steps_before_restart,
            suspended_steps_after_restart,
            resumed_after_result_landed,
            workflows_lost,
        }
    }

    /// ONE-1700 · 08b §4.3: delegation suspends durably on the EXISTING C9
    /// bitemporal wait-for-signal and survives restart; resume fires when
    /// the result lands.
    #[test]
    fn byoa_delegation_wait_for_signal_survives_restart() {
        let durable = arm_byoa_wait_for_signal();
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
        use oneiron::attempt_queue::AttemptQueue;
        use oneiron::human_task::human_followup_records;
        use oneiron::registry::{TypeByteZone, zone_of};
        use oneiron::{EdgeActorClass, task_verb::TaskAssignee, task_verb::TaskCreateSpec};

        let fixture = super::human_fixture::HumanFixture::open();
        let facade = fixture.vault.memory(fixture.owner, EdgeActorClass::Agent);
        let task_ref = facade
            .tasks_create(
                &TaskCreateSpec::new(
                    rmpv::Value::from("review the draft"),
                    Some("review the draft".to_owned()),
                    None,
                    Some(super::CONSULT_NOW),
                )
                .with_assignee(TaskAssignee::Human {
                    actor_ref: fixture.person,
                }),
            )
            .expect("human create effects")
            .task_ref
            .expect("an effected create mints one TASK");
        let task_hex = task_ref.to_hex();

        // The lease-bearing plane stays empty: a person is not a worker, so
        // NOTHING realizes this task.
        let jobs_realized = AttemptQueue::new(&fixture.vault)
            .list()
            .expect("list local jobs")
            .iter()
            .filter(|job| job.task_ref.as_deref() == Some(task_hex.as_str()))
            .count();
        // Dreamer follow-up engaged instead: one durable, rebuildable cursor.
        let dreamer_followups_engaged = human_followup_records(&fixture.vault)
            .expect("follow-up cursors")
            .iter()
            .filter(|record| record.task_ref == task_ref)
            .count();

        let oneiron::task_verb::TaskDescription::Section(section) =
            facade.describe(None).expect("render the board")
        else {
            panic!("describe without a task returns the TASKS section");
        };
        let rows: Vec<_> = section
            .rows
            .iter()
            .filter(|row| row.id == task_hex)
            .collect();
        let row_shows_human_assignee = rows.iter().all(|row| {
            row.folded_job_count == 0
                && row
                    .line
                    .split_whitespace()
                    .any(|token| token == format!("assignee=person:{}", fixture.person.to_hex()))
        }) && !rows.is_empty();

        // An installed pack owns entity-type bytes in the pack half of the byte
        // space. A vault with none has no row anywhere in that zone — which is
        // exactly the NATIVE claim: engine-level, no pack needed.
        let plugin_packs_installed = (u8::MIN..=u8::MAX)
            .filter(|byte| {
                matches!(
                    zone_of(*byte),
                    TypeByteZone::PackHandle | TypeByteZone::PackExperimental
                ) && !fixture
                    .vault
                    .entities_by_type(*byte)
                    .unwrap_or_default()
                    .is_empty()
            })
            .count();

        HumanTaskOutcome {
            jobs_realized,
            dreamer_followups_engaged,
            tasks_section_rows: rows.len(),
            row_shows_human_assignee,
            plugin_packs_installed,
        }
    }

    /// ONE-1708 · 08b §4.4 (r12): assignee=human → NO job realization;
    /// Dreamer follow-up machinery instead; renders in the same TASKS
    /// section with the assignee column telling the story. Ticket AC:
    /// NATIVE humans are "Engine-level, no pack needed".
    #[test]
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
    ///
    /// The "before the response" observation is taken against a foreign inbound
    /// event — an app turn from somebody who is not the bound person — because
    /// silence proves nothing: a wait that nothing tried to wake is not
    /// evidence that the wait holds.
    fn arm_wait_for_human_signal() -> HumanSignalResume {
        use oneiron::dreamer_runner::{
            DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
            ParkDreamerAttempt,
        };
        use oneiron::human_task::{HumanResponseSignal, human_wait_binding, signal_human_response};
        use oneiron::llm::{
            DurableStepContext, consume_trap_signal, open_trap, register_wait,
            trap_for_durable_wait, trap_park_owner,
        };
        use oneiron::registry::ENTITY_TYPE_PERSON;
        use oneiron::{
            EdgeActorClass, EntityId, TimeRange, WriteActor, code_run::HostSelfDispatcher,
            code_run::SelfAskCall, code_run::SelfCall, code_run::SelfDispatchOutcome,
            code_run::SelfDispatcher, task_verb::TaskAssignee, task_verb::TaskCreateSpec,
        };

        const NOW: u64 = super::CONSULT_NOW;
        let step_hash = [0x71u8; 32];

        let fixture = super::human_fixture::HumanFixture::open();
        let task_ref = fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Agent)
            .tasks_create(
                &TaskCreateSpec::new(rmpv::Value::from("decide"), None, None, Some(NOW))
                    .with_assignee(TaskAssignee::Human {
                        actor_ref: fixture.person,
                    }),
            )
            .expect("human create effects")
            .task_ref
            .expect("an effected create mints one TASK");

        // A workflow step asks the person and parks on the EXISTING C9 trap.
        let runner = DreamerRunnerStore::new(&fixture.vault);
        let attempt_id = match runner
            .enqueue(EnqueueDreamerAttempt {
                attempt_type: "human-workflow-step".to_owned(),
                input: rmpv::Value::from("step"),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some("human-run".to_owned()),
                now: NOW,
            })
            .expect("enqueue the workflow step")
        {
            EnqueueDreamerAttemptOutcome::Enqueued(status)
            | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
            other => panic!("unexpected enqueue outcome: {other:?}"),
        };
        let ctx = DurableStepContext {
            vault: &fixture.vault,
            attempt_id,
            run_id: Some("human-run".to_owned()),
            envelope_actor: WriteActor::new(fixture.owner, EdgeActorClass::Agent),
            subject: fixture.person,
            deadline: None,
            now_ms: NOW,
        };
        let trap = open_trap(
            &fixture.vault,
            &ctx,
            trap_for_durable_wait(&fixture.human_input_wait(task_ref), step_hash),
            step_hash,
            "human response",
        )
        .expect("open the human trap");
        let dispatcher = HostSelfDispatcher::for_human_task(
            &fixture.vault,
            WriteActor::new(fixture.owner, EdgeActorClass::Agent),
            "human-run",
            task_ref,
            trap,
        )
        .expect("bind dispatcher to the human TASK");
        let wait = match dispatcher
            .dispatch(SelfCall::Ask(SelfAskCall::new("decide")))
            .expect("dispatch ask")
        {
            SelfDispatchOutcome::DurableWait(wait) => wait,
            other => panic!("unexpected ask-human outcome: {other:?}"),
        };
        assert_eq!(wait.wait_id, task_ref, "the TASK is the durable wait key");
        let binding = human_wait_binding(&fixture.vault, task_ref)
            .expect("read wait binding")
            .expect("dispatch persists the human wait binding");
        runner
            .park_attempt(ParkDreamerAttempt {
                attempt_id,
                reason: "human response".to_owned(),
                park_owner: trap_park_owner(&trap.trap_claim_id),
                now: NOW,
            })
            .expect("park the suspended step");
        register_wait(&fixture.vault, &trap, NOW).expect("register the wait");

        let suspended_steps = usize::from(
            runner
                .parked_attempt(attempt_id)
                .expect("read parked row")
                .is_some(),
        );

        // Somebody ELSE writes in on the same surface. It must move nothing.
        let intruder = EntityId::from_bytes([0x6D; 16]).expect("intruder id");
        fixture
            .vault
            .put_entity(
                &intruder,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"intruder",
            )
            .expect("store intruder");
        let _ = signal_human_response(
            &fixture.vault,
            &binding,
            intruder,
            &HumanResponseSignal {
                task_ref,
                responder_ref: intruder,
                surface_event_ref: EntityId::from_bytes([0x6E; 16]).expect("event id"),
                occurred_at: NOW + 5,
            },
        );
        let resumed_before_response =
            usize::from(consume_trap_signal(&fixture.vault, &runner, &trap, NOW + 6).is_ok());

        // The bound person answers through their channel/app.
        signal_human_response(
            &fixture.vault,
            &binding,
            fixture.person,
            &HumanResponseSignal {
                task_ref,
                responder_ref: fixture.person,
                surface_event_ref: EntityId::from_bytes([0x6F; 16]).expect("event id"),
                occurred_at: NOW + 10,
            },
        )
        .expect("the bound person may signal");
        let resumed_on_human_response = usize::from(
            consume_trap_signal(&fixture.vault, &runner, &trap, NOW + 11)
                .expect("consume resumes once")
                == attempt_id,
        );

        HumanSignalResume {
            suspended_steps,
            resumed_on_human_response,
            resumed_before_response,
        }
    }

    /// ONE-1708 · 08b §4.4: durable workflows wait on humans exactly as on
    /// agents — suspend, then resume on the human's response, never before.
    #[test]
    fn workflow_waits_for_human_signal_and_resumes_on_response() {
        let resume = arm_wait_for_human_signal();
        assert_eq!(resume.suspended_steps, 1);
        assert_eq!(resume.resumed_on_human_response, 1);
        assert_eq!(resume.resumed_before_response, 0);
    }
}
