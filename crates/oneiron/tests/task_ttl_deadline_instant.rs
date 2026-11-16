//! UC-12 PR 2 (PLAN-UC-12 row 2, N1; FIX TASK-TTL-DEADLINE-SECOND-SPLIT): one
//! instant for a TASK's TTL. A consult is dead at its `deadline_at` second
//! (`now >= deadline_at`), as the room thread, the fan-out admission and the
//! create doors already read it. At exactly that second:
//! - the assignee's answer is refused: the consult is the expiry sweep's;
//! - the asker's board reads it expired before the sweep has run;
//! - the expiry sweep settles it;
//! - a member's word on an ask still counts under the ask's own cutoff, and
//!   the member TASK is left to the sweep, which settles it;
//! - the room thread drops its wait. That door already read the deadline
//!   second as dead; one second earlier the wait shows, so the consult is
//!   bound to the thread and the check is not vacuous.
//!
//! On main 11e4bdb4d360 the first four are red: the answer lands, the board
//! reads the consult open, the sweep skips it, and the member's word
//! completes the member TASK. The fifth is green on both.
//!
//! Public paths only, no test doors:
//! `cargo test --locked -p oneiron --all-features --test task_ttl_deadline_instant`.

use std::sync::Arc;

use oneiron::context_board::{TaskBoardStatus, TaskIntentPresence};
use oneiron::federation::Scope;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::{
    ConsultDigestRoute, ConsultPayload, ConsultPayloadRef, ConsultResultInput, ConsultResultKind,
    TaskAskDefault, TaskAskQuestion, TaskAskSettlementReason, TaskAskSpec, TaskAskStatus,
    TaskAskTarget, TaskAskWord, TaskAssignee, TaskCreateSpec, TaskKind, TaskTerminalDisposition,
    TaskTtl,
};
use oneiron::workspace_roster::{ProjectRecord, RoomThreadPolicy};
use oneiron::{
    EdgeActorClass, EntityId, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, TimeRange, Vault,
    VaultConfig,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The engine clock when the fixture opens; every consult and ask is created
/// here.
const T0: u64 = 1_772_400_000;
/// The deadline second of every consult and ask in this file.
const DEADLINE: u64 = T0 + 3_600;

/// One vault on a clock the test moves, with a project room holding one
/// thread: a trunk turn, the thread's root, and a question turn replying in
/// it. The owner speaks; the asker (an agent) and the peer are on the
/// project's roster.
struct Fixture {
    clock: Arc<ManualClock>,
    vault: Vault,
    owner: EntityId,
    asker: EntityId,
    peer: EntityId,
    room: EntityId,
    /// The room's trunk turn: an existing TURN an answer can name.
    trunk: EntityId,
    /// The question TURN, a reply inside the thread.
    question: EntityId,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn open() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let clock = ManualClock::new(T0);
        let mut config = VaultConfig::default();
        config.store_clock = clock.bundle();
        // `open_owned` holds the writer lease the owner's policy door asks for.
        let vault = Vault::open_owned(directory.path(), config)?;
        let owner = vault.ensure_embedded_owner_actor()?;
        // The seeded first-party actor: the default policy grants it an Auto
        // ceiling, so its consult create takes direct effect.
        let asker = EntityId::from_bytes([0xE1; 16])?;
        let peer = EntityId::from_bytes([0xE2; 16])?;
        for actor in [asker, peer] {
            vault.put_entity(
                &actor,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"room member",
            )?;
        }
        grant_reads(&vault, owner, &[owner, asker, peer])?;
        let root_project = vault.root_project()?;
        let project_id = EntityId::now();
        let mut project = ProjectRecord::new(project_id, Some(root_project), root_project, owner)?;
        project.roster.extend([asker.to_hex(), peer.to_hex()]);
        vault.put_project(project_id, &project, T0)?;
        let room = EntityId::from_hex(&project.home_room)?;
        let trunk = EntityId::now();
        speak(&vault, owner, room, trunk, serde_json::json!({}))?;
        let root = EntityId::now();
        speak(
            &vault,
            owner,
            room,
            root,
            serde_json::json!({"room_thread_of": trunk.to_hex()}),
        )?;
        let question = EntityId::now();
        speak(
            &vault,
            owner,
            room,
            question,
            serde_json::json!({"room_reply_to": root.to_hex()}),
        )?;
        Ok(Self {
            clock,
            vault,
            owner,
            asker,
            peer,
            room,
            trunk,
            question,
            _directory: directory,
        })
    }

    fn owner_facade(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    fn asker_facade(&self) -> Memory<'_> {
        self.vault.memory(self.asker, EdgeActorClass::Agent)
    }

    fn peer_facade(&self) -> Memory<'_> {
        self.vault.memory(self.peer, EdgeActorClass::Agent)
    }

    /// The asker's consult to the peer on the question turn, due at
    /// `DEADLINE`, created at `T0`.
    fn consult(&self) -> TestResult<EntityId> {
        let spec = TaskCreateSpec::new(rmpv::Value::Nil, None, None, Some(T0))
            .with_kind(TaskKind::Consult)
            .with_consult(ConsultPayload::question(
                ConsultPayloadRef::Turn(self.question),
                Vec::new(),
                EntityId::now(),
            ))
            .with_assignee(TaskAssignee::Peer {
                actor_ref: self.peer,
            })
            .with_ttl(TaskTtl::at(DEADLINE));
        Ok(self
            .asker_facade()
            .tasks_create(&spec)?
            .task_ref
            .ok_or("the asker's consult takes direct effect")?)
    }

    /// The consult's row on the asker's board, read at the engine clock.
    fn board_row(&self, task: EntityId) -> TestResult<TaskIntentPresence> {
        let task_hex = task.to_hex();
        Ok(self
            .asker_facade()
            .describe_rows()?
            .intents
            .into_iter()
            .find(|intent| intent.id == task_hex)
            .ok_or("the consult is on the asker's board")?)
    }

    /// The waits `task` holds in the room's threads, read with the engine
    /// clock and the room's fold both at `now`.
    fn room_waits_on(&self, task: EntityId, now: u64) -> TestResult<usize> {
        self.clock.set(now);
        let threads = self.owner_facade().rooms_threads(
            self.room,
            RoomThreadPolicy {
                now,
                ..RoomThreadPolicy::default()
            },
        )?;
        Ok([threads.active, threads.waiting, threads.quiet]
            .iter()
            .flat_map(|list| &list.rows)
            .flat_map(|thread| &thread.waits)
            .filter(|wait| wait.task == task)
            .count())
    }
}

/// The owner puts the default policy manifest back with a `core:read` row
/// for each actor, the shipped rows (the asker's Auto ceiling among them)
/// kept.
fn grant_reads(vault: &Vault, owner: EntityId, actors: &[EntityId]) -> TestResult {
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.policy_manifests.put")?;
    let view =
        policy_manifests_as_owner(vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    for actor in actors {
        rows.push(PolicyScopedGrantRow {
            // Bare census keys carry no actor class.
            actor_class: None,
            actor_ref: Some(actor.to_hex()),
            effector: "core:read".into(),
            scope: Scope::top(),
            selectors: None,
            budget: None,
            receipt_required: false,
        });
    }
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    Ok(())
}

/// The owner's witness turn `turn` in `room`: one MESSAGE carrying
/// `metadata`.
fn speak(
    vault: &Vault,
    owner: EntityId,
    room: EntityId,
    turn: EntityId,
    metadata: serde_json::Value,
) -> TestResult {
    vault
        .memory(owner, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "room message".into(),
                parts: None,
                metadata: Some(metadata),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: Some(T0),
            assertions: Default::default(),
        })?;
    Ok(())
}

/// No asker has a digest route: an expiry still settles without one.
fn no_digest_route(_asker: EntityId) -> Result<Option<ConsultDigestRoute>, MemoryError> {
    Ok(None)
}

#[test]
fn an_answer_at_the_deadline_second_is_refused() -> TestResult {
    let fixture = Fixture::open()?;
    let consult = fixture.consult()?;
    fixture.clock.set(DEADLINE);
    let refused = fixture
        .peer_facade()
        .land_consult_result(
            consult,
            &ConsultResultInput {
                kind: ConsultResultKind::Answer {
                    result_ref: fixture.trunk,
                    option: None,
                    evidence_refs: vec![ConsultPayloadRef::Turn(fixture.question)],
                },
                completed_at: DEADLINE,
                measured_spend: None,
            },
        )
        .err()
        .ok_or("an answer at the consult's deadline second must not land")?;
    assert_eq!(refused.code, MEMORY_CODE_INVALID_STATE);
    assert_eq!(refused.message, "the consult's deadline has passed");
    Ok(())
}

#[test]
fn the_board_reads_a_consult_expired_at_its_deadline_second() -> TestResult {
    let fixture = Fixture::open()?;
    let consult = fixture.consult()?;
    fixture.clock.set(DEADLINE - 1);
    let before = fixture.board_row(consult)?;
    assert_eq!(
        before.terminal_disposition, None,
        "one second before its deadline the consult is open"
    );
    fixture.clock.set(DEADLINE);
    let at = fixture.board_row(consult)?;
    assert_eq!(
        (at.status, at.terminal_disposition),
        (
            TaskBoardStatus::Failed,
            Some(TaskTerminalDisposition::Expired)
        ),
        "at its deadline second the board derives the expiry before any sweep"
    );
    Ok(())
}

#[test]
fn the_sweep_settles_a_consult_at_its_deadline_second() -> TestResult {
    let fixture = Fixture::open()?;
    let consult = fixture.consult()?;
    fixture.clock.set(DEADLINE - 1);
    let early = fixture
        .vault
        .settle_due_consults(DEADLINE - 1, &no_digest_route)?;
    assert!(
        early.expired_task_refs.is_empty(),
        "one second before its deadline nothing is due"
    );
    fixture.clock.set(DEADLINE);
    let due = fixture
        .vault
        .settle_due_consults(DEADLINE, &no_digest_route)?;
    assert_eq!(due.expired_task_refs, vec![consult]);
    let again = fixture
        .vault
        .settle_due_consults(DEADLINE, &no_digest_route)?;
    assert!(
        again.expired_task_refs.is_empty(),
        "an expired consult is settled once"
    );
    assert_eq!(
        fixture.board_row(consult)?.terminal_disposition,
        Some(TaskTerminalDisposition::Expired)
    );
    Ok(())
}

#[test]
fn a_member_word_at_the_deadline_second_counts_and_leaves_the_member_task_to_the_sweep()
-> TestResult {
    let fixture = Fixture::open()?;
    let owner = fixture.owner_facade();
    let receipt = owner.tasks_ask(&TaskAskSpec::shorthand(
        Some(TaskAskTarget::Responder(TaskAssignee::Human {
            actor_ref: fixture.owner,
        })),
        TaskAskQuestion::new(ConsultPayloadRef::Turn(fixture.question)),
        Some(DEADLINE),
        TaskAskDefault::AskMe,
    ))?;
    let [member] = receipt.task_refs[..] else {
        panic!("the ask mints one member TASK, got {:?}", receipt.task_refs);
    };
    fixture.clock.set(DEADLINE);
    owner.tasks_answer(&receipt.handle, &TaskAskWord::new(fixture.owner))?;
    let TaskAskStatus::Settled(result) = owner.tasks_ask_status(receipt.handle)? else {
        panic!("the ask settles at its deadline second");
    };
    assert_eq!(result.settlement.reason, TaskAskSettlementReason::Deadline);
    assert_eq!(
        result.evidence.len(),
        1,
        "the word counts under the ask's own cutoff"
    );
    let swept = fixture
        .vault
        .settle_due_consults(DEADLINE, &no_digest_route)?;
    assert_eq!(
        swept.expired_task_refs,
        vec![member],
        "at its deadline second the member TASK is the sweep's to settle, not the word's"
    );
    Ok(())
}

#[test]
fn the_room_thread_drops_the_consult_wait_at_its_deadline_second() -> TestResult {
    let fixture = Fixture::open()?;
    let consult = fixture.consult()?;
    assert_eq!(
        fixture.room_waits_on(consult, DEADLINE - 1)?,
        1,
        "one second before its deadline the consult waits in its thread"
    );
    assert_eq!(
        fixture.room_waits_on(consult, DEADLINE)?,
        0,
        "at its deadline second the room reads the consult closed"
    );
    Ok(())
}
