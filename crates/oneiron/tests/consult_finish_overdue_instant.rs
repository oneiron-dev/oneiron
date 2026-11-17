//! FIX FINISH-AUDIT-OVERDUE-AT-DEADLINE-SECOND: a consult ladder Finish at
//! its deadline second is recorded overdue.
//!
//! One consult TTL instant, dead at `now >= deadline_at`, as PR #8899 makes
//! every other consult door read it. The `consult_finish` lifecycle record
//! carries `overdue = "true"` when `deadline <= recorded_at`:
//! - a Finish one second before the deadline keeps no `overdue` field;
//! - a Finish at the deadline second keeps `overdue == "true"`;
//! - a Finish one second after the deadline keeps `overdue == "true"`.
//!
//! On main c715a39b45b5 the second is red: the field is absent at the
//! deadline second. The first and third are green on both.
//!
//! Public paths only, no test doors:
//! `cargo test --locked -p oneiron --all-features --test consult_finish_overdue_instant`.

use std::sync::Arc;

use oneiron::consult_ladder::{
    ConsultLadderState, LadderTerminalDisposition, LadderTerminalState, LadderTransition,
    WorkingState,
};
use oneiron::federation::Scope;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::{
    ConsultPayload, ConsultPayloadRef, TaskAssignee, TaskCreateSpec, TaskKind, TaskTtl,
};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Memory, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The engine clock when the fixture opens; every consult is created here.
const T0: u64 = 1_772_400_000;
/// The deadline second of every consult in this file.
const DEADLINE: u64 = T0 + 3_600;

/// One vault on a clock the test moves, with a project room holding one
/// question turn the consult names. The owner speaks; the asker (an agent)
/// and the peer are on the project's roster.
struct Fixture {
    clock: Arc<ManualClock>,
    vault: Vault,
    asker: EntityId,
    peer: EntityId,
    /// The question TURN the consult asks about, also its Finish result.
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
        let question = EntityId::now();
        speak(&vault, owner, room, question, serde_json::json!({}))?;
        Ok(Self {
            clock,
            vault,
            asker,
            peer,
            question,
            _directory: directory,
        })
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

    /// The peer takes the consult to a ladder `Working` state at `T0`.
    fn to_working(&self, task: EntityId) -> TestResult<()> {
        let started = self.peer_facade().mark_task_started(task, T0)?;
        assert_eq!(
            started.started_at, T0,
            "the peer's start stamps the Working state at T0"
        );
        Ok(())
    }

    /// The peer Finishes the ladder from its `Working` state at `T0`,
    /// claiming the Finish second.
    fn finish_at(&self, task: EntityId, at: u64) -> TestResult<()> {
        let working = ConsultLadderState::Working(WorkingState {
            started_at: T0,
            decision_round: 0,
        });
        let terminal = LadderTerminalState {
            disposition: LadderTerminalDisposition::Approved,
            result_ref: self.question,
            counter_task_ref: None,
            finished_at: at,
        };
        self.peer_facade().compare_and_set_consult_ladder(
            task,
            &working,
            LadderTransition::Finish(terminal),
        )?;
        Ok(())
    }

    /// This TASK's `consult_finish` lifecycle record, read through the
    /// public receipt family. Its absence fails the test, never passes it.
    fn finish_record(&self, task: EntityId) -> TestResult<ReceiptRecord> {
        let query = ReceiptQuery::new(100).with_kind(ReceiptKind::TaskLifecycle);
        let task_hex = task.to_hex();
        let record = self
            .vault
            .receipts(query)?
            .into_iter()
            .find(|receipt| {
                receipt.trigger_ref.as_deref() == Some(task_hex.as_str())
                    && receipt.fields.get("call").map(String::as_str) == Some("consult_finish")
            })
            .ok_or("the Finish kept a consult_finish record for its TASK")?;
        Ok(record)
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
            project: None,
        })?;
    Ok(())
}

/// A Finish one second before the deadline keeps no `overdue` field, and
/// its `recorded_at` is the Finish second.
#[test]
fn a_finish_one_second_before_the_deadline_is_not_overdue() -> TestResult {
    let fixture = Fixture::open()?;
    let consult = fixture.consult()?;
    fixture.to_working(consult)?;
    fixture.clock.set(DEADLINE - 1);
    fixture.finish_at(consult, DEADLINE - 1)?;
    let record = fixture.finish_record(consult)?;
    let recorded = record
        .fields
        .get("recorded_at")
        .ok_or("the finish record names its recorded_at")?;
    let expected = (DEADLINE - 1).to_string();
    assert_eq!(recorded, &expected, "the clock move took effect");
    assert!(
        record.fields.get("overdue").is_none(),
        "one second before its deadline a Finish is not overdue"
    );
    Ok(())
}

/// A Finish at the deadline second keeps `overdue == "true"`. Red on main:
/// the field is absent there.
#[test]
fn a_finish_at_the_deadline_second_is_overdue() -> TestResult {
    let fixture = Fixture::open()?;
    let consult = fixture.consult()?;
    fixture.to_working(consult)?;
    fixture.clock.set(DEADLINE);
    fixture.finish_at(consult, DEADLINE)?;
    let record = fixture.finish_record(consult)?;
    let recorded = record
        .fields
        .get("recorded_at")
        .ok_or("the finish record names its recorded_at")?;
    let expected = DEADLINE.to_string();
    assert_eq!(recorded, &expected, "the clock move took effect");
    assert_eq!(
        record.fields.get("overdue").map(String::as_str),
        Some("true"),
        "at its deadline second a Finish is overdue"
    );
    Ok(())
}

/// A Finish one second after the deadline keeps `overdue == "true"`, so the
/// read sees the field at all and the deadline-second test is not vacuous.
#[test]
fn a_finish_after_the_deadline_is_overdue() -> TestResult {
    let fixture = Fixture::open()?;
    let consult = fixture.consult()?;
    fixture.to_working(consult)?;
    fixture.clock.set(DEADLINE + 1);
    fixture.finish_at(consult, DEADLINE + 1)?;
    let record = fixture.finish_record(consult)?;
    let recorded = record
        .fields
        .get("recorded_at")
        .ok_or("the finish record names its recorded_at")?;
    let expected = (DEADLINE + 1).to_string();
    assert_eq!(recorded, &expected, "the clock move took effect");
    assert_eq!(
        record.fields.get("overdue").map(String::as_str),
        Some("true"),
        "after its deadline a Finish is overdue"
    );
    Ok(())
}
