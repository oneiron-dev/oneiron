//! Restriction wave 18: seven context board caps as owner Setting keys, guard and red tests.
//!
//! Each fixed board cap is an owner-only Setting key defaulting to today's cut, so a board
//! renders as before until the owner moves one. A GUARD test sets nothing and asserts today's
//! exact cut (it passes on the seam and on the head); a RED test sets its key above today's cap
//! and asserts the formerly cut rows now show (it fails by assertion on the seam, where
//! `read_count` returns the default, and passes on the head). Public paths only; no test door:
//! the unprocessed heavy memories plant through `put_entity` / `put_claim` / `put_edge` /
//! `annotate_turn_vad` / `consolidate_claim_vad_now`, as `src/tests/claim_vad.rs` does.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! context_board_rows_shown` (the owner fixture is `tests/setting_primitive.rs`'s).
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::claim::ScopedReadActorKey;
use oneiron::consent::AuthenticatedOwner;
use oneiron::context_board::{
    FoldSummary, People, PeopleView, SectionFold, TaskBoardStatus, TaskIntentPresence,
    TasksSection, TasksSectionRows, fold_attention_rows, fold_line, unprocessed_items,
};
use oneiron::conversation::{ConversationBody, ConversationKind};
use oneiron::memory::Memory;
use oneiron::note::{NoteKind, NoteScope, NoteWriteEnvelope};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionId;
use oneiron::task_type::{SeedTaskType, TaskTypeRef};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::task_verb::sdk::invoke;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EdgeKind, EntityId, TimeRange, Vad, VadAnnotation, VadAnnotationSource, Vault,
    VaultConfig, WriteActor,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SET: &str = "vault.settings.set";
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    _issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned: the
    /// writer lease is what lets the owner's handle call the owner verbs by name.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            _issuer: issuer,
            owner,
            owner_proof,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn vault_scope() -> Value {
    json!({ "kind": "vault" })
}

fn set(key: &str, scope: Value, value: Value) -> Value {
    json!({ "key": key, "scope": scope, "value": value })
}

/// The owner sets `key` to `value` through `vault.settings.set` and reads it back.
fn owner_sets(fx: &Fixture, key: &str, value: u32) {
    let me = fx.as_owner();
    let applied = call(&me, SET, set(key, vault_scope(), json!(value)));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
}

/// One PERSON row holding `body`.
fn put_person(vault: &Vault, body: &[u8]) -> TestResult<EntityId> {
    let person = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        body,
    )?;
    Ok(person)
}

/// `count` TASKS the owner creates and owns, each labelled `task-{index:03}`.
fn owner_tasks(fx: &Fixture, count: usize) -> TestResult<()> {
    let me = fx.as_owner();
    for index in 0..count {
        let receipt = me.tasks_create(&TaskCreateSpec::new(
            rmpv::Value::Nil,
            Some(format!("task-{index:03}")),
            Some(fx.owner),
            Some(fx.vault.now_recorded_at()),
        ))?;
        assert!(
            receipt.task_ref.is_some(),
            "task {index} mints one TASK, got {receipt:?}"
        );
    }
    Ok(())
}

/// The `invite?:` line of a ROOM section, by its prefix.
fn invite_line(section: &oneiron::context_board::BoardSection) -> TestResult<String> {
    section
        .detail_rows()
        .iter()
        .find(|row| row.starts_with("invite?:"))
        .cloned()
        .ok_or_else(|| "the ROOM section names its invite line".into())
}

/// How many persons an `invite?:` line names (its comma-separated labels before any ` +N`).
fn invite_named(line: &str) -> usize {
    let rest = line.strip_prefix("invite?:").unwrap_or(line).trim();
    let named = rest.split(" +").next().unwrap_or(rest).trim();
    if named.is_empty() {
        0
    } else {
        named.split(',').count()
    }
}

/// The owner's read lane, as `graph_ask_centre_owner_read.rs` builds it.
fn owner_read(fx: &Fixture) -> TestResult<oneiron::claim::ScopedRead<'_>> {
    let key: ScopedReadActorKey = fx.as_owner().read_key()?;
    Ok(fx.vault.scoped_read(key))
}

/// One heavy-memory candidate: a CLAIM about `subject` with one VAD turn, consolidated now.
/// The CLAIM is Active, learned at `learned_at`, its VAD state carries `valence`.
fn plant_heavy_memory(
    vault: &Vault,
    subject: EntityId,
    learned_at: u64,
    now: u64,
    valence: f32,
) -> TestResult<EntityId> {
    let turn = EntityId::now();
    vault.put_entity(
        &turn,
        ENTITY_TYPE_TURN,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        &rmp_serde::to_vec_named(&json!({ "txt": "claim VAD fixture turn" }))?,
    )?;
    vault.annotate_turn_vad(
        &turn,
        VadAnnotation::new(
            Vad {
                valence,
                arousal: 0.9,
                dominance: 0.5,
            },
            VadAnnotationSource::ModelInference,
            learned_at + 10,
        )?,
    )?;
    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        "dream.symbol",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("blue door"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.evidence = Some(rmpv::Value::Array(vec![rmpv::Value::Binary(
        turn.as_bytes().to_vec(),
    )]));
    body.source = Some(ClaimSource::Inferred);
    vault.put_claim(
        &claim,
        &body,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
    )?;
    vault.put_edge(&claim, EdgeKind::Mentions, &subject, 0.6)?;
    vault.consolidate_claim_vad_now(&claim, now)?;
    Ok(claim)
}

/// A private diary entry `author` writes, as `turn_program_triggers.rs` writes one.
fn put_diary(vault: &Vault, author: EntityId, markdown: &str) -> TestResult<EntityId> {
    let receipt = vault
        .memory(author, EdgeActorClass::Human)
        .author_note(&NoteWriteEnvelope {
            kind: NoteKind::Diary,
            scope: NoteScope::ActorPrivate { owner_ref: author },
            markdown: markdown.into(),
            source_revision_ref: [0x7a; 16],
            mask: None,
        })?;
    Ok(EntityId::from_hex(&receipt.id_hex)?)
}

// TASKS rows: `context_board.tasks.rows_shown` (100).

/// The rows the owner's board renders from, and how many rows they hold in all.
fn owner_task_rows(fx: &Fixture) -> TestResult<(TasksSectionRows, usize)> {
    let rows = fx.as_owner().describe_rows()?;
    let total = rows.intents.len() + rows.bare_jobs.len();
    Ok((rows, total))
}

#[test]
fn the_board_shows_a_hundred_tasks_rows_and_counts_the_rest() -> TestResult {
    let fx = Fixture::rooted();
    owner_tasks(&fx, 101)?;
    let (rows, total) = owner_task_rows(&fx)?;
    assert!(total >= 101, "every TASK is a row: {total}");
    assert_eq!(rows.rows_shown, 100, "no row set: the default");
    let section = rows.render();
    assert_eq!(section.rows.len(), 100, "today's cut shows 100 rows");
    let overflow = section.overflow.expect("the rows past the cut count");
    assert_eq!(overflow.known_omitted_rows, total - 100);
    assert!(overflow.source_exhausted);
    Ok(())
}

#[test]
fn the_owner_shows_more_tasks_rows_than_the_default_hundred() -> TestResult {
    let fx = Fixture::rooted();
    owner_tasks(&fx, 101)?;
    owner_sets(&fx, "context_board.tasks.rows_shown", 10_000);
    let (rows, total) = owner_task_rows(&fx)?;
    let section = rows.render();
    assert_eq!(section.rows.len(), total, "the looser cap shows every row");
    assert_eq!(section.overflow, None, "nothing omitted, no footer");
    Ok(())
}

// TASKS fits: `context_board.tasks.fits_shown` (3).

/// One open, unassigned row of `task_type` plus one Done row of it per `finishers`.
fn fits_rows(finishers: &[EntityId], task_type: TaskTypeRef) -> (TasksSectionRows, EntityId) {
    let mut rows = TasksSectionRows {
        intents: Vec::new(),
        bare_jobs: Vec::new(),
        source_exhausted: true,
        rows_shown: TasksSection::RENDER_ROW_CAP,
    };
    for person in finishers {
        let mut done = TaskIntentPresence::new(
            EntityId::now().to_hex(),
            TaskBoardStatus::Done,
            None,
            false,
            Vec::new(),
        );
        done.who = Some(*person);
        done.type_ref = Some(task_type.clone());
        rows.intents.push(done);
    }
    let open_task = EntityId::now();
    let mut open = TaskIntentPresence::new(
        open_task.to_hex(),
        TaskBoardStatus::Queued,
        None,
        false,
        Vec::new(),
    );
    open.type_ref = Some(task_type);
    rows.intents.push(open);
    (rows, open_task)
}

fn fits_people(vault: &Vault, persons: &[EntityId]) -> TestResult<(People, BTreeSet<EntityId>)> {
    let now = vault.now_recorded_at();
    let admitted = persons.to_vec();
    let people = People::load(vault, now, &mut |person| Ok(admitted.contains(&person)))?;
    let resident: BTreeSet<EntityId> = persons.iter().copied().collect();
    Ok((people, resident))
}

#[test]
fn the_board_names_three_fits_on_an_open_tasks_row() -> TestResult {
    let fx = Fixture::rooted();
    let mut persons = Vec::new();
    for _ in 0..4 {
        persons.push(put_person(&fx.vault, b"owen")?);
    }
    let tree = oneiron::task_type::type_tree(&fx.vault, None)?;
    let task_type = TaskTypeRef::seed(SeedTaskType::Build, tree.version());
    let (mut rows, open_task) = fits_rows(&persons, task_type);
    let (people, resident) = fits_people(&fx.vault, &persons)?;
    let view = PeopleView::new(&people, &resident);
    rows.attach_people(&fx.vault, &view, &[]);
    let open = rows
        .intents
        .iter()
        .find(|row| row.id == open_task.to_hex())
        .expect("the open task row");
    assert_eq!(open.fits.len(), 3, "today's cut names three fits");
    Ok(())
}

#[test]
fn the_owner_names_four_fits_on_an_open_tasks_row() -> TestResult {
    let fx = Fixture::rooted();
    let mut persons = Vec::new();
    for _ in 0..4 {
        persons.push(put_person(&fx.vault, b"owen")?);
    }
    owner_sets(&fx, "context_board.tasks.fits_shown", 4);
    let tree = oneiron::task_type::type_tree(&fx.vault, None)?;
    let task_type = TaskTypeRef::seed(SeedTaskType::Build, tree.version());
    let (mut rows, open_task) = fits_rows(&persons, task_type);
    let (people, resident) = fits_people(&fx.vault, &persons)?;
    let view = PeopleView::new(&people, &resident);
    rows.attach_people(&fx.vault, &view, &[]);
    let open = rows
        .intents
        .iter()
        .find(|row| row.id == open_task.to_hex())
        .expect("the open task row");
    assert_eq!(open.fits.len(), 4, "the looser cap names all four fits");
    Ok(())
}

// Fold attention: `context_board.fold.attention_rows` (3).

fn fold_fixture() -> (FoldSummary, SectionFold) {
    let summary = FoldSummary::total(4).count_rows(
        "failed",
        4,
        vec![
            "r1".to_owned(),
            "r2".to_owned(),
            "r3".to_owned(),
            "r4".to_owned(),
        ],
    );
    (summary, SectionFold::default())
}

#[test]
fn a_fold_line_names_three_attention_rows_and_counts_one_more() -> TestResult {
    let fx = Fixture::rooted();
    assert_eq!(fold_attention_rows(&fx.vault), 3);
    let (summary, fold) = fold_fixture();
    let line = fold_line("tasks", &summary, &fold, None, 3);
    assert_eq!(
        line,
        "4 \u{00b7} 4 failed: r1, r2, r3 +1 \u{00b7} \
         open: self.board.unfold({section: \"tasks\"})"
    );
    Ok(())
}

#[test]
fn the_owner_names_four_attention_rows_on_a_fold_line() -> TestResult {
    let fx = Fixture::rooted();
    owner_sets(&fx, "context_board.fold.attention_rows", 4);
    assert_eq!(fold_attention_rows(&fx.vault), 4);
    let (summary, fold) = fold_fixture();
    let line = fold_line(
        "tasks",
        &summary,
        &fold,
        None,
        fold_attention_rows(&fx.vault),
    );
    assert_eq!(
        line,
        "4 \u{00b7} 4 failed: r1, r2, r3, r4 \u{00b7} \
         open: self.board.unfold({section: \"tasks\"})"
    );
    Ok(())
}

// Unprocessed: `context_board.unprocessed.max_items` (128).

const HEAVY_MEMORIES: usize = 129;
const THREE_DAYS: u64 = 3 * 24 * 60 * 60;

fn heavy_vault() -> TestResult<Fixture> {
    let fx = Fixture::rooted();
    let now = fx.vault.now_recorded_at();
    let learned_at = now - THREE_DAYS - 24 * 60 * 60;
    let subject = put_person(&fx.vault, b"heavy subject")?;
    for _ in 0..HEAVY_MEMORIES {
        plant_heavy_memory(&fx.vault, subject, learned_at, now, -1.0)?;
    }
    Ok(fx)
}

#[test]
fn the_board_lists_a_hundred_twenty_eight_unprocessed_memories() -> TestResult {
    let fx = heavy_vault()?;
    let now = fx.vault.now_recorded_at();
    let read = owner_read(&fx)?;
    let items = unprocessed_items(&read, now)?;
    assert_eq!(items.len(), 128, "today's cut lists 128 heavy memories");
    Ok(())
}

#[test]
fn the_owner_lists_more_unprocessed_memories_than_the_default() -> TestResult {
    let fx = heavy_vault()?;
    owner_sets(&fx, "context_board.unprocessed.max_items", 200);
    let now = fx.vault.now_recorded_at();
    let read = owner_read(&fx)?;
    let items = unprocessed_items(&read, now)?;
    assert_eq!(items.len(), 129, "the looser cap lists every heavy memory");
    Ok(())
}

// ROOM invites: `context_board.room.invite_shown` (5).

/// An ordinary room seating a leader and a member, and six outsiders: PERSONs with no join of
/// the room, so each is one the owner may invite (`roster_invitee_in_txn`). Returns the room and
/// every PERSON the board admits (the seating plus the six). No invitation is filed: a filed
/// one is a live join, which takes its person off `invite?:`.
fn invite_fixture(fx: &Fixture) -> TestResult<(EntityId, Vec<EntityId>)> {
    let leader = put_person(&fx.vault, b"owen")?;
    let member = put_person(&fx.vault, b"yuki")?;
    let room = EntityId::now();
    fx.vault.create_conversation(
        room,
        &ConversationBody {
            kind: ConversationKind::Group,
            member_ids: vec![leader, member],
            ..Default::default()
        },
        WriteActor::new(fx.owner, EdgeActorClass::Human),
        fx.vault.now_recorded_at(),
    )?;
    let mut persons = vec![leader, member];
    for _ in 0..6 {
        persons.push(put_person(&fx.vault, b"owen-two")?);
    }
    Ok((room, persons))
}

fn room_invite_line(fx: &Fixture, room: EntityId, persons: &[EntityId]) -> TestResult<String> {
    let section = fx.as_owner().rooms_render(room)?;
    let now = fx.vault.now_recorded_at();
    let admitted = persons.to_vec();
    let people = People::load(&fx.vault, now, &mut |person| Ok(admitted.contains(&person)))?;
    let resident: BTreeSet<EntityId> = persons.iter().copied().collect();
    let view = PeopleView::new(&people, &resident);
    let board = section.board_section(&view)?;
    invite_line(&board)
}

#[test]
fn the_room_names_five_invitees_and_counts_the_rest() -> TestResult {
    let fx = Fixture::rooted();
    let (room, persons) = invite_fixture(&fx)?;
    let line = room_invite_line(&fx, room, &persons)?;
    assert_eq!(invite_named(&line), 5, "today's cut names five: {line}");
    assert!(line.contains(" +"), "the rest count: {line}");
    Ok(())
}

#[test]
fn the_owner_names_every_invitee_in_the_room() -> TestResult {
    let fx = Fixture::rooted();
    let (room, persons) = invite_fixture(&fx)?;
    owner_sets(&fx, "context_board.room.invite_shown", 50);
    let line = room_invite_line(&fx, room, &persons)?;
    assert!(
        invite_named(&line) >= 6,
        "the looser cap names every outsider: {line}"
    );
    assert!(!line.contains(" +"), "nothing counted: {line}");
    Ok(())
}

// READERS rows and reason bytes: `context_board.readers.rows_shown` (4) and
// `context_board.readers.reason_bytes` (160).

/// An agent with one diary entry, one granted reader, and five logged reads, each stating the
/// same 200-byte reason (so no assertion depends on the log's order).
fn readers_fixture(fx: &Fixture) -> TestResult<(EntityId, EntityId, String)> {
    let agent = put_person(&fx.vault, b"diary agent")?;
    let reader = put_person(&fx.vault, b"diary reader")?;
    put_diary(&fx.vault, agent, "private journal entry")?;
    fx.as_owner().grant_diary_read(
        &fx.owner_proof,
        WriteActor::new(reader, EdgeActorClass::Agent),
        agent,
        &[],
    )?;
    let long = "L".repeat(200);
    for _ in 0..5 {
        fx.vault
            .memory(reader, EdgeActorClass::Agent)
            .read_agent_diary(None, agent, &long)?;
    }
    Ok((agent, reader, long))
}

fn readers_rows(fx: &Fixture, agent: EntityId) -> TestResult<Vec<String>> {
    let now = fx.vault.now_recorded_at();
    let people = People::load(&fx.vault, now, &mut |_| Ok(true))?;
    let resident: BTreeSet<EntityId> = people.rows().iter().map(|row| row.person).collect();
    let view = PeopleView::new(&people, &resident);
    let section = fx
        .vault
        .memory(agent, EdgeActorClass::Human)
        .board_readers_section(&view)?;
    Ok(section.detail_rows().to_vec())
}

fn read_rows(rows: &[String]) -> Vec<&String> {
    rows.iter()
        .filter(|row| row.starts_with("read: "))
        .collect()
}

#[test]
fn the_readers_block_shows_four_reads_and_clips_a_long_reason() -> TestResult {
    let fx = Fixture::rooted();
    let (agent, _, long) = readers_fixture(&fx)?;
    let rows = readers_rows(&fx, agent)?;
    let reads = read_rows(&rows);
    assert_eq!(reads.len(), 4, "today's cut shows four reads: {rows:?}");
    let clipped = "L".repeat(160);
    for row in &reads {
        assert!(
            row.contains(&clipped),
            "each reason shows its first 160 bytes: {row}"
        );
        assert!(
            !row.contains(&long),
            "no 200-byte reason shows whole: {row}"
        );
    }
    Ok(())
}

#[test]
fn the_owner_shows_five_reads_in_the_readers_block() -> TestResult {
    let fx = Fixture::rooted();
    let (agent, _, _) = readers_fixture(&fx)?;
    owner_sets(&fx, "context_board.readers.rows_shown", 5);
    let rows = readers_rows(&fx, agent)?;
    assert_eq!(
        read_rows(&rows).len(),
        5,
        "the looser cap shows five reads: {rows:?}"
    );
    Ok(())
}

#[test]
fn the_owner_reads_a_long_reason_whole_in_the_readers_block() -> TestResult {
    let fx = Fixture::rooted();
    let (agent, _, long) = readers_fixture(&fx)?;
    owner_sets(&fx, "context_board.readers.reason_bytes", 200);
    let rows = readers_rows(&fx, agent)?;
    let reads = read_rows(&rows);
    assert!(
        reads.iter().any(|row| row.contains(&long)),
        "the 200-byte reason shows whole: {rows:?}"
    );
    Ok(())
}
