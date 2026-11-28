//! SESSION-PROJECT-NOTE-MESSAGE-PLACEMENT PR B, the read side: a key with a session
//! default (an attached session's folder, `Memory::in_session_workspace`) reads a NOTE,
//! MESSAGE or TURN only when its stored project is admitted by the session's projects: with
//! no default every row reads as today, `Unbound` reads none, and a bound closure reads the
//! rows placed in its project or below it. A row with no stamp reads as the default (root)
//! project, which no bound closure admits; a stamp that stands but is unusable, or a
//! placement that does not read, is refused quietly. Every other kind passes as today.
//!
//! PLACEMENT-B-ROOM-ROWS = B: a TURN or MESSAGE read through a room's history is admitted by
//! room membership and skips the session check, so a bound session's `rooms_messages` lists
//! speech placed in any project; the same rows read outside the room stay narrowed.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! session_project_note_message_reads`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::claim::{ScopedReadResult, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::core_write::ConversationCreateInput;
use oneiron::memory::{Memory, WitnessReceipt, WitnessTurn};
use oneiron::note::{NoteReadRequest, NoteReadView};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::session_project::{NO_PROJECT_BOUND_AXIS, SESSION_PROJECT_AXIS, WorkspaceBindRequest};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::test_doors::witness_project::stamped_project;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The digest of the folder bound to `alpha`.
const MAIN_DIGEST: &str = "blake3:a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f";
/// The digest of the folder bound to `beta`.
const BETA_DIGEST: &str = "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// A folder nobody bound.
const UNBOUND_DIGEST: &str =
    "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// One invented word every NOTE below holds and no other row does, so the text query finds
/// exactly the NOTEs whose placement admits them.
const NOTE_TOKEN: &str = "quillharpsharednote";

/// A rooted vault whose owner made `alpha` and `beta` under the root, bound `MAIN_DIGEST` to
/// `alpha` and `BETA_DIGEST` to `beta`. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    alpha: EntityId,
    beta: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let root = vault.root_project()?;
    vault.sign_owner_project(&proof, &vault.owner_project_signer(&issuer)?, root)?;
    let facet = EntityId::now();
    vault.put_entity(
        &facet,
        ENTITY_TYPE_FACET,
        TimeRange { start: 1, end: 1 },
        1,
        &rmp_serde::to_vec_named(&json!({ "name": "session write facet" }))?,
    )?;
    let alpha = project_under(&vault, &issuer, &proof, owner, root, facet)?;
    let beta = project_under(&vault, &issuer, &proof, owner, root, facet)?;
    let binding = vault.bind_workspace_as_owner(
        &proof,
        Some(oneiron::authority::ActSurface::ThisInstall),
        WorkspaceBindRequest {
            folder_digest: MAIN_DIGEST.to_owned(),
            project: alpha,
            label: Some("alpha".to_owned()),
        },
    )?;
    assert_eq!(
        binding.project,
        Some(alpha),
        "FIXTURE: the owner binds the alpha folder"
    );
    let binding = vault.bind_workspace_as_owner(
        &proof,
        Some(oneiron::authority::ActSurface::ThisInstall),
        WorkspaceBindRequest {
            folder_digest: BETA_DIGEST.to_owned(),
            project: beta,
            label: Some("beta".to_owned()),
        },
    )?;
    assert_eq!(
        binding.project,
        Some(beta),
        "FIXTURE: the owner binds the beta folder"
    );
    Ok(Fixture {
        vault,
        owner,
        proof,
        alpha,
        beta,
        _dir: dir,
    })
}

/// An owner-born project under `parent`, sliced to `facet`.
fn project_under(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    proof: &AuthenticatedOwner,
    owner: EntityId,
    parent: EntityId,
    facet: EntityId,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    let mut record = ProjectRecord::new(id, Some(parent), vault.root_project()?, owner)?;
    record.slice.facet = Some(facet);
    record.depth_remaining = 1;
    create_owner_project(
        vault,
        issuer,
        proof,
        &vault.owner_project_signer(issuer)?,
        owner,
        id,
        &record,
    )?;
    Ok(id)
}

impl Fixture {
    /// The owner's handle, bound for its writes to the folder `folder_digest` when given.
    fn writer(&self, folder_digest: Option<&str>) -> Memory<'_> {
        let memory = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_owner_authorship(&self.proof);
        match folder_digest {
            Some(digest) => memory.placing_in_session_workspace(&[digest.to_owned()]),
            None => memory,
        }
    }

    /// The owner's reading handle, with no folder: bound reads add
    /// `.in_session_workspace`, never the placing writer.
    fn reader(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }
}

/// One visible user MESSAGE of `content` in a fresh turn of `conversation`, as `vault.witness`
/// takes it without a project.
fn plain_turn(conversation: &str, content: &str) -> WitnessTurn {
    let value = json!({
        "conversation_ref": conversation,
        "messages": [{
            "author": "user",
            "message_type": "dialogue",
            "content": content,
            "is_visible": true,
            "order": 0,
        }],
        "occurred_at": 900,
    });
    serde_json::from_value(value).expect("the witness turn shape decodes")
}

/// The MESSAGE the witness wrote, as its stamped row.
fn first_message(receipt: &WitnessReceipt) -> EntityId {
    let message = receipt
        .messages
        .first()
        .expect("the witness writes one MESSAGE row");
    EntityId::from_hex(&message.id).expect("the message record ref parses")
}

/// The rows every test reads: three NOTEs and one conversation holding one turn from each
/// folder, each written through the placing handle.
struct Rows {
    note_alpha: EntityId,
    note_beta: EntityId,
    note_root: EntityId,
    conversation: EntityId,
    turn_alpha: EntityId,
    turn_beta: EntityId,
    msg_alpha: EntityId,
    msg_beta: EntityId,
}

fn rows(fixture: &Fixture) -> TestResult<Rows> {
    let write_note = |folder, project| -> TestResult<EntityId> {
        let receipt = fixture
            .writer(folder)
            .create_note(
                "research",
                &format!("The {project} note shares {NOTE_TOKEN}."),
            )
            .map_err(|error| format!("FIXTURE: write {project} NOTE: {error:?}"))?;
        Ok(EntityId::from_hex(&receipt.id_hex)?)
    };
    let note_alpha = write_note(Some(MAIN_DIGEST), "alpha")?;
    let note_beta = write_note(Some(BETA_DIGEST), "beta")?;
    let note_root = write_note(None, "root")?;
    let conversation = EntityId::now();
    let conversation_ref = conversation.to_hex();
    let receipt_alpha = fixture
        .writer(Some(MAIN_DIGEST))
        .witness(&plain_turn(&conversation_ref, "The alpha session speaks."))
        .map_err(|error| format!("FIXTURE: witness alpha: {error:?}"))?;
    let receipt_beta = fixture
        .writer(Some(BETA_DIGEST))
        .witness(&plain_turn(&conversation_ref, "The beta session answers."))
        .map_err(|error| format!("FIXTURE: witness beta: {error:?}"))?;
    let turn_alpha = receipt_alpha.turn_id;
    let turn_beta = receipt_beta.turn_id;
    let msg_alpha = first_message(&receipt_alpha);
    let msg_beta = first_message(&receipt_beta);
    for (name, id, project) in [
        ("alpha NOTE", note_alpha, fixture.alpha),
        ("beta NOTE", note_beta, fixture.beta),
        ("root NOTE", note_root, default_project_id()),
        ("alpha TURN", turn_alpha, fixture.alpha),
        ("beta TURN", turn_beta, fixture.beta),
        ("alpha MESSAGE", msg_alpha, fixture.alpha),
        ("beta MESSAGE", msg_beta, fixture.beta),
    ] {
        assert_eq!(
            stamped_project(&fixture.vault, id)?,
            Some(project),
            "FIXTURE: {name} is placed in its expected project"
        );
    }
    Ok(Rows {
        note_alpha,
        note_beta,
        note_root,
        conversation,
        turn_alpha,
        turn_beta,
        msg_alpha,
        msg_beta,
    })
}

fn read_note(
    memory: &Memory<'_>,
    note: EntityId,
) -> TestResult<ScopedReadResult<Option<NoteReadView>>> {
    let reference = note.to_hex();
    let request: NoteReadRequest = serde_json::from_value(json!({ "note_ref": reference }))?;
    memory
        .read_note(&request)
        .map_err(|error| format!("vault.notes.read {reference}: {error:?}").into())
}

#[test]
fn a_bound_folder_reads_its_projects_note_and_not_another_projects_or_the_roots() -> TestResult {
    let fixture = open()?;
    let written = rows(&fixture)?;
    let session = fixture
        .reader()
        .in_session_workspace(&[MAIN_DIGEST.to_owned()]);
    assert!(
        read_note(&session, written.note_alpha)?.value.is_some(),
        "MAIN reads its own project's NOTE"
    );
    assert!(
        read_note(&session, written.note_beta)?.value.is_none(),
        "MAIN does not read beta's NOTE"
    );
    assert!(
        read_note(&session, written.note_root)?.value.is_none(),
        "MAIN does not read the root NOTE"
    );
    Ok(())
}

#[test]
fn a_handle_with_no_folder_reads_every_note_as_before() -> TestResult {
    let fixture = open()?;
    let written = rows(&fixture)?;
    let memory = fixture.reader();
    for (project, note) in [
        ("alpha", written.note_alpha),
        ("beta", written.note_beta),
        ("root", written.note_root),
    ] {
        let served = read_note(&memory, note)?;
        assert!(served.value.is_some(), "no folder reads the {project} NOTE");
        assert!(
            !served
                .receipt
                .narrowed_axes
                .iter()
                .any(|axis| { axis == SESSION_PROJECT_AXIS || axis == NO_PROJECT_BOUND_AXIS }),
            "no folder names no session axis on the {project} NOTE's receipt"
        );
    }
    Ok(())
}

#[test]
fn an_unbound_folder_reads_no_note_and_its_receipt_says_why() -> TestResult {
    let fixture = open()?;
    let written = rows(&fixture)?;
    let session = fixture
        .reader()
        .in_session_workspace(&[UNBOUND_DIGEST.to_owned()]);
    for (project, note) in [
        ("alpha", written.note_alpha),
        ("beta", written.note_beta),
        ("root", written.note_root),
    ] {
        let served = read_note(&session, note)?;
        assert!(
            served.value.is_none(),
            "UNBOUND does not read the {project} NOTE"
        );
        assert!(
            served
                .receipt
                .narrowed_axes
                .iter()
                .any(|axis| axis == NO_PROJECT_BOUND_AXIS),
            "UNBOUND names no_project_bound on the {project} NOTE's receipt"
        );
    }
    Ok(())
}

#[test]
fn a_point_read_of_another_projects_turn_or_message_reads_nothing() -> TestResult {
    let fixture = open()?;
    let written = rows(&fixture)?;
    let memory = fixture.reader();
    let session = memory.in_session_workspace(&[MAIN_DIGEST.to_owned()]);
    let reads = |reader: &Memory<'_>, id: EntityId| -> TestResult<bool> {
        let reference = id.to_hex();
        Ok(reader
            .get_entity(&reference)
            .map_err(|error| format!("vault.get {reference}: {error:?}"))?
            .value
            .is_some())
    };
    for (name, id, main_reads) in [
        ("alpha TURN", written.turn_alpha, true),
        ("alpha MESSAGE", written.msg_alpha, true),
        ("beta TURN", written.turn_beta, false),
        ("beta MESSAGE", written.msg_beta, false),
    ] {
        assert_eq!(
            reads(&session, id)?,
            main_reads,
            "MAIN point read of {name}"
        );
        assert!(reads(&memory, id)?, "no folder reads the {name}");
    }
    Ok(())
}

#[test]
fn a_bound_folders_transcript_reads_only_its_projects_turns() -> TestResult {
    let fixture = open()?;
    let written = rows(&fixture)?;
    let memory = fixture.reader();
    let alpha = written.turn_alpha.to_hex();
    let beta = written.turn_beta.to_hex();
    for (name, reader, expected) in [
        (
            "MAIN",
            memory.in_session_workspace(&[MAIN_DIGEST.to_owned()]),
            BTreeSet::from([alpha.clone()]),
        ),
        (
            "BETA",
            memory.in_session_workspace(&[BETA_DIGEST.to_owned()]),
            BTreeSet::from([beta.clone()]),
        ),
        ("no folder", memory, BTreeSet::from([alpha, beta])),
    ] {
        let transcript = reader
            .conversation_transcript(&written.conversation, None, 50)
            .map_err(|error| format!("{name} transcript: {error:?}"))?;
        let turns: BTreeSet<_> = transcript
            .value
            .turns
            .into_iter()
            .map(|turn| turn.id)
            .collect();
        assert_eq!(turns, expected, "{name} lists only its expected TURNs");
    }
    Ok(())
}

#[test]
fn a_bound_folders_text_query_finds_only_its_projects_rows() -> TestResult {
    let fixture = open()?;
    let written = rows(&fixture)?;
    let memory = fixture.reader();
    let alpha = written.note_alpha.to_hex();
    let beta = written.note_beta.to_hex();
    let root = written.note_root.to_hex();
    for (name, reader, expected) in [
        (
            "no folder",
            memory.clone(),
            BTreeSet::from([alpha.clone(), beta.clone(), root]),
        ),
        (
            "MAIN",
            memory.in_session_workspace(&[MAIN_DIGEST.to_owned()]),
            BTreeSet::from([alpha]),
        ),
        (
            "BETA",
            memory.in_session_workspace(&[BETA_DIGEST.to_owned()]),
            BTreeSet::from([beta]),
        ),
        (
            "UNBOUND",
            memory.in_session_workspace(&[UNBOUND_DIGEST.to_owned()]),
            BTreeSet::new(),
        ),
    ] {
        let read = reader
            .query_bm25(NOTE_TOKEN, 10)
            .map_err(|error| format!("{name} BM25: {error:?}"))?;
        let notes: BTreeSet<_> = read
            .value
            .into_iter()
            .map(|hit| hit.record.expect("a BM25 hit carries its record ref").id)
            .collect();
        assert_eq!(notes, expected, "{name} finds only its expected NOTEs");
    }
    Ok(())
}

/// One invented word each room speech below holds and no other row does, so the text query
/// finds exactly the MESSAGE whose placement admits it.
const ROOM_ROOT_TOKEN: &str = "quillharproomroot";
const ROOM_BETA_TOKEN: &str = "quillharproombeta";
const ROOM_ALPHA_TOKEN: &str = "quillharproomalpha";

/// One visible user MESSAGE of `content` spoken into the room `room`, as `rooms_speak` takes
/// it: `conversation_ref` names the room, so the speech lands one TURN with one MESSAGE.
fn room_turn(room: &str, content: &str, occurred_at: u64) -> WitnessTurn {
    let value = json!({
        "conversation_ref": room,
        "messages": [{
            "author": "user",
            "message_type": "dialogue",
            "content": content,
            "is_visible": true,
            "order": 0,
        }],
        "occurred_at": occurred_at,
    });
    serde_json::from_value(value).expect("the witness turn shape decodes")
}

/// One ordinary room holding one speech from each folder: root (`writer(None)`), beta, and
/// alpha (the control), each with its TURN and MESSAGE.
struct RoomRows {
    room: EntityId,
    turn_root: EntityId,
    turn_beta: EntityId,
    turn_alpha: EntityId,
    msg_root: EntityId,
    msg_beta: EntityId,
    msg_alpha: EntityId,
}

fn room_rows(fixture: &Fixture) -> TestResult<RoomRows> {
    let created = fixture
        .writer(None)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({
                "v": 1,
                "kind": "group",
                "member_ids": [fixture.owner.to_hex()],
                "title": "session project room",
            }),
            text: None,
        })
        .map_err(|error| format!("FIXTURE: open ordinary room: {error:?}"))?;
    let room = EntityId::from_hex(&created.id)?;
    let room_ref = room.to_hex();
    let speak = |folder: Option<&str>, word: &str, at: u64| {
        fixture
            .writer(folder)
            .rooms_speak(&room_turn(
                &room_ref,
                &format!("The room speech says {word}."),
                at,
            ))
            .map_err(|error| format!("FIXTURE: speak {word}: {error:?}"))
    };
    let receipt_root = speak(None, ROOM_ROOT_TOKEN, 901)?;
    let receipt_beta = speak(Some(BETA_DIGEST), ROOM_BETA_TOKEN, 902)?;
    let receipt_alpha = speak(Some(MAIN_DIGEST), ROOM_ALPHA_TOKEN, 903)?;
    let spoken = RoomRows {
        room,
        turn_root: receipt_root.turn_id,
        turn_beta: receipt_beta.turn_id,
        turn_alpha: receipt_alpha.turn_id,
        msg_root: first_message(&receipt_root),
        msg_beta: first_message(&receipt_beta),
        msg_alpha: first_message(&receipt_alpha),
    };
    for (name, id, project) in [
        ("root TURN", spoken.turn_root, default_project_id()),
        ("beta TURN", spoken.turn_beta, fixture.beta),
        ("alpha TURN", spoken.turn_alpha, fixture.alpha),
        ("root MESSAGE", spoken.msg_root, default_project_id()),
        ("beta MESSAGE", spoken.msg_beta, fixture.beta),
        ("alpha MESSAGE", spoken.msg_alpha, fixture.alpha),
    ] {
        assert_eq!(
            stamped_project(&fixture.vault, id)?,
            Some(project),
            "FIXTURE: {name} is placed in its expected project"
        );
    }
    Ok(spoken)
}

#[test]
fn a_bound_session_reads_root_and_other_project_speech_in_its_room() -> TestResult {
    let fixture = open()?;
    let spoken = room_rows(&fixture)?;
    let session = fixture
        .reader()
        .in_session_workspace(&[MAIN_DIGEST.to_owned()]);
    let history = session
        .rooms_messages(spoken.room)
        .map_err(|error| format!("MAIN room history: {error:?}"))?;
    let turns: BTreeSet<_> = history.iter().map(|turn| turn.turn_id.clone()).collect();
    for (name, id) in [
        ("root", spoken.turn_root),
        ("beta", spoken.turn_beta),
        ("alpha", spoken.turn_alpha),
    ] {
        assert!(
            turns.contains(&id.to_hex()),
            "MAIN's room history lists the {name} speech TURN"
        );
    }
    for (name, turn, message) in [
        ("root", spoken.turn_root, spoken.msg_root),
        ("beta", spoken.turn_beta, spoken.msg_beta),
        ("alpha", spoken.turn_alpha, spoken.msg_alpha),
    ] {
        let row = history
            .iter()
            .find(|row| row.turn_id == turn.to_hex())
            .unwrap_or_else(|| panic!("MAIN's room history lists the {name} speech TURN"));
        assert!(
            row.message_ids.contains(&message.to_hex()),
            "MAIN's room history lists the {name} speech MESSAGE beside its TURN"
        );
    }
    let control = fixture
        .reader()
        .rooms_messages(spoken.room)
        .map_err(|error| format!("no folder room history: {error:?}"))?;
    let turns: BTreeSet<_> = control.iter().map(|turn| turn.turn_id.clone()).collect();
    for (name, id) in [
        ("root", spoken.turn_root),
        ("beta", spoken.turn_beta),
        ("alpha", spoken.turn_alpha),
    ] {
        assert!(
            turns.contains(&id.to_hex()),
            "no folder lists the {name} speech TURN"
        );
    }
    Ok(())
}

#[test]
fn outside_the_room_a_bound_session_still_misses_root_and_other_project_speech() -> TestResult {
    let fixture = open()?;
    let spoken = room_rows(&fixture)?;
    let memory = fixture.reader();
    let session = memory.in_session_workspace(&[MAIN_DIGEST.to_owned()]);
    let reads = |reader: &Memory<'_>, id: EntityId| -> TestResult<bool> {
        let reference = id.to_hex();
        Ok(reader
            .get_entity(&reference)
            .map_err(|error| format!("vault.get {reference}: {error:?}"))?
            .value
            .is_some())
    };
    for (name, id, main_reads) in [
        ("root speech TURN", spoken.turn_root, false),
        ("beta speech TURN", spoken.turn_beta, false),
        ("alpha speech TURN", spoken.turn_alpha, true),
        ("root speech MESSAGE", spoken.msg_root, false),
        ("beta speech MESSAGE", spoken.msg_beta, false),
        ("alpha speech MESSAGE", spoken.msg_alpha, true),
    ] {
        assert_eq!(
            reads(&session, id)?,
            main_reads,
            "MAIN outside the room point read of {name}"
        );
        assert!(reads(&memory, id)?, "no folder reads the {name}");
    }
    for (name, word, message) in [
        ("root", ROOM_ROOT_TOKEN, spoken.msg_root),
        ("beta", ROOM_BETA_TOKEN, spoken.msg_beta),
    ] {
        let found: BTreeSet<_> = session
            .query_bm25(word, 10)
            .map_err(|error| format!("MAIN BM25 {name}: {error:?}"))?
            .value
            .into_iter()
            .map(|hit| hit.record.expect("a BM25 hit carries its record ref").id)
            .collect();
        assert!(
            !found.contains(&message.to_hex()),
            "MAIN outside the room does not recall the {name} speech MESSAGE"
        );
        let control: BTreeSet<_> = memory
            .query_bm25(word, 10)
            .map_err(|error| format!("no folder BM25 {name}: {error:?}"))?
            .value
            .into_iter()
            .map(|hit| hit.record.expect("a BM25 hit carries its record ref").id)
            .collect();
        assert!(
            control.contains(&message.to_hex()),
            "no folder recalls the {name} speech MESSAGE"
        );
    }
    let found: BTreeSet<_> = session
        .query_bm25(ROOM_ALPHA_TOKEN, 10)
        .map_err(|error| format!("MAIN BM25 alpha: {error:?}"))?
        .value
        .into_iter()
        .map(|hit| hit.record.expect("a BM25 hit carries its record ref").id)
        .collect();
    assert!(
        found.contains(&spoken.msg_alpha.to_hex()),
        "MAIN outside the room recalls the alpha speech MESSAGE"
    );
    Ok(())
}

#[test]
fn a_bound_session_pages_its_room_history_past_root_speech_at_the_end() -> TestResult {
    let fixture = open()?;
    let spoken = room_rows(&fixture)?;
    let room_ref = spoken.room.to_hex();
    let mut late = Vec::new();
    for (word, at) in [("quillharproomlate", 904), ("quillharproomlast", 905)] {
        let receipt = fixture
            .writer(None)
            .rooms_speak(&room_turn(
                &room_ref,
                &format!("The room speech says {word}."),
                at,
            ))
            .map_err(|error| format!("FIXTURE: speak {word}: {error:?}"))?;
        assert_eq!(
            stamped_project(&fixture.vault, receipt.turn_id)?,
            Some(default_project_id()),
            "FIXTURE: the {word} TURN is placed at the root"
        );
        late.push(receipt.turn_id);
    }
    let session = fixture
        .reader()
        .in_session_workspace(&[MAIN_DIGEST.to_owned()]);
    let mut listed = Vec::new();
    let mut after = None;
    for _ in 0..16 {
        let page = session
            .rooms_messages_page(spoken.room, after, 1)
            .map_err(|error| format!("MAIN room history page after {after:?}: {error:?}"))?;
        listed.extend(page.rows.iter().map(|turn| turn.turn_id.clone()));
        match page.next_after {
            Some(next) => after = Some(EntityId::from_hex(&next)?),
            None => break,
        }
    }
    for (name, id) in [
        ("root", spoken.turn_root),
        ("beta", spoken.turn_beta),
        ("alpha", spoken.turn_alpha),
        ("late root", late[0]),
        ("last root", late[1]),
    ] {
        assert!(
            listed.contains(&id.to_hex()),
            "MAIN's room history, one page at a time, lists the {name} speech TURN"
        );
    }
    Ok(())
}
