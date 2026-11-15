//! One-vault work talk in the company vault, through public engine doors.
//!
//! PR 2 of PLAN L7-05: with one-vault mode on, a member who brought her own
//! companion opens work talk in the company vault, and exactly the two bound
//! writers (the member's roster actor and the companion's actor) witness in
//! it. Fixture: the seeded workspace of
//! `crates/oneiron/tests/workspace_one_vault_mode.rs` (same Owner manifest
//! install, yuki bringing a model-backed companion), copied here; that file
//! is not edited.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::access_grant::AccessGrant;
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::ConversationKind;
use oneiron::edge::{EdgeActorClass, EdgeKind};
use oneiron::federation::{FederationGrantPreset, FederationGrantRole};
use oneiron::memory::{
    Effort, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, Memory,
    MemoryError, RecallScope, WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::subject_model::{PersonSubstrate, anchor_actor_subject};
use oneiron::workspace_roster::{
    CompanionChoice, MemberGrantBundle, MemberOnboardingIntent, WorkspaceRosterPreset,
};
use oneiron::{CompanionBirthIntent, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const WORKSPACE: &str = "one-vault-work-talk-workspace";
/// The workspace's shared vault. Not 7, the own-device residence scope's id,
/// whose Owner grants read as device access.
const VAULT_ID: u64 = 41;
const VENTURE: &str = "Garden Works";
const OPEN_VERB: &str = "vault.workspace.work_talk.open";
const ACKNOWLEDGE_VERB: &str = "vault.workspace.one_vault.acknowledge";

fn fresh_id() -> EntityId {
    EntityId::from_bytes(uuid::Uuid::now_v7().into_bytes())
        .expect("a fresh v7 uuid is not a reserved id")
}

fn seed_row(vault: &Vault, entity_type: u8, body: &[u8]) -> TestResult<EntityId> {
    let id = fresh_id();
    vault.put_entity(
        &id,
        entity_type,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
        body,
    )?;
    Ok(id)
}

fn definition(agent_id: &str) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "one-vault work talk fixture",
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
        rmpv::Value::Map(vec![(
            rmpv::Value::from("fixture"),
            rmpv::Value::from(agent_id),
        )]),
        None,
        true,
        None,
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    org: EntityId,
    house: EntityId,
}

fn setup() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let org = seed_row(&vault, ENTITY_TYPE_ORG, b"one-vault work talk org")?;
    vault.initialize_shared_vault(&owner_proof, VAULT_ID, None, &[], vault.now_recorded_at())?;
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .expect("sys.default is seeded on open");
    Ok(Fixture {
        _dir: dir,
        vault,
        owner,
        owner_proof,
        org,
        house,
    })
}

fn preset(fixture: &Fixture) -> WorkspaceRosterPreset {
    WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: VAULT_ID,
        org_ref: fixture.org,
        venture_name: VENTURE.to_owned(),
        house_display_name: None,
        house_actor_ref: fixture.house,
        house_identity_ref: None,
    }
}

/// Keeps encoding failures separate from the Owner door's refusal.
fn install_one_vault(fixture: &Fixture, row: Value) -> TestResult<oneiron::Result<()>> {
    let policy = json!({
        "schema_version": "1.2",
        "pack_id": "one-vault-work-talk-test",
        "pack_version": "1.0.0",
        "min_engine_version": "0.0.0",
        "defaults": {},
        "rules": [],
        "actor_ceilings": [],
        "one_vault": row,
    });
    let bytes = rmp_serde::to_vec_named(&policy)?;
    Ok(fixture.vault.install_owner_policy_manifest(
        &fixture.owner_proof,
        fresh_id(),
        bytes,
        fixture.vault.now_recorded_at(),
    ))
}

/// The member's own in-person surface: her PERSON with the owner proof a host
/// bound for it, as the work-talk doors require.
fn member_memory(fixture: &Fixture, member: EntityId) -> TestResult<Memory<'_>> {
    let proof =
        fixture
            .vault
            .authenticate_owner(member, &member.to_hex(), true, GateDecisionId::now())?;
    Ok(fixture
        .vault
        .memory(member, EdgeActorClass::Human)
        .with_owner_authorship(&proof))
}

/// The member opens work talk for her own roster row, in person.
fn open_via_verb(memory: &Memory<'_>) -> Result<Value, MemoryError> {
    oneiron::verbs::invoke(memory, OPEN_VERB, json!({ "workspace_ref": WORKSPACE }))
}

/// The member acknowledges the one-vault notice for her own roster row.
fn acknowledge_via_verb(memory: &Memory<'_>) -> Result<Value, MemoryError> {
    oneiron::verbs::invoke(
        memory,
        ACKNOWLEDGE_VERB,
        json!({ "workspace_ref": WORKSPACE }),
    )
}

/// The open verb answers its conversation as 32-hex EntityId.
fn conversation_of(value: &Value) -> TestResult<EntityId> {
    let hex = value
        .as_str()
        .ok_or("work_talk.open answers its conversation id")?;
    Ok(EntityId::from_hex(hex)?)
}

/// The acknowledge verb answers the told time it stored.
fn told_at_of(value: &Value) -> TestResult<u64> {
    value
        .as_u64()
        .ok_or_else(|| "acknowledge answers its told time".into())
}

/// The roster's told mark for `member` (the companion row names its principal).
fn told_mark(fixture: &Fixture, member: EntityId) -> TestResult<Option<u64>> {
    let roster = fixture
        .vault
        .workspace_roster(WORKSPACE, fixture.vault.now_recorded_at())?;
    let entry = roster
        .iter()
        .find(|entry| entry.principal_ref == Some(member))
        .ok_or("member roster entry")?;
    Ok(entry.one_vault_told)
}

/// One single-message turn witnessed as `memory`'s bound actor.
fn witness_text(
    memory: &Memory<'_>,
    conversation: &EntityId,
    author: WitnessAuthor,
    content: &str,
    occurred_at: u64,
) -> Result<(), MemoryError> {
    memory
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author,
                message_type: "dialogue".to_owned(),
                content: content.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at,
            assertions: WitnessAssertions::default(),
        })
        .map(|_| ())
}

/// Every visible message of `conversation` the reader may read, as (role, text).
/// Roles are the author buckets the writers gave.
fn transcript_roles_texts(
    fixture: &Fixture,
    reader: EntityId,
    conversation: &EntityId,
) -> TestResult<Vec<(String, String)>> {
    let memory = fixture.vault.memory(reader, EdgeActorClass::Human);
    let page = memory
        .conversation_transcript(conversation, None, 50)?
        .value;
    let mut out = Vec::new();
    for turn in &page.turns {
        for message in &turn.messages {
            out.push((message.role.clone(), message.text.clone()));
        }
    }
    Ok(out)
}

/// One witnessed MESSAGE's exact `AuthoredBy` target: the bound actor that wrote
/// it. Public edge reader; independent of transcript roles.
fn authored_by(fixture: &Fixture, message: &EntityId) -> TestResult<EntityId> {
    let authors: Vec<EntityId> = fixture
        .vault
        .edges_out(message)?
        .into_iter()
        .filter(|edge| edge.kind == EdgeKind::AuthoredBy)
        .map(|edge| edge.target)
        .collect();
    let [author] = authors
        .try_into()
        .map_err(|_| "one exact AuthoredBy edge per message")?;
    Ok(author)
}

/// (text, stored author) per visible message of `conversation`.
fn transcript_message_authors(
    fixture: &Fixture,
    reader: EntityId,
    conversation: &EntityId,
) -> TestResult<Vec<(String, EntityId)>> {
    let memory = fixture.vault.memory(reader, EdgeActorClass::Human);
    let page = memory
        .conversation_transcript(conversation, None, 50)?
        .value;
    let mut out = Vec::new();
    for turn in &page.turns {
        for message in &turn.messages {
            let id = EntityId::from_hex(&message.id)?;
            out.push((message.text.clone(), authored_by(fixture, &id)?));
        }
    }
    Ok(out)
}

/// Company recall, as the vault's owner, for one needle.
fn company_recall_finds(fixture: &Fixture, query: &str, needle: &str) -> TestResult<bool> {
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let pack = memory.recall(
        query,
        Effort::Light,
        &RecallScope::default(),
        10,
        None,
        None,
    )?;
    Ok(pack.items.iter().any(|item| {
        matches!(item.kind.as_str(), "TURN" | "MESSAGE") && item.value_text.contains(needle)
    }))
}

/// Binding standing on the room-bound door: the two bound roster actors open a
/// room turn on the talk, the member reads as a Direct participant, and a member
/// outside the talk meets an unknown room. Precedent: `tests/project_extra_rooms.rs`
/// (`RoomTurnHandle` carries no `Debug`, so refusals are matched).
fn assert_binding_turn_standing(
    fixture: &Fixture,
    member_actor: EntityId,
    companion: EntityId,
    member_person: EntityId,
    outsider: EntityId,
    talk: &EntityId,
) -> TestResult {
    for (actor, class, note) in [
        (member_actor, EdgeActorClass::Agent, "the member actor"),
        (companion, EdgeActorClass::Agent, "the companion"),
        (
            member_person,
            EdgeActorClass::Human,
            "the member as participant",
        ),
    ] {
        assert!(
            fixture
                .vault
                .memory(actor, class)
                .for_room_turn(*talk)
                .is_ok(),
            "{note} holds binding standing"
        );
    }
    assert!(
        fixture
            .vault
            .memory(companion, EdgeActorClass::Agent)
            .room_read_scope(*talk)
            .is_ok(),
        "the companion holds the room scope"
    );
    let Err(refused) = fixture
        .vault
        .memory(outsider, EdgeActorClass::Human)
        .for_room_turn(*talk)
    else {
        panic!("a member outside the talk holds no binding standing");
    };
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
    assert_eq!(refused.message, "unknown room");
    let Err(refused) = fixture
        .vault
        .memory(outsider, EdgeActorClass::Human)
        .room_read_scope(*talk)
    else {
        panic!("a member outside the talk holds no room scope");
    };
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
    assert_eq!(refused.message, "unknown room");
    Ok(())
}

/// Binding-scoped company read: the companion opens her room turn on the bound
/// talk and recalls through it. No grant involved.
fn companion_turn_recall_finds(
    fixture: &Fixture,
    companion: EntityId,
    talk: &EntityId,
    query: &str,
    needles: &[&str],
) -> TestResult<bool> {
    let turn = fixture
        .vault
        .memory(companion, EdgeActorClass::Agent)
        .for_room_turn(*talk)?;
    let pack = turn.recall(
        query,
        Effort::Light,
        &RecallScope::default(),
        10,
        None,
        None,
    )?;
    Ok(needles.iter().all(|needle| {
        pack.items.iter().any(|item| {
            matches!(item.kind.as_str(), "TURN" | "MESSAGE") && item.value_text.contains(needle)
        })
    }))
}

/// Plain grant-gated transcript refuses the grantless companion: the withheld
/// conversation row reads back nothing.
fn assert_plain_transcript_closed_to_companion(
    fixture: &Fixture,
    companion: EntityId,
    talk: &EntityId,
) -> TestResult {
    let memory = fixture.vault.memory(companion, EdgeActorClass::Agent);
    let Err(refused) = memory.conversation_transcript(talk, None, 10) else {
        panic!("plain transcript must not serve the talk to the companion");
    };
    assert_eq!(refused.code, MEMORY_CODE_NOT_FOUND, "{refused:?}");
    assert_eq!(refused.message, "conversation not found");
    Ok(())
}

/// Establishes the workspace preset with owen, whose companion is born in the
/// company vault. Returns owen's PERSON.
fn onboard_owen_work(
    fixture: &Fixture,
    onboarding_id: &str,
) -> TestResult<(EntityId, oneiron::MemberOnboardingOutcome)> {
    let member = seed_row(&fixture.vault, ENTITY_TYPE_PERSON, b"owen")?;
    let member_facet = seed_row(&fixture.vault, ENTITY_TYPE_FACET, b"owen work facet")?;
    let companion_facet = seed_row(&fixture.vault, ENTITY_TYPE_FACET, b"owen companion facet")?;
    let profile_grant = fresh_id();
    let intent = MemberOnboardingIntent {
        onboarding_id: onboarding_id.to_owned(),
        workspace: preset(fixture),
        person_ref: member,
        actor_ref: fresh_id(),
        actor_definition: definition("garden.member"),
        work_facet_ref: member_facet,
        grant_bundle: MemberGrantBundle {
            federation_grant_ref: fresh_id(),
            role: FederationGrantRole::Member,
            preset: FederationGrantPreset::Member,
            companion_profile_grant_ref: Some(profile_grant),
        },
        companion: CompanionChoice::Work(CompanionBirthIntent {
            person_ref: fresh_id(),
            actor_ref: fresh_id(),
            work_facet_ref: companion_facet,
            profile_grant_ref: profile_grant,
            actor_definition: definition("garden.companion"),
            display_name: "yuki".to_owned(),
        }),
        delegated_mailbox: None,
        occurred_at: fixture.vault.now_recorded_at(),
    };
    let outcome = fixture.vault.onboard_workspace_member(
        intent,
        &WriteActor::new(fixture.owner, EdgeActorClass::Human),
        None,
    )?;
    Ok((member, outcome))
}

/// Brings a model-backed companion with an anchored actor and a profile-read grant.
/// Returns yuki's PERSON, the companion PERSON, the companion actor, and the outcome.
fn onboard_yuki_bring(
    fixture: &Fixture,
    onboarding_id: &str,
) -> TestResult<(
    EntityId,
    EntityId,
    EntityId,
    oneiron::MemberOnboardingOutcome,
)> {
    let yuki = seed_row(&fixture.vault, ENTITY_TYPE_PERSON, b"yuki")?;
    let member_facet = seed_row(&fixture.vault, ENTITY_TYPE_FACET, b"yuki work facet")?;
    let companion_person = seed_row(
        &fixture.vault,
        ENTITY_TYPE_PERSON,
        b"yuki companion owen@example.com",
    )?;
    let companion_facet = seed_row(&fixture.vault, ENTITY_TYPE_FACET, b"yuki companion facet")?;
    let companion_actor = fresh_id();
    fixture.vault.define_agent(
        &companion_actor,
        &definition("yuki.companion"),
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
    )?;
    let writer = WriteActor::new(fixture.owner, EdgeActorClass::Human);
    fixture.vault.set_person_substrate(
        companion_person,
        PersonSubstrate::Model,
        &writer,
        fixture.vault.now_recorded_at(),
    )?;
    anchor_actor_subject(
        &fixture.vault,
        companion_actor,
        companion_person,
        writer,
        fixture.vault.now_recorded_at(),
    )?;
    fixture.vault.create_access_grant(
        &fresh_id(),
        &AccessGrant::companion_profile_read(
            yuki,
            companion_person,
            None,
            fixture.vault.now_recorded_at(),
        ),
    )?;
    let member_proof =
        fixture
            .vault
            .authenticate_owner(yuki, &yuki.to_hex(), true, GateDecisionId::now())?;
    let intent = MemberOnboardingIntent {
        onboarding_id: onboarding_id.to_owned(),
        workspace: preset(fixture),
        person_ref: yuki,
        actor_ref: fresh_id(),
        actor_definition: definition("garden.member"),
        work_facet_ref: member_facet,
        grant_bundle: MemberGrantBundle {
            federation_grant_ref: fresh_id(),
            role: FederationGrantRole::Member,
            preset: FederationGrantPreset::Member,
            companion_profile_grant_ref: None,
        },
        companion: CompanionChoice::Bring {
            person: companion_person,
            actor: companion_actor,
            work_facet: companion_facet,
            proof: member_proof,
        },
        delegated_mailbox: None,
        occurred_at: fixture.vault.now_recorded_at(),
    };
    let outcome = fixture.vault.onboard_workspace_member(
        intent,
        &WriteActor::new(fixture.owner, EdgeActorClass::Human),
        None,
    )?;
    Ok((yuki, companion_person, companion_actor, outcome))
}

#[test]
fn one_vault_mode_saves_member_companion_work_talk_in_company_vault() -> TestResult {
    let fixture = setup()?;
    install_one_vault(&fixture, json!({ "version": 1, "mode": "on" }))??;

    // A member with a born work companion holds no brought one: talk with it
    // is company-homed already, so the open names that refusal instead.
    let (owen, _) = onboard_owen_work(&fixture, "work-talk-main-owen")?;
    let refused = open_via_verb(&member_memory(&fixture, owen)?)
        .expect_err("a work companion needs no work talk");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert_eq!(
        refused.message,
        "work talk requires a brought companion; a work companion is already company-homed"
    );

    let (yuki, companion_person, companion_actor, outcome) =
        onboard_yuki_bring(&fixture, "work-talk-main-yuki")?;
    assert!(
        outcome.one_vault,
        "the joining client shows line 2 one-vault"
    );

    let talk = conversation_of(&open_via_verb(&member_memory(&fixture, yuki)?)?)?;
    assert_eq!(
        fixture.vault.conversation_body(talk)?.kind,
        ConversationKind::Direct
    );
    let members = fixture.vault.members(talk)?;
    assert_eq!(members.len(), 2, "the talk seats its two people");
    assert!(
        members.contains(&yuki) && members.contains(&companion_person),
        "the talk seats the member and her brought companion: {members:?}"
    );

    // The two bound roster actors write as themselves: the member as her
    // member actor, the companion as her own actor.
    let at = fixture.vault.now_recorded_at();
    let member_text = "quarterly numbers look off, check the March invoice";
    witness_text(
        &fixture
            .vault
            .memory(outcome.actor_ref, EdgeActorClass::Agent),
        &talk,
        WitnessAuthor::User,
        member_text,
        at,
    )?;
    let companion_text = "on it: pulling the March invoice and flagging the mismatch";
    witness_text(
        &fixture.vault.memory(companion_actor, EdgeActorClass::Agent),
        &talk,
        WitnessAuthor::Companion,
        companion_text,
        at,
    )?;

    assert!(
        company_recall_finds(&fixture, "March invoice", "March invoice")?,
        "company recall finds the work-talk turn"
    );
    let mut read_back = transcript_roles_texts(&fixture, yuki, &talk)?;
    read_back.sort();
    let mut expected = vec![
        ("user".to_owned(), member_text.to_owned()),
        ("companion".to_owned(), companion_text.to_owned()),
    ];
    expected.sort();
    assert_eq!(
        read_back, expected,
        "the conversation reads back with both authors"
    );
    let mut authors = transcript_message_authors(&fixture, yuki, &talk)?;
    authors.sort();
    let mut expected_authors = vec![
        (member_text.to_owned(), outcome.actor_ref),
        (companion_text.to_owned(), companion_actor),
    ];
    expected_authors.sort();
    assert_eq!(
        authors, expected_authors,
        "the stored authors are the two bound actors"
    );
    assert_binding_turn_standing(
        &fixture,
        outcome.actor_ref,
        companion_actor,
        yuki,
        owen,
        &talk,
    )?;
    assert!(
        companion_turn_recall_finds(
            &fixture,
            companion_actor,
            &talk,
            "March invoice",
            &["quarterly numbers look off", "flagging the mismatch"]
        )?,
        "the companion reads the work talk through her binding"
    );
    assert_plain_transcript_closed_to_companion(&fixture, companion_actor, &talk)?;
    Ok(())
}

#[test]
fn work_talk_refuses_to_open_when_one_vault_mode_is_off() -> TestResult {
    let fixture = setup()?;
    let (yuki, _, _, outcome) = onboard_yuki_bring(&fixture, "work-talk-off-yuki")?;
    assert!(!outcome.one_vault, "the joining client shows plain line 2");
    let refused = open_via_verb(&member_memory(&fixture, yuki)?)
        .expect_err("work talk stays with the member while off");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert_eq!(
        refused.message,
        "workspace one_vault mode is off: work talk stays with the member"
    );
    Ok(())
}

#[test]
fn work_talk_refuses_a_member_who_was_not_told() -> TestResult {
    let fixture = setup()?;
    let (yuki, _, _, outcome) = onboard_yuki_bring(&fixture, "work-talk-untold-yuki")?;
    assert!(!outcome.one_vault, "yuki joined while the mode was off");
    install_one_vault(&fixture, json!({ "version": 1, "mode": "on" }))??;

    let refused = open_via_verb(&member_memory(&fixture, yuki)?)
        .expect_err("an untold member opens no work talk");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert_eq!(
        refused.message,
        "workspace one_vault notice has not been acknowledged by this member"
    );

    let first = told_at_of(&acknowledge_via_verb(&member_memory(&fixture, yuki)?)?)?;
    assert_eq!(
        told_mark(&fixture, yuki)?,
        Some(first),
        "the acknowledge marks the member told"
    );
    let second = told_at_of(&acknowledge_via_verb(&member_memory(&fixture, yuki)?)?)?;
    assert_eq!(
        second, first,
        "an identical retry keeps the first told time"
    );
    assert_eq!(told_mark(&fixture, yuki)?, Some(first));

    let talk = conversation_of(&open_via_verb(&member_memory(&fixture, yuki)?)?)?;
    assert_eq!(
        fixture.vault.conversation_body(talk)?.kind,
        ConversationKind::Direct
    );
    Ok(())
}

#[test]
fn a_third_writer_cannot_witness_into_work_talk() -> TestResult {
    let fixture = setup()?;
    install_one_vault(&fixture, json!({ "version": 1, "mode": "on" }))??;
    let (yuki, _, _, yuki_outcome) = onboard_yuki_bring(&fixture, "work-talk-third-yuki")?;
    // Owen is a member with a vault Content grant, so the binding is the only
    // refusal below: his own conversation lands first.
    let (owen, _) = onboard_owen_work(&fixture, "work-talk-third-owen")?;
    let talk = conversation_of(&open_via_verb(&member_memory(&fixture, yuki)?)?)?;

    let at = fixture.vault.now_recorded_at();
    witness_text(
        &fixture.vault.memory(owen, EdgeActorClass::Human),
        &fresh_id(),
        WitnessAuthor::User,
        "owen's own note",
        at,
    )?;
    witness_text(
        &fixture
            .vault
            .memory(yuki_outcome.actor_ref, EdgeActorClass::Agent),
        &talk,
        WitnessAuthor::User,
        "quarterly numbers look off, check the March invoice",
        at,
    )?;

    for (writer, class, note) in [
        (owen, EdgeActorClass::Human, "another member"),
        (yuki, EdgeActorClass::Human, "the member's PERSON"),
    ] {
        let refused = witness_text(
            &fixture.vault.memory(writer, class),
            &talk,
            WitnessAuthor::User,
            "owen was never invited",
            at,
        )
        .expect_err("a third writer is refused");
        assert!(
            refused
                .message
                .contains("conversation actor is not authorized"),
            "{note}: {refused:?}"
        );
        assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{note}: {refused:?}");
    }

    let read_back = transcript_roles_texts(&fixture, yuki, &talk)?;
    assert_eq!(
        read_back.len(),
        1,
        "the refused turns land nowhere: {read_back:?}"
    );
    assert!(read_back[0].1.contains("March invoice"));
    Ok(())
}

#[test]
fn the_brought_companion_writes_nowhere_else_in_the_company_vault() -> TestResult {
    let fixture = setup()?;
    install_one_vault(&fixture, json!({ "version": 1, "mode": "on" }))??;
    let (yuki, _, companion_actor, yuki_outcome) =
        onboard_yuki_bring(&fixture, "work-talk-scope-yuki")?;
    let talk = conversation_of(&open_via_verb(&member_memory(&fixture, yuki)?)?)?;
    let at = fixture.vault.now_recorded_at();

    // Control: the companion's bound write lands.
    witness_text(
        &fixture
            .vault
            .memory(yuki_outcome.actor_ref, EdgeActorClass::Agent),
        &talk,
        WitnessAuthor::User,
        "quarterly numbers look off, check the March invoice",
        at,
    )?;
    witness_text(
        &fixture.vault.memory(companion_actor, EdgeActorClass::Agent),
        &talk,
        WitnessAuthor::Companion,
        "on it: pulling the March invoice",
        at,
    )?;

    // ...but nowhere else: no federation grant was minted for her, so the
    // shared-vault Content gate refuses the write outside the binding.
    let refused = witness_text(
        &fixture.vault.memory(companion_actor, EdgeActorClass::Agent),
        &fresh_id(),
        WitnessAuthor::Companion,
        "outside the binding",
        at,
    )
    .expect_err("the binding grants only its conversation");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        refused
            .message
            .contains("shared-vault role or named power does not authorize this write"),
        "{refused:?}"
    );

    let read_back = transcript_roles_texts(&fixture, yuki, &talk)?;
    assert_eq!(
        read_back.len(),
        2,
        "only the two bound turns read back: {read_back:?}"
    );
    Ok(())
}

#[test]
fn work_talk_stays_company_record_after_the_mode_turns_off() -> TestResult {
    let fixture = setup()?;
    install_one_vault(&fixture, json!({ "version": 1, "mode": "on" }))??;
    let (yuki, _, companion_actor, yuki_outcome) =
        onboard_yuki_bring(&fixture, "work-talk-record-yuki")?;
    let talk = conversation_of(&open_via_verb(&member_memory(&fixture, yuki)?)?)?;
    let at = fixture.vault.now_recorded_at();
    witness_text(
        &fixture
            .vault
            .memory(yuki_outcome.actor_ref, EdgeActorClass::Agent),
        &talk,
        WitnessAuthor::User,
        "quarterly numbers look off, check the March invoice",
        at,
    )?;
    witness_text(
        &fixture.vault.memory(companion_actor, EdgeActorClass::Agent),
        &talk,
        WitnessAuthor::Companion,
        "on it: pulling the March invoice",
        at,
    )?;

    install_one_vault(&fixture, json!({ "version": 1, "mode": "off" }))??;

    assert!(
        company_recall_finds(&fixture, "March invoice", "March invoice")?,
        "existing work talk stays a company record"
    );
    let refused = open_via_verb(&member_memory(&fixture, yuki)?)
        .expect_err("no new opens while the mode is off");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert_eq!(
        refused.message,
        "workspace one_vault mode is off: work talk stays with the member"
    );
    let read_back = transcript_roles_texts(&fixture, yuki, &talk)?;
    assert_eq!(
        read_back.len(),
        2,
        "the old talk remains readable: {read_back:?}"
    );
    Ok(())
}
