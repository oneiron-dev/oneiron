//! The limit answers of the room pages, lens proposals and skill library lists (UC-13 PR 4b).
//!
//! A later commit moves each list's limit arithmetic into one call of the shared resolver
//! (`oneiron-base/src/request_limits.rs`). It must change no answer. This file pins today's
//! answer of each list at `limit: Some(0)`, `Some(1)` and `Some(max + 1)` (and `None` where
//! the request takes it), so it passes on today's code and after the move. It never calls
//! the resolver fns.
//!
//! Rule R = zero refused (an error), absent = default, else min(asked, max).
//! Rule O = zero served as one row, absent = default, else min(asked, max).
//!
//! Room pages refuse zero with `invalid config: invalid room operation` (rule R). Lens
//! proposals serve zero as one row (rule O); the empty vault below holds no proposals, so
//! every accepted ask answers an empty page. The skill library refuses zero with
//! `limit must be positive` (rule R). The Files source files list is NOT pinned here:
//! no test under `crates/oneiron/tests/` drives a Files source, so there is no public-path
//! setup to copy (see REPORT.md).
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test rooms_lens_skills_list_limits`.

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::lens::{LENS_LIST_MAX_PAGE, LensListRequest};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_NOT_FOUND, Memory, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use oneiron::policy_manifest_doors::{
    PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use oneiron::snapshot_read::{skill_library_list_as_reader, skill_library_list_embedded};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentDefinitionSpec, SkillLibraryListRequest,
    skill_library_list_as_owner,
};
use oneiron::workspace_roster::{
    OfferDraft, OffersRequest, ParticipantsRequest, ProjectRecord, RoomMessagesRequest,
};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
    WriteActor,
};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The label this file's offer intent keys carry.
const FIXTURE_PATH: &str = "crates/oneiron/tests/rooms_lens_skills_list_limits.rs";

/// An agent made through the agent-definition door, as the owner.
fn create_agent(vault: &Vault, owner: EntityId, name: &str) -> TestResult<EntityId> {
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(json!({
        "agent_id": name,
        "display_name": name,
        "desc": name,
        "version": "1",
        "ceiling": "auto",
    }))?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    oneiron::verbs::create_agent_definition_as(
        vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition,
        },
    )?;
    Ok(agent)
}

/// Every named actor reads the vault's records: one `core:read` row each, added to the
/// default policy manifest, the shipped rows kept.
fn grant_reads(vault: &Vault, owner: EntityId, readers: &[EntityId]) -> TestResult {
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let view =
        policy_manifests_as_owner(vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    for actor in readers {
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

/// A project led by `leader`, and its home room. The roster holds the leader alone.
fn project_home_room(vault: &Vault, leader: EntityId) -> TestResult<EntityId> {
    let root = vault.root_project()?;
    let id = EntityId::now();
    let record = ProjectRecord::new(id, Some(root), root, leader)?;
    vault.put_project(id, &record, vault.now_recorded_at())?;
    Ok(EntityId::from_hex(&record.home_room)?)
}

/// `principal` reads `room`'s MESSAGEs under an active grant.
fn grant_messages(vault: &Vault, room: EntityId, principal: EntityId) -> TestResult {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant {
            authority_scope,
            principal_ref: principal,
            scope: AccessGrantScope::ConversationMessages {
                conversation_ref: room,
            },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            revoked_at: None,
            expires_at: None,
            companion_bounds: None,
        },
    )?;
    Ok(())
}

/// `speaker`'s witness turn on the room's trunk, one MESSAGE. Returns the TURN.
fn speak_trunk(vault: &Vault, speaker: EntityId, room: EntityId) -> TestResult<EntityId> {
    let turn = EntityId::now();
    vault
        .memory(speaker, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: Some(json!({})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    Ok(turn)
}

/// `speaker`'s plain reply on `anchor`: the first opens the thread, a later one continues
/// it. Returns the TURN.
fn plain_reply(
    vault: &Vault,
    speaker: EntityId,
    room: EntityId,
    anchor: EntityId,
) -> TestResult<EntityId> {
    let now = vault.now_recorded_at();
    let input = AppendRecord {
        conversation: room,
        parent: None,
        reply_to: None,
        quote: None,
        address: AddressMode::Broadcast,
        recipients: Vec::new(),
        advance: false,
        kind: ENTITY_TYPE_TURN,
        containing_turn: None,
        occurred: TimeRange {
            start: now,
            end: now,
        },
        learned_at: now,
        body: rmp_serde::to_vec_named(&json!({ "txt": "owen" }))?,
        text: Vec::new(),
        session: None,
        actor: WriteActor::new(speaker, EdgeActorClass::Human),
        thread_audience: None,
    };
    Ok(vault
        .reply_in_thread(
            &vault.memory(speaker, EdgeActorClass::Human),
            anchor,
            &input,
        )?
        .id)
}

/// `agent`'s room-wide offer card in `room`. It stays current and open: the host never
/// answers it here.
fn offer_room_wide(vault: &Vault, room: EntityId, agent: EntityId, intent: &str) -> TestResult {
    vault
        .memory(agent, EdgeActorClass::Agent)
        .rooms_offer(&OfferDraft {
            room,
            branch: None,
            agent,
            what: "Work the room's thread tasks.".to_owned(),
            artifact_ref: Some("artifact:thread-tasks".to_owned()),
            spend_scope: None,
            until: None,
            intent_key: intent.to_owned(),
        })?;
    Ok(())
}

/// A project's home room led by owen, holding two threads (the first with a continuation)
/// and two open room-wide offer cards from two agents. The vault closes before its
/// directory goes.
struct RoomFixture {
    vault: Vault,
    owen: EntityId,
    room: EntityId,
    thread: EntityId,
    _directory: tempfile::TempDir,
}

impl RoomFixture {
    fn owen(&self) -> Memory<'_> {
        self.vault.memory(self.owen, EdgeActorClass::Human)
    }
}

fn open_room_fixture() -> TestResult<RoomFixture> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let owen = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &owen,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        b"owen",
    )?;
    let agent_b = create_agent(&vault, owner, "yuki")?;
    let agent_c = create_agent(&vault, owner, "yuki-two")?;
    grant_reads(&vault, owner, &[owen, agent_b, agent_c])?;
    let room = project_home_room(&vault, owen)?;
    grant_messages(&vault, room, owen)?;
    let anchor = speak_trunk(&vault, owen, room)?;
    let root = plain_reply(&vault, owen, room, anchor)?;
    plain_reply(&vault, owen, room, anchor)?;
    let anchor_two = speak_trunk(&vault, owen, room)?;
    plain_reply(&vault, owen, room, anchor_two)?;
    offer_room_wide(
        &vault,
        room,
        agent_b,
        &format!("{FIXTURE_PATH}:offer:{}", agent_b.to_hex()),
    )?;
    offer_room_wide(
        &vault,
        room,
        agent_c,
        &format!("{FIXTURE_PATH}:offer:{}", agent_c.to_hex()),
    )?;
    Ok(RoomFixture {
        vault,
        owen,
        room,
        thread: root,
        _directory: directory,
    })
}

/// An owner-authored candidate with no runtime package: in the owner's library, never
/// loadable.
fn put_candidate(vault: &Vault, skill_id: &str, desc: &str) -> TestResult<EntityId> {
    let id = EntityId::now();
    let tree = canonical_skill_tree_hash([("SKILL.md", b"# a candidate skill\n".as_slice())])?;
    let record = SkillRecord::new(
        skill_id,
        desc,
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.9,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("limit-pin-fixture"),
        )]),
    )
    .with_content_hash(tree);
    vault.put_skill_record(&id, &record, TimeRange { start: 10, end: 10 }, 11)?;
    Ok(id)
}

/// A vault with two candidate skills and a grantless agent reader. The vault closes before
/// its directory goes.
struct SkillFixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    skill_a: EntityId,
    skill_b: EntityId,
    _directory: tempfile::TempDir,
}

fn open_skill_fixture() -> TestResult<SkillFixture> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let agent = create_agent(&vault, owner, "limit-pin-reader")?;
    let skill_a = put_candidate(&vault, "limit-pin.first", "First limit-pin skill")?;
    let skill_b = put_candidate(&vault, "limit-pin.second", "Second limit-pin skill")?;
    Ok(SkillFixture {
        vault,
        owner,
        agent,
        skill_a,
        skill_b,
        _directory: directory,
    })
}

/// Rule R on the room page and the thread page of `vault.rooms.messages`: zero is
/// refused, one serves one row, absent and max + 1 serve every row.
#[test]
fn room_messages_selected_refuses_zero_and_serves_one() -> TestResult {
    let fx = open_room_fixture()?;
    let owen = fx.owen();
    // `PAGE_LIMIT` (rooms/history.rs) is the default and the max: 256.
    let page = |limit: Option<usize>, thread_ref: Option<String>| RoomMessagesRequest {
        room_ref: fx.room.to_hex(),
        after: None,
        limit,
        thread_ref,
    };
    let Err(error) = owen.rooms_messages_selected(&page(Some(0), None)) else {
        return Err("rooms.messages with limit Some(0) is refused".into());
    };
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "invalid config: invalid room operation");
    let one = owen.rooms_messages_selected(&page(Some(1), None))?;
    assert_eq!(one.rows.len(), 1, "limit Some(1) serves one row");
    assert!(one.next_after.is_some(), "one row of many continues");
    let all = owen.rooms_messages_selected(&page(None, None))?;
    assert!(all.rows.len() >= 2, "the room holds turns to cut");
    assert!(all.next_after.is_none(), "the absent ask serves every row");
    let over = owen.rooms_messages_selected(&page(Some(257), None))?;
    assert_eq!(over.rows.len(), all.rows.len(), "max + 1 serves every row");
    assert!(over.next_after.is_none());
    // The thread page: the first thread holds its root and one continuation.
    let Err(error) = owen.rooms_messages_selected(&page(Some(0), Some(fx.thread.to_hex()))) else {
        return Err("rooms.messages on a thread with limit Some(0) is refused".into());
    };
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "invalid config: invalid room operation");
    let one = owen.rooms_messages_selected(&page(Some(1), Some(fx.thread.to_hex())))?;
    assert_eq!(one.rows.len(), 1, "limit Some(1) serves one thread row");
    assert!(one.next_after.is_some(), "one row of two continues");
    let all = owen.rooms_messages_selected(&page(None, Some(fx.thread.to_hex())))?;
    assert_eq!(all.rows.len(), 2, "the thread holds its root and one reply");
    assert!(all.next_after.is_none());
    let over = owen.rooms_messages_selected(&page(Some(257), Some(fx.thread.to_hex())))?;
    assert_eq!(over.rows.len(), 2, "max + 1 serves the whole thread");
    Ok(())
}

/// Rule R on the room thread find: zero is refused, one serves one root, max + 1 serves
/// every root. Both public doors over the shared page size are pinned.
#[test]
fn room_thread_find_refuses_zero_and_serves_one() -> TestResult {
    let fx = open_room_fixture()?;
    let owen = fx.owen();
    // `PAGE_LIMIT` (rooms/history.rs) is the max: 256. The room holds two threads.
    let Err(error) = owen.rooms_find_threads_page(fx.room, None, 0) else {
        return Err("rooms.find_threads_page with limit 0 is refused".into());
    };
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "invalid config: invalid room operation");
    let one = owen.rooms_find_threads_page(fx.room, None, 1)?;
    assert_eq!(one.rows.len(), 1, "limit 1 serves one root");
    assert!(one.next_after.is_some(), "one root of two continues");
    let over = owen.rooms_find_threads_page(fx.room, None, 257)?;
    assert_eq!(over.rows.len(), 2, "max + 1 serves every root");
    assert!(over.next_after.is_none());
    let Err(error) = owen.rooms_find_threads(fx.room, None, 0) else {
        return Err("rooms.find_threads with limit 0 is refused".into());
    };
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "invalid config: invalid room operation");
    assert_eq!(owen.rooms_find_threads(fx.room, None, 1)?.len(), 1);
    assert_eq!(owen.rooms_find_threads(fx.room, None, 257)?.len(), 2);
    Ok(())
}

/// Rule R on `vault.rooms.offers`: zero is refused before the audience check, one serves
/// one card, absent and max + 1 serve every card.
#[test]
fn room_offers_refuse_zero_and_serve_one() -> TestResult {
    let fx = open_room_fixture()?;
    let owen = fx.owen();
    // `PAGE_LIMIT` (rooms/history.rs) is the default and the max: 256.
    let page = |room: EntityId, limit: Option<u32>| OffersRequest {
        room,
        branch: None,
        after: None,
        limit,
    };
    let Err(error) = owen.rooms_offers(&page(fx.room, Some(0))) else {
        return Err("rooms.offers with limit Some(0) is refused".into());
    };
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "invalid config: invalid room operation");
    let one = owen.rooms_offers(&page(fx.room, Some(1)))?;
    assert_eq!(one.rows.len(), 1, "limit Some(1) serves one card");
    assert!(one.next_after.is_some(), "one card of two continues");
    let all = owen.rooms_offers(&page(fx.room, None))?;
    assert_eq!(all.rows.len(), 2, "the room holds two open cards");
    assert!(all.next_after.is_none());
    let over = owen.rooms_offers(&page(fx.room, Some(257)))?;
    assert_eq!(over.rows.len(), 2, "max + 1 serves every card");
    // The zero check runs before the audience check: an unknown room with Some(0) gives
    // the zero refusal, while Some(1) reaches the audience check and is not found.
    let unknown = EntityId::now();
    let Err(error) = owen.rooms_offers(&page(unknown, Some(0))) else {
        return Err("rooms.offers with limit Some(0) is refused before any lookup".into());
    };
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "invalid config: invalid room operation");
    let Err(missing) = owen.rooms_offers(&page(unknown, Some(1))) else {
        return Err("rooms.offers for an unknown room is not found".into());
    };
    assert_eq!(missing.code, MEMORY_CODE_NOT_FOUND);
    assert_eq!(missing.message, "no room or thread the caller reads");
    Ok(())
}

/// Rule R on `vault.rooms.participants`: zero is refused, one serves one participant,
/// absent and max + 1 serve every participant.
#[test]
fn room_participants_refuse_zero_and_serve_one() -> TestResult {
    let fx = open_room_fixture()?;
    let owen = fx.owen();
    // `PAGE_LIMIT` (rooms/history.rs) is the default and the max: 256.
    let page = |limit: Option<u32>| ParticipantsRequest {
        room: fx.room,
        branch: None,
        after: None,
        limit,
    };
    let Err(error) = owen.rooms_participants(&page(Some(0))) else {
        return Err("rooms.participants with limit Some(0) is refused".into());
    };
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "invalid config: invalid room operation");
    let one = owen.rooms_participants(&page(Some(1)))?;
    assert_eq!(one.rows.len(), 1, "limit Some(1) serves one participant");
    let all = owen.rooms_participants(&page(None))?;
    assert!(!all.rows.is_empty(), "the room holds participants to serve");
    let over = owen.rooms_participants(&page(Some(257)))?;
    assert_eq!(
        over.rows.len(),
        all.rows.len(),
        "max + 1 serves every participant"
    );
    Ok(())
}

/// Rule O on `vault.lenses.list`: zero is served as one row, never refused. The empty
/// vault holds no proposals, so every accepted ask answers an empty page.
#[test]
fn lens_list_serves_zero_as_one() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let limits: [Option<u32>; 4] = [None, Some(0), Some(1), Some(LENS_LIST_MAX_PAGE as u32 + 1)];
    for limit in limits {
        let page = memory.lenses_list(LensListRequest {
            limit,
            ..Default::default()
        })?;
        assert!(page.rows.is_empty(), "no proposals to serve at {limit:?}");
        assert!(page.next_after.is_none());
    }
    Ok(())
}

/// Rule R on the owner's skill library list: zero is refused, one serves one skill, and
/// max + 1 serves every skill.
#[test]
fn skill_library_owner_list_refuses_zero_and_serves_one() -> TestResult {
    let fx = open_skill_fixture()?;
    let proof = fx
        .vault
        .memory(fx.owner, EdgeActorClass::Human)
        .embedded_owner("vault.skills.list")?;
    let Err(error) = skill_library_list_as_owner(
        &fx.vault,
        &proof,
        &SkillLibraryListRequest {
            after: None,
            limit: 0,
        },
    ) else {
        return Err("the owner's skill list with limit 0 is refused".into());
    };
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "limit must be positive");
    let one = skill_library_list_as_owner(
        &fx.vault,
        &proof,
        &SkillLibraryListRequest {
            after: None,
            limit: 1,
        },
    )?;
    assert_eq!(one.skills.len(), 1, "limit 1 serves one skill");
    assert!(one.next_after.is_some());
    let two = skill_library_list_as_owner(
        &fx.vault,
        &proof,
        &SkillLibraryListRequest {
            after: None,
            limit: 2,
        },
    )?;
    assert_eq!(two.skills.len(), 2, "limit 2 serves two skills");
    // `MAX_TYPE_QUERY_RESULTS` (vault/entities.rs) + 1: the type index cuts the ask.
    let over = skill_library_list_as_owner(
        &fx.vault,
        &proof,
        &SkillLibraryListRequest {
            after: None,
            limit: 100_001,
        },
    )?;
    assert!(over.skills.len() >= 2, "max + 1 serves every skill");
    assert!(
        over.skills.iter().any(|skill| skill.entity == fx.skill_a),
        "the first candidate is listed"
    );
    assert!(
        over.skills.iter().any(|skill| skill.entity == fx.skill_b),
        "the second candidate is listed"
    );
    Ok(())
}

/// Rule R on the reader's skill library list and its dispatcher: zero is refused with
/// the owner's text, and 1 / max + 1 are accepted. The agent holds no read grant, so
/// every page it is served is empty.
#[test]
fn skill_library_reader_list_refuses_zero_and_accepts_pages() -> TestResult {
    let fx = open_skill_fixture()?;
    let owner = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    let agent = fx.vault.memory(fx.agent, EdgeActorClass::Agent);
    let Err(error) = skill_library_list_as_reader(
        &agent,
        &SkillLibraryListRequest {
            after: None,
            limit: 0,
        },
    ) else {
        return Err("the reader's skill list with limit 0 is refused".into());
    };
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "limit must be positive");
    let Err(error) = skill_library_list_as_reader(
        &owner,
        &SkillLibraryListRequest {
            after: None,
            limit: 0,
        },
    ) else {
        return Err("the reader door refuses limit 0 for the owner too".into());
    };
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "limit must be positive");
    // `MAX_TYPE_QUERY_RESULTS` (vault/entities.rs) + 1.
    for limit in [1, 100_001] {
        let page =
            skill_library_list_as_reader(&agent, &SkillLibraryListRequest { after: None, limit })?;
        assert!(page.skills.is_empty(), "a grantless reader reads no skill");
        assert!(page.next_after.is_none());
    }
    // The dispatcher serves the owner through the owner door and anyone else through
    // the reader door, with the same zero refusal on both sides.
    let Err(error) = skill_library_list_embedded(
        &owner,
        &SkillLibraryListRequest {
            after: None,
            limit: 0,
        },
    ) else {
        return Err("the embedded skill list with limit 0 is refused for the owner".into());
    };
    assert_eq!(error.message, "limit must be positive");
    let Err(error) = skill_library_list_embedded(
        &agent,
        &SkillLibraryListRequest {
            after: None,
            limit: 0,
        },
    ) else {
        return Err("the embedded skill list with limit 0 is refused for the reader".into());
    };
    assert_eq!(error.message, "limit must be positive");
    let owned = skill_library_list_embedded(
        &owner,
        &SkillLibraryListRequest {
            after: None,
            limit: 1,
        },
    )?;
    assert_eq!(owned.skills.len(), 1, "the owner is served one skill");
    let read = skill_library_list_embedded(
        &agent,
        &SkillLibraryListRequest {
            after: None,
            limit: 1,
        },
    )?;
    assert!(
        read.skills.is_empty(),
        "the grantless reader reads no skill"
    );
    let owned_over = skill_library_list_embedded(
        &owner,
        &SkillLibraryListRequest {
            after: None,
            limit: 100_001,
        },
    )?;
    assert!(
        owned_over.skills.len() >= 2,
        "the owner is served every skill"
    );
    let read_over = skill_library_list_embedded(
        &agent,
        &SkillLibraryListRequest {
            after: None,
            limit: 100_001,
        },
    )?;
    assert!(read_over.skills.is_empty());
    Ok(())
}
