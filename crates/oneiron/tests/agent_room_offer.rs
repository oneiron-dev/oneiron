//! A custom agent asks to join a room by an offer card (ARCH-0006a, OF-530 = A).
//!
//! `vault.agents.create` gives every custom AGENT_DEF its own model PERSON on
//! the PEOPLE board (ARCH-0067) and anchors the agent to it. That anchor does
//! not make the agent a person's pen: the agent mints its room-wide offer
//! card, the card waits on the room host's admission alone, because the agent
//! stands through the vault's owner, and the host's yes settles the card as
//! joined, once. An AGENT_DEF anchored to a member's own PERSON is still that
//! member's pen, and its offer card is still refused.
//!
//! Public paths only: the agent-definition create verb, the conversation,
//! offer and offer-answer doors on `Memory`, and the public subject-anchor
//! setter. The one fixture beside them is the agent's room read, one policy
//! row written through `oneiron::test_support`, as the in-crate room tests
//! grant it.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test agent_room_offer`.

use std::collections::BTreeSet;

use oneiron::core_write::ConversationCreateInput;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::MEMORY_CODE_BAD_REQUEST;
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_TURN};
use oneiron::subject_model::{ActorSubjectAnchor, SubjectKind};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{
    ConsentNeed, ConsentPart, JoinDecision, OfferAnswer, OfferAnswerRequest, OfferDraft,
    OfferState, OffersRequest, RequiredParty,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The offer door's refusal for an actor that takes part as a person.
const PEN_REFUSAL: &str = "a person's pen joins by writing as its person, not by an offer card";

/// The shipped default policy pack, whose manifest the room read is added to.
const SHIPPED_POLICY_PACK: &str = "oneiron-default-policy";

/// A vault this process owns, its embedded owner, and one group room the
/// owner created and so hosts. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    room: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    // `open_owned` holds the vault's writer lease, which the owner's doors
    // ask of the embedded owner.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({
                "v": 1,
                "kind": "group",
                "member_ids": [owner.to_hex()],
                "title": "agent offer room",
            }),
            text: None,
        })?;
    let room = EntityId::from_hex(&receipt.id)?;
    Ok(Fixture {
        vault,
        owner,
        room,
        _dir: dir,
    })
}

/// A custom agent made through the agent-definition door, as the owner: the
/// door anchors it to its own model PERSON.
fn create_agent(fixture: &Fixture, agent_id: &str) -> TestResult<EntityId> {
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(json!({
        "agent_id": agent_id,
        "display_name": agent_id,
        "desc": format!("{agent_id} offers one artifact"),
        "version": "1",
    }))?;
    let host = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    oneiron::verbs::create_agent_definition_as(
        &fixture.vault,
        &host.embedded_owner("vault.agents.create")?,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition,
        },
    )?;
    Ok(agent)
}

/// Lets `agent` read the vault's room records: one actor-bound `core:read`
/// row added to the shipped policy manifest, its other rows kept. A custom
/// agent reads no room record it was not given, and an offer's asker must
/// read its room.
fn permit_room_reads(fixture: &Fixture, agent: EntityId) -> TestResult {
    let vault = &fixture.vault;
    let mut shipped = None;
    for id in vault.entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)? {
        let Some(bytes) = vault.get(&id)? else {
            continue;
        };
        let manifest: serde_json::Value = rmp_serde::from_slice(&bytes)?;
        if manifest["pack_id"] == SHIPPED_POLICY_PACK {
            shipped = Some((id, manifest));
            break;
        }
    }
    let (id, mut manifest) = shipped.ok_or("the vault holds no shipped policy manifest")?;
    let mut read = Scope::top();
    read.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    manifest["scoped_grants"]
        .as_array_mut()
        .ok_or("the shipped policy manifest has no scoped grants")?
        .push(json!({
            "actor_ref": agent.to_hex(),
            "effector": "core:read",
            "scope": read,
            "receipt_required": false,
            "selectors": {"entity_types": [ENTITY_TYPE_CONVERSATION]},
        }));
    oneiron::test_support::put_policy_manifest_bytes(
        vault,
        id,
        &rmp_serde::to_vec_named(&manifest)?,
    )?;
    Ok(())
}

/// `agent`'s room-wide card in `room`, under `intent_key`.
fn offer_draft(room: EntityId, agent: EntityId, intent_key: &str) -> OfferDraft {
    OfferDraft {
        room,
        branch: None,
        agent,
        what: "Summarise the open questions in this room.".to_owned(),
        artifact_ref: Some("artifact:open-questions".to_owned()),
        spend_scope: None,
        until: None,
        intent_key: intent_key.to_owned(),
    }
}

/// The PERSON `actor`'s subject anchor names now.
fn anchored_person(fixture: &Fixture, actor: EntityId) -> TestResult<Option<EntityId>> {
    let at = fixture.vault.now_recorded_at();
    Ok(fixture
        .vault
        .actor_subject_anchor(&actor, at)?
        .filter(|anchor| anchor.subject_kind == SubjectKind::Person)
        .map(|anchor| anchor.subject_ref))
}

#[test]
fn a_custom_agent_made_through_the_agent_definition_door_can_mint_a_room_offer_card_and_the_room_host_can_accept_it()
-> TestResult {
    let fixture = open()?;
    let room = fixture.room;
    let agent = create_agent(&fixture, "offer-agent")?;
    let anchor = anchored_person(&fixture, agent)?;
    assert!(
        anchor.is_some_and(|person| person != fixture.owner),
        "the door anchors the agent to its own model PERSON, no member's"
    );
    permit_room_reads(&fixture, agent)?;
    let host = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let asker = fixture.vault.memory(agent, EdgeActorClass::Agent);
    let draft = offer_draft(room, agent, "agent-room-offer-1");

    // The agent asks by a card, and the card waits on the host's admission
    // alone: the agent stands through the vault's owner, who is a member,
    // not through its own model PERSON, who is none.
    let card = asker
        .rooms_offer(&draft)
        .expect("a custom agent mints its room offer card");
    assert_eq!(card.room, room);
    assert_eq!(card.branch, None);
    assert_eq!(card.agent, agent);
    assert_eq!(
        card.state,
        OfferState::Open {
            needs: vec![ConsentNeed {
                part: ConsentPart::Admission,
                party: RequiredParty::RoomHost { room },
            }],
        },
        "the card waits on the room host's admission and nothing else"
    );

    // The room's host accepts: the join is Ready and the card settles as
    // joined, with the agent's acceptance turn and the join's receipt.
    let answer = OfferAnswerRequest {
        offer_id: card.offer_id.clone(),
        action: OfferAnswer::Join,
        intent_key: "agent-room-offer-answer-1".to_owned(),
    };
    let accepted = host.rooms_offer_answer(&answer)?;
    assert_eq!(accepted.offer_id, card.offer_id);
    let join = accepted
        .join
        .as_ref()
        .ok_or("the host's answer carries the join")?;
    assert_eq!(join.decision.state, JoinDecision::Ready);
    let OfferState::Joined { turn, receipt_ref } = &accepted.state else {
        panic!(
            "the host's yes settles the card as joined, not {:?}",
            accepted.state
        );
    };
    assert_eq!(join.receipt_ref.as_deref(), Some(receipt_ref.as_str()));
    assert_eq!(accepted.turn_ref, Some(turn.to_hex()));
    assert_eq!(fixture.vault.get_entity_type(turn)?, Some(ENTITY_TYPE_TURN));

    // Exactly once: a replayed answer and a replayed card land nothing new,
    // and the room holds one card for the agent, joined on that turn.
    let again = host.rooms_offer_answer(&answer)?;
    assert_eq!(
        again.state, accepted.state,
        "a replayed answer lands no turn"
    );
    assert_eq!(again.turn_ref, accepted.turn_ref);
    let replayed = asker.rooms_offer(&draft)?;
    assert_eq!(replayed.offer_id, card.offer_id);
    assert_eq!(replayed.state, accepted.state);
    let page = host.rooms_offers(&OffersRequest {
        room,
        branch: None,
        after: None,
        limit: None,
    })?;
    let cards: Vec<_> = page.rows.iter().filter(|row| row.agent == agent).collect();
    assert_eq!(cards.len(), 1, "one card for the agent in the room");
    assert_eq!(cards[0].offer_id, card.offer_id);
    assert_eq!(cards[0].state, accepted.state);
    Ok(())
}

/// The fix does not widen the rule: an AGENT_DEF anchored to a member's own
/// PERSON takes part as that person, who joins by writing.
#[test]
fn a_members_own_pen_is_still_refused_a_room_offer_card() -> TestResult {
    let fixture = open()?;
    let pen = create_agent(&fixture, "member-pen")?;
    permit_room_reads(&fixture, pen)?;
    // The owner makes the agent their own actor: its anchor now names the
    // owner's PERSON, a live member of the room, not its own model PERSON.
    fixture.vault.set_actor_subject_anchor(
        ActorSubjectAnchor {
            actor_ref: pen,
            subject_ref: fixture.owner,
            subject_kind: SubjectKind::Person,
        },
        &WriteActor::new(fixture.owner, EdgeActorClass::Human),
        fixture.vault.now_recorded_at(),
    )?;
    assert_eq!(anchored_person(&fixture, pen)?, Some(fixture.owner));

    let refusal = fixture
        .vault
        .memory(pen, EdgeActorClass::Agent)
        .rooms_offer(&offer_draft(fixture.room, pen, "member-pen-offer-1"))
        .expect_err("a member's pen joins by writing, not by an offer card");
    assert_eq!(refusal.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(refusal.message, PEN_REFUSAL);
    Ok(())
}
