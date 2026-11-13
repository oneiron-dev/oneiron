//! A paired agent asks into a room by an offer card on a rooted vault
//! (ARCH-0006a:243: "An agent that wants in asks by an offer card, never by
//! a turn"; FIX ROOM-OFFER-PAIRED-AGENT-UNBOUND, E2E COORDINATION-03).
//!
//! Pairing binds no agent in the authority log: the agent acts through its
//! capability slips, whose keys never enter the roster. On a rooted vault
//! the room join and consent doors still asked every writer for an active
//! binding, so the agent's own card was refused "writer has no active
//! authority binding". The doors now take one of the vault's own agents
//! while its definition stands (active, enabled and approved), read at each
//! use: the card files and waits on the host's admission, the host's yes
//! lands it once, and an unrelated agent is refused the host's part for its
//! party, not for its binding. A definition switched off refuses the next
//! card, and an agent whose binding was revoked stays refused.
//!
//! Public paths: the owner's pairing link and its redemption, the agent
//! definition create and update doors, and the conversation, offer, offer
//! answer and consent doors on `Memory`. Fixtures beside them: the rooted
//! install (`oneiron::test_support`), the agent's room read (one policy row,
//! as the in-crate room tests grant it), and the host root's binding and
//! revocation of an agent (`test_support::bind_host_actor`,
//! `test_doors::steward::revoke_base_agent_bindings`).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test room_offer_paired_agent`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{HostSlipIssuer, MachineRole, PairingPrincipal};
use oneiron::consent::AuthenticatedOwner;
use oneiron::core_write::ConversationCreateInput;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_TURN};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{
    ConsentAnswer, ConsentNeed, ConsentPart, JoinDecision, OfferAnswer, OfferAnswerRequest,
    OfferCard, OfferDraft, OfferState, OffersRequest, RequiredParty,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The admission refusal a party other than the room's host gets.
const ADMISSION_REFUSAL: &str =
    "only the room's owner, a delegated host or its nearest project leader answers its admission";

/// The join doors' refusal for an unbound agent whose definition does not stand.
const DEFINITION_REFUSAL: &str = "an agent with no authority binding writes here only as one of this vault's own agents whose definition is active, enabled and approved";

/// The rooted writer rule's two refusals: no binding, or a revoked one.
const UNBOUND_REFUSAL: &str = "writer has no active authority binding";
const QUARANTINE_REFUSAL: &str = "write is concurrent with an actor revocation/regrant window";

/// The shipped default policy pack, whose manifest the room read is added to.
const SHIPPED_POLICY_PACK: &str = "oneiron-default-policy";

/// The challenge the paired agent signs to prove its slip.
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:room-offer-paired-agent";

/// A rooted vault this process owns, as a serving start leaves it: the host
/// root, the engine's machines, this install's profile and the embedded
/// owner bound under the root. One group room the owner created, and so
/// hosts. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    room: EntityId,
    _dir: tempfile::TempDir,
}

fn rooted() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let (owner, owner_proof) = embedded_owner(&vault)?;
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
                "title": "paired agent offer room",
            }),
            text: None,
        })?;
    let room = EntityId::from_hex(&receipt.id)?;
    Ok(Fixture {
        vault,
        issuer,
        owner,
        owner_proof,
        room,
        _dir: dir,
    })
}

/// A custom agent the owner makes through the agent-definition door, as
/// `vault.agents.create` does: active, approved and enabled by default.
fn create_agent(fixture: &Fixture, agent_id: &str) -> TestResult<EntityId> {
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(json!({
        "agent_id": agent_id,
        "display_name": agent_id,
        "desc": format!("{agent_id} offers one artifact"),
        "version": "1",
    }))?;
    oneiron::verbs::create_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition,
        },
    )?;
    Ok(agent)
}

/// `agent` pairs as class `agent` on a link the owner issues and redeems it,
/// proving possession of its slip, as `engine.pairActor` does over HTTP
/// (the Scope `oneiron token read` gives: every world, `core:read`).
fn pair_agent(fixture: &Fixture, agent: EntityId, binding_seed: u8) -> TestResult {
    let vault = &fixture.vault;
    let holder_ref = agent.to_hex();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
    let link = vault.issue_owner_pairing_link(
        &fixture.issuer,
        &fixture.owner_proof,
        scope,
        3_600,
        PairingPrincipal {
            holder_ref: Some(holder_ref.clone()),
            actor_class: Some("agent".to_owned()),
            ..PairingPrincipal::default()
        },
    )?;
    let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder_ref,
        link.pin.as_ref(),
    )?;
    let slip = vault.redeem_pairing_link(
        &fixture.issuer,
        &link.code,
        &holder_ref,
        binding_key,
        &signing_key.sign(&transcript).to_bytes(),
    )?;
    let signature = signing_key
        .sign(&slip.binding_transcript(REQUEST_CHALLENGE)?)
        .to_bytes();
    vault.verify_capability_slip(
        &fixture.issuer.public_key(),
        &slip,
        REQUEST_CHALLENGE,
        &signature,
    )?;
    Ok(())
}

/// Whether the authority log binds any key to `actor`.
fn binds(vault: &Vault, actor: EntityId) -> TestResult<bool> {
    Ok(vault
        .authority_fold()?
        .actor_bindings
        .values()
        .any(|binding| binding.actor_ref == actor))
}

/// Lets `agent` read the vault's room records: one actor-bound `core:read`
/// row added to the shipped policy manifest, its other rows kept. An offer's
/// asker must read its room.
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

/// The room's current cards for `agent`, as its host reads them.
fn cards_of(fixture: &Fixture, agent: EntityId) -> TestResult<Vec<OfferCard>> {
    let page = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .rooms_offers(&OffersRequest {
            room: fixture.room,
            branch: None,
            after: None,
            limit: None,
        })?;
    Ok(page
        .rows
        .into_iter()
        .filter(|row| row.agent == agent)
        .collect())
}

/// The card's one open need: the room host's admission.
fn waits_on_host(room: EntityId) -> OfferState {
    OfferState::Open {
        needs: vec![ConsentNeed {
            part: ConsentPart::Admission,
            party: RequiredParty::RoomHost { room },
        }],
    }
}

#[test]
fn a_paired_agent_on_a_rooted_vault_files_its_offer_card_and_the_host_admits_it_once() -> TestResult
{
    let fixture = rooted()?;
    let room = fixture.room;
    let companion = create_agent(&fixture, "companion")?;
    let unrelated = create_agent(&fixture, "worker-a")?;
    pair_agent(&fixture, companion, 0x61)?;
    pair_agent(&fixture, unrelated, 0x62)?;
    assert!(
        !binds(&fixture.vault, companion)? && !binds(&fixture.vault, unrelated)?,
        "pairing binds no agent in the authority log: each acts on its slip"
    );
    permit_room_reads(&fixture, companion)?;
    permit_room_reads(&fixture, unrelated)?;
    let host = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let asker = fixture.vault.memory(companion, EdgeActorClass::Agent);
    let draft = offer_draft(room, companion, "paired-agent-offer-1");

    // The agent's own ask files on the rooted vault and waits on the host.
    let card = asker
        .rooms_offer(&draft)
        .map_err(|error| format!("the paired agent's offer card is refused: {error}"))?;
    assert_eq!(
        (card.room, card.branch, card.agent),
        (room, None, companion)
    );
    assert_eq!(card.state, waits_on_host(room));
    let listed = cards_of(&fixture, companion)?;
    assert_eq!(listed.len(), 1, "the host reads one card for the agent");
    assert_eq!(listed[0].offer_id, card.offer_id);
    assert_eq!(listed[0].state, card.state);

    // An unrelated agent passes the writer check and is refused the host's
    // part for its party; the asker cannot admit itself.
    let consent = fixture
        .vault
        .memory(unrelated, EdgeActorClass::Agent)
        .rooms_consent(&ConsentAnswer {
            join_ref: card.join_ref.clone(),
            part: ConsentPart::Admission,
            grant: true,
            spend_scope: None,
        })
        .expect_err("an unrelated agent does not answer the room's admission");
    assert!(
        consent.message.contains(ADMISSION_REFUSAL),
        "the refusal names the admission party: {consent:?}"
    );
    let answer = |intent_key: &str| OfferAnswerRequest {
        offer_id: card.offer_id.clone(),
        action: OfferAnswer::Join,
        intent_key: intent_key.to_owned(),
    };
    let self_admit = asker
        .rooms_offer_answer(&answer("paired-agent-self-admit"))
        .expect_err("the agent does not admit itself");
    assert!(
        self_admit.message.contains(ADMISSION_REFUSAL),
        "the refusal names the admission party: {self_admit:?}"
    );
    assert_eq!(cards_of(&fixture, companion)?[0].state, card.state);

    // The host's yes lands the agent's acceptance turn and join, once.
    let accepted = host.rooms_offer_answer(&answer("paired-agent-answer-1"))?;
    assert_eq!(accepted.offer_id, card.offer_id);
    let join = accepted
        .join
        .as_ref()
        .ok_or("the host's answer carries the join")?;
    assert_eq!(join.decision.state, JoinDecision::Ready);
    let OfferState::Joined { turn, receipt_ref } = &accepted.state else {
        return Err(format!(
            "the host's yes settles the card as joined, not {:?}",
            accepted.state
        )
        .into());
    };
    assert_eq!(join.receipt_ref.as_deref(), Some(receipt_ref.as_str()));
    assert_eq!(accepted.turn_ref, Some(turn.to_hex()));
    assert_eq!(fixture.vault.get_entity_type(turn)?, Some(ENTITY_TYPE_TURN));
    let again = host.rooms_offer_answer(&answer("paired-agent-answer-1"))?;
    assert_eq!(
        again.state, accepted.state,
        "a replayed answer lands no turn"
    );
    let replayed = asker.rooms_offer(&draft)?;
    assert_eq!(replayed.offer_id, card.offer_id);
    assert_eq!(replayed.state, accepted.state);
    let after = cards_of(&fixture, companion)?;
    assert_eq!(after.len(), 1, "one card for the agent in the room");
    assert_eq!(after[0].state, accepted.state);
    Ok(())
}

#[test]
fn a_paired_agent_whose_definition_is_switched_off_is_refused_its_next_offer_card() -> TestResult {
    let fixture = rooted()?;
    let agent = create_agent(&fixture, "switched-off")?;
    pair_agent(&fixture, agent, 0x63)?;
    permit_room_reads(&fixture, agent)?;
    let asker = fixture.vault.memory(agent, EdgeActorClass::Agent);
    let first = asker
        .rooms_offer(&offer_draft(fixture.room, agent, "switched-off-offer-1"))
        .map_err(|error| format!("the paired agent's first card is refused: {error}"))?;
    assert_eq!(first.state, waits_on_host(fixture.room));

    // The owner switches the agent off; the definition is read at each use.
    let mut definition = fixture
        .vault
        .get_agent_definition(&agent)?
        .ok_or("the agent's definition reads back")?;
    definition.enabled = false;
    definition.version = "2".to_owned();
    let now = fixture.vault.now_recorded_at();
    fixture.vault.update_agent_definition_as(
        &fixture.owner_proof,
        &agent,
        &definition,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    let refused = asker
        .rooms_offer(&offer_draft(fixture.room, agent, "switched-off-offer-2"))
        .expect_err("a switched-off agent files no new card");
    assert!(
        refused.message.contains(DEFINITION_REFUSAL),
        "the refusal names the definition's standing: {refused:?}"
    );
    let cards = cards_of(&fixture, agent)?;
    assert_eq!(cards.len(), 1, "the refused card replaced nothing");
    assert_eq!(cards[0].offer_id, first.offer_id);
    assert_eq!(cards[0].state, first.state);
    Ok(())
}

#[test]
fn an_agent_whose_binding_was_revoked_stays_refused_its_offer_card() -> TestResult {
    let fixture = rooted()?;
    let agent = create_agent(&fixture, "revoked")?;
    permit_room_reads(&fixture, agent)?;
    // The host root binds the agent, then withdraws that binding. The host
    // key held the owner's binding, so the owner reads nothing after this.
    oneiron::test_support::bind_host_actor(&fixture.vault, &fixture.issuer, agent, "agent")?;
    assert_eq!(
        oneiron::test_doors::steward::revoke_base_agent_bindings(&fixture.vault, agent)?,
        1,
        "the host root revokes the agent's one binding"
    );
    let refused = fixture
        .vault
        .memory(agent, EdgeActorClass::Agent)
        .rooms_offer(&offer_draft(fixture.room, agent, "revoked-offer-1"))
        .expect_err("a revoked binding never falls back to the definition");
    assert!(
        refused.message.contains(QUARANTINE_REFUSAL) || refused.message.contains(UNBOUND_REFUSAL),
        "the rooted writer rule refuses the revoked agent: {refused:?}"
    );
    Ok(())
}
