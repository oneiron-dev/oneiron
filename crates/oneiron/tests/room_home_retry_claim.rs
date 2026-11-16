//! A Retry in a project's home room takes the claim it answers
//! (HOMERETRY-AUTHORITY = C, lead 16 Nov 23:2x; FIX
//! THREAD-TASK-NATIVE-AGENT-RETRY-HOME-ROOM). The person's Retry press is the
//! address: a Retry of an agent's turn whose parent holds no claim first
//! takes the claim on that parent, held by the agent and authored by the
//! person who pressed it, in the write that lands the new reply, then answers
//! on the claimed-Retry permit (FIX 3149). The home room keeps its one rule,
//! claim before speech.
//!
//! Fixture: owen, the vault's owner, leads a project whose home room seats
//! owen and agent A. Agent B holds no seat: it asks to join one thread by an
//! offer card, and owen's Join lands B's acceptance turn as B's answer to the
//! thread's root, with no claim on that root (OF-530). B then streams its
//! reply on that turn, so the turn holds one generated reply. That is the
//! one home-room agent turn whose parent holds no claim.
//!
//! - Owen's Retry of B's reply lands a new reply and keeps the old one. On
//!   main the Retry is refused at queue time ("the room no longer lets its
//!   agent answer this turn again").
//! - A requester who may not address B there is refused, with no claim
//!   written: agent A, seated, presses Retry as an agent (an agent speaks
//!   only on its own claim or task, so its press addresses no one).
//! - The claim the Retry took holds the root for B, and its receipt names
//!   owen, who pressed Retry.
//! - Under `--cfg oneiron_test_support`: erasing the person who pressed Retry
//!   leaves no claim row, and no carried copy of one, naming that person
//!   (HOMERETRY-CLAIM-AUTHOR = B, Engine 16 Nov 23:32).
//!
//! The first three use public paths only; the erase case reads and plants
//! claim rows through `oneiron::test_doors::room_claim_erase`.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test room_home_retry_claim`.

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use oneiron::conversation::{TURN_ACTION_ATTEMPT_KIND, TurnActionAttempt, TurnActionRequest};
use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    MEMORY_CODE_INVALID_STATE, Memory, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{
    JoinDecision, OfferAnswer, OfferAnswerRequest, OfferDraft, ProjectRecord, RoomClaimOutcome,
    RoomTurn,
};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

/// The label this file's offer and answer intents carry.
const FIXTURE_PATH: &str = "crates/oneiron/tests/room_home_retry_claim.rs";

/// The receipt prefix of a claim a Retry took; the rest names who pressed it.
const RETRY_CLAIM_RECEIPT_PREFIX: &str = "vault.conversations.turn.retry:";

/// The refusal a home room gives a Retry it does not let its agent answer.
const REFUSAL: &str = "the room no longer lets its agent answer this turn again";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The home room, its thread, and agent B's reply on the thread's root.
struct Origin {
    vault: Vault,
    owen: EntityId,
    agent_a: EntityId,
    agent_b: EntityId,
    room: EntityId,
    /// Owen's trunk turn the thread hangs on.
    anchor: EntityId,
    /// Owen's thread root: the parent B's turn answers, holding no claim.
    root: EntityId,
    /// B's acceptance turn, holding B's streamed reply.
    reply_turn: EntityId,
    /// B's streamed reply on that turn: the generated MESSAGE a Retry acts on.
    reply_message: EntityId,
    _directory: tempfile::TempDir,
}

impl Origin {
    fn owen(&self) -> Memory<'_> {
        self.vault.memory(self.owen, EdgeActorClass::Human)
    }

    fn agent_b(&self) -> Memory<'_> {
        self.vault.memory(self.agent_b, EdgeActorClass::Agent)
    }

    /// The room row of `turn`, read through owen's room history.
    fn row(&self, turn: EntityId) -> TestResult<RoomTurn> {
        self.owen()
            .rooms_messages(self.room)?
            .into_iter()
            .find(|row| row.turn_id == turn.to_hex())
            .ok_or_else(|| format!("the home room keeps no row for {}", turn.to_hex()).into())
    }

    /// The room row holding `message`, read through owen's room history.
    fn row_holding(&self, message: EntityId) -> TestResult<RoomTurn> {
        self.owen()
            .rooms_messages(self.room)?
            .into_iter()
            .find(|row| row.message_ids.contains(&message.to_hex()))
            .ok_or_else(|| format!("no room row holds {}", message.to_hex()).into())
    }
}

/// An agent made through the agent-definition door, as the owner.
fn create_agent(vault: &Vault, owner: EntityId, name: &str) -> TestResult<EntityId> {
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
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

/// Both agents ask under their own Auto ceiling, and owen and both agents
/// read the vault's records: rows added to the default policy manifest, the
/// shipped rows kept.
fn grant_reads(vault: &Vault, owen: EntityId, agent_a: EntityId, agent_b: EntityId) -> TestResult {
    let proof = vault
        .memory(owen, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let view =
        policy_manifests_as_owner(vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    for agent in [agent_a, agent_b] {
        manifest.actor_ceilings.push(ActorCeiling {
            actor_class: "agent".into(),
            actor_ref: Some(agent.to_hex()),
            ceiling: PolicyCeiling::Auto,
        });
    }
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    for actor in [owen, agent_a, agent_b] {
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

/// A project led by owen whose roster also seats `seated`. Returns its home
/// room.
fn home_room(vault: &Vault, owen: EntityId, seated: &[EntityId]) -> TestResult<EntityId> {
    let root = vault.root_project()?;
    let id = EntityId::now();
    let mut record = ProjectRecord::new(id, Some(root), root, owen)?;
    record.roster.extend(seated.iter().map(EntityId::to_hex));
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

/// One empty Companion MESSAGE a stream opens, with `metadata`, at `order`.
fn companion_message(metadata: Option<serde_json::Value>, order: u32) -> WitnessMessage {
    WitnessMessage {
        id: None,
        author: WitnessAuthor::Companion,
        message_type: "text".into(),
        content: String::new(),
        parts: None,
        metadata,
        is_visible: true,
        order,
        quote: None,
    }
}

/// The home room, owen's thread on its trunk, B's accepted offer card on
/// that thread, and B's streamed reply on its acceptance turn.
fn origin() -> TestResult<Origin> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owen = vault.ensure_embedded_owner_actor()?;
    let agent_a = create_agent(&vault, owen, "yuki")?;
    let agent_b = create_agent(&vault, owen, "yuki-two")?;
    grant_reads(&vault, owen, agent_a, agent_b)?;
    let room = home_room(&vault, owen, &[agent_a])?;
    for principal in [agent_a, agent_b] {
        grant_messages(&vault, room, principal)?;
    }
    let (anchor, root, reply_turn, reply_message) = {
        let owen_memory = vault.memory(owen, EdgeActorClass::Human);

        // owen's trunk turn, then his plain reply on it: the thread's root.
        let anchor = EntityId::now();
        owen_memory.rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(anchor.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: Some(serde_json::json!({})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
        let now = vault.now_recorded_at();
        let root = vault
            .reply_in_thread(
                &owen_memory,
                anchor,
                &AppendRecord {
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
                    body: rmp_serde::to_vec_named(&serde_json::json!({"txt": "owen"}))?,
                    text: Vec::new(),
                    session: None,
                    actor: WriteActor::new(owen, EdgeActorClass::Human),
                    thread_audience: None,
                },
            )?
            .id;

        // B, holding no seat, asks to join the thread; owen's Join lands B's
        // acceptance turn as its answer to the root, with no claim on the root.
        let agent_b_memory = vault.memory(agent_b, EdgeActorClass::Agent);
        let card = agent_b_memory.rooms_offer(&OfferDraft {
            room,
            branch: Some(root),
            agent: agent_b,
            what: "Work this thread.".to_owned(),
            artifact_ref: Some("artifact:thread-tasks".to_owned()),
            spend_scope: None,
            until: None,
            intent_key: format!("{FIXTURE_PATH}:offer:{}", agent_b.to_hex()),
        })?;
        let settled = owen_memory.rooms_offer_answer(&OfferAnswerRequest {
            offer_id: card.offer_id.clone(),
            action: OfferAnswer::Join,
            intent_key: format!("{FIXTURE_PATH}:answer:{}", agent_b.to_hex()),
        })?;
        let join = settled
            .join
            .ok_or("fixture: owen's answer carries no join")?;
        if join.decision.state != JoinDecision::Ready {
            return Err(
                format!("fixture: the join is {:?}, not Ready", join.decision.state).into(),
            );
        }
        let reply_turn = EntityId::from_hex(
            settled
                .turn_ref
                .as_deref()
                .ok_or("fixture: the Join landed no acceptance turn")?,
        )?;

        // B streams its reply on its acceptance turn: the one generated reply
        // the turn holds.
        let handle = agent_b_memory.begin_message_stream(
            &WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: Some(reply_turn.to_hex()),
                thread_audience: None,
                messages: vec![companion_message(
                    Some(serde_json::json!({
                        "room_reply_to": root.to_hex(),
                        "room_thread_of": anchor.to_hex(),
                    })),
                    1,
                )],
                occurred_at: vault.now_recorded_at(),
                assertions: Default::default(),
            },
            None,
        )?;
        agent_b_memory.append_to_stream(handle, "yuki answers")?;
        let reply_message = agent_b_memory.finalize_stream(handle)?.message_id;
        (anchor, root, reply_turn, reply_message)
    };

    let origin = Origin {
        vault,
        owen,
        agent_a,
        agent_b,
        room,
        anchor,
        root,
        reply_turn,
        reply_message,
        _directory: directory,
    };
    let root_row = origin.row(root)?;
    assert_eq!(root_row.reply_to, Some(anchor.to_hex()), "fixture: root");
    assert_eq!(root_row.thread_of, Some(anchor.to_hex()), "fixture: root");
    assert!(root_row.addressed_agents.is_empty(), "fixture: root");
    let reply_row = origin.row(reply_turn)?;
    assert_eq!(reply_row.actor, agent_b.to_hex(), "fixture: B's turn");
    assert_eq!(reply_row.reply_to, Some(root.to_hex()), "fixture: B's turn");
    assert_eq!(
        reply_row.thread_of,
        Some(anchor.to_hex()),
        "fixture: B's turn"
    );
    assert!(
        reply_row.message_ids.contains(&reply_message.to_hex()),
        "fixture: B's turn holds its streamed reply"
    );
    Ok(origin)
}

/// Owen's Retry of B's reply, claimed as the host's turn-action worker
/// claims it.
fn queue_retry(origin: &Origin) -> TestResult<TurnActionAttempt> {
    let receipt = origin.owen().conversations_turn_retry(&TurnActionRequest {
        turn_id: origin.reply_turn.to_hex(),
    })?;
    assert_eq!(receipt.turn_id, origin.reply_turn.to_hex());
    let claimed = AttemptQueue::new(&origin.vault).claim_kind(
        TURN_ACTION_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "room-home-retry-claim".to_owned(),
            now: origin.vault.now_recorded_at(),
        },
    )?;
    let ClaimOutcome::Claimed(attempt) = claimed else {
        return Err(format!("fixture: the Retry is not claimable: {claimed:?}").into());
    };
    let action = TurnActionAttempt::decode(&attempt)?;
    assert_eq!(action.conversation, origin.room);
    assert_eq!(action.assistant_turn, origin.reply_turn);
    assert_eq!(action.message, origin.reply_message);
    assert_eq!(action.actor, origin.owen);
    Ok(action)
}

/// B answers the Retry as the chat host does: a fresh stream on the room,
/// one empty Companion MESSAGE, then its words. Returns the new MESSAGE.
fn answer_retry(origin: &Origin, action: &TurnActionAttempt) -> TestResult<EntityId> {
    let agent = origin.agent_b();
    let handle = agent.begin_message_regeneration(
        &WitnessTurn {
            conversation_ref: action.conversation.to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![companion_message(None, 0)],
            occurred_at: origin.vault.now_recorded_at(),
            assertions: Default::default(),
        },
        action,
        None,
    )?;
    agent.append_to_stream(handle, "yuki answers again")?;
    Ok(agent.finalize_stream(handle)?.message_id)
}

/// Owen's Retry, answered by B: returns the new MESSAGE.
fn retry_lands(origin: &Origin) -> TestResult<EntityId> {
    let action = queue_retry(origin)?;
    answer_retry(origin, &action)
}

/// Test 1: owen's Retry of B's reply lands a new reply, answering the same
/// root in the same thread, and the old reply stays. On main the Retry is
/// refused at queue time.
#[test]
fn a_home_room_retry_of_an_accepted_offer_reply_lands_a_new_reply_and_keeps_the_old() -> TestResult
{
    let origin = origin()?;
    let message = retry_lands(&origin)?;
    assert_ne!(message, origin.reply_message);
    assert_eq!(
        origin.vault.get_entity_type(&message)?,
        Some(ENTITY_TYPE_MESSAGE)
    );
    assert!(
        origin
            .vault
            .edges_out(&message)?
            .iter()
            .any(|edge| edge.kind == EdgeKind::Regenerates && edge.target == origin.reply_message),
        "the new reply names the reply it answers again"
    );
    let new_row = origin.row_holding(message)?;
    assert_ne!(new_row.turn_id, origin.reply_turn.to_hex());
    assert_eq!(new_row.actor, origin.agent_b.to_hex());
    assert_eq!(new_row.reply_to, Some(origin.root.to_hex()));
    assert_eq!(new_row.thread_of, Some(origin.anchor.to_hex()));
    // The old reply stays as it was, on its own turn.
    assert_eq!(
        origin.vault.get_entity_type(&origin.reply_message)?,
        Some(ENTITY_TYPE_MESSAGE)
    );
    assert!(
        origin
            .row(origin.reply_turn)?
            .message_ids
            .contains(&origin.reply_message.to_hex()),
        "the old reply stays on B's turn"
    );
    Ok(())
}

/// Test 2: agent A, seated in the room, may not address B there by a Retry
/// press, since an agent speaks only on its own claim or task. Its Retry is
/// refused, and no claim is written: owen then claims the root himself.
#[test]
fn a_retry_pressed_by_a_requester_who_may_not_address_the_agent_is_refused_with_no_claim()
-> TestResult {
    let origin = origin()?;
    let refused = origin
        .vault
        .memory(origin.agent_a, EdgeActorClass::Agent)
        .conversations_turn_retry(&TurnActionRequest {
            turn_id: origin.reply_turn.to_hex(),
        });
    let Err(error) = refused else {
        return Err("agent A's Retry of B's reply was queued".into());
    };
    assert_eq!(error.code, MEMORY_CODE_INVALID_STATE, "{error:?}");
    assert!(error.message.contains(REFUSAL), "{error:?}");
    let probe =
        origin
            .owen()
            .rooms_claim(origin.room, origin.root, origin.vault.now_recorded_at())?;
    let RoomClaimOutcome::Claimed(receipt) = probe else {
        return Err(format!("the refused Retry left a claim on the root: {probe:?}").into());
    };
    assert_eq!(receipt.actor, origin.owen.to_hex());
    assert!(
        receipt.receipt_ref.starts_with("rooms.claim:"),
        "{receipt:?}"
    );
    Ok(())
}

/// Test 3: the claim owen's Retry took holds the root for B, and its receipt
/// names owen, who pressed Retry.
#[test]
fn the_claim_a_home_room_retry_takes_holds_the_root_for_the_agent_and_names_the_presser()
-> TestResult {
    let origin = origin()?;
    retry_lands(&origin)?;
    let probe =
        origin
            .owen()
            .rooms_claim(origin.room, origin.root, origin.vault.now_recorded_at())?;
    let RoomClaimOutcome::HeldBy(receipt) = probe else {
        return Err(format!("the root holds no claim of B's: {probe:?}").into());
    };
    assert_eq!(receipt.room_id, origin.room.to_hex());
    assert_eq!(receipt.turn_id, origin.root.to_hex());
    assert_eq!(receipt.actor, origin.agent_b.to_hex());
    assert_eq!(
        receipt.receipt_ref,
        format!("{RETRY_CLAIM_RECEIPT_PREFIX}{}", origin.owen.to_hex())
    );
    Ok(())
}

/// The erase case beside test 3 (HOMERETRY-CLAIM-AUTHOR = B): erasing the
/// person who pressed Retry leaves no claim row, and no carried copy of one,
/// naming that person. Claim rows are planted and read raw through the test
/// door, and carried copies merge as replica sync merges them.
#[cfg(oneiron_test_support)]
mod erase {
    use std::sync::Arc;

    use oneiron::receipt::ERASED_CALL_IDENTITY;
    use oneiron::registry::ENTITY_TYPE_PERSON;
    use oneiron::test_doors::room_claim_erase::{
        merge_carried_room_claim, put_room_claim, room_claim,
    };
    use oneiron::workspace_roster::RoomClaimReceipt;
    use oneiron::{DeleteReason, EntityId, TimeRange, Vault, VaultConfig};

    use super::{RETRY_CLAIM_RECEIPT_PREFIX, TestResult, home_room};

    /// A live PERSON the hard erase accepts.
    fn person(vault: &Vault) -> TestResult<EntityId> {
        let id = EntityId::now();
        vault.put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )?;
        Ok(id)
    }

    /// The claim a Retry pressed by `author` took on `turn` for `holder`.
    fn retry_claim(
        room: EntityId,
        turn: EntityId,
        holder: EntityId,
        author: &str,
        at: u64,
    ) -> RoomClaimReceipt {
        RoomClaimReceipt {
            room_id: room.to_hex(),
            turn_id: turn.to_hex(),
            actor: holder.to_hex(),
            receipt_ref: format!("{RETRY_CLAIM_RECEIPT_PREFIX}{author}"),
            at,
        }
    }

    /// `turn`'s claim row.
    fn held(vault: &Vault, turn: EntityId) -> TestResult<RoomClaimReceipt> {
        Ok(room_claim(vault, turn)?.ok_or_else(|| format!("no claim on {}", turn.to_hex()))?)
    }

    #[test]
    fn erasing_the_presser_leaves_no_claim_row_or_carried_copy_naming_them() -> TestResult {
        let directory = tempfile::tempdir()?;
        let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
        let owen = vault.ensure_embedded_owner_actor()?;
        let room = home_room(&vault, owen, &[])?;
        let presser = person(&vault)?;
        let named = presser.to_hex();
        let erased_author = format!("{RETRY_CLAIM_RECEIPT_PREFIX}{ERASED_CALL_IDENTITY}");
        // A person this vault never erased, whose erased form another
        // machine carries.
        let elsewhere = EntityId::now();
        let agent = EntityId::now();
        let retried = EntityId::now();
        let own = EntityId::now();
        let carried_before = EntityId::now();
        let carried_forms = EntityId::now();
        let carried_after = EntityId::now();

        put_room_claim(&vault, &retry_claim(room, retried, agent, &named, 7))?;
        let own_claim = RoomClaimReceipt {
            room_id: room.to_hex(),
            turn_id: own.to_hex(),
            actor: named.clone(),
            receipt_ref: format!("rooms.claim:{}", EntityId::now().to_hex()),
            at: 8,
        };
        put_room_claim(&vault, &own_claim)?;
        assert_eq!(
            merge_carried_room_claim(&vault, &retry_claim(room, carried_before, agent, &named, 9))?,
            "written"
        );
        // The same receipt's two author forms meet: the erased form wins, as
        // a carried holder's does (REVIEW-4366 round 4).
        put_room_claim(
            &vault,
            &retry_claim(room, carried_forms, agent, &elsewhere.to_hex(), 10),
        )?;
        assert_eq!(
            merge_carried_room_claim(
                &vault,
                &retry_claim(room, carried_forms, agent, ERASED_CALL_IDENTITY, 10)
            )?,
            "written"
        );
        assert_eq!(held(&vault, carried_forms)?.receipt_ref, erased_author);

        // Every delete signs as this install first.
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        vault.delete_entity_with_reason(&presser, DeleteReason::UserHardDelete)?;

        // This vault's rows: the Retry's claim keeps its holder and names
        // its author as erased; the person's own claim names no holder.
        let retried_row = held(&vault, retried)?;
        assert_eq!(retried_row.actor, agent.to_hex());
        assert_eq!(retried_row.receipt_ref, erased_author);
        let own_row = held(&vault, own)?;
        assert_eq!(own_row.actor, ERASED_CALL_IDENTITY);
        assert_eq!(own_row.receipt_ref, own_claim.receipt_ref);
        assert_eq!(held(&vault, carried_before)?.receipt_ref, erased_author);
        // Carried copies after the erase: the copy of a row already scrubbed
        // is held as scrubbed, and a new one lands scrubbed.
        assert_eq!(
            merge_carried_room_claim(&vault, &retry_claim(room, retried, agent, &named, 7))?,
            "held"
        );
        assert_eq!(
            merge_carried_room_claim(&vault, &retry_claim(room, carried_after, agent, &named, 11))?,
            "written"
        );
        assert_eq!(held(&vault, carried_after)?.receipt_ref, erased_author);
        for turn in [retried, own, carried_before, carried_forms, carried_after] {
            let row = held(&vault, turn)?;
            assert!(
                !row.actor.contains(&named) && !row.receipt_ref.contains(&named),
                "a claim row still names the erased presser: {row:?}"
            );
        }
        Ok(())
    }
}
