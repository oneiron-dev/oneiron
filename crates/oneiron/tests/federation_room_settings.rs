//! A member peer's first-party room body obeys the local room-setting doors
//! (FIX row ROOM-BODY-REPLICA-SETTINGS; Engine ruling 20 Nov 23:56 = A).
//! A plain room member cannot reopen a closed room or change its pin policy;
//! a locally seated room Owner can reopen it. Guest-tier replay still cannot
//! replace a live room's birth stamp. All writes and imports use public APIs.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test federation_room_settings`.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use loro::ExportMode;
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, RoomPin, RoomPinPolicy, RoomRole};
use oneiron::federation::{
    FederationGrantRole, FederationGrantScope, InitialSharedMember, decode_federation_grant_body,
};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::{ImportTier, SyncClient, SyncClientConfig};
use oneiron::sync::federation_burst::FederationPeer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::transport::TransportError;
use oneiron::sync::types::WindowKey;
use oneiron::sync::{FederationAdmissionRole, SyncSelector, SyncSelectorWorld};
use oneiron::workspace_roster::RoomClosedSet;
use oneiron::{EdgeActorClass, EntityId, ErrorKind, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_contracts::record_layout::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};

const SHARED_VAULT: u64 = 42;
/// 2026-03-15 00:00 UTC: keep this room in its own historical BASE window.
const ROOM_AT: u64 = 1_773_532_800;

struct Fixture {
    client: SyncClient,
    vault: Arc<Vault>,
    owner: EntityId,
    member: EntityId,
    room: EntityId,
    window: WindowKey,
    // Drop every vault handle before removing its directory.
    _directory: tempfile::TempDir,
}

fn person_proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .unwrap()
}

fn fixture(peer_owns_room: bool, closed: bool) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open_owned(directory.path(), VaultConfig::device()).unwrap());
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().unwrap();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let member = EntityId::now();
    let now = vault.now_recorded_at();
    vault
        .put_entity(
            &member,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"member peer",
        )
        .unwrap();
    vault
        .initialize_shared_vault(
            &person_proof(&vault, owner),
            SHARED_VAULT,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(FederationGrantRole::Owner),
                },
                InitialSharedMember {
                    member_ref: member,
                    role: Some(FederationGrantRole::Member),
                },
            ],
            now,
        )
        .unwrap();
    let proof = person_proof(&vault, member);
    let invitation = vault
        .shared_invitations(&proof, SHARED_VAULT)
        .unwrap()
        .into_iter()
        .find(|invitation| invitation.role == FederationGrantRole::Member)
        .expect("P has a founding Member invitation");
    let acceptance = vault
        .accept_shared_invitation(&proof, SHARED_VAULT, &invitation.id)
        .unwrap();
    assert_eq!(acceptance.grants.len(), 1, "acceptance mints P's grant");
    let grant_id = EntityId::from_hex(&acceptance.grants[0]).unwrap();
    let grant_raw = vault.get_raw(&grant_id).unwrap().unwrap();
    let grant = decode_federation_grant_body(&grant_raw[ENTITY_METADATA_HEADER_LEN..]).unwrap();
    assert_eq!(grant.member_ref, member);
    assert_eq!(grant.role, FederationGrantRole::Member);
    assert_eq!(grant.scope, FederationGrantScope::vault(SHARED_VAULT));
    assert!(vault.is_live_member_person(&member).unwrap());

    let room = EntityId::now();
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    vault
        .create_conversation(
            room,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![member],
                ..Default::default()
            },
            actor,
            ROOM_AT,
        )
        .unwrap();
    if peer_owns_room {
        vault
            .set_room_role(room, member, RoomRole::Owner, actor)
            .unwrap();
    }
    let body = vault.conversation_body(room).unwrap();
    assert_eq!(
        body.roles.get(&member.to_hex()),
        peer_owns_room.then_some(&RoomRole::Owner)
    );
    assert!(!body.closed);
    if closed {
        vault
            .memory(owner, EdgeActorClass::Human)
            .rooms_closed_set(&RoomClosedSet {
                room_ref: room,
                closed: true,
            })
            .unwrap();
    }
    assert_eq!(vault.conversation_body(room).unwrap().closed, closed);

    let raw = vault.get_raw(&room).unwrap().unwrap();
    let header = EntityMetadataHeader::parse(&raw).unwrap();
    assert_eq!(header.entity_type, ENTITY_TYPE_CONVERSATION);
    assert_eq!(
        header.learned_at, ROOM_AT,
        "setting doors preserve the header"
    );
    // CONVERSATION is BASE, not a world row. Open its learned-at month,
    // exactly the range the production reverse-materializer scans.
    let window = WindowKey::from_timestamp(header.learned_at);
    // Seed the identical held row as a persisted local mirror, using the
    // public snapshot fixture from it_sync/sync_window_manager.rs:68-74.
    // Its one op has lamport 0, peer 0; admission rebuilds the peer's one
    // row at lamport 0 with a guaranteed nonzero peer (admission/mod.rs:438).
    // Thus a permitted body wins deterministically in this SAME window,
    // rather than accidentally losing to recovery's random local peer.
    let mirror = create_window_doc("room-settings-recipient", &window);
    mirror.set_peer_id(0).unwrap();
    mirror
        .get_map("entities")
        .insert(&room.to_hex(), raw.as_slice())
        .unwrap();
    mirror.commit();
    vault
        .sync_state_put(
            &format!("d:w:{}", window.as_str()),
            &mirror.export(ExportMode::Snapshot).unwrap(),
        )
        .unwrap();
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "room-settings-recipient",
    ));
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::Base, vec![], vec![]);
    let peer = FederationPeer::authorize(
        &vault,
        member,
        FederationGrantScope::vault(SHARED_VAULT),
        &selector,
    )
    .unwrap();
    let (client, _events) = SyncClient::new(
        manager,
        SyncClientConfig {
            federation_peer: Some(peer),
            ..Default::default()
        },
    )
    .unwrap();
    let loaded = client.ensure_window(window.as_str()).unwrap();
    assert_eq!(
        loaded
            .doc
            .get_map("entities")
            .get(&room.to_hex())
            .map(|value| value.get_deep_value()),
        mirror
            .get_map("entities")
            .get(&room.to_hex())
            .map(|value| value.get_deep_value()),
        "the loaded window holds the exact local room before the peer writes"
    );
    Fixture {
        client,
        vault,
        owner,
        member,
        room,
        window,
        _directory: directory,
    }
}

/// Keep the held row's type, occurred interval, learned-at and row version;
/// replace only its body, as a peer's CONVERSATION row arrives on the wire.
fn edited_blob(fx: &Fixture, edit: impl FnOnce(&mut ConversationBody)) -> Vec<u8> {
    let raw = fx.vault.get_raw(&fx.room).unwrap().unwrap();
    let mut body = ConversationBody::from_bytes(&raw[ENTITY_METADATA_HEADER_LEN..]).unwrap();
    edit(&mut body);
    let mut blob = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
    blob.extend_from_slice(&body.to_bytes().unwrap());
    blob
}

fn import_member(fx: &mut Fixture, blob: &[u8]) -> Result<(), TransportError> {
    let peer = create_window_doc("room-settings-peer", &fx.window);
    peer.get_map("entities")
        .insert(&fx.room.to_hex(), blob)
        .unwrap();
    peer.commit();
    let update = peer.export(ExportMode::all_updates()).unwrap();
    fx.client.import_federated_window_update(
        fx.window.as_str(),
        &update,
        FederationAdmissionRole::Member,
    )
}

#[test]
fn a_member_peer_without_the_owner_role_cannot_reopen_a_closed_room() {
    let mut fx = fixture(false, true);
    let blob = edited_blob(&fx, |body| body.closed = false);
    let result = import_member(&mut fx, &blob);
    assert!(
        matches!(result, Err(TransportError::InvalidPayload(_))),
        "{result:?}"
    );
    fx.client.replay_deferred_federation_update().unwrap();
    assert!(fx.vault.conversation_body(fx.room).unwrap().closed);
}

#[test]
fn a_member_peer_that_owns_the_room_reopens_it() {
    let mut fx = fixture(true, true);
    let blob = edited_blob(&fx, |body| body.closed = false);
    import_member(&mut fx, &blob).expect("a locally seated Owner may reopen the room");
    fx.client.replay_deferred_federation_update().unwrap();
    assert!(
        !fx.vault.conversation_body(fx.room).unwrap().closed,
        "the body must actually land, not merely pass admission in a wrong window"
    );
}

#[test]
fn a_guest_tier_replay_over_the_closed_room_stays_refused() {
    let fx = fixture(false, true);
    let blob = edited_blob(&fx, |body| body.closed = false);
    let header = EntityMetadataHeader::parse(&blob).unwrap();
    let error = replay_entity(
        &fx.vault,
        ReplicatedEntity {
            id: fx.room,
            entity_type: header.entity_type,
            occurred: TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at: header.learned_at,
            row_version: header.row_version,
            body: &blob[ENTITY_METADATA_HEADER_LEN..],
        },
        ImportTier::Federated(FederationAdmissionRole::Guest),
    )
    .expect_err("guest grading cannot replace a live room's birth stamp");
    assert_eq!(error.kind(), ErrorKind::InvalidConversationBody);
    assert!(fx.vault.conversation_body(fx.room).unwrap().closed);
}

#[test]
fn a_member_peer_that_runs_no_room_cannot_set_its_pin_policy() {
    let mut fx = fixture(false, false);
    let before = fx.vault.conversation_body(fx.room).unwrap().pin_policy;
    assert_eq!(before, RoomPinPolicy::Members);
    let blob = edited_blob(&fx, |body| body.pin_policy = RoomPinPolicy::Managers);
    let result = import_member(&mut fx, &blob);
    assert!(
        matches!(result, Err(TransportError::InvalidPayload(_))),
        "{result:?}"
    );
    fx.client.replay_deferred_federation_update().unwrap();
    assert_eq!(
        fx.vault.conversation_body(fx.room).unwrap().pin_policy,
        before
    );
}

/// A pin record as the member's body carries it, made a minute after the room.
fn pin_by(target: EntityId, pinned_by: EntityId) -> RoomPin {
    RoomPin {
        target,
        pinned_by,
        acting_agent: None,
        pinned_at: ROOM_AT + 60,
    }
}

#[test]
fn a_member_peer_cannot_add_a_pin_in_another_persons_name() {
    let mut fx = fixture(false, false);
    let forged = pin_by(fx.member, fx.owner);
    let blob = edited_blob(&fx, |body| body.pins.push(forged));
    let result = import_member(&mut fx, &blob);
    assert!(
        matches!(result, Err(TransportError::InvalidPayload(_))),
        "{result:?}"
    );
    fx.client.replay_deferred_federation_update().unwrap();
    assert!(fx.vault.conversation_body(fx.room).unwrap().pins.is_empty());
}

#[test]
fn a_member_peer_adds_a_pin_in_its_own_name() {
    let mut fx = fixture(false, false);
    let own = pin_by(fx.owner, fx.member);
    let blob = edited_blob(&fx, |body| body.pins.push(own.clone()));
    import_member(&mut fx, &blob).expect("a member pins under the Members policy as itself");
    fx.client.replay_deferred_federation_update().unwrap();
    assert_eq!(fx.vault.conversation_body(fx.room).unwrap().pins, vec![own]);
}
