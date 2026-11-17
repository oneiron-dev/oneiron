// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! A promoted window's write is judged for its destination in the committing
//! transaction: a world privacy change that commits after the pre-write check
//! still meets the write (PROMOTED-WRITE-DESTINATION-AT-COMMIT).

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use oneiron::authority::{
    ActSurface, EffectiveRead, HostSlipIssuer, MachineRole, PairingPrincipal, ReadLocation,
    WorldPrivacy, pairing_binding_transcript_pinned,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::NoteSyncSession;
use oneiron::sync::transport::{self, window_sub_tags};
use oneiron::sync::{
    ConnectionConfig, SyncClient, SyncClientConfig, SyncConnection, SyncSelector,
    SyncSelectorWorld, SyncTransportCredential, WindowKey, WindowManager,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use oneiron_keystore::{DeviceKeystore, KeystoreError, KeystoreLocality, KeystoreSlot, SlotKind};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use zeroize::Zeroizing;

const FIRST_CONFIDENCE: f32 = 0.25;
const SECOND_CONFIDENCE: f32 = 0.75;

/// Process memory key slots, so the test reads back the host issuer seed the
/// server's bootstrap draws: no fixture keystore, no derived seed.
struct MapKeystore {
    slots: std::sync::Mutex<HashMap<KeystoreSlot, [u8; 32]>>,
}

impl DeviceKeystore for MapKeystore {
    fn get(&self, slot: &KeystoreSlot) -> oneiron_keystore::Result<Option<Zeroizing<[u8; 32]>>> {
        Ok(self
            .slots
            .lock()
            .unwrap()
            .get(slot)
            .copied()
            .map(Zeroizing::new))
    }

    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> oneiron_keystore::Result<()> {
        let mut slots = self.slots.lock().unwrap();
        if slots.contains_key(slot) {
            return Err(KeystoreError::AlreadyExists);
        }
        slots.insert(*slot, *secret);
        Ok(())
    }

    fn delete(&self, slot: &KeystoreSlot) -> oneiron_keystore::Result<()> {
        self.slots.lock().unwrap().remove(slot);
        Ok(())
    }

    fn replace(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> oneiron_keystore::Result<bool> {
        let mut slots = self.slots.lock().unwrap();
        let Some(held) = slots.get_mut(slot) else {
            return Ok(false);
        };
        *held = *secret;
        Ok(true)
    }

    fn locality(&self) -> KeystoreLocality {
        KeystoreLocality::ThisDeviceOnly
    }
}

/// Re-encodes a CLAIM body with a new confidence: an edit of the record that
/// keeps its identity, predicate, value and world.
fn with_confidence(body: &[u8], confidence: f32) -> Vec<u8> {
    let rmpv::Value::Map(mut entries) = rmpv::decode::read_value(&mut &body[..]).unwrap() else {
        panic!("claim body is a map");
    };
    let slot = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("conf"))
        .unwrap();
    slot.1 = rmpv::Value::F32(confidence);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(entries)).unwrap();
    out
}

/// Whether `vault`'s CLAIM row carries `confidence` past its metadata header.
fn carries_confidence(vault: &Vault, claim: EntityId, confidence: f32) -> bool {
    let Some(raw) = vault.get_raw(&claim).unwrap() else {
        return false;
    };
    let rmpv::Value::Map(entries) = rmpv::decode::read_value(&mut &raw[25..]).unwrap() else {
        return false;
    };
    entries.iter().any(|(key, value)| {
        key.as_str() == Some("conf") && value.as_f64() == Some(f64::from(confidence))
    })
}

/// This window's whole state as one residence update: the edit's bytes as the
/// writer judges them.
fn residence_update_payload(seq: u64, doc: &loro::LoroDoc) -> Vec<u8> {
    let delta = doc
        .export(loro::ExportMode::updates(&loro::VersionVector::new()))
        .unwrap();
    let mut payload = seq.to_be_bytes().to_vec();
    payload.extend_from_slice(&delta);
    payload
}

#[tokio::test]
async fn promoted_write_after_world_privacy_change_is_refused_at_commit() {
    let home_dir = tempfile::tempdir().unwrap();
    let device_dir = tempfile::tempdir().unwrap();
    let home = Arc::new(Vault::open(home_dir.path(), VaultConfig::device()).unwrap());
    let keystore = Arc::new(MapKeystore {
        slots: std::sync::Mutex::new(HashMap::new()),
    });
    home.install_device_keystore(keystore.clone());
    let now = oneiron_vault_contract::now_ts();
    let at = TimeRange {
        start: now,
        end: now,
    };
    let owner = home.ensure_embedded_owner_actor().expect("embedded owner");
    let world = EntityId::now();
    let claim = EntityId::now();
    home.put_entity(&world, ENTITY_TYPE_WORLD, at, now, b"world")
        .unwrap();
    // The CLAIM's subject edge names a shared base-month PERSON.
    let subject = EntityId::now();
    home.put_entity(&subject, ENTITY_TYPE_PERSON, at, now, b"subject")
        .unwrap();
    let mut body = ClaimBody::new(
        "test.promoted_write_destination",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("world fact"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = Some(world);
    home.put_claim(&claim, &body, at, now).unwrap();
    let window = WindowKey::for_world(now, world);
    // Boot lists the world-month window from the CLAIM row, and roots the
    // vault with the seed this test reads back for its slips.
    let server = Arc::new(
        SyncServer::new(
            home.clone(),
            SyncServerConfig {
                auth_secret: Some("promoted-write-destination".into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let seed = keystore
        .slots
        .lock()
        .unwrap()
        .iter()
        .find_map(|(slot, seed)| (slot.kind == SlotKind::HostIssuerSeed).then_some(*seed))
        .expect("the server roots with a host issuer seed");
    let issuer = HostSlipIssuer::from_seed(&seed).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let server_task = tokio::spawn(async move {
        axum::serve(listener, build_app(server)).await.unwrap();
    });
    home.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("live install profile to carry owner acts");
    let owner_proof = home
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("authenticated owner");
    // Pairing provisions the owner's residence grant and names it in the
    // paired slip, where the device's selector reads it.
    let owner_hex = owner.to_hex();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    let link = home
        .issue_owner_pairing_link(
            &issuer,
            &owner_proof,
            scope,
            3600,
            PairingPrincipal {
                holder_ref: Some(owner_hex.clone()),
                actor_class: Some("human".to_owned()),
                ..Default::default()
            },
        )
        .unwrap();
    let holder_key = SigningKey::from_bytes(
        blake3::hash(b"promoted-write-destination-at-commit/holder").as_bytes(),
    );
    let binding_key = holder_key.verifying_key().to_bytes();
    let transcript =
        pairing_binding_transcript_pinned(&link.code, &binding_key, &owner_hex, link.pin.as_ref())
            .unwrap();
    let binding_signature = holder_key.sign(&transcript).to_bytes();
    let slip = home
        .redeem_pairing_link(
            &issuer,
            &link.code,
            &owner_hex,
            binding_key,
            &binding_signature,
        )
        .unwrap();
    let grant_id = EntityId::from_hex(
        &slip
            .claims
            .grant_ref
            .clone()
            .expect("pairing provisions the owner's residence grant"),
    )
    .unwrap();
    assert_eq!(
        home.get_entity_type(&grant_id).unwrap(),
        Some(oneiron::registry::ENTITY_TYPE_FEDERATION_GRANT),
        "the paired grant is stored"
    );
    // The socket upgrade proves a holder-bound slip of its own.
    let transport_key = SigningKey::from_bytes(
        blake3::hash(b"promoted-write-destination-at-commit/transport").as_bytes(),
    );
    let root = home.ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims;
    claims.slip_id = *blake3::hash(b"promoted-write-destination-at-commit/transport-id").as_bytes();
    claims.parent_id = None;
    claims.holder_ref = "host".to_owned();
    claims.binding_key = transport_key.verifying_key().to_bytes();
    claims.actor_class = None;
    claims.org_ref = None;
    claims.records = BTreeSet::new();
    claims.scope = Scope::top();
    let transport_slip = home.mint_capability_slip(&issuer, claims).unwrap();
    let device = Arc::new(Vault::open(device_dir.path(), VaultConfig::device()).unwrap());
    let manager = Arc::new(WindowManager::new(
        device.clone(),
        Arc::new(Materializer::new()),
        "device",
    ));
    let selector = SyncSelector::new(grant_id, owner, SyncSelectorWorld::All, vec![], vec![]);
    let mut request = url.as_str().into_client_request().unwrap();
    let timestamp = home.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let proof = transport_slip
        .binding_transcript(challenge.as_bytes())
        .unwrap();
    let signature: String = transport_key
        .sign(&proof)
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", transport_slip.to_token().unwrap())
            .parse()
            .unwrap(),
    );
    request.headers_mut().insert(
        "x-oneiron-binding",
        serde_json::json!({"timestamp": timestamp, "nonce": nonce, "signature": signature})
            .to_string()
            .parse()
            .unwrap(),
    );
    let config = SyncClientConfig {
        server_url: url.clone(),
        transport_credential: Some(SyncTransportCredential::new(
            transport_slip.to_token().unwrap(),
            transport_key,
        )),
        note_session: Some(NoteSyncSession::new(slip.to_token().unwrap(), holder_key)),
        residence_selector: Some(selector.clone()),
        ..Default::default()
    };
    let (mut client, _events) = SyncClient::new(manager.clone(), config.clone()).unwrap();
    let mut socket = tokio_tungstenite::connect_async(request).await.unwrap().0;
    for frame in client.generate_initial_sync() {
        socket.send(Message::Binary(frame.into())).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        while !client
            .server_windows()
            .contains(&window.as_str().to_owned())
        {
            if let Some(Ok(Message::Binary(frame))) = socket.next().await {
                for reply in client.handle_server_message(&frame).unwrap() {
                    socket.send(Message::Binary(reply.into())).await.unwrap();
                }
            }
        }
    })
    .await
    .unwrap();
    // The promotion is granted while the world reads everywhere.
    let promotion = transport::encode_window_sync(
        window.as_str(),
        window_sub_tags::PROMOTION_REQUEST,
        &oneiron::sync::encode_sync_selector(&selector).unwrap(),
    )
    .into_result()
    .unwrap();
    socket
        .send(Message::Binary(promotion.into()))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Binary(frame))) => {
                    if frame.first() == Some(&transport::TAG_WINDOW_SYNC) {
                        let (key, tag, _) = transport::decode_window_sync(&frame[1..]).unwrap();
                        assert_eq!(key, window.as_str());
                        if tag == window_sub_tags::PROMOTION_GRANTED {
                            break;
                        }
                    }
                    for reply in client.handle_server_message(&frame).unwrap() {
                        socket.send(Message::Binary(reply.into())).await.unwrap();
                    }
                }
                other => panic!("socket ended before promotion granted: {other:?}"),
            }
        }
    })
    .await
    .unwrap();
    // The device fetches the thin CLAIM and makes its first edit through the
    // opened-item door, which promotes the world-month window.
    client.fetch_item(&window, claim).await.unwrap();
    let thin = client.thin_item(claim).unwrap().unwrap();
    assert_eq!(thin.window, window);
    assert!(
        device.get_raw(&claim).unwrap().is_none(),
        "a thin read is not a writable CRDT row"
    );
    let conn = SyncConnection::new(
        manager.clone(),
        ConnectionConfig {
            client_config: config.clone(),
            auto_reconnect: false,
        },
    )
    .unwrap();
    let edited = with_confidence(&thin.raw[25..], FIRST_CONFIDENCE);
    conn.edit_opened_item(&window, claim, ENTITY_TYPE_CLAIM, at, now, &edited)
        .await
        .unwrap();
    assert!(
        device
            .sync_state_get(&format!("rp:w:{window}"))
            .unwrap()
            .is_some()
    );
    // A write while the world reads everywhere is acknowledged: the guard.
    let loaded = manager.open_window(&window).unwrap();
    let update = transport::encode_window_sync(
        window.as_str(),
        window_sub_tags::RESIDENCE_UPDATE,
        &residence_update_payload(1, &loaded.doc),
    )
    .into_result()
    .unwrap();
    socket.send(Message::Binary(update.into())).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Binary(frame))) => {
                    if frame.first() == Some(&transport::TAG_WINDOW_SYNC) {
                        let (key, tag, _) = transport::decode_window_sync(&frame[1..]).unwrap();
                        assert_eq!(key, window.as_str());
                        if tag == window_sub_tags::RESIDENCE_ACK {
                            break;
                        }
                    }
                    for reply in client.handle_server_message(&frame).unwrap() {
                        socket.send(Message::Binary(reply.into())).await.unwrap();
                    }
                }
                other => panic!("socket ended before the first write was acknowledged: {other:?}"),
            }
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !carries_confidence(&home, claim, FIRST_CONFIDENCE) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the pre-change write lands");
    // The owner narrows the world's read to his machines after the last
    // check: an unproved destination may no longer read it.
    home.set_world_privacy_as(
        &owner_proof,
        ActSurface::ThisInstall,
        world,
        WorldPrivacy {
            read: ReadLocation::MyMachines,
            ..WorldPrivacy::default()
        },
        None,
    )
    .unwrap();
    assert_eq!(
        home.world_privacy(world).unwrap().read,
        EffectiveRead::MyMachines,
        "the world's read leaves destinations nobody proved"
    );
    // A second edit goes as the next residence update on the same socket.
    let edited_again = with_confidence(&thin.raw[25..], SECOND_CONFIDENCE);
    conn.edit_opened_item(&window, claim, ENTITY_TYPE_CLAIM, at, now, &edited_again)
        .await
        .unwrap();
    let loaded = manager.open_window(&window).unwrap();
    let update = transport::encode_window_sync(
        window.as_str(),
        window_sub_tags::RESIDENCE_UPDATE,
        &residence_update_payload(2, &loaded.doc),
    )
    .into_result()
    .unwrap();
    socket.send(Message::Binary(update.into())).await.unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Binary(frame))) => {
                    if frame.first() == Some(&transport::TAG_WINDOW_SYNC) {
                        let (_, tag, _) = transport::decode_window_sync(&frame[1..]).unwrap();
                        if tag == window_sub_tags::RESIDENCE_ACK {
                            return "acknowledged";
                        }
                    }
                    for reply in client.handle_server_message(&frame).unwrap() {
                        socket.send(Message::Binary(reply.into())).await.unwrap();
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return "closed",
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        outcome, "closed",
        "a promoted write after the world's read left this destination is refused at commit"
    );
    assert!(
        !carries_confidence(&home, claim, SECOND_CONFIDENCE),
        "the refused write lands nothing"
    );
    assert!(
        carries_confidence(&home, claim, FIRST_CONFIDENCE),
        "the acknowledged first write stays"
    );
    server_task.abort();
}
