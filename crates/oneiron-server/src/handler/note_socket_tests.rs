//! Real websocket NOTE commands: actor binding, durable pins, reviewed edits.
use crate::config::SyncServerConfig;
use crate::server::SyncServer;
use futures_util::{SinkExt, StreamExt};
use oneiron::note::{NoteChange, NoteEdit, NoteEditOutcome, NoteOperation, TakeTarget};
use oneiron::sync::transport::{self, document_sub_tags};
use oneiron::sync::{SyncClient, SyncClientConfig, SyncSelector, SyncSelectorWorld, WindowManager};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
const SECRET: &str = "note-socket-fixture-root";
const JTI: &str = "22222222222222222222222222222222";
type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct ServerTask(tokio::task::JoinHandle<()>);
impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn socket(url: &str) -> Socket {
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {SECRET}").parse().unwrap());
    tokio_tungstenite::connect_async(request).await.unwrap().0
}
async fn send(socket: &mut Socket, bytes: Vec<u8>) {
    socket.send(Message::Binary(bytes.into())).await.unwrap();
}
async fn pump_until(socket: &mut Socket, client: &mut SyncClient, mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !ready() {
            match socket.next().await.unwrap().unwrap() {
                Message::Binary(bytes) => {
                    for response in client.handle_server_message(&bytes).unwrap() {
                        send(socket, response).await;
                    }
                }
                Message::Ping(_) | Message::Pong(_) => {}
                other => panic!("unexpected socket state: {other:?}"),
            }
        }
    })
    .await
    .unwrap();
}
fn mirror_row(from: &Vault, to: &Vault, id: EntityId) {
    let raw = from.get_raw(&id).unwrap().unwrap();
    // Carry birth rows through the production ledger replay, not raw NOTE put.
    let learned = u64::from_be_bytes(raw[17..25].try_into().unwrap());
    let key = oneiron::sync::WindowKey::from_timestamp(learned);
    let doc = oneiron::sync::schema::create_window_doc("replica", &key);
    doc.get_map("entities")
        .insert(&id.to_hex(), raw.as_slice())
        .unwrap();
    // A replica serves a NOTE only with its birth stamp.
    for edge in from.edges_out(&id).unwrap() {
        if edge.kind == oneiron::EdgeKind::FacetOf {
            doc.get_map("edges")
                .insert(
                    &oneiron::sync::bridge::format_edge_key(&id, edge.kind, &edge.target),
                    oneiron::sync::bridge::encode_edge_value_for_crdt(
                        edge.kind,
                        edge.weight,
                        edge.created_at,
                        edge.vad,
                        edge.provenance,
                    )
                    .unwrap()
                    .as_slice(),
                )
                .unwrap();
        }
    }
    doc.commit();
    oneiron::sync::window::forward_rematerialize(
        to,
        &doc,
        &oneiron::sync::bridge::Materializer::new(),
        &key,
    )
    .unwrap();
    assert!(to.get_raw(&id).unwrap().is_some());
}
fn command(
    vault: &Vault,
    note: EntityId,
    start: usize,
    delete: usize,
    insert: &str,
) -> NoteOperation {
    NoteOperation {
        request_id: EntityId::now(),
        change: NoteChange::Edit {
            base: vault.note_document(note).unwrap().frontier,
            edits: vec![NoteEdit {
                start,
                delete,
                insert: insert.into(),
            }],
        },
    }
}

#[tokio::test]
async fn authenticated_note_socket_preserves_pins_provenance_and_review_after_reopen() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a = Arc::new(Vault::open(a_dir.path(), VaultConfig::device()).unwrap());
    let actor = EntityId::now();
    a.put_entity(
        &actor,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"author",
    )
    .unwrap();
    let memory = a.memory(actor, EdgeActorClass::Human);
    let claim = EntityId::now();
    memory
        .claim_upsert(&oneiron::memory::ClaimInput {
            id: Some(claim.to_hex()),
            predicate: "profile.name".into(),
            subject_ref: actor.to_hex(),
            value: serde_json::json!("quoted"),
            confidence: 0.9,
            source: "user_stated".into(),
            world_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
            relationship_ref: None,
        })
        .unwrap();
    let source = EntityId::from_hex(
        &memory
            .author_take(TakeTarget::Subject(actor), "before quoted after")
            .unwrap()
            .id_hex,
    )
    .unwrap();
    memory.bless_brief_kind().unwrap();
    let pin = a.pin_note_span(source, claim, 7, 13).unwrap();
    let brief =
        EntityId::from_hex(&memory.author_brief("A cited brief", &[]).unwrap().id_hex).unwrap();
    let grant_id = EntityId::now();
    let grant = oneiron::federation::FederationGrant::new(
        oneiron::FederationGrantScope::vault(7),
        actor,
        oneiron::federation::FederationGrantRole::Member,
        oneiron::federation::FederationGrantPreset::Member,
    );
    oneiron::sync::put_selector_test_federation_grant(&a, &grant_id, &grant, 1).unwrap();
    let selector = SyncSelector::new(grant_id, actor, SyncSelectorWorld::All, vec![], vec![]);
    let server = Arc::new(
        SyncServer::new(
            a.clone(),
            SyncServerConfig {
                auth_secret: Some(SECRET.into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let app = crate::build_app(server.clone());
    let _task = ServerTask(tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    }));
    let b = Arc::new(Vault::open(b_dir.path(), VaultConfig::device()).unwrap());
    for id in [actor, claim, source, brief] {
        mirror_row(&a, &b, id);
    }
    let manager = Arc::new(WindowManager::new(
        b.clone(),
        Arc::new(oneiron::sync::bridge::Materializer::new()),
        "replica",
    ));
    for id in [source, brief] {
        manager.documents().subscribe_entity(id, &selector).unwrap();
    }
    let (slip, key) = crate::test_credentials::credential(
        &server,
        &format!(
            "scope=core:read,core:write;principal_ref={};actor_class=human;jti={JTI}",
            actor.to_hex()
        ),
    );
    let (mut client, _events) = SyncClient::new(
        manager.clone(),
        SyncClientConfig {
            server_url: url.clone(),
            auth_token: SECRET.into(),
            default_window_count: 0,
            note_session: Some(oneiron::sync::client::NoteSyncSession::new(
                slip.to_token().unwrap(),
                key,
            )),
            ..Default::default()
        },
    )
    .unwrap();
    let mut socket = socket(&url).await;
    for frame in client.generate_initial_sync() {
        send(&mut socket, frame).await;
    }
    pump_until(&mut socket, &mut client, || {
        b.note_document(brief)
            .is_ok_and(|view| view.authorship.len() > 1)
    })
    .await;
    let cite = NoteOperation {
        request_id: EntityId::now(),
        change: NoteChange::Cite { pin: pin.clone() },
    };
    manager.documents().submit_note(brief, &cite).unwrap();
    send(
        &mut socket,
        transport::encode_document(brief, document_sub_tags::NOTE_OPS, &cite.encode().unwrap())
            .into_result()
            .unwrap(),
    )
    .await;
    pump_until(&mut socket, &mut client, || {
        manager
            .documents()
            .note_receipt(brief, cite.request_id)
            .unwrap()
            .is_some()
    })
    .await;
    assert_eq!(b.note_document(brief).unwrap().pins, vec![pin.clone()]);
    assert_eq!(
        a.resolve_note_pin(&pin).unwrap(),
        b.resolve_note_pin(&pin).unwrap()
    );
    let edit = command(&b, source, 0, 0, "A ");
    manager.documents().submit_note(source, &edit).unwrap();
    send(
        &mut socket,
        transport::encode_document(source, document_sub_tags::NOTE_OPS, &edit.encode().unwrap())
            .into_result()
            .unwrap(),
    )
    .await;
    pump_until(&mut socket, &mut client, || {
        manager
            .documents()
            .note_receipt(source, edit.request_id)
            .unwrap()
            .is_some()
    })
    .await;
    assert_eq!(
        a.note_document(source).unwrap(),
        b.note_document(source).unwrap()
    );
    assert!(
        b.note_document(source)
            .unwrap()
            .authorship
            .iter()
            .any(|record| record.operation == edit.request_id && record.actor == actor)
    );
    assert!(matches!(
        b.resolve_note_pin(&pin).unwrap(),
        oneiron::note::NoteSpanResolution::Mapped {
            start: 9,
            end: 15,
            ..
        }
    ));
    let before = b.note_document(source).unwrap();
    let cited_edit = command(&b, source, 10, 1, "x");
    manager
        .documents()
        .submit_note(source, &cited_edit)
        .unwrap();
    send(
        &mut socket,
        transport::encode_document(
            source,
            document_sub_tags::NOTE_OPS,
            &cited_edit.encode().unwrap(),
        )
        .into_result()
        .unwrap(),
    )
    .await;
    pump_until(&mut socket, &mut client, || {
        manager
            .documents()
            .note_receipt(source, cited_edit.request_id)
            .unwrap()
            .is_some()
    })
    .await;
    let receipt = manager
        .documents()
        .note_receipt(source, cited_edit.request_id)
        .unwrap()
        .unwrap();
    assert!(
        matches!(receipt.outcome, NoteEditOutcome::Proposed(ref r) if r.approval == "proposed" && r.receipt_ref.starts_with("gate:"))
    );
    assert_eq!(b.note_document(source).unwrap(), before);
    assert_eq!(a.note_document(source).unwrap(), before);
    drop(socket);
    drop(client);
    drop(manager);
    drop(b);
    let b = Vault::open(b_dir.path(), VaultConfig::device()).unwrap();
    assert_eq!(b.note_document(source).unwrap(), before);
    assert_eq!(b.note_document(brief).unwrap().pins, vec![pin.clone()]);
    assert_eq!(
        a.resolve_note_pin(&pin).unwrap(),
        b.resolve_note_pin(&pin).unwrap()
    );
}

#[tokio::test]
async fn document_handler_refuses_unbound_and_selector_impersonation_and_raw_pin_injection() {
    use super::{conn_state::ConnState, documents::handle_document};
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let author = EntityId::now();
    let stranger = EntityId::now();
    for actor in [author, stranger] {
        vault
            .put_entity(
                &actor,
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"actor",
            )
            .unwrap();
    }
    let note = EntityId::from_hex(
        &vault
            .memory(author, EdgeActorClass::Human)
            .author_take(TakeTarget::Subject(author), "protected")
            .unwrap()
            .id_hex,
    )
    .unwrap();
    let grant_id = EntityId::now();
    let grant = oneiron::federation::FederationGrant::new(
        oneiron::FederationGrantScope::vault(7),
        author,
        oneiron::federation::FederationGrantRole::Member,
        oneiron::federation::FederationGrantPreset::Member,
    );
    oneiron::sync::put_selector_test_federation_grant(&vault, &grant_id, &grant, 1).unwrap();
    let selector = SyncSelector::new(grant_id, author, SyncSelectorWorld::All, vec![], vec![]);
    let config = SyncServerConfig {
        auth_secret: Some(SECRET.into()),
        ..Default::default()
    };
    let server = SyncServer::new(vault.clone(), config).unwrap();
    let mut state = ConnState::new(transport::PROTOCOL_VERSION);
    let (direct, mut responses) = tokio::sync::mpsc::unbounded_channel();
    let request =
        oneiron::sync::encode_selector_vv_request(&selector, &loro::VersionVector::new().encode())
            .unwrap();
    assert!(
        handle_document(
            &server,
            1,
            note,
            document_sub_tags::REQUEST,
            &request,
            &direct,
            &mut state
        )
        .is_err()
    );
    let recipe = |actor: EntityId| {
        format!(
            "scope=core:read,core:write;principal_ref={};actor_class=human;jti={JTI}-{}",
            actor.to_hex(),
            actor.to_hex()
        )
    };
    let bind = |actor: EntityId| crate::test_credentials::authenticate(&server, &recipe(actor));
    state.bound_auth = Some(bind(stranger));
    assert!(
        handle_document(
            &server,
            1,
            note,
            document_sub_tags::REQUEST,
            &request,
            &direct,
            &mut state
        )
        .is_err()
    );
    state.bound_auth = Some(bind(author));
    handle_document(
        &server,
        1,
        note,
        document_sub_tags::REQUEST,
        &request,
        &direct,
        &mut state,
    )
    .unwrap();
    let before = vault.note_document(note).unwrap();
    let raw = loro::LoroDoc::new();
    raw.get_map("pins")
        .insert("forged", "peer-controlled")
        .unwrap();
    raw.commit_with(
        loro::CommitOptions::new()
            .commit_msg(&format!("oneiron.note/v1 actor={}", author.to_hex())),
    );
    let bytes = raw.export(loro::ExportMode::Snapshot).unwrap();
    assert!(
        handle_document(
            &server,
            1,
            note,
            document_sub_tags::UPDATE,
            &bytes,
            &direct,
            &mut state
        )
        .is_err()
    );
    assert!(
        handle_document(
            &server,
            1,
            note,
            document_sub_tags::STATE,
            &bytes,
            &direct,
            &mut state
        )
        .is_err()
    );
    assert_eq!(vault.note_document(note).unwrap(), before);
    // Consume initial REQUEST response, then exercise the actual ordered
    // delivery queue twice: once on admission and once on idempotent replay.
    responses.try_recv().unwrap();
    let operation = command(&vault, note, 0, 0, "admitted ");
    let mut last_delivery = None;
    for _ in 0..2 {
        handle_document(
            &server,
            1,
            note,
            document_sub_tags::NOTE_OPS,
            &operation.encode().unwrap(),
            &direct,
            &mut state,
        )
        .unwrap();
        let notice = responses.try_recv().unwrap();
        let decoded = transport::decode_document(&notice[1..]).unwrap();
        assert_eq!(decoded.kind, document_sub_tags::UPDATE);
        assert!(decoded.payload.is_empty());
        let receipt_frame = responses.try_recv().unwrap();
        let receipt_doc = transport::decode_document(&receipt_frame[1..]).unwrap();
        assert_eq!(receipt_doc.kind, document_sub_tags::NOTE_RECEIPT);
        let receipt: oneiron::note::NoteOperationReceipt =
            serde_json::from_slice(receipt_doc.payload).unwrap();
        assert_eq!(receipt.request_id, operation.request_id);
        let exported = super::documents::document_delivery(&server, &state, &notice).unwrap();
        let replica = loro::LoroDoc::new();
        let state_frame = transport::decode_document(&exported[0][1..]).unwrap();
        assert_eq!(state_frame.kind, document_sub_tags::STATE);
        assert!(
            replica
                // A NOTE frame names its head and head sequence first.
                .import(&state_frame.payload[24..])
                .unwrap()
                .pending
                .is_none()
        );
        let NoteEditOutcome::Applied(view) = &receipt.outcome else {
            panic!("free text must be applied");
        };
        let frontier = loro::Frontiers::decode(&view.frontier).unwrap();
        assert!(matches!(
            replica.cmp_frontiers(&replica.oplog_frontiers(), &frontier),
            Ok(Some(
                std::cmp::Ordering::Equal | std::cmp::Ordering::Greater
            ))
        ));
        assert_eq!(
            super::documents::document_delivery(&server, &state, &receipt_frame).unwrap(),
            vec![receipt_frame.clone()]
        );
        last_delivery = Some((notice, receipt_frame));
    }
    // An in-flight full-view receipt is also a derived carrier. After a
    // cited source is erased, the NOTE itself remains exportable, but this
    // older queued receipt must not restore the removed quote on the wire.
    let claim = EntityId::now();
    let body = oneiron::claim::ClaimBody::new(
        "profile.name",
        oneiron::claim::ClaimSubject::Entity(author),
        rmpv::Value::from("queued quote"),
        0.9,
        oneiron::claim::ClaimApprovalStatus::Approved,
        oneiron::claim::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    vault
        .put_claim(&claim, &body, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    let memory = vault.memory(author, EdgeActorClass::Human);
    let source = EntityId::from_hex(
        &memory
            .author_take(TakeTarget::Subject(author), "queued quote")
            .unwrap()
            .id_hex,
    )
    .unwrap();
    let pin = vault.pin_note_span(source, claim, 0, 12).unwrap();
    memory.cite_note_span(note, &pin).unwrap();
    let edit = command(&vault, note, 0, 0, "edit ");
    handle_document(
        &server,
        1,
        note,
        document_sub_tags::NOTE_OPS,
        &edit.encode().unwrap(),
        &direct,
        &mut state,
    )
    .unwrap();
    let notice = responses.try_recv().unwrap();
    let stale_receipt = responses.try_recv().unwrap();
    let frame = transport::decode_document(&stale_receipt[1..]).unwrap();
    let receipt: oneiron::note::NoteOperationReceipt =
        serde_json::from_slice(frame.payload).unwrap();
    assert!(matches!(&receipt.outcome, NoteEditOutcome::Applied(view) if view.pins == vec![pin]));
    assert_eq!(
        super::documents::document_delivery(&server, &state, &stale_receipt).unwrap(),
        vec![stale_receipt.clone()]
    );
    vault.delete_entity(&source).unwrap();
    assert!(vault.note_document(note).unwrap().pins.is_empty());
    assert_eq!(
        super::documents::document_delivery(&server, &state, &notice)
            .unwrap()
            .len(),
        1
    );
    assert!(
        super::documents::document_delivery(&server, &state, &stale_receipt)
            .unwrap()
            .is_empty()
    );
    let before = vault.note_document(note).unwrap();
    crate::test_credentials::revoke(&server, &recipe(author));
    let (notice, receipt_frame) = last_delivery.unwrap();
    // A revoked credential fails closed: delivery refuses, it never exports.
    assert!(super::documents::document_delivery(&server, &state, &notice).is_err());
    assert!(super::documents::document_delivery(&server, &state, &receipt_frame).is_err());
    let operation = command(&vault, note, 0, 0, "revoked ");
    assert!(
        handle_document(
            &server,
            1,
            note,
            document_sub_tags::NOTE_OPS,
            &operation.encode().unwrap(),
            &direct,
            &mut state
        )
        .is_err()
    );
    assert_eq!(vault.note_document(note).unwrap(), before);
}

#[tokio::test]
async fn document_socket_update_cannot_use_a_downgraded_subscription() {
    use super::{conn_state::ConnState, documents::handle_document};
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let id = EntityId::now();
    let facet = EntityId::now();
    vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            b"turn",
        )
        .unwrap();
    vault
        .put_entity(
            &facet,
            oneiron::registry::ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"turn facet",
        )
        .unwrap();
    vault
        .put_edge(&id, oneiron::EdgeKind::FacetOf, &facet, 1.0)
        .unwrap();
    let member = EntityId::now();
    let grant_id = EntityId::now();
    let mut grant = oneiron::federation::FederationGrant::new(
        oneiron::FederationGrantScope::vault(7),
        member,
        oneiron::federation::FederationGrantRole::Member,
        oneiron::federation::FederationGrantPreset::Member,
    );
    oneiron::sync::put_selector_test_federation_grant(&vault, &grant_id, &grant, 1).unwrap();
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet],
        vec![oneiron::federation::SelectorRange::Core],
    );
    let server = SyncServer::new(
        vault.clone(),
        SyncServerConfig {
            auth_secret: Some(SECRET.into()),
            ..Default::default()
        },
    )
    .unwrap();
    let mut state = ConnState::new(transport::PROTOCOL_VERSION);
    state.bound_auth = Some(crate::test_credentials::authenticate(
        &server,
        &format!(
            "scope=core:read,core:write;principal_ref={}",
            member.to_hex()
        ),
    ));
    let (direct, _responses) = tokio::sync::mpsc::unbounded_channel();
    let request =
        oneiron::sync::encode_selector_vv_request(&selector, &loro::VersionVector::new().encode())
            .unwrap();
    handle_document(
        &server,
        1,
        id,
        document_sub_tags::REQUEST,
        &request,
        &direct,
        &mut state,
    )
    .unwrap();
    let remote = loro::LoroDoc::new();
    remote.get_text("body").insert(0, "first").unwrap();
    remote.commit();
    let update = remote.export(loro::ExportMode::all_updates()).unwrap();
    handle_document(
        &server,
        1,
        id,
        document_sub_tags::UPDATE,
        &update,
        &direct,
        &mut state,
    )
    .unwrap();
    let before = remote.oplog_vv();
    remote.get_text("body").insert(5, " forbidden").unwrap();
    remote.commit();
    let update = remote.export(loro::ExportMode::updates(&before)).unwrap();
    grant.role = oneiron::federation::FederationGrantRole::Viewer;
    oneiron::sync::put_selector_test_federation_grant(&vault, &grant_id, &grant, 2).unwrap();
    assert!(
        handle_document(
            &server,
            1,
            id,
            document_sub_tags::UPDATE,
            &update,
            &direct,
            &mut state
        )
        .is_err()
    );
    assert_eq!(
        server
            .reassert_manager
            .documents()
            .open(id)
            .unwrap()
            .text()
            .unwrap(),
        "first"
    );
}

#[tokio::test]
async fn owner_document_lane_refuses_a_principal_that_is_not_the_owner() {
    use super::{conn_state::ConnState, documents::handle_document};
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let note = vault
        .create_note(
            "research",
            "owner text",
            oneiron::WriteActor::new(owner, oneiron::EdgeActorClass::Human),
        )
        .unwrap();
    let agent = EntityId::now();
    vault
        .put_entity(
            &agent,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )
        .unwrap();
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some(SECRET.into()),
            ..Default::default()
        },
    )
    .unwrap();
    let mut state = ConnState::new(transport::CHUNK_FULL_WINDOW_PROTOCOL_VERSION);
    state.bound_auth = Some(crate::test_credentials::authenticate(
        &server,
        &format!(
            "scope=core:read,core:write;principal_ref={};actor_class=agent",
            agent.to_hex()
        ),
    ));
    let (direct, _responses) = tokio::sync::mpsc::unbounded_channel();
    let request = [
        0u32.to_be_bytes().as_slice(),
        &loro::VersionVector::new().encode(),
    ]
    .concat();

    assert!(
        handle_document(
            &server,
            1,
            note,
            document_sub_tags::REQUEST,
            &request,
            &direct,
            &mut state,
        )
        .is_err()
    );
}
