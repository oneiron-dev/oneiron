//! L9-52 (Engine RULING L9-52-ROOM-STRUCTURE = A, 14 Nov 14:29): one rule
//! decides every door that serves a room's structure, the rule its DAG
//! records and roster doors keep (FIX 8153, 8209). A reader whose lane reads
//! the room's row and its turns, but who neither sits in the room nor holds
//! a grant that opens its relationship, gets at each door what a missing
//! room or row gets. A member is served at each.

use super::credential_reads::{Room, room};
use super::*;

/// A request to one door that serves a room's structure.
struct DoorRequest {
    door: &'static str,
    method: &'static str,
    uri: String,
    body: Option<Value>,
}

impl DoorRequest {
    fn new(door: &'static str, method: &'static str, uri: String, body: Option<Value>) -> Self {
        Self {
            door,
            method,
            uri,
            body,
        }
    }
}

/// The requests to each row and turn door for the room `room` and its turn
/// `turn`, both hex.
fn row_door_requests(room: &str, turn: &str) -> Vec<DoorRequest> {
    vec![
        DoorRequest::new(
            "legacy room row",
            "GET",
            format!("/api/entity/{room}?view=full"),
            None,
        ),
        DoorRequest::new(
            "legacy turn row",
            "GET",
            format!("/api/entity/{turn}?view=full"),
            None,
        ),
        DoorRequest::new(
            "legacy room edges",
            "GET",
            format!("/api/edges/{room}"),
            None,
        ),
        DoorRequest::new(
            "legacy turn edges",
            "GET",
            format!("/api/edges/{turn}"),
            None,
        ),
        DoorRequest::new(
            "turn list",
            "GET",
            format!("/v1/core/conversations/{room}/turns?view=full"),
            None,
        ),
        DoorRequest::new(
            "turn read",
            "GET",
            format!("/v1/core/turns/{turn}?view=full"),
            None,
        ),
        DoorRequest::new(
            "context pack",
            "POST",
            "/v1/core/context-pack".to_owned(),
            Some(json!({ "conversation_id": room, "query": "credkey" })),
        ),
    ]
}

/// The requests to each DAG shape door for the room `room` and its turn
/// `turn`, both hex.
fn dag_door_requests(room: &str, turn: &str) -> Vec<DoorRequest> {
    let conversation = format!("/v1/core/conversations/{room}");
    vec![
        DoorRequest::new(
            "dag scope",
            "POST",
            format!("{conversation}/scope"),
            Some(json!({ "path": "canonical" })),
        ),
        DoorRequest::new(
            "dag canonical",
            "GET",
            format!("{conversation}/canonical"),
            None,
        ),
        DoorRequest::new(
            "dag thread",
            "GET",
            format!("{conversation}/records/{turn}/thread"),
            None,
        ),
    ]
}

/// The requests to the single hydrate door for the room's short ref
/// `room_ref` and its turn's `turn_ref`.
fn hydrate_door_requests(room_ref: &str, turn_ref: &str) -> Vec<DoorRequest> {
    vec![
        DoorRequest::new(
            "hydrate room",
            "POST",
            "/v1/core/hydrate".to_owned(),
            Some(json!({ "ref": room_ref })),
        ),
        DoorRequest::new(
            "hydrate turn",
            "POST",
            "/v1/core/hydrate".to_owned(),
            Some(json!({ "ref": turn_ref })),
        ),
    ]
}

/// What `request` answers `authorization`: its status, and its error code
/// when it refuses.
async fn answer(
    server: &Arc<SyncServer>,
    authorization: &str,
    request: &DoorRequest,
) -> (StatusCode, Value) {
    let (status, body) = route_json(
        server.clone(),
        core_request_with_authz(
            request.method,
            &request.uri,
            authorization.to_owned(),
            request.body.as_ref(),
        ),
    )
    .await;
    (status, body["error"]["code"].clone())
}

/// The outsider of `room`: a reader on a records grant that reads its
/// CONVERSATION and TURN rows, with no seat in it and no grant that opens its
/// relationship (F16 H145's reader).
fn outsider(room: &Room) -> String {
    let outsider = seeded_test_entity_id(0x2401_0052);
    super::context_board_history::restrict_principal_read_types(
        &room.server,
        outsider,
        &[
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::registry::ENTITY_TYPE_CONVERSATION,
        ],
    );
    test_bearer(&format!(
        "scope=core:read;principal_ref={}",
        outsider.to_hex()
    ))
}

/// The first turn of `conversation`, as the vault's owner lists it.
async fn first_turn(
    server: &Arc<SyncServer>,
    conversation: oneiron::EntityId,
) -> oneiron::EntityId {
    let (status, body) = route_json(
        server.clone(),
        core_request_with_authz(
            "GET",
            &format!(
                "/v1/core/conversations/{}/turns?view=full",
                conversation.to_hex()
            ),
            owner_bearer(),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let turn = body["items"][0]["id"].as_str().expect("a turn of the room");
    oneiron::EntityId::from_hex(turn).expect("turn id")
}

/// A group room the vault's owner made in the relationship `space`, holding
/// the owner alone, with one turn the owner said in it.
fn relationship_room(room: &Room, space: oneiron::EntityId) -> oneiron::EntityId {
    let id = seeded_test_entity_id(0x2401_0055);
    let vault = &room.server.vault;
    vault
        .create_conversation(
            id,
            &oneiron::conversation::ConversationBody {
                kind: oneiron::conversation::ConversationKind::Group,
                member_ids: vec![room.owner],
                relationship: Some(space),
                ..Default::default()
            },
            oneiron::WriteActor::new(room.owner, oneiron::EdgeActorClass::Human),
            1,
        )
        .expect("the relationship's room");
    vault
        .memory(room.owner, oneiron::EdgeActorClass::Human)
        .rooms_speak(&oneiron::memory::WitnessTurn {
            conversation_ref: id.to_hex(),
            turn_ref: Some(oneiron::EntityId::now().to_hex()),
            messages: vec![oneiron::memory::WitnessMessage {
                id: Some(oneiron::EntityId::now().to_hex()),
                author: oneiron::memory::WitnessAuthor::User,
                message_type: "text".into(),
                content: "a word in the relationship credkey".into(),
                metadata: Some(json!({ "rel": space.to_hex() })),
                is_visible: true,
                order: 0,
                parts: None,
                quote: None,
            }],
            occurred_at: 4,
            assertions: Default::default(),
            thread_audience: None,
        })
        .expect("speak in the relationship's room");
    id
}

/// Each door of `real` answers the outsider as its twin in `missing` answers
/// it, and serves the member: one line per door that does not.
async fn door_mismatches(
    room: &Room,
    real: &[DoorRequest],
    missing: &[DoorRequest],
) -> Vec<String> {
    let outsider = outsider(room);
    let member = test_bearer(&room.agent_recipe(None));
    let mut mismatches = Vec::new();
    for (request, twin) in real.iter().zip(missing) {
        let refused = answer(&room.server, &outsider, request).await;
        let absent = answer(&room.server, &outsider, twin).await;
        if refused != absent {
            mismatches.push(format!(
                "{}: the outsider got {refused:?}, a missing one gets {absent:?}",
                request.door
            ));
        }
        let served = answer(&room.server, &member, request).await;
        if served.0 != StatusCode::OK {
            mismatches.push(format!("{}: the member got {served:?}", request.door));
        }
    }
    mismatches
}

/// The room's row and turns, at the legacy row and edge doors, the TURN
/// doors and the context pack: an outsider whose lane reads them reads a
/// missing room; a member reads them.
#[tokio::test]
async fn an_outsider_reads_a_rooms_rows_and_turns_as_missing() {
    let room = room();
    let turn = first_turn(&room.server, room.room).await;
    let real = row_door_requests(&room.room.to_hex(), &turn.to_hex());
    let missing = row_door_requests(
        &seeded_test_entity_id(0x2401_0053).to_hex(),
        &seeded_test_entity_id(0x2401_0054).to_hex(),
    );
    let mismatches = door_mismatches(&room, &real, &missing).await;
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

/// The room's DAG shape, at the scope, canonical and thread doors: an
/// outsider whose lane reads its turns reads a missing room; a member reads
/// its shape.
#[tokio::test]
async fn an_outsider_reads_no_dag_shape_of_a_room() {
    let room = room();
    let turn = first_turn(&room.server, room.room).await;
    let real = dag_door_requests(&room.room.to_hex(), &turn.to_hex());
    let missing = dag_door_requests(
        &seeded_test_entity_id(0x2401_0053).to_hex(),
        &seeded_test_entity_id(0x2401_0054).to_hex(),
    );
    let mismatches = door_mismatches(&room, &real, &missing).await;
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

/// The room's row and turn by short ref, at the single and batch hydrate
/// doors: an outsider whose lane reads them hydrates a missing ref; a member
/// hydrates them.
#[tokio::test]
async fn an_outsider_hydrates_a_rooms_refs_as_missing() {
    let room = room();
    let turn = first_turn(&room.server, room.room).await;
    let short_ref = |id: &oneiron::EntityId| {
        let short =
            oneiron::retrieval_depth::short_ref_or_hex(&room.server.vault, id).expect("short ref");
        assert!(short.contains(':'), "{} holds no short id", id.to_hex());
        short
    };
    let (room_ref, turn_ref) = (short_ref(&room.room), short_ref(&turn));
    let missing_ref = "tn999:aa";
    let real = hydrate_door_requests(&room_ref, &turn_ref);
    let missing = hydrate_door_requests(missing_ref, missing_ref);
    let mut mismatches = door_mismatches(&room, &real, &missing).await;
    // The batch door answers each ref in its own slot; the last is missing.
    let refs = [room_ref.as_str(), turn_ref.as_str(), missing_ref];
    let refused = batch_outcomes(&room.server, outsider(&room), &refs).await;
    if refused.len() != 3 || refused[0] != refused[2] || refused[1] != refused[2] {
        mismatches.push(format!(
            "batch hydrate: the outsider got {refused:?}, the last ref is missing"
        ));
    }
    let member = test_bearer(&room.agent_recipe(None));
    let served = batch_outcomes(&room.server, member, &refs).await;
    if served.len() != 3 || served[0] == served[2] || served[1] == served[2] {
        mismatches.push(format!(
            "batch hydrate: the member got {served:?}, the last ref is missing"
        ));
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

/// Each slot's outcome the batch hydrate door answers `authorization` for
/// `refs`, in order.
async fn batch_outcomes(
    server: &Arc<SyncServer>,
    authorization: String,
    refs: &[&str],
) -> Vec<Value> {
    let (status, body) = route_json(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/batch/shortId/hydrate",
            authorization,
            Some(&json!({ "refs": refs })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["results"]
        .as_array()
        .map(|results| results.iter().map(|item| item["outcome"].clone()).collect())
        .unwrap_or_default()
}

/// A room in a relationship, at the row, turn, context pack and DAG shape
/// doors: a reader outside it, on a live grant that opens its relationship,
/// reads it as the room's own list shows it to that reader.
#[tokio::test]
async fn a_relationship_grantee_reads_the_room() {
    let room = room();
    let space = seeded_test_entity_id(0x2401_0056);
    let opened = relationship_room(&room, space);
    let grantee = seeded_test_entity_id(0x2401_0057);
    super::context_board_history::restrict_principal_read_types(
        &room.server,
        grantee,
        &[
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::registry::ENTITY_TYPE_CONVERSATION,
        ],
    );
    room.server
        .vault
        .create_access_grant(
            &seeded_test_entity_id(0x2401_0058),
            &oneiron::access_grant::AccessGrant {
                principal_ref: grantee,
                scope: oneiron::access_grant::AccessGrantScope::Messages { space_ref: space },
                capability: oneiron::access_grant::AccessGrantCapability::MessagesRead,
                authority_scope: oneiron::federation::Scope::top(),
                status: oneiron::access_grant::AccessGrantStatus::Active,
                created_at: 1,
                revoked_at: None,
                expires_at: None,
                companion_bounds: None,
            },
        )
        .expect("grant the relationship");
    let authorization = test_bearer(&format!(
        "scope=core:read;principal_ref={}",
        grantee.to_hex()
    ));
    let turn = first_turn(&room.server, opened).await;
    let (opened, turn) = (opened.to_hex(), turn.to_hex());
    let mut refused = Vec::new();
    for request in row_door_requests(&opened, &turn)
        .iter()
        .chain(&dag_door_requests(&opened, &turn))
    {
        let served = answer(&room.server, &authorization, request).await;
        if served.0 != StatusCode::OK {
            refused.push(format!("{}: the grantee got {served:?}", request.door));
        }
    }
    assert!(refused.is_empty(), "{refused:#?}");
}
