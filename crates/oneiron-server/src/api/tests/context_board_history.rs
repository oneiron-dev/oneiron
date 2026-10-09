//! Board history on the board's own surface (ARCH-0067 §3): hydrations that
//! name their TURN record its board, and a past turn's board reconstructs.

use super::*;

fn put_person(server: &SyncServer, id: oneiron::EntityId, name: &str) {
    let bytes = rmp_serde::to_vec_named(&json!({ "name": name })).unwrap();
    server
        .vault
        .batch()
        .put(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            &bytes,
        )
        .text(&id, &[("name", name)])
        .commit()
        .unwrap();
}

/// A TURN whose body carries the author stamp its door writes.
fn put_turn(server: &SyncServer, id: oneiron::EntityId, author: oneiron::EntityId) {
    let body = rmp_serde::to_vec_named(&json!({ "actor": author.to_hex() })).unwrap();
    server
        .vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 2, end: 2 },
            2,
            &body,
        )
        .unwrap();
}

/// A board hydration by `principal` naming `turn`.
fn hydrate(principal: oneiron::EntityId, scope: &str, body: &Value) -> Request<Body> {
    core_request_with_principal_ref(
        "POST",
        "/v1/core/context-board",
        scope,
        &principal.to_hex(),
        Some(body),
    )
}

/// `reader`'s read-back of `turn`'s board.
fn history(turn: oneiron::EntityId, reader: oneiron::EntityId) -> Request<Body> {
    core_request_with_principal_ref(
        "GET",
        &format!("/v1/core/context-board/turns/{}", turn.to_hex()),
        "core:read",
        &reader.to_hex(),
        None,
    )
}

/// A delegated board reader the disclosure clamp serves: a counterparty
/// contact cleared for everything. A reader with no contact is cleared for
/// nothing, and its board shows no rows.
fn cleared_reader(server: &SyncServer, principal: oneiron::EntityId, identity: oneiron::EntityId) {
    seed_counterparty_contact(server, principal, identity, "board-reader@example.test");
    seed_disclosure_scope(server, principal, oneiron::federation::Scope::top());
}

/// Narrows `principal`'s reads to the `allowed` entity types with a policy
/// manifest grant. Its credential stays live; rows of any other type stop
/// being readable to it.
fn restrict_principal_read_types(
    server: &SyncServer,
    principal: oneiron::EntityId,
    allowed: &[u8],
) {
    use oneiron::federation::{Scope, ScopeAxis};
    use rmpv::Value as Mp;
    let owner_ref = server.vault.ensure_embedded_owner_actor().unwrap();
    let owner = server
        .vault
        .authenticate_owner(
            owner_ref,
            &owner_ref.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    let id = server
        .vault
        .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
        .unwrap()[0];
    let bytes = server.vault.get(&id).unwrap().unwrap();
    let Mp::Map(mut entries) = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap() else {
        panic!("the policy manifest is a map");
    };
    entries.retain(|(key, _)| key.as_str() != Some("scoped_grants"));
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(["read".to_owned()].into());
    scope.bands = ScopeAxis::Some(allowed.iter().copied().collect());
    let scope = rmp_serde::to_vec_named(&scope).unwrap();
    let scope = rmpv::decode::read_value(&mut scope.as_slice()).unwrap();
    entries.push((
        Mp::from("scoped_grants"),
        Mp::Array(vec![Mp::Map(vec![
            (Mp::from("actor_ref"), Mp::from(principal.to_hex())),
            (Mp::from("effector"), Mp::from("core:read")),
            (Mp::from("scope"), scope),
            (Mp::from("receipt_required"), Mp::Boolean(false)),
        ])]),
    ));
    let mut manifest = Vec::new();
    rmpv::encode::write_value(&mut manifest, &Mp::Map(entries)).unwrap();
    server
        .vault
        .install_owner_policy_manifest(&owner, id, manifest, 200)
        .unwrap();
}

fn pin_ref(server: &SyncServer, id: oneiron::EntityId, query: &str) -> String {
    let pack = server
        .vault
        .context_pack()
        .search_text(query, 10)
        .run()
        .unwrap();
    let row = pack.results.iter().find(|row| row.id == id).unwrap();
    format!("{}:{:02x}", row.short_id, row.content_hash)
}

/// REV-9 item 7 done-means: a turn's board can be reconstructed after later
/// turns change it. Writes are delta-only: an unchanged turn anchors with no
/// new selection claim. Another principal cannot read the board back.
#[tokio::test]
async fn a_turns_board_reconstructs_after_later_turns_change_it() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal = seeded_test_entity_id(0x2067_0001);
    let first = seeded_test_entity_id(0x2067_0002);
    let second = seeded_test_entity_id(0x2067_0003);
    cleared_reader(&server, principal, seeded_test_entity_id(0x2067_0004));
    put_person(&server, first, "first pin needle");
    put_person(&server, second, "second pin needle");
    let refs = [
        pin_ref(&server, first, "first pin needle"),
        pin_ref(&server, second, "second pin needle"),
    ];
    let turns: Vec<_> = (0..3)
        .map(|n| {
            let turn = seeded_test_entity_id(0x2067_0010 + n);
            put_turn(&server, turn, principal);
            turn
        })
        .collect();

    let mut changed = Vec::new();
    for (turn, pin) in turns.iter().zip([&refs[0], &refs[1], &refs[1]]) {
        let (status, board) = route_json(
            server.clone(),
            hydrate(
                principal,
                "core:read,core:write",
                &json!({
                    "retrieval": {"query": "unrelated empty query", "limit": 1},
                    "memories": {"shared_total": 0, "pinned_refs": [pin]},
                    "session": {"session_id": principal.to_hex()},
                    "turn": {"id": turn.to_hex()}
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{board:#}");
        assert_eq!(board["board_turn"]["turn"], turn.to_hex());
        changed.push(
            board["board_turn"]["changed_claims"]
                .as_array()
                .unwrap()
                .len(),
        );
    }
    assert_eq!(
        changed,
        [1, 1, 0],
        "selection claims are written on change only"
    );

    for (turn, pinned) in [(turns[0], first), (turns[1], second), (turns[2], second)] {
        let (status, board) = route_json(server.clone(), history(turn, principal)).await;
        assert_eq!(status, StatusCode::OK, "{board:#}");
        assert_eq!(board["selection"]["pinned"], json!([pinned.to_hex()]));
        assert!(
            board["documents"].get(pinned.to_hex()).is_some(),
            "{board:#}"
        );
    }
    let (status, _) = route_json(server.clone(), history(turns[0], first)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Recording a turn's board writes, so it needs `core:write`.
#[tokio::test]
async fn naming_a_turn_needs_core_write() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal = seeded_test_entity_id(0x2067_0101);
    put_person(&server, principal, "board owner");
    let turn = seeded_test_entity_id(0x2067_0102);
    server
        .vault
        .put_entity(
            &turn,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 2, end: 2 },
            2,
            b"board turn",
        )
        .unwrap();
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            &principal.to_hex(),
            Some(&json!({ "turn": {"id": turn.to_hex()} })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body:#}");
    assert_eq!(server.vault.board_turn_owner(&turn).unwrap(), None);
}

/// Sol F2 (REV-9 D2a): reading a turn is no authority over its board. Another
/// principal with read and write access cannot claim the turn's board first;
/// the actor the TURN names still records its own.
#[tokio::test]
async fn a_reader_cannot_claim_another_actors_turn_board() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let author = seeded_test_entity_id(0x2067_0201);
    let reader = seeded_test_entity_id(0x2067_0202);
    put_person(&server, author, "turn author");
    put_person(&server, reader, "turn reader");
    let turn = seeded_test_entity_id(0x2067_0203);
    put_turn(&server, turn, author);
    let claim = json!({ "turn": {"id": turn.to_hex()} });

    let (status, refused) = route_json(
        server.clone(),
        hydrate(reader, "core:read,core:write", &claim),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused:#}");
    assert!(
        refused.to_string().contains("board_turn_of_another_actor"),
        "{refused:#}"
    );
    assert_eq!(server.vault.board_turn_owner(&turn).unwrap(), None);

    let (status, board) = route_json(
        server.clone(),
        hydrate(author, "core:read,core:write", &claim),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{board:#}");
    assert_eq!(board["board_turn"]["turn"], turn.to_hex());
    assert_eq!(server.vault.board_turn_owner(&turn).unwrap(), Some(author));
}

/// Sol F8 (REV-9 D2a): a hydration refused by its final token-budget check
/// records nothing, so the turn can still record the board it is served.
#[tokio::test]
async fn a_refused_hydration_leaves_its_turn_free_to_record() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let actor = seeded_test_entity_id(0x2067_0301);
    let world = seeded_test_entity_id(0x2067_0302);
    put_person(&server, actor, "standing agent");
    server
        .vault
        .put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"world",
        )
        .unwrap();
    let owner_ref = server.vault.ensure_embedded_owner_actor().unwrap();
    let owner = server
        .vault
        .authenticate_owner(
            owner_ref,
            &owner_ref.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    server
        .vault
        .open_standing_block(&owner, actor, world, "identity", 64)
        .unwrap();
    let turn = seeded_test_entity_id(0x2067_0303);
    put_turn(&server, turn, actor);
    let request = |token_budget: usize| {
        core_request_with_authz(
            "POST",
            "/v1/core/context-board",
            test_bearer(&format!(
                "scope=core:read,core:write;principal_ref={};actor_class=agent",
                actor.to_hex()
            )),
            Some(&json!({
                "standing": {"world_ref": world.to_hex(), "token_budget": token_budget},
                "turn": {"id": turn.to_hex()}
            })),
        )
    };

    let (status, refused) = route_json(server.clone(), request(64)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused:#}");
    assert_eq!(
        refused["error"]["message"], "session prefix and retrieval exceed the token budget",
        "{refused:#}"
    );
    assert_eq!(server.vault.board_turn_owner(&turn).unwrap(), None);

    let (status, board) = route_json(server.clone(), request(65_536)).await;
    assert_eq!(status, StatusCode::OK, "{board:#}");
    assert_eq!(board["board_turn"]["turn"], turn.to_hex());
}

/// Sol F4 (REV-9 D2a): a past board never re-grants a read. Once the reader
/// can no longer read a document its board selected, the board is refused
/// whole, not handed back from the history the turn recorded.
#[tokio::test]
async fn a_past_board_never_returns_a_document_its_reader_lost() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal = seeded_test_entity_id(0x2067_0401);
    let document = seeded_test_entity_id(0x2067_0402);
    cleared_reader(&server, principal, seeded_test_entity_id(0x2067_0403));
    put_person(&server, document, "revocable pin needle");
    let pin = pin_ref(&server, document, "revocable pin needle");
    let turn = seeded_test_entity_id(0x2067_0404);
    put_turn(&server, turn, principal);
    let (status, board) = route_json(
        server.clone(),
        hydrate(
            principal,
            "core:read,core:write",
            &json!({
                "retrieval": {"query": "unrelated empty query", "limit": 1},
                "memories": {"shared_total": 0, "pinned_refs": [pin]},
                "session": {"session_id": principal.to_hex()},
                "turn": {"id": turn.to_hex()}
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{board:#}");
    let (status, past) = route_json(server.clone(), history(turn, principal)).await;
    assert_eq!(status, StatusCode::OK, "{past:#}");
    assert_eq!(past["selection"]["pinned"], json!([document.to_hex()]));

    // The reader keeps its credential and the turn, and loses PERSON rows.
    restrict_principal_read_types(&server, principal, &[oneiron::registry::ENTITY_TYPE_TURN]);
    let (status, refused) = route_json(server.clone(), history(turn, principal)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused:#}");
    assert!(
        refused.to_string().contains("board_document_unreadable"),
        "{refused:#}"
    );
}

/// Sol F9 (REV-9 D2a): the board records under the caller's own verified
/// capability. A CLAIM the caller's slip reads, and the board serves, records
/// and reads back, where a proof-less key for the same principal is refused.
#[tokio::test]
async fn a_claim_board_records_under_the_callers_own_capability() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal = seeded_test_entity_id(0x2067_0501);
    let person = seeded_test_entity_id(0x2067_0502);
    server
        .vault
        .put_entity(
            &person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"reader person",
        )
        .unwrap();
    cleared_reader(&server, principal, seeded_test_entity_id(0x2067_0503));
    server
        .vault
        .put_edge(&principal, oneiron::EdgeKind::About, &person, 1.0)
        .unwrap();
    let claim = seeded_test_entity_id(0x2067_0504);
    let mut body = oneiron::ClaimBody::new(
        "profile.route_test",
        oneiron::ClaimSubject::Entity(person),
        rmpv::Value::from("served public pin"),
        0.9,
        oneiron::ClaimApprovalStatus::Auto,
        oneiron::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("sensitivity"),
        rmpv::Value::from("public"),
    )]));
    server
        .vault
        .put_claim(&claim, &body, oneiron::TimeRange { start: 10, end: 10 }, 10)
        .unwrap();
    let plain = server
        .vault
        .scoped_read(oneiron::claim::ScopedReadActorKey::new(principal.to_hex()).unwrap());
    assert!(!plain.is_entity_readable(&claim).unwrap());
    let pin = oneiron::retrieval_depth::short_ref_or_hex(&server.vault, &claim).unwrap();
    let turn = seeded_test_entity_id(0x2067_0505);
    put_turn(&server, turn, principal);

    let (status, board) = route_json(
        server.clone(),
        hydrate(
            principal,
            "core:read,core:write",
            &json!({
                "retrieval": {"query": "zzzzunrelatedpinquery", "limit": 1},
                "memories": {"shared_total": 0, "pinned_refs": [pin]},
                "session": {"session_id": "claim-pin"},
                "turn": {"id": turn.to_hex()}
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{board:#}");
    assert_eq!(
        board["board_turn"]["changed_claims"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let (status, past) = route_json(server.clone(), history(turn, principal)).await;
    assert_eq!(status, StatusCode::OK, "{past:#}");
    assert_eq!(past["selection"]["pinned"], json!([claim.to_hex()]));
    assert!(past["documents"].get(claim.to_hex()).is_some(), "{past:#}");
}

/// Sol F5 (REV-9 D2a): history keeps the revision the board served. A
/// document whose newer edit is not yet indexed is served at its indexed
/// revision, and the turn's board reads back that text, not the live edit.
#[tokio::test]
async fn a_turns_board_keeps_the_revision_it_served() {
    use base64::Engine as _;
    use oneiron::memory::ReadMode;
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal = seeded_test_entity_id(0x2067_0601);
    let person = seeded_test_entity_id(0x2067_0602);
    put_person(&server, person, "reader person");
    cleared_reader(&server, principal, seeded_test_entity_id(0x2067_0603));
    server
        .vault
        .put_edge(&principal, oneiron::EdgeKind::About, &person, 1.0)
        .unwrap();
    let document = seeded_test_entity_id(0x2067_0604);
    let put = |name: &str, at: u64| {
        let bytes = rmp_serde::to_vec_named(&json!({ "name": name })).unwrap();
        server
            .vault
            .batch()
            .put(
                &document,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: at, end: at },
                at,
                &bytes,
            )
            .text(&document, &[("name", name)])
            .commit()
            .unwrap();
    };
    put("revision needle oldalpha", 10);
    server.vault.set_indexed_idle_delay_ms(0).unwrap();
    server
        .vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .unwrap();
    let served = server.vault.indexed_revision(&document).unwrap().unwrap();
    // The edit stays unindexed for the rest of the test.
    server.vault.set_indexed_idle_delay_ms(u64::MAX).unwrap();
    put("revision needle newbeta", 20);
    assert_ne!(server.vault.pin_entity_revision(&document).unwrap(), served);
    assert_ne!(
        server
            .vault
            .get_raw_with_mode(&document, ReadMode::Live)
            .unwrap(),
        server
            .vault
            .get_raw_with_mode(&document, ReadMode::Indexed)
            .unwrap()
    );
    let turn = seeded_test_entity_id(0x2067_0605);
    put_turn(&server, turn, principal);

    let (status, board) = route_json(
        server.clone(),
        hydrate(
            principal,
            "core:read,core:write",
            &json!({
                "retrieval": {
                    "query": "oldalpha", "limit": 1,
                    "depth": {"edge_hop": 0, "max_neighbors": 0},
                    "policy": {"hydrate": true, "view": "full"},
                    "budget": {"retrieval": {
                        "claims": 0, "turns": 0, "summaries": 0, "facets": 0,
                        "other": 1, "selected_edges": 0
                    }}
                },
                "memories": {
                    "enabled": true,
                    "slots": {"claims": 0, "turns": 0, "summaries": 0,
                              "facets": 0, "companions": 0, "other": 1},
                    "shared_total": 1,
                    "pinned_refs": []
                },
                "session": {"session_id": "revision-served"},
                "turn": {"id": turn.to_hex()}
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{board:#}");
    let served_row = board["pack"]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == document.to_hex());
    assert!(served_row.is_some(), "the document is served: {board:#}");
    let served_row = served_row.unwrap();
    assert_eq!(served_row["fields"]["name"], "revision needle oldalpha");

    let (status, past) = route_json(server.clone(), history(turn, principal)).await;
    assert_eq!(status, StatusCode::OK, "{past:#}");
    assert_eq!(past["selection"]["top_snippet"], json!([document.to_hex()]));
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(past["documents"][document.to_hex()].as_str().unwrap())
        .unwrap();
    let recorded: Value = rmp_serde::from_slice(&bytes).unwrap();
    assert_eq!(recorded["name"], "revision needle oldalpha");
}

/// `principal`'s hydration that pins `pin` and names `turn`.
fn pin_board(principal: oneiron::EntityId, turn: oneiron::EntityId, pin: &str) -> Value {
    json!({
        "retrieval": {"query": "unrelated empty query", "limit": 1},
        "memories": {"shared_total": 0, "pinned_refs": [pin]},
        "session": {"session_id": principal.to_hex()},
        "turn": {"id": turn.to_hex()}
    })
}

/// Astra 1 (REV-9 D2a): a past board never re-discloses. It passes the
/// disclosure clamp a new board would apply now: once the owner marks a
/// document Tier A, or revokes the reader's clearance, the board that served
/// it is refused, though the reader keeps its credential and read grant.
#[tokio::test]
async fn a_past_board_never_discloses_what_its_reader_is_no_longer_cleared_for() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal = seeded_test_entity_id(0x2067_0701);
    cleared_reader(&server, principal, seeded_test_entity_id(0x2067_0702));
    let marked = seeded_test_entity_id(0x2067_0703);
    let kept = seeded_test_entity_id(0x2067_0704);
    put_person(&server, marked, "tier marked pin needle");
    put_person(&server, kept, "cleared pin needle");
    let marked_turn = seeded_test_entity_id(0x2067_0705);
    let kept_turn = seeded_test_entity_id(0x2067_0706);
    for (turn, document, query) in [
        (marked_turn, marked, "tier marked pin needle"),
        (kept_turn, kept, "cleared pin needle"),
    ] {
        put_turn(&server, turn, principal);
        let pin = pin_ref(&server, document, query);
        let (status, board) = route_json(
            server.clone(),
            hydrate(
                principal,
                "core:read,core:write",
                &pin_board(principal, turn, &pin),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{board:#}");
        let (status, past) = route_json(server.clone(), history(turn, principal)).await;
        assert_eq!(status, StatusCode::OK, "{past:#}");
        assert!(
            past["documents"].get(document.to_hex()).is_some(),
            "{past:#}"
        );
    }

    // The owner marks one document Tier A: only the board that served it is
    // withheld.
    server.vault.set_disclosure_tier_a(&marked, 300).unwrap();
    let (status, refused) = route_json(server.clone(), history(marked_turn, principal)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused:#}");
    assert!(
        refused.to_string().contains("board_document_unreadable"),
        "{refused:#}"
    );
    let (status, past) = route_json(server.clone(), history(kept_turn, principal)).await;
    assert_eq!(status, StatusCode::OK, "{past:#}");

    // The owner revokes the reader's clearance: every board it was served
    // goes with it.
    let mut revoked = oneiron::disclosure::DisclosureScope::new(
        oneiron::federation::Scope::top(),
        "party planning",
        400,
    )
    .unwrap();
    revoked.status = oneiron::disclosure::DisclosureScopeStatus::Revoked;
    server
        .vault
        .set_counterparty_disclosure_scope(&principal, &revoked)
        .unwrap();
    let (status, refused) = route_json(server.clone(), history(kept_turn, principal)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused:#}");
    assert!(
        refused.to_string().contains("board_document_unreadable"),
        "{refused:#}"
    );
}

/// Astra 3 (REV-9 D2a): a hydration that records its TURN is a keyed
/// mutation. A retry under the same `Idempotency-Key`, after a lost response,
/// replays the first success, where an unkeyed retry meets the recorded turn.
/// A hydration that names no TURN stays a read the key never caches.
#[tokio::test]
async fn a_keyed_board_turn_retry_replays_its_first_success() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal = seeded_test_entity_id(0x2067_0801);
    cleared_reader(&server, principal, seeded_test_entity_id(0x2067_0802));
    let document = seeded_test_entity_id(0x2067_0803);
    put_person(&server, document, "retried pin needle");
    let pin = pin_ref(&server, document, "retried pin needle");
    let turn = seeded_test_entity_id(0x2067_0804);
    put_turn(&server, turn, principal);
    let keyed = |key: &'static str, body: &Value| {
        let mut request = hydrate(principal, "core:read,core:write", body);
        request
            .headers_mut()
            .insert("Idempotency-Key", axum::http::HeaderValue::from_static(key));
        request
    };

    let body = pin_board(principal, turn, &pin);
    let (status, first) = route_json(server.clone(), keyed("board-turn-retry", &body)).await;
    assert_eq!(status, StatusCode::OK, "{first:#}");
    assert_eq!(first["board_turn"]["turn"], turn.to_hex());
    let (status, retried) = route_json(server.clone(), keyed("board-turn-retry", &body)).await;
    assert_eq!(status, StatusCode::OK, "{retried:#}");
    assert_eq!(retried, first);
    let (status, unkeyed) = route_json(
        server.clone(),
        hydrate(principal, "core:read,core:write", &body),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{unkeyed:#}");
    assert!(
        unkeyed.to_string().contains("board_turn_already_recorded"),
        "{unkeyed:#}"
    );

    // No TURN: two different reads under one key both run.
    for query in ["first keyed read", "second keyed read"] {
        let read = json!({
            "retrieval": {"query": query, "limit": 1},
            "session": {"session_id": "keyed-read"}
        });
        let (status, board) = route_json(server.clone(), keyed("board-read", &read)).await;
        assert_eq!(status, StatusCode::OK, "{board:#}");
        assert!(board.get("board_turn").is_none(), "{board:#}");
    }
}
