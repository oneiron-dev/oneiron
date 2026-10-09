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
    put_person(&server, principal, "board owner");
    put_person(&server, first, "first pin needle");
    put_person(&server, second, "second pin needle");
    let refs = [
        pin_ref(&server, first, "first pin needle"),
        pin_ref(&server, second, "second pin needle"),
    ];
    let turns: Vec<_> = (0..3)
        .map(|n| {
            let turn = seeded_test_entity_id(0x2067_0010 + n);
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
            turn
        })
        .collect();

    let mut changed = Vec::new();
    for (turn, pin) in turns.iter().zip([&refs[0], &refs[1], &refs[1]]) {
        let (status, board) = route_json(
            server.clone(),
            core_request_with_principal_ref(
                "POST",
                "/v1/core/context-board",
                "core:read,core:write",
                &principal.to_hex(),
                Some(&json!({
                    "retrieval": {"query": "unrelated empty query", "limit": 1},
                    "memories": {"shared_total": 0, "pinned_refs": [pin]},
                    "session": {"session_id": principal.to_hex()},
                    "turn": {"id": turn.to_hex()}
                })),
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

    let history = |turn: oneiron::EntityId, reader: oneiron::EntityId| {
        route_json(
            server.clone(),
            core_request_with_principal_ref(
                "GET",
                &format!("/v1/core/context-board/turns/{}", turn.to_hex()),
                "core:read",
                &reader.to_hex(),
                None,
            ),
        )
    };
    for (turn, pinned) in [(turns[0], first), (turns[1], second), (turns[2], second)] {
        let (status, board) = history(turn, principal).await;
        assert_eq!(status, StatusCode::OK, "{board:#}");
        assert_eq!(board["selection"]["pinned"], json!([pinned.to_hex()]));
        assert!(
            board["documents"].get(pinned.to_hex()).is_some(),
            "{board:#}"
        );
    }
    let (status, _) = history(turns[0], first).await;
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
