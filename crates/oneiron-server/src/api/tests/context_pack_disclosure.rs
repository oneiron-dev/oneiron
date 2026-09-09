//! Context-pack telemetry, interlocutor echo/stamps, owner-absence clamping, scope-smuggling resistance.

use super::*;

#[tokio::test]
async fn context_pack_route_returns_pack_evidence_and_records_telemetry() {
    let (_dir, server) = test_server();
    let (batch_status, batch_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/batch",
            json!({
                "entities": [{
                    "entity_type": ENTITY_TYPE_TURN,
                    "learned_at": 500_u64,
                    "occurred_start": 500_u64,
                    "occurred_end": 500_u64,
                    "body": {
                        "txt": "public context pack evidence needle",
                        "spkr": "user",
                        "at": 500_u64
                    },
                    "text": [{ "field": "body", "value": "public context pack evidence needle" }]
                }]
            }),
        ),
    )
    .await;
    assert_eq!(batch_status, StatusCode::OK);
    let id = batch_body["entities"][0]["id"]
        .as_str()
        .expect("written id")
        .to_owned();

    let (status, body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "evidence needle",
                "limit": 5,
                "depth": { "edge_hop": 1, "max_neighbors": 5 },
                "policy": {
                    "hydrate": true,
                    "include_edges": true,
                    "view": "full",
                    "boost_confidence": true
                },
                "time": { "occurred_start": 500_u64, "occurred_end": 500_u64 },
                "budget": {
                    "max_item_tokens": 64,
                    "retrieval": {
                        "claims": 0,
                        "turns": 1,
                        "summaries": 0,
                        "facets": 0,
                        "other": 0,
                        "selected_edges": 5
                    }
                }
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["results"][0]["id"], Value::from(id.clone()));
    assert_eq!(body["state"]["kind"], Value::from("ok"));
    assert_eq!(body["evidence"]["telemetry_persisted"], Value::from(true));
    assert_eq!(
        body["evidence"]["result_ids"],
        Value::Array(vec![Value::from(id.clone())])
    );
    assert_eq!(body["evidence"]["scores"][0]["result_id"], Value::from(id));
    assert_eq!(
        body["evidence"]["scores"][0]["access_factor"],
        Value::from(1.0),
        "HTTP score evidence must expose the applied neutral factor"
    );
    assert_eq!(
        body["evidence"]["scores"][0]["components"][0]["signal"],
        Value::from("text")
    );

    let runs = server.vault.retrieval_runs(1).expect("retrieval runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(
        runs[0].run_id.to_hex(),
        body["evidence"]["retrieval_run_id"]
    );
    assert_eq!(runs[0].action, oneiron::store::RetrievalAction::ContextPack);
}

#[tokio::test]
async fn core_context_pack_owner_present_true_on_scoped_bearer_is_forbidden() {
    let (_dir, server) = interlocutor_test_server();
    let principal_ref = seeded_test_entity_id(0x1516_0001).to_hex();
    let request = json!({
        "query": "hallway",
        "interlocutors": { "owner_present": true }
    });
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref,
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        body["error"]["details"]["requiredScope"],
        Value::from("interlocutors.owner_present")
    );
    assert!(
        body.get("results").is_none(),
        "nothing is assembled on the forbidden path"
    );
}

#[tokio::test]
async fn core_context_pack_owner_session_without_block_carries_no_interlocutors_field() {
    let (_dir, server) = interlocutor_test_server();
    seed_turn(&server, "owner alone regression needle");
    let request = json!({ "query": "regression needle", "limit": 3 });
    let (status, body) = owner_json(
        server.clone(),
        "POST",
        "/v1/core/context-pack",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("interlocutors").is_none(),
        "owner-grade auth with no block must stay byte-identical: {body:?}"
    );

    // The same request on a scope-narrowed token is NOT the owner-grade path:
    // a delegated credential resolves an interlocutor set and gets echoed
    // stamps even though it carries no principal_ref.
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("interlocutors").is_some(),
        "a scope-narrowed token is not owner-grade: {body:?}"
    );
}

#[tokio::test]
async fn core_context_pack_echoes_stamps_for_supplied_block_on_owner_session() {
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x1516_0011);
    let contact_id = seeded_test_entity_id(0x1516_0012);
    seed_counterparty_contact(&server, contact_id, identity_ref, "kenji@example.com");

    let request = json!({
        "query": "hallway",
        "interlocutors": {
            "third_parties": [
                { "contact_ref": contact_id.to_hex() },
                {
                    "channel_identity_ref": identity_ref.to_hex(),
                    "counterparty": "stranger@example.com"
                },
                { "label": "unknown speaker 2", "claimed_owner": true }
            ]
        }
    });
    let (status, body) = owner_json(server, "POST", "/v1/core/context-pack", Some(&request)).await;
    assert_eq!(status, StatusCode::OK);
    let stamps = body["interlocutors"].as_array().expect("stamps echoed");
    assert_eq!(stamps.len(), 4);
    for (speaker, class, claims_not_instructions) in [
        ("owner".to_owned(), "owner", false),
        (contact_id.to_hex(), "known_contact", true),
        ("stranger@example.com".to_owned(), "unknown", true),
        ("unknown speaker 2".to_owned(), "unknown", true),
    ] {
        let stamp = stamps
            .iter()
            .find(|stamp| stamp["speaker"].as_str() == Some(speaker.as_str()))
            .expect("speaker stamp");
        assert_eq!(stamp["class"], Value::from(class));
        assert_eq!(
            stamp["claims_not_instructions"],
            Value::from(claims_not_instructions),
        );
    }
}

#[tokio::test]
async fn core_context_pack_owner_present_false_narrows_owner_session() {
    let (_dir, server) = interlocutor_test_server();
    let request = json!({
        "query": "hallway",
        "interlocutors": {
            "owner_present": false,
            "third_parties": [{ "label": "guest", "claimed_owner": true }]
        }
    });
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let stamps = body["interlocutors"].as_array().expect("stamps echoed");
    assert_eq!(stamps.len(), 1, "narrowing removes the owner entry");
    assert_eq!(stamps[0]["speaker"], Value::from("guest"));
    assert_eq!(stamps[0]["class"], Value::from("unknown"));
    assert_eq!(stamps[0]["claims_not_instructions"], Value::from(true));
}

#[tokio::test]
async fn core_context_pack_scoped_bearer_gets_implicit_interlocutor_echo() {
    let (_dir, server) = interlocutor_test_server();

    // Companion-style principal with no contact row -> one Unknown stamp
    // labeled with the principal hex.
    let unknown_principal = seeded_test_entity_id(0x1516_0021).to_hex();
    let request = json!({ "query": "hallway" });
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &unknown_principal,
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let stamps = body["interlocutors"].as_array().expect("implicit echo");
    assert_eq!(stamps.len(), 1);
    assert_eq!(stamps[0]["speaker"], Value::from(unknown_principal.clone()));
    assert_eq!(stamps[0]["class"], Value::from("unknown"));
    assert_eq!(stamps[0]["claims_not_instructions"], Value::from(true));

    // A principal whose entity id IS a contact row -> KnownContact stamp.
    let identity_ref = seeded_test_entity_id(0x1516_0022);
    let contact_principal = seeded_test_entity_id(0x1516_0023);
    seed_counterparty_contact(
        &server,
        contact_principal,
        identity_ref,
        "kenji@example.com",
    );
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &contact_principal.to_hex(),
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let stamps = body["interlocutors"].as_array().expect("implicit echo");
    assert_eq!(stamps.len(), 1);
    assert_eq!(
        stamps[0]["speaker"],
        Value::from(contact_principal.to_hex())
    );
    assert_eq!(stamps[0]["class"], Value::from("known_contact"));
    assert_eq!(stamps[0]["claims_not_instructions"], Value::from(true));
}

#[tokio::test]
async fn core_context_pack_scoped_bearer_merges_principal_with_supplied_block() {
    // N14 (shape level, RATIFY-20260710 R8 merge-always): a scoped token
    // naming a wider-scoped contact gets BOTH operands into the resolved
    // set — the supplied block can never displace the principal party.
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x1516_0031);
    let wider_contact = seeded_test_entity_id(0x1516_0032);
    seed_counterparty_contact(&server, wider_contact, identity_ref, "wider@example.com");
    let principal_ref = seeded_test_entity_id(0x1516_0033).to_hex();

    let request = json!({
        "query": "hallway",
        "interlocutors": {
            "third_parties": [{ "contact_ref": wider_contact.to_hex() }]
        }
    });
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref,
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let stamps = body["interlocutors"].as_array().expect("merged echo");
    assert_eq!(
        stamps.len(),
        2,
        "both the supplied contact and the implicit principal party resolve",
    );
    for (speaker, class) in [
        (wider_contact.to_hex(), "known_contact"),
        (principal_ref, "unknown"),
    ] {
        let stamp = stamps
            .iter()
            .find(|stamp| stamp["speaker"].as_str() == Some(speaker.as_str()))
            .expect("merged speaker stamp");
        assert_eq!(stamp["class"], Value::from(class));
    }
    assert!(
        stamps.iter().all(|stamp| stamp["class"] != "owner"),
        "no owner entry on a scoped token",
    );
}

#[tokio::test]
async fn core_context_pack_rejects_malformed_interlocutor_parties() {
    let (_dir, server) = interlocutor_test_server();
    let contact_hex = seeded_test_entity_id(0x1516_0041).to_hex();

    let cases = [
        (
            json!({ "contact_ref": contact_hex, "label": "guest" }),
            "interlocutors.third_parties[0]",
        ),
        (json!({}), "interlocutors.third_parties[0]"),
        (
            json!({ "contact_ref": "not-hex" }),
            "interlocutors.third_parties[0].contact_ref",
        ),
        (
            json!({ "channel_identity_ref": contact_hex }),
            "interlocutors.third_parties[0]",
        ),
        (
            json!({ "channel_identity_ref": contact_hex, "counterparty": "  " }),
            "interlocutors.third_parties[0].counterparty",
        ),
        (
            json!({ "channel_identity_ref": contact_hex, "counterparty": " kenji@example.com " }),
            "interlocutors.third_parties[0].counterparty",
        ),
        (
            json!({ "channel_identity_ref": contact_hex, "counterparty": "k".repeat(513) }),
            "interlocutors.third_parties[0].counterparty",
        ),
        (
            json!({ "label": "   " }),
            "interlocutors.third_parties[0].label",
        ),
        (
            json!({ "label": "l".repeat(513) }),
            "interlocutors.third_parties[0].label",
        ),
        (
            json!({ "contact_ref": contact_hex, "claimed_owner": true }),
            "interlocutors.third_parties[0].claimed_owner",
        ),
    ];
    for (party, expected_field) in cases {
        let request = json!({
            "query": "hallway",
            "interlocutors": { "third_parties": [party.clone()] }
        });
        let (status, body) = core_json(
            server.clone(),
            "POST",
            "/v1/core/context-pack",
            "core:read",
            Some(&request),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "party {party:?}");
        assert_error_envelope(&body, "BAD_REQUEST");
        assert_eq!(
            body["error"]["details"]["field"],
            Value::from(expected_field),
            "party {party:?}"
        );
    }
}

#[tokio::test]
async fn core_context_pack_owner_absent_happy_path_clamps_to_scope() {
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x1517_0001);
    let contact_principal = seeded_test_entity_id(0x1517_0002);
    seed_counterparty_contact(
        &server,
        contact_principal,
        identity_ref,
        "kenji@example.com",
    );
    let party = seed_text_turn(&server, "hanami party planning needle17");
    let diary = seed_text_turn(&server, "private diary entry needle17");
    seed_disclosure_scope(&server, contact_principal, vec![party]);

    // Scoped bearer whose principal IS the contact row; no block (N13 shape
    // with a real scope). AbsenceClamp admits only the allowlisted party.
    let request = json!({ "query": "needle17", "limit": 10 });
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &contact_principal.to_hex(),
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["disclosure"]["mode"], Value::from("absence_clamp"));
    assert!(
        body["disclosure"]["notice"].is_null(),
        "notice is Some iff supervised"
    );
    assert!(
        body["disclosure"]["clamped_out"].as_u64().unwrap_or(0) > 0,
        "candidate sweep counted removals: {body:?}"
    );
    let result_ids: Vec<&str> = body["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter_map(|entity| entity["id"].as_str())
        .collect();
    assert!(result_ids.contains(&party.to_hex().as_str()));
    assert!(
        !result_ids.contains(&diary.to_hex().as_str()),
        "out-of-scope Tier-B memory absent from the assembled context"
    );
    let neighbors = body["neighbors"].as_array().expect("neighbors");
    assert!(neighbors.is_empty());
    let stamps = body["disclosure"]["interlocutors"]
        .as_array()
        .expect("stamps");
    assert_eq!(stamps.len(), 1);
    assert_eq!(stamps[0]["class"], Value::from("known_contact"));
}

#[tokio::test]
async fn core_context_pack_supervised_path_carries_notice_and_tier_b() {
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x1517_0011);
    let contact_id = seeded_test_entity_id(0x1517_0012);
    seed_counterparty_contact(&server, contact_id, identity_ref, "kenji@example.com");
    let diary = seed_text_turn(&server, "tier b memory needle18");

    let request = json!({
        "query": "needle18",
        "interlocutors": {
            "owner_present": true,
            "third_parties": [{ "contact_ref": contact_id.to_hex() }]
        }
    });
    // Supervised mode requires an owner-grade credential: `owner_present:
    // true` is a 403 on any narrowed token.
    let (status, body) = owner_json(server, "POST", "/v1/core/context-pack", Some(&request)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["disclosure"]["mode"], Value::from("supervised"));
    let notice = body["disclosure"]["notice"].as_str().expect("notice");
    assert!(!notice.trim().is_empty(), "disclosure warning is present");
    let stamps = body["interlocutors"]
        .as_array()
        .expect("participant stamps");
    for (speaker, class) in [
        ("owner".to_owned(), "owner"),
        (contact_id.to_hex(), "known_contact"),
    ] {
        let stamp = stamps
            .iter()
            .find(|stamp| stamp["speaker"].as_str() == Some(speaker.as_str()))
            .expect("present participant");
        assert_eq!(stamp["class"], Value::from(class));
    }
    let diary_id = diary.to_hex();
    let found = body["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter_map(|entity| entity["id"].as_str())
        .any(|id| id == diary_id);
    assert!(found, "supervised mode keeps Tier B present");
}

#[tokio::test]
async fn core_context_pack_n4_spoofed_owner_claim_stays_absence_clamped() {
    let (_dir, server) = interlocutor_test_server();
    let diary = seed_text_turn(&server, "tier b memory needle19");

    // Owner-grade auth narrows itself away; the only party is a spoofed
    // "it's me" claim. The claim is a label, never authority (I3/I4).
    let request = json!({
        "query": "needle19",
        "interlocutors": {
            "owner_present": false,
            "third_parties": [{ "label": "it's me", "claimed_owner": true }]
        }
    });
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["disclosure"]["mode"], Value::from("absence_clamp"));
    let stamps = body["disclosure"]["interlocutors"]
        .as_array()
        .expect("stamps");
    assert_eq!(stamps.len(), 1);
    assert_eq!(stamps[0]["speaker"], Value::from("it's me"));
    assert_eq!(stamps[0]["class"], Value::from("unknown"));
    assert!(
        body["results"].as_array().expect("results").is_empty(),
        "unknown party gets the deny-all scope: {diary:?} must not surface"
    );
}

#[tokio::test]
async fn core_context_pack_n5_voice_session_seam_cannot_widen() {
    // The ILD-3 roster seam is accepted but inert: a voice_session_ref with
    // no session owner resolves to no roster entries and stays AbsenceClamp.
    // The enrolled-print corroboration case (owner_print_matched) lands with
    // ONE-1518 and can never mint an Owner entry by construction.
    let (_dir, server) = interlocutor_test_server();
    seed_text_turn(&server, "tier b memory needle20");

    let request = json!({
        "query": "needle20",
        "interlocutors": {
            "owner_present": false,
            "third_parties": [{ "label": "speaker 1", "claimed_owner": false }],
            "voice_session_ref": "call-123"
        }
    });
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["disclosure"]["mode"], Value::from("absence_clamp"));
    assert!(body["results"].as_array().expect("results").is_empty());
}

#[tokio::test]
async fn core_context_pack_n9_scope_smuggling_members_are_ignored() {
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x1517_0021);
    let contact_id = seeded_test_entity_id(0x1517_0022);
    seed_counterparty_contact(&server, contact_id, identity_ref, "kenji@example.com");
    let party = seed_text_turn(&server, "party event needle21");
    let diary = seed_text_turn(&server, "private diary needle21");
    seed_disclosure_scope(&server, contact_id, vec![party]);

    let clean = json!({
        "query": "needle21",
        "interlocutors": {
            "owner_present": false,
            "third_parties": [{ "contact_ref": contact_id.to_hex() }]
        }
    });
    // No request field can name scope entities; smuggled members fall to
    // serde's ignored-unknown-fields floor and change nothing.
    let smuggled = json!({
        "query": "needle21",
        "interlocutors": {
            "owner_present": false,
            "third_parties": [{ "contact_ref": contact_id.to_hex() }],
            "scope": { "entities": [diary.to_hex()] },
            "entities": [diary.to_hex()]
        }
    });
    let (clean_status, clean_body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&clean),
    )
    .await;
    let (smuggled_status, smuggled_body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&smuggled),
    )
    .await;
    assert_eq!(clean_status, StatusCode::OK);
    assert_eq!(smuggled_status, StatusCode::OK);
    let party_id = party.to_hex();
    let diary_id = diary.to_hex();
    let contact_ref = contact_id.to_hex();
    for body in [&clean_body, &smuggled_body] {
        let results = body["results"].as_array().expect("results");
        assert!(
            results
                .iter()
                .any(|entity| entity["id"].as_str() == Some(party_id.as_str())),
            "stored scope admits the party memory",
        );
        assert!(
            results
                .iter()
                .all(|entity| entity["id"].as_str() != Some(diary_id.as_str())),
            "request fields cannot admit the out-of-scope diary",
        );
        let mode = body["disclosure"]["mode"]
            .as_str()
            .expect("disclosure mode");
        assert!(!mode.is_empty());
        assert_ne!(mode, "supervised");
        let stamps = body["interlocutors"]
            .as_array()
            .expect("participant stamps");
        let contact = stamps
            .iter()
            .find(|stamp| stamp["speaker"].as_str() == Some(contact_ref.as_str()))
            .expect("scope-bearing contact");
        assert_eq!(contact["class"], Value::from("known_contact"));
        assert_eq!(contact["claims_not_instructions"], Value::from(true));
        assert!(stamps.iter().all(|stamp| stamp["class"] != "owner"));
    }
    assert_eq!(
        clean_body["disclosure"]["mode"], smuggled_body["disclosure"]["mode"],
        "smuggled members cannot change disclosure mode",
    );
}

#[tokio::test]
async fn core_context_pack_n13_scoped_token_defaults_to_absence_clamp() {
    let (_dir, server) = interlocutor_test_server();
    let diary = seed_text_turn(&server, "tier b memory needle22");
    let principal_ref = seeded_test_entity_id(0x1517_0031).to_hex();

    let request = json!({ "query": "needle22", "limit": 10 });
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref,
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["disclosure"]["mode"],
        Value::from("absence_clamp"),
        "principal_ref tokens with no block assemble under AbsenceClamp"
    );
    let result_ids: Vec<&str> = body["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter_map(|entity| entity["id"].as_str())
        .collect();
    assert!(
        !result_ids.contains(&diary.to_hex().as_str()),
        "N1-style assertion: Tier-B memory absent for an unknown principal"
    );
    assert!(result_ids.is_empty());
}

#[tokio::test]
async fn core_context_pack_n14_wider_scoped_contact_cannot_widen_scoped_token() {
    // CONTENT-level N14 (RATIFY-20260710 R8): a bearer scoped to X naming a
    // wider-scoped contact Y resolves {X ∩ Y} — no Tier-B data readable via
    // the wider-scoped contact.
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x1517_0041);
    let wider_contact = seeded_test_entity_id(0x1517_0042);
    seed_counterparty_contact(&server, wider_contact, identity_ref, "wider@example.com");
    let party = seed_text_turn(&server, "party event needle23");
    seed_disclosure_scope(&server, wider_contact, vec![party]);
    // Principal X has no contact row: it contributes the deny-all scope.
    let principal_ref = seeded_test_entity_id(0x1517_0043).to_hex();

    let request = json!({
        "query": "needle23",
        "interlocutors": {
            "third_parties": [{ "contact_ref": wider_contact.to_hex() }]
        }
    });
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref,
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["disclosure"]["mode"], Value::from("absence_clamp"));
    let stamps = body["disclosure"]["interlocutors"]
        .as_array()
        .expect("stamps");
    assert_eq!(stamps.len(), 2, "both operands enter the resolved set");
    assert!(
        body["results"].as_array().expect("results").is_empty(),
        "deny-all ∩ wider scope = nothing readable: {body:?}"
    );
}

#[tokio::test]
async fn core_context_pack_owner_auth_without_block_carries_no_disclosure_field() {
    let (_dir, server) = interlocutor_test_server();
    seed_text_turn(&server, "owner alone regression needle24");
    let request = json!({ "query": "needle24", "limit": 3 });
    let (status, body) = owner_json(server, "POST", "/v1/core/context-pack", Some(&request)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("disclosure").is_none(),
        "owner-grade auth with no block stays byte-identical: {body:?}"
    );
    assert!(
        !body["results"].as_array().expect("results").is_empty(),
        "owner-alone behavior unchanged"
    );
}

/// P1 regression (`l1-r2-verdicts`): a v2 token narrowed by SCOPE ALONE — no
/// `principal_ref` — is a delegated read-only credential, not the owner.
///
/// The old `is_owner_session` predicate read only `principal_ref.is_none()`,
/// so this token classified as owner-present: `resolve_core_interlocutor_set`
/// returned `None` and NO absence clamp applied, handing a delegated bearer
/// the owner's full Tier-B vault. Both halves of the fix are pinned here: the
/// clamp now applies, and `owner_present: true` is refused.
#[tokio::test]
async fn core_context_pack_scope_only_token_is_clamped_and_cannot_assert_owner_present() {
    let (_dir, server) = interlocutor_test_server();
    let diary = seed_text_turn(&server, "tier b memory needle25");
    let request = json!({ "query": "needle25", "limit": 10 });

    // The owner-grade credential still reads its own vault, unclamped.
    let (status, owner_body) = owner_json(
        server.clone(),
        "POST",
        "/v1/core/context-pack",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(owner_body.get("disclosure").is_none());
    let diary_id = diary.to_hex();
    assert!(
        owner_body["results"]
            .as_array()
            .expect("results")
            .iter()
            .filter_map(|entity| entity["id"].as_str())
            .any(|id| id == diary_id),
        "owner-grade verdict unchanged: {owner_body:?}"
    );

    // The same request on `scope=core:read` with NO principal_ref takes the
    // absence clamp. No party is identified, so the deny-all scope applies.
    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["disclosure"]["mode"],
        Value::from("absence_clamp"),
        "an unbound scoped token must receive the clamp: {body:?}"
    );
    assert!(
        body["results"].as_array().expect("results").is_empty(),
        "Tier-B memory must not reach a delegated read-only token: {body:?}"
    );

    // ...and it cannot buy the supervised path back by asserting presence.
    let asserted = json!({
        "query": "needle25",
        "limit": 10,
        "interlocutors": { "owner_present": true }
    });
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&asserted),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        body["error"]["details"]["requiredScope"],
        Value::from("interlocutors.owner_present")
    );
}

#[tokio::test]
async fn core_context_pack_caps_the_third_parties_block() {
    let (_dir, server) = interlocutor_test_server();

    let party = |index: usize| json!({ "label": format!("guest {index}") });
    let at_cap: Vec<Value> = (0..MAX_INTERLOCUTOR_THIRD_PARTIES).map(party).collect();
    let over_cap: Vec<Value> = (0..=MAX_INTERLOCUTOR_THIRD_PARTIES).map(party).collect();

    let request = json!({
        "query": "hallway",
        "interlocutors": { "third_parties": at_cap }
    });
    let (status, body) = owner_json(
        server.clone(),
        "POST",
        "/v1/core/context-pack",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "at-cap block accepted: {body:?}");
    assert_eq!(
        body["interlocutors"].as_array().map(Vec::len),
        Some(MAX_INTERLOCUTOR_THIRD_PARTIES + 1),
        "owner stamp plus every supplied party"
    );

    let request = json!({
        "query": "hallway",
        "interlocutors": { "third_parties": over_cap }
    });
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        body["error"]["details"]["field"],
        Value::from("interlocutors.third_parties")
    );
}

#[tokio::test]
async fn core_context_pack_dangling_contact_ref_fails_loudly() {
    let (_dir, server) = interlocutor_test_server();
    let request = json!({
        "query": "hallway",
        "interlocutors": {
            "third_parties": [
                { "contact_ref": seeded_test_entity_id(0x1516_0051).to_hex() }
            ]
        }
    });
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_error_envelope(&body, "NOT_FOUND");
}
