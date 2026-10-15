//! Context-pack telemetry, interlocutor echo/stamps, owner-absence clamping, scope-smuggling resistance.

use super::*;
use oneiron::federation::{ScopeAxis, ScopeId};

#[tokio::test]
async fn context_pack_route_returns_pack_evidence_and_records_telemetry() {
    let (_dir, server) = auth_test_server();
    let (batch_status, batch_body) = route_json_auth(
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

    let (status, body) = route_json_auth(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/context-pack",
            owner_bearer(),
            Some(&json!({
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
            })),
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
    // A base-world claim leaves capacity for the other-world claim under the
    // context pack's non-base-world claim fraction.
    let base_claim = seed_disclosure_claim_in_world(
        &server,
        party,
        "party details needle17",
        oneiron::claim::base_world_id(),
    );
    let diary_world = seeded_test_entity_id(0x1517_00f1);
    let diary =
        seed_disclosure_claim_in_world(&server, party, "private diary entry needle17", diary_world);
    seed_disclosure_scope(
        &server,
        contact_principal,
        disclosure_base_world_clearance(),
    );

    // Scoped bearer whose principal IS the contact row; no block (N13 shape
    // with a base-world clearance). AbsenceClamp excludes the other-world claim.
    let request = json!({ "query": "needle17", "limit": 10 });
    let call = || {
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &contact_principal.to_hex(),
            Some(&request),
        )
    };
    let (status, body) = route_json(server.clone(), call()).await;
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
    assert!(result_ids.contains(&base_claim.to_hex().as_str()));
    assert!(
        !result_ids.contains(&diary.to_hex().as_str()),
        "out-of-world Tier-B claim absent from the assembled context"
    );
    let neighbors = body["neighbors"].as_array().expect("neighbors");
    assert!(neighbors.is_empty());
    let stamps = body["disclosure"]["interlocutors"]
        .as_array()
        .expect("stamps");
    assert_eq!(stamps.len(), 1);
    assert_eq!(stamps[0]["class"], Value::from("known_contact"));

    // Keep the stored Tier-B claim unchanged. Widen only this contact's world
    // clearance, then prove the previously excluded claim is retrievable.
    let mut widened = disclosure_base_world_clearance();
    widened.worlds = ScopeAxis::Some(
        [
            ScopeId(oneiron::claim::base_world_id()),
            ScopeId(diary_world),
        ]
        .into(),
    );
    seed_disclosure_scope(&server, contact_principal, widened);
    let (status, widened_body) = route_json(server, call()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        widened_body["disclosure"]["mode"],
        Value::from("absence_clamp")
    );
    assert!(
        widened_body["results"]
            .as_array()
            .expect("widened results")
            .iter()
            .any(|entity| entity["id"].as_str() == Some(diary.to_hex().as_str())),
        "the same Tier-B claim is admitted by the wider world clearance: {widened_body:?}"
    );
}

#[tokio::test]
async fn core_context_pack_supervised_path_carries_notice_and_tier_b() {
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x1517_0011);
    let contact_id = seeded_test_entity_id(0x1517_0012);
    seed_counterparty_contact(&server, contact_id, identity_ref, "kenji@example.com");
    // Owner presence never widens a guest's clearance; this one admits tier B.
    server
        .vault
        .set_counterparty_disclosure_scope(
            &contact_id,
            &oneiron::disclosure::DisclosureScope::new(
                oneiron::federation::Scope::top(),
                "supervised tier b",
                101,
            )
            .expect("clearance"),
        )
        .expect("clear the contact");
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
    assert!(found, "supervised mode keeps cleared Tier B present");
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
async fn core_context_pack_n9_scope_smuggling_members_are_ignored() {
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x1517_0021);
    let contact_id = seeded_test_entity_id(0x1517_0022);
    seed_counterparty_contact(&server, contact_id, identity_ref, "kenji@example.com");
    let party = seed_text_turn(&server, "party event needle21");
    let base_claim = seed_disclosure_claim_in_world(
        &server,
        party,
        "party details needle21",
        oneiron::claim::base_world_id(),
    );
    let diary_world = seeded_test_entity_id(0x1517_00f2);
    let diary =
        seed_disclosure_claim_in_world(&server, party, "private diary needle21", diary_world);
    seed_disclosure_scope(&server, contact_id, disclosure_base_world_clearance());

    let clean = json!({
        "query": "needle21",
        "interlocutors": {
            "owner_present": false,
            "third_parties": [{ "contact_ref": contact_id.to_hex() }]
        }
    });
    // Request fields cannot widen stored world clearance; smuggled fields fall
    // to serde's ignored-unknown-fields floor and change nothing.
    let smuggled = json!({
        "query": "needle21",
        "interlocutors": {
            "owner_present": false,
            "third_parties": [{ "contact_ref": contact_id.to_hex() }],
            "scope": { "worlds": [seeded_test_entity_id(0x1517_00f2).to_hex()] },
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
        server.clone(),
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
            "TURN-band scope admits the party memory",
        );
        assert!(
            results
                .iter()
                .any(|entity| entity["id"].as_str() == Some(base_claim.to_hex().as_str())),
            "base-world Tier-B claim reaches the same disclosure door",
        );
        assert!(
            results
                .iter()
                .all(|entity| entity["id"].as_str() != Some(diary_id.as_str())),
            "request fields cannot admit the out-of-world diary",
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

    // The stored diary is Tier B and can surface when the contact actually
    // widens its world clearance, rather than via caller-supplied scope fields.
    let mut widened = disclosure_base_world_clearance();
    widened.worlds = ScopeAxis::Some(
        [
            ScopeId(oneiron::claim::base_world_id()),
            ScopeId(diary_world),
        ]
        .into(),
    );
    seed_disclosure_scope(&server, contact_id, widened);
    let (status, widened_body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&clean),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        widened_body["results"]
            .as_array()
            .expect("widened results")
            .iter()
            .any(|entity| entity["id"].as_str() == Some(diary_id.as_str())),
        "widening the contact's world clearance admits the same diary: {widened_body:?}"
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
    seed_disclosure_scope(&server, wider_contact, disclosure_base_world_clearance());
    // Principal X has no contact row: it contributes the deny-all scope.
    let principal_ref = seeded_test_entity_id(0x1517_0043).to_hex();

    let request = json!({
        "query": "needle23",
        "interlocutors": {
            "third_parties": [{ "contact_ref": wider_contact.to_hex() }]
        }
    });
    let (wide_status, wide_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &wider_contact.to_hex(),
            Some(&request),
        ),
    )
    .await;
    assert_eq!(wide_status, StatusCode::OK);
    assert!(
        wide_body["results"]
            .as_array()
            .expect("wider results")
            .iter()
            .any(|row| row["id"] == party.to_hex()),
        "contact clearance alone must admit the party, so X ∩ Y is asymmetric: {wide_body:?}"
    );

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

async fn room_owner_json(
    server: std::sync::Arc<SyncServer>,
    owner: oneiron::EntityId,
    request: &Value,
) -> (StatusCode, Value) {
    route_json(
        server,
        core_request_with_authz(
            "POST",
            "/v1/core/context-pack",
            test_bearer(&format!(
                "principal_ref={};actor_class=human",
                owner.to_hex()
            )),
            Some(request),
        ),
    )
    .await
}

#[tokio::test]
async fn roster_room_applies_each_members_disclosure_dial_and_owner_presence() {
    let (_dir, server) = interlocutor_test_server();
    let owner = seeded_test_entity_id(0x2094_0101);
    let peer = seeded_test_entity_id(0x2094_0102);
    for person in [owner, peer] {
        server
            .vault
            .put_entity(
                &person,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"room member",
            )
            .expect("onboard person");
    }
    bind_room_owner(&server, owner);
    let root = server.vault.root_project().expect("root project");
    let project = seeded_test_entity_id(0x2094_0103);
    let mut roster =
        oneiron::workspace_roster::ProjectRecord::new(project, Some(root), root, owner).unwrap();
    create_owned_project(&server, owner, project, &roster);
    roster.roster.push(peer.to_hex());
    let room = oneiron::EntityId::from_hex(&roster.home_room).unwrap();
    let exact_room = oneiron::workspace_roster::ProjectRoom {
        schema_version: 1,
        kind: "channel".into(),
        project_id: project.to_hex(),
        member_ids: roster.roster.clone(),
        claims_scope_ref: roster.claims_scope_ref.clone(),
        origin: None,
    };
    // A public batch can submit the exact derived room beside its PROJECT
    // edit; the owner-signed birth above admitted the PROJECT itself.
    server
        .vault
        .batch()
        .put(
            &project,
            server.vault.project_type_byte().unwrap(),
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&roster).unwrap(),
        )
        .put(
            &room,
            oneiron::registry::ENTITY_TYPE_CONVERSATION,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&exact_room).unwrap(),
        )
        .commit()
        .expect("onboard exact project and room in one batch");
    assert_eq!(
        server.vault.room_audience_members(room).unwrap(),
        vec![owner, peer]
    );

    let identity = seeded_test_entity_id(0x2094_0104);
    let peer_contact = seeded_test_entity_id(0x2094_0106);
    seed_counterparty_contact(&server, peer_contact, identity, "peer@example.com");
    server
        .vault
        .put_edge(&peer_contact, oneiron::EdgeKind::About, &peer, 1.0)
        .expect("peer contact link");
    let tier_a = seed_text_turn(&server, "private room needle");
    let tier_b = seed_text_turn(&server, "public room needle");
    server
        .vault
        .set_disclosure_tier_a(&tier_a, 101)
        .expect("private mark");
    seed_disclosure_scope(&server, peer_contact, oneiron::federation::Scope::top());

    let request = |owner_present: bool| {
        json!({
            "conversation_id": room.to_hex(),
            "query": "room needle",
            "limit": 10,
            "interlocutors": { "owner_present": owner_present }
        })
    };
    let (status, absent) = room_owner_json(server.clone(), owner, &request(false)).await;
    assert_eq!(status, StatusCode::OK, "{absent}");
    assert_eq!(absent["disclosure"]["mode"], "absence_clamp");
    let absent_ids: Vec<_> = absent["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect();
    assert!(
        !absent_ids.contains(&tier_a.to_hex().as_str()),
        "tier A absent: {absent}"
    );
    assert!(
        absent_ids.contains(&tier_b.to_hex().as_str()),
        "both dials admit tier B: {absent}"
    );

    let (status, present) = room_owner_json(server.clone(), owner, &request(true)).await;
    assert_eq!(status, StatusCode::OK, "{present}");
    assert_eq!(present["disclosure"]["mode"], "supervised");
    let present_ids: Vec<_> = present["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect();
    assert!(
        !present_ids.contains(&tier_a.to_hex().as_str()),
        "tier A stays private: {present}"
    );
    assert!(
        present_ids.contains(&tier_b.to_hex().as_str()),
        "tier B visible: {present}"
    );

    // The second member's dial is part of the meet, not replaced by the
    // caller's list or the first member's clearance.
    let mut public_only = oneiron::federation::Scope::top();
    public_only.sensitivity =
        oneiron::federation::SensitivityCeiling::AtMost(oneiron::federation::Sensitivity::Public);
    server
        .vault
        .set_counterparty_disclosure_scope(
            &peer_contact,
            &oneiron::disclosure::DisclosureScope::new(public_only, "room public only", 101)
                .unwrap(),
        )
        .unwrap();
    let (status, narrowed) = room_owner_json(server.clone(), owner, &request(false)).await;
    assert_eq!(status, StatusCode::OK, "{narrowed}");
    assert!(
        !narrowed["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == tier_b.to_hex()),
        "second dial refuses tier B: {narrowed}"
    );
    let (status, supervised_narrowed) =
        room_owner_json(server.clone(), owner, &request(true)).await;
    assert_eq!(status, StatusCode::OK, "{supervised_narrowed}");
    assert_eq!(supervised_narrowed["disclosure"]["mode"], "supervised");
    assert!(
        !supervised_narrowed["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == tier_b.to_hex()),
        "owner presence alone cannot override a narrower peer clearance: {supervised_narrowed}"
    );

    // A client-supplied contact cannot replace a missing roster identity:
    // losing the unique person link makes that member unknown and denies the
    // absent-owner Tier-B read even when the caller names the contact.
    seed_disclosure_scope(&server, peer_contact, oneiron::federation::Scope::top());
    assert!(
        server
            .vault
            .delete_edge(&peer_contact, oneiron::EdgeKind::About, &peer)
            .expect("unlink peer")
    );
    let (status, unlinked) = room_owner_json(
        server.clone(),
        owner,
        &json!({
            "conversation_id": room.to_hex(),
            "query": "room needle",
            "interlocutors": {
                "owner_present": false,
                "third_parties": [{ "contact_ref": peer_contact.to_hex() }]
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{unlinked}");
    assert!(
        !unlinked["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == tier_b.to_hex()),
        "missing roster identity cannot be replaced by a wire party: {unlinked}"
    );

    server
        .vault
        .put_edge(&peer_contact, oneiron::EdgeKind::About, &peer, 1.0)
        .expect("relink peer");
    let other_contact = seeded_test_entity_id(0x2094_0107);
    seed_counterparty_contact(&server, other_contact, identity, "ambiguous@example.com");
    seed_disclosure_scope(&server, other_contact, oneiron::federation::Scope::top());
    server
        .vault
        .put_edge(&other_contact, oneiron::EdgeKind::About, &peer, 1.0)
        .expect("second contact linked to peer");
    let (status, two_contacts) = room_owner_json(server.clone(), owner, &request(false)).await;
    assert_eq!(status, StatusCode::OK, "{two_contacts}");
    assert!(
        !two_contacts["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == tier_b.to_hex()),
        "two contacts for one person fail closed: {two_contacts}"
    );
    server
        .vault
        .delete_edge(&other_contact, oneiron::EdgeKind::About, &peer)
        .expect("remove extra contact");
    let stranger = seeded_test_entity_id(0x2094_0108);
    server
        .vault
        .put_entity(
            &stranger,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"stranger",
        )
        .expect("other person");
    server
        .vault
        .put_edge(&peer_contact, oneiron::EdgeKind::About, &stranger, 1.0)
        .expect("contact points to two people");
    let (status, two_people) = room_owner_json(server.clone(), owner, &request(false)).await;
    assert_eq!(status, StatusCode::OK, "{two_people}");
    assert!(
        !two_people["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == tier_b.to_hex()),
        "one contact for two people fails closed: {two_people}"
    );

    // Omission is not authenticated presence in a room, even on owner auth.
    let (status, implicit) = room_owner_json(
        server,
        owner,
        &json!({"conversation_id": room.to_hex(), "query": "room needle"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{implicit}");
    assert_eq!(implicit["disclosure"]["mode"], "absence_clamp");
}

#[tokio::test]
async fn owner_only_room_requires_an_authenticated_person_binding() {
    let (_dir, server) = interlocutor_test_server();
    let owner = seeded_test_entity_id(0x2094_0201);
    server
        .vault
        .put_entity(
            &owner,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .unwrap();
    bind_room_owner(&server, owner);
    let root = server.vault.root_project().unwrap();
    let project = seeded_test_entity_id(0x2094_0202);
    let record =
        oneiron::workspace_roster::ProjectRecord::new(project, Some(root), root, owner).unwrap();
    create_owned_project(&server, owner, project, &record);
    let room = oneiron::EntityId::from_hex(&record.home_room).unwrap();
    let private = seed_text_turn(&server, "owner alone private2094");
    server.vault.set_disclosure_tier_a(&private, 101).unwrap();
    let request = json!({"conversation_id":room.to_hex(),"query":"private2094",
        "interlocutors":{"owner_present":true}});
    let (status, bound) = room_owner_json(server.clone(), owner, &request).await;
    assert_eq!(status, StatusCode::OK, "{bound}");
    assert_eq!(bound["disclosure"]["mode"], "owner_alone");
    assert!(
        bound["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == private.to_hex()),
        "bound owner alone retains Tier A: {bound}"
    );

    // A bare owner-grade host secret names no PERSON. It cannot turn the
    // roster's owner into an authenticated owner entry by assertion alone.
    let (status, unbound) =
        owner_json(server, "POST", "/v1/core/context-pack", Some(&request)).await;
    assert_eq!(status, StatusCode::OK, "{unbound}");
    assert_eq!(unbound["disclosure"]["mode"], "supervised");
    assert!(
        !unbound["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == private.to_hex()),
        "unbound host cannot disclose Tier A: {unbound}"
    );
}

/// Engine-lane ruling 2026-10-11 (ARCH-0067 §8): the vault's own agent acts
/// for the owner and adds no clearance term; its own grant bounds what the
/// room reads instead. A room holding the bound owner and that agent
/// assembles its own default-Sensitive history, owner present or away, once
/// the agent may read it too: a policy grant for the room's records and a
/// relationship grant for its message's space. Before, the agent was an
/// unknown party and the room public-only.
#[tokio::test]
async fn a_room_with_the_owners_own_agent_reads_its_own_history() {
    let (_dir, server) = interlocutor_test_server();
    let owner = seeded_test_entity_id(0x2094_0301);
    let agent = seeded_test_entity_id(0x2094_0302);
    server
        .vault
        .put_entity(
            &owner,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"room member",
        )
        .expect("onboard person");
    bind_room_owner(&server, owner);
    // The host key holds the owner's binding, so the vault's own agent here
    // is one of its live agent definitions.
    let definition = oneiron::agent_def::AgentDefinition::new(
        "oneiron.agent.room",
        "Room member fixture",
        "1.0.0",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        oneiron::agent_def::AgentScope::All,
        oneiron::agent_def::AgentCeiling::Proposed,
        None,
        oneiron::ClaimApprovalStatus::Approved,
        oneiron::ClaimLifecycleStatus::Active,
        oneiron::ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("test"),
        )]),
        None,
        true,
        None,
    );
    server
        .vault
        .put_agent_definition(
            &agent,
            &definition,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
        )
        .expect("agent definition");
    let root = server.vault.root_project().expect("root project");
    let project = seeded_test_entity_id(0x2094_0303);
    let mut roster =
        oneiron::workspace_roster::ProjectRecord::new(project, Some(root), root, owner).unwrap();
    create_owned_project(&server, owner, project, &roster);
    roster.roster.push(agent.to_hex());
    let room = oneiron::EntityId::from_hex(&roster.home_room).unwrap();
    let exact_room = oneiron::workspace_roster::ProjectRoom {
        schema_version: 1,
        kind: "channel".into(),
        project_id: project.to_hex(),
        member_ids: roster.roster.clone(),
        claims_scope_ref: roster.claims_scope_ref.clone(),
        origin: None,
    };
    server
        .vault
        .batch()
        .put(
            &project,
            server.vault.project_type_byte().unwrap(),
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&roster).unwrap(),
        )
        .put(
            &room,
            oneiron::registry::ENTITY_TYPE_CONVERSATION,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&exact_room).unwrap(),
        )
        .commit()
        .expect("onboard exact project and room in one batch");
    let space = seeded_test_entity_id(0x2094_0304);
    server
        .vault
        .memory(owner, oneiron::EdgeActorClass::Human)
        .rooms_speak(&oneiron::memory::WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(oneiron::EntityId::now().to_hex()),
            messages: vec![oneiron::memory::WitnessMessage {
                id: Some(oneiron::EntityId::now().to_hex()),
                author: oneiron::memory::WitnessAuthor::User,
                message_type: "text".into(),
                content: "lantern harbor room2094".into(),
                metadata: Some(json!({ "rel": space.to_hex() })),
                is_visible: true,
                order: 0,
            }],
            occurred_at: 2,
        })
        .expect("speak");

    // Nothing, the policy grant alone, then both: only the agent's whole
    // read of the message lets the room read it.
    for grants in 0..3 {
        if grants == 1 {
            super::context_board_history::restrict_principal_read_types(
                &server,
                agent,
                &[
                    oneiron::registry::ENTITY_TYPE_TURN,
                    oneiron::registry::ENTITY_TYPE_MESSAGE,
                ],
            );
        }
        if grants == 2 {
            server
                .vault
                .create_access_grant(
                    &seeded_test_entity_id(0x2094_0305),
                    &oneiron::access_grant::AccessGrant {
                        principal_ref: agent,
                        scope: oneiron::access_grant::AccessGrantScope::Messages {
                            space_ref: space,
                        },
                        capability: oneiron::access_grant::AccessGrantCapability::MessagesRead,
                        authority_scope: oneiron::federation::Scope::top(),
                        status: oneiron::access_grant::AccessGrantStatus::Active,
                        created_at: 1,
                        revoked_at: None,
                        expires_at: None,
                    },
                )
                .expect("grant the message's space");
        }
        for (owner_present, mode) in [(None, "absence_clamp"), (Some(true), "owner_alone")] {
            let mut request = json!({"conversation_id": room.to_hex(), "query": "room2094"});
            if let Some(present) = owner_present {
                request["interlocutors"] = json!({ "owner_present": present });
            }
            let (status, body) = room_owner_json(server.clone(), owner, &request).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["disclosure"]["mode"], mode, "{body}");
            assert_eq!(
                body.to_string().contains("lantern harbor room2094"),
                grants == 2,
                "the room reads its history only as its agent may ({grants}, {mode}): {body}"
            );
        }
    }
}

/// A bare host secret proves no PERSON, so the vault's own agents stay
/// unknown parties to it: a room of agents alone never reads as the owner
/// alone, presence asserted or not, and reads only public rows. The agent
/// reading on its own credential is the room's proven reader: it adds no
/// clearance term, so the room reads what its own grant admits, and never
/// Tier A.
#[tokio::test]
async fn an_agent_only_room_never_reads_as_the_owner_alone_for_a_bare_host() {
    let (_dir, server) = interlocutor_test_server();
    let agent = seeded_test_entity_id(0x2094_0401);
    server
        .vault
        .put_entity(
            &agent,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"room agent",
        )
        .expect("onboard agent");
    bind_room_actor(&server, agent, "agent");
    let creator = server.vault.ensure_embedded_owner_actor().unwrap();
    let room = oneiron::EntityId::now();
    server
        .vault
        .create_conversation(
            room,
            &oneiron::conversation::ConversationBody {
                kind: oneiron::conversation::ConversationKind::Channel,
                member_ids: vec![agent],
                ..Default::default()
            },
            oneiron::WriteActor::new(creator, oneiron::EdgeActorClass::Human),
            1,
        )
        .expect("agent-only room");
    let private = seed_text_turn(&server, "agent room private2094");
    server.vault.set_disclosure_tier_a(&private, 101).unwrap();
    let sensitive = seed_text_turn(&server, "agent room sensitive2094");
    let request = json!({"conversation_id": room.to_hex(), "query": "agent room"});
    let ids = |body: &Value| -> Vec<String> {
        body["results"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| row["id"].as_str().map(str::to_owned))
            .collect()
    };
    for interlocutors in [None, Some(json!({"owner_present": true}))] {
        let mut request = request.clone();
        if let Some(interlocutors) = interlocutors {
            request["interlocutors"] = interlocutors;
        }
        let (status, body) = owner_json(
            server.clone(),
            "POST",
            "/v1/core/context-pack",
            Some(&request),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_ne!(body["disclosure"]["mode"], "owner_alone", "{body}");
        assert!(
            !ids(&body).contains(&private.to_hex()) && !ids(&body).contains(&sensitive.to_hex()),
            "a bare host reads only public rows through an agent-only room: {body}"
        );
    }

    let agent_reads = |server: std::sync::Arc<SyncServer>| {
        route_json(
            server,
            core_request_with_authz(
                "POST",
                "/v1/core/context-pack",
                test_bearer(&format!(
                    "scope=core:read;principal_ref={};actor_class=agent",
                    agent.to_hex()
                )),
                Some(&request),
            ),
        )
    };
    // The agent's slip reads every record kind until a manifest grant names
    // it, so a grant that reads only MESSAGEs is the narrow start.
    super::context_board_history::restrict_principal_read_types(
        &server,
        agent,
        &[oneiron::registry::ENTITY_TYPE_MESSAGE],
    );
    let (status, before) = agent_reads(server.clone()).await;
    assert_eq!(status, StatusCode::OK, "{before}");
    assert!(
        !ids(&before).contains(&sensitive.to_hex()),
        "the agent's own read bounds the room: {before}"
    );
    super::context_board_history::restrict_principal_read_types(
        &server,
        agent,
        &[oneiron::registry::ENTITY_TYPE_TURN],
    );
    let (status, after) = agent_reads(server.clone()).await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_ne!(after["disclosure"]["mode"], "owner_alone", "{after}");
    assert!(
        ids(&after).contains(&sensitive.to_hex()),
        "the agent reads the room as its own grant admits: {after}"
    );
    assert!(
        !ids(&after).contains(&private.to_hex()),
        "an agent's room never holds Tier A: {after}"
    );
}

/// F16 H145: a narrowed reader that names a contact it cannot read learns
/// nothing of it. An explicit `contact_ref` fails exactly as a missing one
/// does, and a channel pair that finds the contact stays the unknown label
/// the reader sent, never the contact's id. Once the reader's grant admits
/// contact rows, the same requests resolve the contact.
#[tokio::test]
async fn a_narrowed_reader_resolves_no_contact_it_cannot_read() {
    let (_dir, server) = interlocutor_test_server();
    let principal = seeded_test_entity_id(0x2516_0001);
    let identity = seeded_test_entity_id(0x2516_0002);
    let contact = seeded_test_entity_id(0x2516_0003);
    let missing = seeded_test_entity_id(0x2516_0004);
    seed_counterparty_contact(&server, contact, identity, "hidden@example.com");
    let pack = |party: Value| {
        route_json(
            server.clone(),
            core_request_with_principal_ref(
                "POST",
                "/v1/core/context-pack",
                "core:read",
                &principal.to_hex(),
                Some(&json!({
                    "query": "anything",
                    "interlocutors": { "third_parties": [party] }
                })),
            ),
        )
    };
    let by_ref = |id: oneiron::EntityId| json!({ "contact_ref": id.to_hex() });
    let by_channel = json!({
        "channel_identity_ref": identity.to_hex(),
        "counterparty": "hidden@example.com"
    });
    let error = |body: &Value| {
        (
            body["error"]["code"].clone(),
            body["error"]["message"].clone(),
            body["error"]["details"].clone(),
        )
    };
    let stamp = |body: &Value, speaker: &str| -> Value {
        body["interlocutors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|stamp| stamp["speaker"] == speaker)
            .cloned()
            .unwrap_or(Value::Null)
    };

    super::context_board_history::restrict_principal_read_types(
        &server,
        principal,
        &[oneiron::registry::ENTITY_TYPE_TURN],
    );
    let (missing_status, missing_body) = pack(by_ref(missing)).await;
    assert_eq!(missing_status, StatusCode::NOT_FOUND, "{missing_body}");
    let (status, body) = pack(by_ref(contact)).await;
    assert_eq!(
        (status, error(&body)),
        (missing_status, error(&missing_body)),
        "a contact the reader cannot read is a missing one: {body}"
    );
    let (status, body) = pack(by_channel.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body.to_string().contains(&contact.to_hex()), "{body}");
    assert_eq!(
        stamp(&body, "hidden@example.com")["class"],
        "unknown",
        "{body}"
    );

    super::context_board_history::restrict_principal_read_types(
        &server,
        principal,
        &[
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT,
        ],
    );
    for party in [by_ref(contact), by_channel] {
        let (status, body) = pack(party).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            stamp(&body, &contact.to_hex())["class"],
            "known_contact",
            "a reader that reads the contact resolves it: {body}"
        );
    }
}

/// F16 (S-F5): a sealed secret custody id a caller names as a contact or a
/// room is a ref that resolves to nothing, as a missing id is: the same
/// status and error, never a server error that tells the two apart.
#[tokio::test]
async fn a_named_custody_id_reads_as_a_missing_ref() {
    let (_dir, server) = interlocutor_test_server();
    let principal = seeded_test_entity_id(0x2516_0011);
    let custody = server
        .vault
        .register_test_secret("ref-placeholder", b"placeholder", Vec::new(), 1)
        .unwrap();
    let missing = seeded_test_entity_id(0x2516_0012);
    let pack = |body: Value| {
        route_json(
            server.clone(),
            core_request_with_principal_ref(
                "POST",
                "/v1/core/context-pack",
                "core:read",
                &principal.to_hex(),
                Some(&body),
            ),
        )
    };
    let error = |body: &Value| {
        (
            body["error"]["code"].clone(),
            body["error"]["message"].clone(),
            body["error"]["details"].clone(),
        )
    };
    let requests: [fn(oneiron::EntityId) -> Value; 2] = [
        |id| {
            json!({
                "query": "anything",
                "interlocutors": { "third_parties": [{ "contact_ref": id.to_hex() }] }
            })
        },
        |id| json!({ "query": "anything", "conversation_id": id.to_hex() }),
    ];
    for request in requests {
        let (missing_status, missing_body) = pack(request(missing)).await;
        assert_eq!(missing_status, StatusCode::NOT_FOUND, "{missing_body}");
        let (status, body) = pack(request(custody)).await;
        assert_eq!(
            (status, error(&body)),
            (missing_status, error(&missing_body)),
            "{body}"
        );
    }
}

/// F19 H146 and H287: a narrowed reader's pack counts no row it cannot read.
/// The clamp's count names only withheld rows the reader reads, and no stat
/// counts the claims its own grant withholds, so a query that matches hidden
/// claims reads the same as before they existed.
#[tokio::test]
async fn a_narrowed_readers_pack_counts_no_row_it_cannot_read() {
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x2519_0001);
    let principal = seeded_test_entity_id(0x2519_0002);
    seed_counterparty_contact(&server, principal, identity_ref, "lantern@example.com");
    let party = seed_text_turn(&server, "lantern festival needle19");
    seed_disclosure_scope(&server, principal, disclosure_base_world_clearance());
    // The reader reads turns and its own contact row, never a claim.
    super::context_board_history::restrict_principal_read_types(
        &server,
        principal,
        &[
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT,
        ],
    );
    let counts = || async {
        let (status, body) = route_json(
            server.clone(),
            core_request_with_principal_ref(
                "POST",
                "/v1/core/context-pack",
                "core:read",
                &principal.to_hex(),
                Some(&json!({ "query": "needle19", "limit": 10 })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["disclosure"]["mode"], "absence_clamp", "{body}");
        (
            body["disclosure"]["clamped_out"].clone(),
            body["stats"]["claims_suppressed"].clone(),
        )
    };
    let before = counts().await;
    // One claim the clamp withholds (another world), one the reader's own
    // grant withholds (a claim, in the base world the clamp admits).
    seed_disclosure_claim_in_world(
        &server,
        party,
        "private diary entry needle19",
        seeded_test_entity_id(0x2519_00f1),
    );
    seed_disclosure_claim_in_world(
        &server,
        party,
        "festival details needle19",
        oneiron::claim::base_world_id(),
    );
    assert_eq!(counts().await, before, "hidden matches move no count");
    assert_eq!(before, (json!(0), json!(0)));
}

/// F19 review round 1 (Sol F1, Astra F1): a narrowed reader's empty pack
/// reads alike whether or not a row it cannot read matches. Its empty reason
/// and hint name no filter its own grant applied.
#[tokio::test]
async fn a_narrowed_readers_empty_pack_reads_alike_beside_a_hidden_match() {
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x2519_0011);
    let principal = seeded_test_entity_id(0x2519_0012);
    seed_counterparty_contact(&server, principal, identity_ref, "harbor@example.com");
    let party = seed_text_turn(&server, "harbor evening walk");
    seed_disclosure_scope(&server, principal, disclosure_base_world_clearance());
    // The reader reads turns and its own contact row, never a claim.
    super::context_board_history::restrict_principal_read_types(
        &server,
        principal,
        &[
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT,
        ],
    );
    let empty = || async {
        let (status, body) = route_json(
            server.clone(),
            core_request_with_principal_ref(
                "POST",
                "/v1/core/context-pack",
                "core:read",
                &principal.to_hex(),
                Some(&json!({ "query": "quillwort19", "limit": 10 })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["results"], json!([]), "{body}");
        (body["state"].clone(), body["empty"].clone())
    };
    // FACET-READ: the pack and board doors refuse a credential limited to a
    // facet before they retrieve, so a hidden match moves neither answer.
    let faceted = || async {
        let bearer = test_bearer(&format!(
            "scope=core:read;facets={}",
            seeded_test_entity_id(0x2519_0013).to_hex()
        ));
        let mut answers = Vec::new();
        for (uri, request) in [
            (
                "/v1/core/context-pack",
                json!({ "query": "quillwort19", "limit": 10 }),
            ),
            ("/v1/core/context-board", json!({})),
        ] {
            let (status, mut body) = route_json(
                server.clone(),
                core_request_with_authz("POST", uri, bearer.clone(), Some(&request)),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
            body["error"].as_object_mut().unwrap().remove("requestId");
            answers.push(body);
        }
        answers
    };
    let before = empty().await;
    let refused = faceted().await;
    // A claim in the base world the clamp admits, which the reader's own
    // grant withholds.
    seed_disclosure_claim_in_world(
        &server,
        party,
        "quillwort19 private note",
        oneiron::claim::base_world_id(),
    );
    assert_eq!(empty().await, before, "a hidden match reads as no match");
    assert_eq!(before.0["reason"], "filter_matched_none", "{before:?}");
    assert_eq!(faceted().await, refused);
}

/// F19 review round 3 (Sol F2 = Astra F3): no key reads every row. A claim
/// private to another principal stays unread even to the owner's own key, so
/// the owner's empty pack reads alike whether or not such a claim matches.
/// The same claim private to the owner is one the owner's pack finds.
#[tokio::test]
async fn an_owners_empty_pack_reads_alike_beside_another_principals_match() {
    let (_dir, server) = interlocutor_test_server();
    let owner_ref = server.vault.ensure_embedded_owner_actor().unwrap();
    let owner = test_bearer(&format!(
        "principal_ref={};actor_class=human",
        owner_ref.to_hex()
    ));
    let subject = seed_text_turn(&server, "meadow walk");
    let pack = |query: &'static str| {
        let owner = owner.clone();
        let server = server.clone();
        async move {
            let (status, body) = route_json(
                server,
                core_request_with_authz(
                    "POST",
                    "/v1/core/context-pack",
                    owner,
                    Some(&json!({ "query": query, "limit": 10 })),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body
        }
    };
    let private_to = |principal: oneiron::EntityId, text: &str| {
        let id = oneiron::EntityId::now();
        let mut claim = oneiron::ClaimBody::new(
            "event.note",
            oneiron::ClaimSubject::Entity(subject),
            rmpv::Value::from(text),
            1.0,
            oneiron::ClaimApprovalStatus::Auto,
            oneiron::ClaimLifecycleStatus::Active,
        )
        .unwrap();
        claim.scope = Some(rmpv::Value::Map(vec![(
            rmpv::Value::from("principal"),
            rmpv::Value::Binary(principal.as_bytes().to_vec()),
        )]));
        server
            .vault
            .put_claim(&id, &claim, oneiron::TimeRange { start: 1, end: 1 }, 1)
            .unwrap();
        server
            .vault
            .batch()
            .text(&id, &[("body", text)])
            .commit()
            .unwrap();
        id
    };
    let empty = |body: Value| {
        assert_eq!(body["results"], json!([]), "{body}");
        (body["state"].clone(), body["empty"].clone())
    };
    let before = empty(pack("larkspur20").await);
    private_to(
        seeded_test_entity_id(0x2519_0031),
        "larkspur20 private note",
    );
    assert_eq!(
        empty(pack("larkspur20").await),
        before,
        "another principal's match reads as no match"
    );
    let own = private_to(owner_ref, "larkspur21 private note");
    assert!(
        pack("larkspur21").await["results"]
            .to_string()
            .contains(&own.to_hex()),
        "the owner's pack finds a claim private to the owner"
    );
}

/// F19 review round 1 (Astra F2): the clamp's count names a withheld TURN
/// only when the reader may retrieve it. A TURN whose message the reader
/// cannot read is not, so a query only that message's words match reads as
/// one nothing matches. (On round 1's point-read count the same TURN counts
/// once.)
#[tokio::test]
async fn a_clamped_turn_whose_message_the_reader_cannot_read_moves_no_count() {
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x2519_0021);
    let principal = seeded_test_entity_id(0x2519_0022);
    seed_counterparty_contact(&server, principal, identity_ref, "meadow@example.com");
    seed_disclosure_scope(&server, principal, disclosure_base_world_clearance());
    // The reader reads turns and its own contact row, never a message.
    super::context_board_history::restrict_principal_read_types(
        &server,
        principal,
        &[
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT,
        ],
    );
    let clamped = || async {
        let (status, body) = route_json(
            server.clone(),
            core_request_with_principal_ref(
                "POST",
                "/v1/core/context-pack",
                "core:read",
                &principal.to_hex(),
                Some(&json!({ "query": "sorrel19", "limit": 10 })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["disclosure"]["mode"], "absence_clamp", "{body}");
        assert_eq!(body["results"], json!([]), "{body}");
        body["disclosure"]["clamped_out"]
            .as_u64()
            .expect("clamp count")
    };
    let before = clamped().await;
    // A turn whose one message the owner marked Tier A: the clamp withholds
    // the turn, and the reader's grant reads no message.
    let turn = oneiron::EntityId::now();
    let message = oneiron::EntityId::now();
    witness_vad_message_fixture(&server, &turn, &message, "sorrel19 private words", 100);
    // The turn's own text holds its message's words, so the turn itself is a
    // candidate the query retrieves.
    server
        .vault
        .batch()
        .text(&turn, &[("body", "sorrel19 private words")])
        .commit()
        .expect("index the turn's text");
    server
        .vault
        .set_disclosure_tier_a(&message, 101)
        .expect("mark the message Tier A");
    assert_eq!(
        clamped().await,
        before,
        "an unreadable message moves no count"
    );
    assert_eq!(before, 0);
}
