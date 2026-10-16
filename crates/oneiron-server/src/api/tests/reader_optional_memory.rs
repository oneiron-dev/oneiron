//! A reader's optional-memory profile (ZERO-RETRIEVAL = A, ARCH-0004
//! #reader-budget): zero optional memory keeps pins, disclosure and the
//! standing prefix, and no profile widens what the caller asked for.

use super::*;
use oneiron::agent_def::{
    AgentDefinition, CompactionOwnership, MemoryProfile, OptionalMemory, OptionalMemoryProfile,
};
use std::num::NonZeroU64;

/// A reader whose default is the widest setting there is, whose `narrow`
/// family takes 16 tokens at summary detail, and whose `no_memory` family
/// takes no optional memory.
fn put_reader(server: &SyncServer, id: oneiron::EntityId) {
    let widest = OptionalMemory::Budget {
        tokens: NonZeroU64::MAX,
        view: oneiron::FieldProfile::Full,
    };
    let narrow = OptionalMemory::Budget {
        tokens: NonZeroU64::new(16).unwrap(),
        view: oneiron::FieldProfile::Minimal,
    };
    let profile = MemoryProfile::new(
        1_000,
        oneiron::ModelTierRef("test.summary".to_owned()),
        CompactionOwnership::Engine,
    )
    .with_optional_memory(
        OptionalMemoryProfile::new(widest)
            .with_family("narrow", narrow)
            .with_family("no_memory", OptionalMemory::None),
    );
    let definition = AgentDefinition::new(
        "oneiron.agent.reader",
        "Optional-memory reader fixture",
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
    )
    .with_memory_profile(Some(profile));
    server
        .vault
        .put_agent_definition(&id, &definition, oneiron::TimeRange { start: 1, end: 1 }, 1)
        .expect("persist reader definition");
}

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

#[tokio::test]
async fn zero_optional_memory_keeps_pins_and_disclosure_and_no_profile_widens() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal = seeded_test_entity_id(0x1016_0001);
    let pinned = seeded_test_entity_id(0x1016_0002);
    let contact = seeded_test_entity_id(0x1016_0003);
    let recalled = seeded_test_entity_id(0x1016_0004);
    let reader = seeded_test_entity_id(0x1016_0005);
    put_person(&server, pinned, "pin needle");
    put_person(&server, recalled, "recall needle");
    put_reader(&server, reader);
    let pack = server
        .vault
        .context_pack()
        .search_text("pin needle", 10)
        .run()
        .unwrap();
    let row = pack.results.iter().find(|row| row.id == pinned).unwrap();
    let reference = format!("{}:{:02x}", row.short_id, row.content_hash);
    seed_counterparty_contact(&server, principal, contact, "reader@example.com");
    seed_disclosure_scope(&server, principal, oneiron::federation::Scope::top());

    let as_reader = |family: Option<&str>| match family {
        None => json!({ "definition": reader.to_hex() }),
        Some(family) => json!({ "definition": reader.to_hex(), "task_family": family }),
    };
    // Each call reads in its own session, so no call sees rows an earlier
    // one already delivered.
    let mut session = 0x1016_0100;
    let mut board = |reader: Value| {
        session += 1;
        let mut retrieval = json!({ "query": "recall needle", "limit": 5 });
        if !reader.is_null() {
            retrieval["reader"] = reader;
        }
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            &principal.to_hex(),
            Some(&json!({
                "retrieval": retrieval,
                "memories": { "shared_total": 0, "pinned_refs": [reference] },
                "session": { "session_id": seeded_test_entity_id(session).to_hex() }
            })),
        )
    };

    let (status, control) = route_json(server.clone(), board(Value::Null)).await;
    assert_eq!(status, StatusCode::OK, "{control}");
    assert!(
        !control["pack"]["results"].as_array().unwrap().is_empty(),
        "{control}"
    );
    assert_eq!(
        control["memories"]["rows"][0]["tier"], "pinned",
        "{control}"
    );

    // Zero optional memory: no recall, a typed reason, and the same explicit
    // and manifest pin reads as the control, with the same pinned row.
    let (status, skipped) = route_json(server.clone(), board(as_reader(Some("no_memory")))).await;
    assert_eq!(status, StatusCode::OK, "{skipped}");
    assert!(
        skipped["pack"]["results"].as_array().unwrap().is_empty(),
        "{skipped}"
    );
    assert_eq!(skipped["pack"]["state"]["kind"], "skipped", "{skipped}");
    assert_eq!(
        skipped["pack"]["state"]["reason"], "skipped_by_profile",
        "{skipped}"
    );
    assert_eq!(skipped["memories"]["rows"], control["memories"]["rows"]);
    assert_eq!(
        skipped["pack"]["pin_narrowing"],
        control["pack"]["pin_narrowing"]
    );

    // The widest setting over the caller's request changes nothing.
    let (status, widest) = route_json(server.clone(), board(as_reader(None))).await;
    assert_eq!(status, StatusCode::OK, "{widest}");
    assert_eq!(widest["pack"]["results"], control["pack"]["results"]);
    assert_eq!(widest["memories"]["rows"], control["memories"]["rows"]);

    // A narrower profile narrows exactly as the caller narrowing itself
    // would; the widest one leaves a narrow request as it was.
    let pack = |extra: Value| {
        let mut request = json!({ "query": "recall needle", "limit": 5 });
        for (key, value) in extra.as_object().unwrap() {
            request[key] = value.clone();
        }
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal.to_hex(),
            Some(&request),
        )
    };
    let narrow_request = json!({ "view": "summary", "budget": { "token_budget": 16 } });
    let (_, wide) = route_json(server.clone(), pack(json!({}))).await;
    let (status, by_caller) = route_json(server.clone(), pack(narrow_request.clone())).await;
    assert_eq!(status, StatusCode::OK, "{by_caller}");
    assert_ne!(by_caller["results"], wide["results"], "{wide}");
    let (_, by_profile) = route_json(
        server.clone(),
        pack(json!({ "reader": as_reader(Some("narrow")) })),
    )
    .await;
    assert_eq!(by_profile["results"], by_caller["results"], "{by_profile}");
    let mut widest_over_narrow = narrow_request;
    widest_over_narrow["reader"] = as_reader(None);
    let (_, kept) = route_json(server.clone(), pack(widest_over_narrow)).await;
    assert_eq!(kept["results"], by_caller["results"], "{kept}");

    // Disclosure stands whatever the profile: a pin the audience may not
    // see stays withheld under the widest setting and under zero.
    seed_disclosure_scope(&server, principal, oneiron::federation::Scope::default());
    let (_, denied) = route_json(server.clone(), board(Value::Null)).await;
    assert!(denied["memories"]["rows"].as_array().unwrap().is_empty());
    for family in [None, Some("no_memory")] {
        let (status, body) = route_json(server.clone(), board(as_reader(family))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["memories"]["rows"].as_array().unwrap().is_empty(),
            "{body}"
        );
        assert_eq!(
            body["pack"]["pin_narrowing"],
            denied["pack"]["pin_narrowing"]
        );
        if family.is_none() {
            assert_eq!(body["pack"]["results"], denied["pack"]["results"]);
        }
    }
}

/// The standing prefix is built before retrieval, so a reader with zero
/// optional memory still opens with it.
#[tokio::test]
async fn zero_optional_memory_keeps_the_standing_prefix() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let actor = seeded_test_entity_id(0x1016_0201);
    let world = seeded_test_entity_id(0x1016_0202);
    let reader = seeded_test_entity_id(0x1016_0203);
    for (id, kind, body) in [
        (actor, oneiron::registry::ENTITY_TYPE_PERSON, &b"agent"[..]),
        (world, oneiron::registry::ENTITY_TYPE_WORLD, &b"world"[..]),
    ] {
        server
            .vault
            .put_entity(&id, kind, oneiron::TimeRange { start: 1, end: 1 }, 1, body)
            .unwrap();
    }
    put_person(&server, seeded_test_entity_id(0x1016_0204), "recall needle");
    put_reader(&server, reader);
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
    let board = |reader: Value| {
        let mut retrieval = json!({ "query": "recall needle", "limit": 5 });
        if !reader.is_null() {
            retrieval["reader"] = reader;
        }
        core_request_with_authz(
            "POST",
            "/v1/core/context-board",
            test_bearer(&format!(
                "scope=core:read;principal_ref={};actor_class=agent",
                actor.to_hex()
            )),
            Some(&json!({
                "standing": { "world_ref": world.to_hex(), "token_budget": 65_536 },
                "retrieval": retrieval
            })),
        )
    };
    let (status, control) = route_json(server.clone(), board(Value::Null)).await;
    assert_eq!(status, StatusCode::OK, "{control}");
    assert_eq!(
        control["standing"]["world_ref"],
        world.to_hex(),
        "{control}"
    );
    let (status, skipped) = route_json(
        server,
        board(json!({ "definition": reader.to_hex(), "task_family": "no_memory" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{skipped}");
    assert_eq!(skipped["standing"], control["standing"]);
    assert_eq!(
        skipped["pack"]["state"]["reason"], "skipped_by_profile",
        "{skipped}"
    );
    assert!(skipped["pack"]["results"].as_array().unwrap().is_empty());
}
