//! Router proofs for session observations and turn-local capability riders.
use super::*;
use oneiron::context_board::{BoardStreamFrame, DeltaRow, FrameKind};

fn seed_board_skill(server: &SyncServer, id: oneiron::EntityId, needle: &str) -> String {
    let mut record = oneiron::skill::SkillRecord::new(
        "skill.board-fixture",
        needle,
        "v2",
        oneiron::ClaimApprovalStatus::Approved,
        oneiron::skill::SkillLifecycle::Candidate,
        oneiron::ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![("source".into(), "board-test".into())]),
    );
    let body = oneiron::skill::encode_skill_record(&record).expect("skill body");
    server
        .vault
        .batch()
        .put(
            &id,
            oneiron::registry::ENTITY_TYPE_SKILL,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .text(&id, &[("body", needle)])
        .commit()
        .expect("seed skill");
    record.lifecycle_status = oneiron::skill::SkillLifecycle::Active;
    server
        .vault
        .update_skill_record(&id, &record, oneiron::TimeRange { start: 1, end: 1 }, 1)
        .expect("admit user skill");
    server
        .vault
        .batch()
        .text(&id, &[("body", needle)])
        .commit()
        .expect("index admitted skill");
    server
        .vault
        .set_indexed_idle_delay_ms(0)
        .expect("idle delay");
    server
        .vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("publish admitted skill");
    oneiron::retrieval_depth::short_ref_or_hex(&server.vault, &id).expect("skill short ref")
}

async fn core_board(server: &Arc<SyncServer>, principal: &str, session: &str) -> Value {
    let (status, response) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read",
            principal,
            Some(&json!({"session":{"session_id": session}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response:#}");
    response
}

#[tokio::test]
async fn board_host_core_get_query_and_sessions_have_distinct_clocks() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal = seeded_test_entity_id(0x2477_1001).to_hex();
    let other = seeded_test_entity_id(0x2477_1002).to_hex();
    let skill = seeded_test_entity_id(0x2477_1003);
    let reference = seed_board_skill(&server, skill, "boardhostskillneedle");
    let (status, summary) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/query",
            "core:read",
            &principal,
            Some(&json!({"query":"boardhostskillneedle", "view":"summary", "session_id":"s1"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{summary:#}");
    assert_eq!(summary["items"][0]["id"], skill.to_hex());
    assert_eq!(
        core_board(&server, &principal, "s1").await["skills"],
        json!(["loaded: "])
    );
    let (status, hydrated) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/hydrate",
            "core:read",
            &principal,
            Some(&json!({"ref":reference, "session_id":"s1"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{hydrated:#}");
    assert_eq!(hydrated["status"], "live");
    let loaded = format!("loaded: {}@v2", skill.to_hex());
    assert_eq!(
        core_board(&server, &principal, "s1").await["skills"],
        json!([loaded])
    );
    assert_eq!(
        core_board(&server, &principal, "s2").await["skills"],
        json!(["loaded: "])
    );
    assert_eq!(
        core_board(&server, &other, "s1").await["skills"],
        json!(["loaded: "])
    );
    let (status, full) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/query",
            "core:read",
            &principal,
            Some(&json!({"query":"boardhostskillneedle", "view":"full", "session_id":"s2"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{full:#}");
    assert_eq!(
        core_board(&server, &principal, "s2").await["skills"],
        json!([loaded])
    );
    // Shared owner-bearer reads never become one user's session observations.
    let (_, shared) = core_json(
        server.clone(),
        "POST",
        "/v1/core/hydrate",
        "core:read",
        Some(&json!({"ref":reference, "view":"full", "session_id":"shared"})),
    )
    .await;
    assert_eq!(shared["status"], "live");
    assert_eq!(
        core_board(&server, &principal, "shared").await["skills"],
        json!(["loaded: "])
    );
}

#[tokio::test]
async fn board_host_query_tracks_only_the_returned_page() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let subject = seeded_test_entity_id(0x2477_2001);
    let principal = subject.to_hex();
    server
        .vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    let old = [
        seeded_test_entity_id(0x2477_2002),
        seeded_test_entity_id(0x2477_2003),
    ];
    let next = [
        seeded_test_entity_id(0x2477_2004),
        seeded_test_entity_id(0x2477_2005),
    ];
    for id in old {
        seed_active_claim(&server, id, subject, "boardhostclaimneedle", 1);
        server
            .vault
            .batch()
            .text(&id, &[("body", "boardhostclaimneedle")])
            .commit()
            .unwrap();
    }
    for id in next {
        seed_active_claim(&server, id, subject, "replacement", 2);
    }
    let (status, response) = route_json(server.clone(), core_request_with_principal_ref(
        "POST", "/v1/core/query", "core:read", &principal,
        Some(&json!({"query":"boardhostclaimneedle", "view":"standard", "limit":1, "session_id":"observed"})),
    )).await;
    assert_eq!(status, StatusCode::OK, "{response:#}");
    assert_eq!(response["items"].as_array().unwrap().len(), 1);
    let served = response["items"][0]["id"].as_str().unwrap();
    for (a, b) in old.into_iter().zip(next) {
        server.vault.supersede_claim(&b, &a, 3).unwrap();
    }
    let board = core_board(&server, &principal, "observed").await;
    let successor = if served == old[0].to_hex() {
        next[0]
    } else {
        next[1]
    };
    assert_eq!(
        board["changed"],
        json!([
            "changed[1:]{id,to}:",
            format!("{served}: superseded:{}", successor.to_hex()),
        ])
    );
    assert_eq!(
        core_board(&server, &principal, "unobserved").await["changed"],
        json!([])
    );
}

async fn board_mcp_call(
    server: &Arc<SyncServer>,
    credential: &str,
    actor: oneiron::EntityId,
    tool: &str,
    arguments: Value,
) -> Value {
    let path = if tool == "setup_oneiron" {
        "/mcp"
    } else {
        MCP_TOOL_FIRST_PATH
    };
    let envelope = mcp_endpoint_envelope(actor, "read_board");
    let arguments = if tool == "setup_oneiron" {
        envelope
    } else {
        mcp_merge_args(envelope, json!({"arguments":arguments}))
    };
    let (status, reply) = route_json(
        server.clone(),
        mcp_endpoint_call_request(path, credential, "board-event", tool, arguments),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply:#}");
    assert!(reply.get("error").is_none(), "{reply:#}");
    reply
}

async fn enqueue_board_frame(server: &Arc<SyncServer>, credential: &str, kind: FrameKind) {
    let mut registry = server.mcp_registry.lock().await;
    let connection = registry
        .resolve(&mcp_registered_credential(server, credential), 1, |_, _| {
            true
        })
        .unwrap()
        .stream_connection;
    registry.enqueue_stream_frame(&connection, BoardStreamFrame { epoch: 88, kind });
}

#[tokio::test]
async fn board_host_mcp_get_loaded_and_changed_only_ride_existing_frames() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let actor = seeded_test_entity_id(0x2477_3001);
    let skill = seeded_test_entity_id(0x2477_3002);
    let old = seeded_test_entity_id(0x2477_3003);
    let next = seeded_test_entity_id(0x2477_3004);
    for credential in ["board-main", "board-other"] {
        register_mcp_actor(&server, credential, actor, oneiron::EdgeActorClass::Human).await;
    }
    let reference = seed_board_skill(&server, skill, "boardmcpneedle");
    seed_active_claim(&server, old, actor, "boardmcpclaim", 1);
    seed_active_claim(&server, next, actor, "replacement", 2);
    server
        .vault
        .batch()
        .text(&old, &[("body", "boardmcpclaim")])
        .commit()
        .unwrap();
    board_mcp_call(
        &server,
        "board-main",
        actor,
        "memory.hydrate",
        json!({"request":{"ref":reference, "view":"standard"}}),
    )
    .await;
    let metadata_only =
        board_mcp_call(&server, "board-main", actor, "setup_oneiron", json!({})).await;
    assert!(
        !metadata_only["result"]["structuredContent"]["board"]["keyframe"]
            .as_str()
            .unwrap()
            .contains(&format!("{}@v2", skill.to_hex()))
    );
    let get = board_mcp_call(
        &server,
        "board-main",
        actor,
        "memory.hydrate",
        json!({"request":{"ref":reference}}),
    )
    .await;
    assert!(get["result"].get("carrier").is_none());
    let observation_lock = server.memories_cursors.lock().await;
    let query = board_mcp_call(
        &server,
        "board-main",
        actor,
        "memory.query",
        json!({"request":{"query":"boardmcpclaim","view":"standard"}}),
    );
    tokio::pin!(query);
    assert!(futures_util::poll!(query.as_mut()).is_pending());
    server.vault.supersede_claim(&next, &old, 3).unwrap();
    drop(observation_lock);
    let query = query.await;
    assert_eq!(
        query["result"]["structuredContent"]["output"]["response"]["items"][0]["id"],
        old.to_hex()
    );
    let no_push = board_mcp_call(&server, "board-main", actor, "describe", json!({})).await;
    assert!(no_push["result"].get("carrier").is_none());
    let setup = board_mcp_call(&server, "board-main", actor, "setup_oneiron", json!({})).await;
    let keyframe = setup["result"]["structuredContent"]["board"]["keyframe"]
        .as_str()
        .unwrap();
    assert!(keyframe.contains(&format!("loaded: {}@v2", skill.to_hex())));
    assert!(keyframe.contains(&format!("{}: superseded:{}", old.to_hex(), next.to_hex())));
    let isolated = board_mcp_call(&server, "board-other", actor, "setup_oneiron", json!({})).await;
    let isolated = isolated["result"]["structuredContent"]["board"]["keyframe"]
        .as_str()
        .unwrap();
    assert!(!isolated.contains(&skill.to_hex()));
    assert!(!isolated.contains(&old.to_hex()));
    // The same actor on Core is not the credential-bound MCP session.
    let core = core_board(&server, &actor.to_hex(), "board-main").await;
    assert_eq!(core["skills"], json!(["loaded: "]));
    assert_eq!(core["changed"], json!([]));
    enqueue_board_frame(
        &server,
        "board-main",
        FrameKind::Keyframe("<memory surface=\"board\">\nlegend: fixture\n</memory>".into()),
    )
    .await;
    let keyframe = board_mcp_call(&server, "board-main", actor, "describe", json!({})).await;
    assert_eq!(
        keyframe["result"]["carrier"]["frame"]["kind"]["kind"],
        "keyframe"
    );
    enqueue_board_frame(
        &server,
        "board-main",
        FrameKind::Delta(vec![DeltaRow {
            key: "task".into(),
            line: "task ready".into(),
        }]),
    )
    .await;
    let carried = board_mcp_call(&server, "board-main", actor, "describe", json!({})).await;
    let rows = carried["result"]["carrier"]["frame"]["kind"]["payload"]
        .as_array()
        .unwrap();
    assert_eq!(rows[0]["key"], "changed");
    assert!(rows[0]["line"].as_str().unwrap().contains(&old.to_hex()));
    assert!(
        rows.iter()
            .any(|row| row["key"] == "task" && row["line"] == "task ready")
    );
    let exhausted = board_mcp_call(&server, "board-main", actor, "describe", json!({})).await;
    assert!(exhausted["result"].get("carrier").is_none());
    let refreshed = board_mcp_call(&server, "board-main", actor, "board.refresh", json!({})).await;
    assert!(
        refreshed["result"]["structuredContent"]["output"]["frame"]["kind"]["payload"]
            .as_str()
            .unwrap()
            .contains("changed[1:]")
    );
}

#[tokio::test]
async fn board_host_capabilities_are_turn_local_and_shed_before_carried_memory() {
    let (_dir, server) = auth_test_server();
    let actor = seeded_test_entity_id(0x2477_4001);
    let skill = seeded_test_entity_id(0x2477_4002);
    let agent = seeded_test_entity_id(0x2477_4003);
    let memory = seeded_test_entity_id(0x2477_4004);
    register_mcp_actor(&server, "board-caps", actor, oneiron::EdgeActorClass::Human).await;
    seed_board_skill(&server, skill, "boardcapsneedle");
    let definition = oneiron::agent_def::AgentDefinition::new(
        "agent.board-fixture",
        "boardcapsneedle",
        "v1",
        None,
        vec![],
        vec![],
        vec![],
        None,
        oneiron::agent_def::AgentScope::All,
        oneiron::agent_def::AgentCeiling::Proposed,
        None,
        oneiron::ClaimApprovalStatus::Proposed,
        oneiron::ClaimLifecycleStatus::Active,
        oneiron::ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![("source".into(), "board-test".into())]),
        None,
        false,
        None,
    );
    let bytes = oneiron::agent_def::encode_agent_definition(&definition).unwrap();
    server
        .vault
        .batch()
        .put(
            &agent,
            oneiron::registry::ENTITY_TYPE_AGENT_DEF,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            &bytes,
        )
        .text(&agent, &[("body", "boardcapsneedle")])
        .commit()
        .unwrap();
    seed_active_claim(&server, memory, actor, "boardcapsneedle", 1);
    server
        .vault
        .batch()
        .text(&memory, &[("body", "boardcapsneedle")])
        .commit()
        .unwrap();
    // Prime the stream's epoch without retaining a frame.
    enqueue_board_frame(&server, "board-caps", FrameKind::Keyframe("fixture".into())).await;
    board_mcp_call(&server, "board-caps", actor, "describe", json!({})).await;
    let pack_args = json!({"request":{"query":"boardcapsneedle", "limit":1}});
    enqueue_board_frame(
        &server,
        "board-caps",
        FrameKind::Delta(vec![DeltaRow {
            key: "memory".into(),
            line: "memory snippet".into(),
        }]),
    )
    .await;
    let found = board_mcp_call(
        &server,
        "board-caps",
        actor,
        "memory.context_pack",
        pack_args.clone(),
    )
    .await;
    let pack = &found["result"]["structuredContent"]["output"]["response"];
    assert_eq!(pack["results"][0]["id"], memory.to_hex());
    assert_eq!(pack["capabilities"].as_array().unwrap().len(), 2);
    let rows = found["result"]["carrier"]["frame"]["kind"]["payload"]
        .as_array()
        .unwrap();
    assert!(
        rows.iter()
            .any(|row| row["key"] == "SKILLS" && row["line"].as_str().unwrap().contains(" found "))
    );
    assert!(
        rows.iter()
            .any(|row| row["key"] == "AGENTS:cand"
                && row["line"].as_str().unwrap().contains(" cand "))
    );
    let retained = "memory snippet ".repeat(2000);
    enqueue_board_frame(
        &server,
        "board-caps",
        FrameKind::Delta(vec![DeltaRow {
            key: "memory".into(),
            line: retained.clone(),
        }]),
    )
    .await;
    let shed = board_mcp_call(
        &server,
        "board-caps",
        actor,
        "memory.context_pack",
        pack_args,
    )
    .await;
    let rows = shed["result"]["carrier"]["frame"]["kind"]["payload"]
        .as_array()
        .unwrap();
    assert!(
        rows.iter()
            .any(|row| row["key"] == "memory" && row["line"] == retained)
    );
    assert!(
        rows.iter()
            .any(|row| row["key"] == "SKILLS" && row["line"] == "loaded: ")
    );
    assert!(
        rows.iter()
            .any(|row| row["key"] == "AGENTS:cand" && row["line"] == "")
    );
    enqueue_board_frame(
        &server,
        "board-caps",
        FrameKind::Delta(vec![DeltaRow {
            key: "task".into(),
            line: "ready".into(),
        }]),
    )
    .await;
    let later = board_mcp_call(&server, "board-caps", actor, "describe", json!({})).await;
    let rows = later["result"]["carrier"]["frame"]["kind"]["payload"]
        .as_array()
        .unwrap();
    assert!(
        rows.iter()
            .any(|row| row["key"] == "AGENTS:cand" && row["line"] == "")
    );
    assert!(
        rows.iter()
            .any(|row| row["key"] == "SKILLS" && row["line"] == "loaded: ")
    );
}

#[tokio::test]
async fn board_host_narrow_connector_never_delivers_a_rider() {
    let (_dir, server) = auth_test_server();
    let actor = seeded_test_entity_id(0x2477_5001);
    let scope =
        crate::mcp::McpConnectorScope::scoped(Some(seeded_test_entity_id(0x2477_5002)), None);
    register_scoped_mcp_actor(&server, "board-narrow", actor, scope.clone()).await;
    enqueue_board_frame(
        &server,
        "board-narrow",
        FrameKind::Keyframe("<memory surface=\"board\">\nlegend: fixture\n</memory>".into()),
    )
    .await;
    let (_, result) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            "board-narrow",
            "narrow-rider",
            "describe",
            mcp_scoped_envelope(actor, "read_board", &scope),
        ),
    )
    .await;
    assert!(result.get("error").is_none(), "{result:#}");
    assert!(result["result"].get("carrier").is_none());
    let (_, refused) = route_json(
        server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            "board-narrow",
            "narrow-get",
            "memory.query",
            mcp_merge_args(
                mcp_scoped_envelope(actor, "read_board", &scope),
                json!({"arguments":{"request":{"query":"needle"}}}),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&refused, "mcp_scope_refused");
}

#[tokio::test]
async fn board_host_pack_install_is_changed_line_and_live_section_next_render() {
    use oneiron::skill_hub::pack_catalog::{
        PackFitPolicy, PackFitVerdict, PackInstallDisposition, PackPermissions, PackSource,
        PackSourceAdapter,
    };
    use oneiron::skill_hub::{
        HubFile, HubPackage, HubPin, HubRef, HubSyncPolicy, SkillHubAdapter, SkillHubKind,
        SkillHubRecord, SkillHubTrustTier,
    };
    struct Adapter {
        hub: oneiron::EntityId,
        source: PackSource,
    }
    impl SkillHubAdapter for Adapter {
        fn hub_id(&self) -> oneiron::EntityId {
            self.hub
        }
        fn kind(&self) -> SkillHubKind {
            SkillHubKind::Git
        }
        fn endpoint(&self) -> Option<&str> {
            Some("https://example.invalid/board-pack")
        }
        fn fetch_package(&self, _: &HubRef) -> oneiron::Result<HubPackage> {
            Err(oneiron::Error::EntityNotFound)
        }
    }
    impl PackSourceAdapter for Adapter {
        fn fetch_pack_source(&self, _: &HubRef) -> oneiron::Result<PackSource> {
            Ok(self.source.clone())
        }
    }
    struct Fit;
    impl PackFitPolicy for Fit {
        fn evaluate(
            &self,
            _: &PackSource,
            card: &PackPermissions,
        ) -> oneiron::Result<PackFitVerdict> {
            assert_eq!(card.section_authorities, ["read"]);
            Ok(PackFitVerdict {
                fits: true,
                rules_hit: false,
                code_auto_install: true,
            })
        }
    }
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let actor = seeded_test_entity_id(0x2477_9111);
    for credential in ["pack-main", "pack-other"] {
        register_mcp_actor(&server, credential, actor, oneiron::EdgeActorClass::Human).await;
    }
    let initial = board_mcp_call(&server, "pack-main", actor, "setup_oneiron", json!({})).await;
    assert!(
        !initial["result"]["structuredContent"]["board"]["keyframe"]
            .as_str()
            .unwrap()
            .contains("alice.board.panel")
    );
    let core_before = core_board(&server, &actor.to_hex(), "pack-session").await;
    assert_eq!(core_before["changed"], json!([]));
    let section = json!({"section_id":"alice.board.panel", "state_family":{"family":"claim","version":1},
        "verbs":["board.expand"], "authority_lane":"read", "budget_policy":"board.plugin_sections.v1"});
    let source = PackSource::from_files(vec![
        HubFile::new("PACK.md", b"---\nname: alice.board\ndescription: board pack\nversion: 1\nkind: capability\npredicates: [\"alice.board.topic\"]\n---\nBoard pack\n"),
        HubFile::new("knowledge/sections/alice.board.panel.json", serde_json::to_vec(&section).unwrap()),
    ]).unwrap();
    let owner_id = oneiron::EntityId::now();
    let occurred = oneiron::TimeRange { start: 4, end: 4 };
    server
        .vault
        .put_entity(
            &owner_id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            occurred,
            4,
            b"owner",
        )
        .unwrap();
    let owner = server
        .vault
        .authenticate_owner(
            owner_id,
            "principal:board-pack",
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    let hub = oneiron::EntityId::now();
    server
        .vault
        .configure_skill_hub(
            &owner,
            &hub,
            &SkillHubRecord::new(
                SkillHubKind::Git,
                "https://example.invalid/board-pack",
                SkillHubTrustTier::Verified,
                HubSyncPolicy::ContentHashFrozen,
            )
            .unwrap(),
            occurred,
            4,
        )
        .unwrap();
    let publisher = server
        .vault
        .admit_skill_publisher(&owner, "publisher:board-pack", hub)
        .unwrap();
    let reference = HubRef::new(
        hub,
        "packs/alice.board",
        HubPin::ContentHash(source.content_hash().to_hex()),
    )
    .unwrap();
    let PackInstallDisposition::Installed(receipt) = server
        .vault
        .install_pack_from_adapter(
            &Adapter { hub, source },
            &reference,
            &publisher,
            &Fit,
            occurred,
            4,
        )
        .unwrap()
    else {
        panic!("post-fit board pack")
    };
    let row = seeded_test_entity_id(0x2477_9112);
    server
        .vault
        .put_claim(
            &row,
            &oneiron::ClaimBody::new(
                "alice.board.topic",
                oneiron::ClaimSubject::Entity(actor),
                rmpv::Value::from("board topic"),
                0.9,
                oneiron::ClaimApprovalStatus::Auto,
                oneiron::ClaimLifecycleStatus::Active,
            ),
            oneiron::TimeRange { start: 5, end: 5 },
            5,
        )
        .unwrap();
    let setup = board_mcp_call(&server, "pack-main", actor, "setup_oneiron", json!({})).await;
    let keyframe = setup["result"]["structuredContent"]["board"]["keyframe"]
        .as_str()
        .unwrap();
    assert!(keyframe.contains("alice.board.panel"), "{keyframe}");
    assert!(keyframe.contains("alice.board.topic"), "{keyframe}");
    assert!(keyframe.contains("alice.board: installed:"), "{keyframe}");
    assert!(keyframe.contains(&receipt.content_hash));
    let other = board_mcp_call(&server, "pack-other", actor, "setup_oneiron", json!({})).await;
    assert!(
        !other["result"]["structuredContent"]["board"]["keyframe"]
            .as_str()
            .unwrap()
            .contains("alice.board: installed:")
    );
    let core_after = core_board(&server, &actor.to_hex(), "pack-session").await;
    assert!(
        core_after["changed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line
                .as_str()
                .unwrap_or_default()
                .contains("alice.board: installed:"))
    );
}
