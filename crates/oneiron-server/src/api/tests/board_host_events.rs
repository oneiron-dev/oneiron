//! Router proofs for session observations and turn-local capability riders.
use super::*;
use oneiron::context_board::{BoardStreamFrame, DeltaRow, FrameKind};
use oneiron::skill_hub::pack_catalog::{
    PackFitPolicy, PackFitVerdict, PackInstallDisposition, PackPermissions, PackSource,
    PackSourceAdapter,
};
use oneiron::skill_hub::{
    HubFile, HubPackage, HubPin, HubRef, HubSyncPolicy, SkillHubAdapter, SkillHubKind,
    SkillHubRecord, SkillHubTrustTier,
};

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
    fn evaluate(&self, _: &PackSource, card: &PackPermissions) -> oneiron::Result<PackFitVerdict> {
        assert_eq!(card.section_authorities, ["read"]);
        Ok(PackFitVerdict {
            fits: true,
            rules_hit: false,
            code_auto_install: true,
        })
    }
}

/// Installs a one-section board pack named `name` from a verified hub, as
/// the owner, and returns its receipt's content hash.
fn install_board_pack(server: &SyncServer, name: &str) -> String {
    install_board_pack_version(server, name, 1)
}

/// [`install_board_pack`] at `version`: a later version replaces the earlier
/// one's install and leaves its source stored.
fn install_board_pack_version(server: &SyncServer, name: &str, version: u32) -> String {
    let section = json!({"section_id": format!("{name}.panel"), "state_family":{"family":"claim","version":1},
        "verbs":["board.expand"], "authority_lane":"read", "budget_policy":"board.plugin_sections.v1"});
    let manifest = format!(
        "---\nname: {name}\ndescription: board pack\nversion: {version}\nkind: capability\n\
         predicates: [\"{name}.topic\"]\n---\nBoard pack\n"
    );
    let source = PackSource::from_files(vec![
        HubFile::new("PACK.md", manifest.as_bytes()),
        HubFile::new(
            format!("knowledge/sections/{name}.panel.json"),
            serde_json::to_vec(&section).unwrap(),
        ),
    ])
    .unwrap();
    let occurred = oneiron::TimeRange { start: 4, end: 4 };
    let owner_id = oneiron::EntityId::now();
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
            &format!("principal:{name}:{version}"),
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
        .admit_skill_publisher(&owner, &format!("publisher:{name}:{version}"), hub)
        .unwrap();
    let reference = HubRef::new(
        hub,
        format!("packs/{name}"),
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
    receipt.content_hash
}

/// F16 H385: the core board's changed line names only packs whose source row
/// its reader reads. To a reader that cannot read the pack's source, the
/// pack is not installed; once its grant reads the source, it sees the
/// install.
#[tokio::test]
async fn a_board_names_no_pack_its_reader_cannot_read() {
    use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal = seeded_test_entity_id(0x2516_0201).to_hex();
    let restrict = |types: &[u8]| {
        super::context_board_history::restrict_principal_read_types(
            &server,
            seeded_test_entity_id(0x2516_0201),
            types,
        );
    };
    restrict(&[ENTITY_TYPE_TURN, ENTITY_TYPE_PERSON]);
    for session in ["hidden-session", "shown-session"] {
        assert_eq!(
            core_board(&server, &principal, session).await["changed"],
            json!([])
        );
    }
    let hash = install_board_pack(&server, "alice.hidden");
    let hidden = core_board(&server, &principal, "hidden-session").await;
    assert!(
        !hidden.to_string().contains("alice.hidden") && !hidden.to_string().contains(&hash),
        "{hidden:#}"
    );
    restrict(&[ENTITY_TYPE_TURN, ENTITY_TYPE_PERSON, ENTITY_TYPE_ASSET]);
    let shown = core_board(&server, &principal, "shown-session").await;
    assert!(
        shown["changed"].to_string().contains("alice.hidden"),
        "a reader that reads the pack's source sees it installed: {shown:#}"
    );
}

#[tokio::test]
async fn board_host_pack_install_is_changed_line_and_live_section_next_render() {
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
    let mut healthy_files = source.files().to_vec();
    for file in &mut healthy_files {
        file.path = file.path.replace("alice.board", "alice.healthy");
        file.content = String::from_utf8(file.content.clone())
            .expect("fixture UTF-8")
            .replace("alice.board", "alice.healthy")
            .into_bytes();
    }
    let healthy_source = PackSource::from_files(healthy_files).unwrap();
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
            )
            .unwrap(),
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
    // Delete one installed source through the ordinary door. Only that pack
    // disappears; board hydration and unrelated sections stay readable.
    let healthy_ref = HubRef::new(
        hub,
        "packs/alice.healthy",
        HubPin::ContentHash(healthy_source.content_hash().to_hex()),
    )
    .unwrap();
    let PackInstallDisposition::Installed(healthy) = server
        .vault
        .install_pack_from_adapter(
            &Adapter {
                hub,
                source: healthy_source,
            },
            &healthy_ref,
            &publisher,
            &Fit,
            occurred,
            6,
        )
        .unwrap()
    else {
        panic!("healthy pack")
    };
    let healthy_row = seeded_test_entity_id(0x2477_9113);
    server
        .vault
        .put_claim(
            &healthy_row,
            &oneiron::ClaimBody::new(
                "alice.healthy.topic",
                oneiron::ClaimSubject::Entity(actor),
                rmpv::Value::from("healthy topic"),
                0.9,
                oneiron::ClaimApprovalStatus::Auto,
                oneiron::ClaimLifecycleStatus::Active,
            )
            .unwrap(),
            oneiron::TimeRange { start: 7, end: 7 },
            7,
        )
        .unwrap();
    server
        .vault
        .delete_entity(&oneiron::EntityId::from_hex(&receipt.source_id).unwrap())
        .unwrap();
    let core = core_board(&server, &actor.to_hex(), "pack-session").await;
    let changed = core["changed"].as_array().unwrap();
    assert!(
        changed.iter().any(|line| line
            .as_str()
            .unwrap_or_default()
            .contains("alice.healthy: installed:")),
        "{core}"
    );
    assert!(
        !changed.iter().any(|line| line
            .as_str()
            .unwrap_or_default()
            .contains("alice.board: installed:")),
        "{core}"
    );
    let latest = board_mcp_call(&server, "pack-main", actor, "setup_oneiron", json!({})).await;
    let board = latest["result"]["structuredContent"]["board"]["keyframe"]
        .as_str()
        .unwrap();
    assert!(board.contains("alice.healthy.panel"), "{board}");
    assert!(board.contains("alice.healthy.topic"), "{board}");
    assert!(board.contains(&healthy.content_hash), "{board}");
    assert!(!board.contains("alice.board.panel"), "{board}");
    assert!(!board.contains("alice.board.topic"), "{board}");
    assert!(!board.contains(&receipt.content_hash), "{board}");
}

/// An agent's board read over Core, under its own authenticated slip.
async fn agent_board(
    server: &Arc<SyncServer>,
    agent: oneiron::EntityId,
    session: &str,
) -> Vec<String> {
    let (status, response) = route_json(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/context-board",
            test_bearer(&format!(
                "scope=core:read;principal_ref={};actor_class=agent",
                agent.to_hex()
            )),
            Some(&json!({"session":{"session_id": session}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response:#}");
    serde_json::from_value(response["changed"].clone()).unwrap()
}

/// The owner answers a whole run through the owner route, as the app does.
async fn settle_run(server: &Arc<SyncServer>, run_id: &str, action: &str) {
    let owner = test_bearer(&format!(
        "principal_ref={};actor_class=human",
        server.vault.ensure_embedded_owner_actor().unwrap().to_hex()
    ));
    let (status, review) = route_json(
        server.clone(),
        core_request_with_authz(
            "GET",
            &format!("/v1/owner/runs/review?run_id={run_id}"),
            owner.clone(),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{review}");
    let (status, resolved) = route_json(
        server.clone(),
        core_request_with_authz(
            "POST",
            &format!("/v1/owner/runs/{action}"),
            owner,
            Some(&json!({"run_id": run_id, "bundle_id": review["bundle_id"]})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resolved}");
}

/// ARCH-0067: the changed line carries this agent's own proposals that moved,
/// with the answer by reference, and a rejection arrives with its diagnostic
/// on the next wake, once. Another agent's proposal never rides it.
#[tokio::test]
async fn own_proposal_outcome_rides_the_next_board_read_once() {
    let (_dir, server) = auth_test_server();
    let agent = seeded_test_entity_id(0x1021_0001);
    let stranger = seeded_test_entity_id(0x1021_0002);
    let park = |run: &str, author: oneiron::EntityId, value: &str| {
        server
            .vault
            .park_run_proposal_for_test(run, author, oneiron::EntityId::now(), value)
            .unwrap()
    };
    // Settled before the session ever read a board: still owed to it.
    let early = park("rider-early", agent, "zero");
    settle_run(&server, "rider-early", "decline").await;
    let own = park("rider-own", agent, "one");
    let foreign = park("rider-foreign", stranger, "two");
    let rejected =
        |id: oneiron::EntityId| format!("claim:{}: rejected why=word:bundle:", id.to_hex());
    let first = agent_board(&server, agent, "rider").await;
    assert_eq!(first.len(), 2, "{first:?}");
    assert!(first[1].starts_with(&rejected(early)), "{first:?}");
    assert!(first[1].contains(" diagnostic="), "{first:?}");
    settle_run(&server, "rider-own", "decline").await;
    settle_run(&server, "rider-foreign", "decline").await;
    let changed = agent_board(&server, agent, "rider").await;
    assert_eq!(changed.len(), 2, "{changed:?}");
    assert_eq!(changed[0], "changed[1:]{id,to}:");
    assert!(changed[1].starts_with(&rejected(own)), "{changed:?}");
    assert!(changed[1].contains(" diagnostic="), "{changed:?}");
    assert!(!changed.iter().any(|row| row.contains(&foreign.to_hex())));
    // Delivered once: the next wake has nothing new to say.
    assert!(agent_board(&server, agent, "rider").await.is_empty());
}

/// An outcome reaches the rider through every door that closes a proposal:
/// the owner's inbox reject, which leaves the claim as proposed and records
/// the person's word on its closing receipt, and a retraction, answered by
/// its own receipt.
#[tokio::test]
async fn every_door_that_closes_a_proposal_reaches_the_rider() {
    let (_dir, server) = auth_test_server();
    let agent = seeded_test_entity_id(0x1021_0006);
    let park = |run: &str, value: &str| {
        server
            .vault
            .park_run_proposal_for_test(run, agent, oneiron::EntityId::now(), value)
            .unwrap()
    };
    let declined = park("rider-inbox", "one");
    let retracted = park("rider-retract", "two");
    assert!(agent_board(&server, agent, "rider-doors").await.is_empty());
    server
        .vault
        .resolve_inbox_group("rider-inbox", oneiron::inbox::InboxBulkVerb::RejectAll)
        .unwrap();
    server.vault.retract_claim(&retracted, 10_000).unwrap();
    let changed = agent_board(&server, agent, "rider-doors").await;
    assert_eq!(changed[0], "changed[2:]{id,to}:", "{changed:?}");
    let word = format!(
        "claim:{}: rejected why=word:bundle:dreamer_run:rider-inbox diagnostic=",
        declined.to_hex()
    );
    assert!(
        changed.iter().any(|row| row.starts_with(&word)),
        "{changed:?}"
    );
    let receipt = format!("claim:{}: retracted why=receipt:gate:", retracted.to_hex());
    assert!(
        changed.iter().any(|row| row.starts_with(&receipt)),
        "{changed:?}"
    );
    assert!(agent_board(&server, agent, "rider-doors").await.is_empty());
}

/// The epoch a keyframe returns stays the board's after its rider is
/// delivered: delivering an outcome is not a change to the board.
#[tokio::test]
async fn delivering_an_outcome_keeps_the_returned_epoch_current() {
    let (_dir, server) = auth_test_server();
    let agent = seeded_test_entity_id(0x1021_0005);
    register_mcp_actor(
        &server,
        "rider-epoch",
        agent,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    board_mcp_call(&server, "rider-epoch", agent, "setup_oneiron", json!({})).await;
    server
        .vault
        .park_run_proposal_for_test("rider-epoch", agent, oneiron::EntityId::now(), "one")
        .unwrap();
    board_mcp_call(&server, "rider-epoch", agent, "setup_oneiron", json!({})).await;
    settle_run(&server, "rider-epoch", "decline").await;
    let setup = board_mcp_call(&server, "rider-epoch", agent, "setup_oneiron", json!({})).await;
    let board = &setup["result"]["structuredContent"]["board"];
    assert!(
        board["keyframe"].as_str().unwrap().contains(": rejected"),
        "{board}"
    );
    let epoch = board["epoch"].as_u64().unwrap();
    board_mcp_call(
        &server,
        "rider-epoch",
        agent,
        "board.expand",
        json!({"key": "VERBS", "frame_epoch": epoch}),
    )
    .await;
}

/// A full cap of older outcomes cannot hold a rejection back, and whatever
/// the cap holds back is delivered on the following wake.
#[tokio::test]
async fn a_rejection_rides_ahead_of_a_full_cap_of_approvals() {
    let (_dir, server) = auth_test_server();
    let agent = seeded_test_entity_id(0x1021_0003);
    let approved: Vec<_> = (0..17)
        .map(|n| {
            server
                .vault
                .park_run_proposal_for_test(
                    "rider-approve",
                    agent,
                    oneiron::EntityId::now(),
                    format!("approved {n}"),
                )
                .unwrap()
        })
        .collect();
    let rejected = server
        .vault
        .park_run_proposal_for_test("rider-reject", agent, oneiron::EntityId::now(), "late")
        .unwrap();
    assert!(agent_board(&server, agent, "cap").await.is_empty());
    settle_run(&server, "rider-approve", "approve").await;
    settle_run(&server, "rider-reject", "decline").await;
    let first = agent_board(&server, agent, "cap").await;
    assert_eq!(first[0], "changed[16:]{id,to}:", "{first:?}");
    assert!(
        first[1].starts_with(&format!("claim:{}: rejected", rejected.to_hex())),
        "{first:?}"
    );
    assert_eq!(first.last().unwrap(), "changed: +2");
    let second = agent_board(&server, agent, "cap").await;
    assert_eq!(second[0], "changed[2:]{id,to}:", "{second:?}");
    let delivered: Vec<_> = first[2..17].iter().chain(&second[1..]).collect();
    for id in &approved {
        assert_eq!(
            delivered
                .iter()
                .filter(|row| row.starts_with(&format!("claim:{}: approved", id.to_hex())))
                .count(),
            1,
            "{first:?} {second:?}"
        );
    }
    assert!(agent_board(&server, agent, "cap").await.is_empty());
}

/// ARCH-0067: a connector installed mid-epoch renders in the tail until the
/// next keyframe, which carries it, and no later frame repeats it.
#[tokio::test]
async fn a_connector_installed_mid_epoch_rides_the_tail_until_the_next_keyframe() {
    let (_dir, server) = auth_test_server();
    let agent = seeded_test_entity_id(0x1021_0004);
    register_mcp_actor(&server, "rider-mcp", agent, oneiron::EdgeActorClass::Human).await;
    let keyframe = |reply: &Value| {
        reply["result"]["structuredContent"]["board"]["keyframe"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    // Core reads mid-epoch: the first sets the baseline, later ones keep the
    // change on the tail.
    assert!(agent_board(&server, agent, "tail").await.is_empty());
    let first = board_mcp_call(&server, "rider-mcp", agent, "setup_oneiron", json!({})).await;
    assert!(!keyframe(&first).contains("connector installed"));
    let key = oneiron::EntityId::now();
    server
        .vault
        .register_connector_key(
            &key,
            oneiron::connector_key::ConnectorKeyRecord::active("rider_mail", None, Vec::new(), 1),
        )
        .unwrap();
    let installed = format!("rider_mail: connector installed key={}", key.to_hex());
    for _ in 0..2 {
        let tail = agent_board(&server, agent, "tail").await;
        assert!(
            tail.iter().any(|row| row.starts_with(&installed)),
            "{tail:?}"
        );
    }
    // MCP: the next keyframe carries it once and moves it into the prefix.
    let next = board_mcp_call(&server, "rider-mcp", agent, "setup_oneiron", json!({})).await;
    assert!(keyframe(&next).contains(&installed), "{}", keyframe(&next));
    let after = board_mcp_call(&server, "rider-mcp", agent, "setup_oneiron", json!({})).await;
    assert!(!keyframe(&after).contains("connector installed"));
}

/// A connector's removal names the key it ran under whole, so two connectors
/// whose long names share every byte the row keeps are still told apart.
#[tokio::test]
async fn a_removed_connector_is_named_by_its_whole_key() {
    let (_dir, server) = auth_test_server();
    let agent = seeded_test_entity_id(0x1021_0005);
    let stem = "rider_mail_".repeat(30);
    let (kept, removed) = (oneiron::EntityId::now(), oneiron::EntityId::now());
    for (key, tail) in [(kept, "a"), (removed, "b")] {
        server
            .vault
            .register_connector_key(
                &key,
                oneiron::connector_key::ConnectorKeyRecord::active(
                    format!("{stem}{tail}"),
                    None,
                    Vec::new(),
                    1,
                ),
            )
            .unwrap();
    }
    // The first read sets the baseline both connectors are in.
    assert!(agent_board(&server, agent, "removal").await.is_empty());
    server.vault.revoke_connector_key(&removed, 2).unwrap();
    let tail = agent_board(&server, agent, "removal").await;
    let removals: Vec<_> = tail
        .iter()
        .filter(|row| row.contains(": connector removed"))
        .collect();
    assert_eq!(removals.len(), 1, "{tail:?}");
    assert!(
        removals[0].ends_with(&format!("key={}", removed.to_hex())),
        "{tail:?}"
    );
}

/// F16 (S-F4): the own-change rider carries an outcome or a connector only
/// while the caller's read reads its row. An agent whose grant reads no claim
/// and no connector key learns of neither; the outcome stays owed, and both
/// ride once its read admits them.
#[tokio::test]
async fn the_rider_carries_no_outcome_or_connector_its_reader_cannot_read() {
    let (_dir, server) = auth_test_server();
    let agent = seeded_test_entity_id(0x2516_0401);
    let own = server
        .vault
        .park_run_proposal_for_test("rider-hidden", agent, oneiron::EntityId::now(), "one")
        .unwrap();
    assert!(agent_board(&server, agent, "hidden").await.is_empty());
    settle_run(&server, "rider-hidden", "decline").await;
    let key = oneiron::EntityId::now();
    server
        .vault
        .register_connector_key(
            &key,
            oneiron::connector_key::ConnectorKeyRecord::active("rider_hidden", None, Vec::new(), 1),
        )
        .unwrap();
    let names = |rows: &[String], needle: &str| rows.iter().any(|row| row.contains(needle));

    super::context_board_history::restrict_principal_read_types(
        &server,
        agent,
        &[oneiron::registry::ENTITY_TYPE_TURN],
    );
    let hidden = agent_board(&server, agent, "hidden").await;
    for needle in [own.to_hex(), key.to_hex(), "rider_hidden".to_owned()] {
        assert!(!names(&hidden, &needle), "{needle}: {hidden:?}");
    }

    super::context_board_history::restrict_principal_read_types(
        &server,
        agent,
        &[
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::registry::ENTITY_TYPE_CLAIM,
            oneiron::registry::ENTITY_TYPE_CONNECTOR_KEY,
        ],
    );
    let shown = agent_board(&server, agent, "hidden").await;
    assert!(
        names(&shown, &format!("claim:{}: rejected", own.to_hex())),
        "the withheld outcome was still owed: {shown:?}"
    );
    assert!(names(&shown, &key.to_hex()), "{shown:?}");
}

/// A keyed board hydration by `principal` naming its own `turn`, in
/// `session`, under `key`.
fn keyed_board(
    principal: oneiron::EntityId,
    turn: oneiron::EntityId,
    session: &str,
    key: &'static str,
) -> axum::http::Request<axum::body::Body> {
    let mut request = core_request_with_authz(
        "POST",
        "/v1/core/context-board",
        test_bearer(&format!(
            "scope=core:read,core:write;principal_ref={};actor_class=agent",
            principal.to_hex()
        )),
        Some(&json!({"session": {"session_id": session}, "turn": {"id": turn.to_hex()}})),
    );
    request
        .headers_mut()
        .insert("Idempotency-Key", axum::http::HeaderValue::from_static(key));
    request
}

/// A TURN `author` wrote.
fn put_authored_turn(server: &SyncServer, author: oneiron::EntityId) -> oneiron::EntityId {
    let turn = oneiron::EntityId::now();
    server
        .vault
        .put_entity(
            &turn,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 2, end: 2 },
            2,
            &rmp_serde::to_vec_named(&json!({ "actor": author.to_hex() })).unwrap(),
        )
        .unwrap();
    turn
}

/// F16 round 2 (Sol F2, Astra F2): a keyed board's replay re-admits its
/// rider, the own outcome and the connector key it carried, under its
/// reader's read as it stands then. Once that read reads neither, the replay
/// is refused rather than repeating them.
#[tokio::test]
async fn a_keyed_board_replays_no_rider_its_reader_no_longer_reads() {
    use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONNECTOR_KEY, ENTITY_TYPE_TURN};
    let (_dir, server) = auth_test_server();
    let agent = seeded_test_entity_id(0x2516_0411);
    let own = server
        .vault
        .park_run_proposal_for_test("rider-keyed", agent, oneiron::EntityId::now(), "one")
        .unwrap();
    assert!(agent_board(&server, agent, "keyed").await.is_empty());
    settle_run(&server, "rider-keyed", "decline").await;
    let key = oneiron::EntityId::now();
    server
        .vault
        .register_connector_key(
            &key,
            oneiron::connector_key::ConnectorKeyRecord::active("rider_keyed", None, Vec::new(), 1),
        )
        .unwrap();
    let turn = put_authored_turn(&server, agent);
    super::context_board_history::restrict_principal_read_types(
        &server,
        agent,
        &[
            ENTITY_TYPE_TURN,
            ENTITY_TYPE_CLAIM,
            ENTITY_TYPE_CONNECTOR_KEY,
        ],
    );
    let keyed = || {
        route_json(
            server.clone(),
            keyed_board(agent, turn, "keyed", "rider-keyed"),
        )
    };
    let (status, first) = keyed().await;
    assert_eq!(status, StatusCode::OK, "{first:#}");
    let changed = first["changed"].to_string();
    assert!(
        changed.contains(&format!("claim:{}: rejected", own.to_hex())),
        "{first:#}"
    );
    assert!(changed.contains(&key.to_hex()), "{first:#}");
    let (status, again) = keyed().await;
    assert_eq!(status, StatusCode::OK, "{again:#}");
    assert_eq!(again, first);

    super::context_board_history::restrict_principal_read_types(
        &server,
        agent,
        &[ENTITY_TYPE_TURN],
    );
    let (status, refused) = keyed().await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused:#}");
    let refused = refused.to_string();
    assert!(refused.contains("board_document_unreadable"), "{refused}");
    assert!(!refused.contains(&own.to_hex()) && !refused.contains(&key.to_hex()));
}

/// F16 round 2 (Sol F4, Astra F4): a keyed board's replay re-admits the exact
/// source of each pack it named, whatever the catalog installs now. A later
/// version's install leaves the first source stored; once the reader's grant
/// reads no source, the replay is refused rather than naming the first.
#[tokio::test]
async fn a_keyed_board_replays_no_pack_whose_source_its_reader_no_longer_reads() {
    use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal = seeded_test_entity_id(0x2516_0421);
    let restrict = |types: &[u8]| {
        super::context_board_history::restrict_principal_read_types(&server, principal, types);
    };
    restrict(&[ENTITY_TYPE_TURN, ENTITY_TYPE_PERSON, ENTITY_TYPE_ASSET]);
    assert_eq!(
        core_board(&server, &principal.to_hex(), "pack-keyed").await["changed"],
        json!([])
    );
    let first_hash = install_board_pack_version(&server, "alice.keyed", 1);
    // A board's owner is a row: its history is recorded against it.
    server
        .vault
        .put_entity(
            &principal,
            ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"pack reader",
        )
        .unwrap();
    let turn = put_authored_turn(&server, principal);
    let keyed = || {
        route_json(
            server.clone(),
            keyed_board(principal, turn, "pack-keyed", "pack-keyed"),
        )
    };
    let (status, first) = keyed().await;
    assert_eq!(status, StatusCode::OK, "{first:#}");
    assert!(
        first["changed"].to_string().contains(&first_hash),
        "{first:#}"
    );
    let (status, again) = keyed().await;
    assert_eq!(status, StatusCode::OK, "{again:#}");
    assert_eq!(again, first);

    let second_hash = install_board_pack_version(&server, "alice.keyed", 2);
    assert_ne!(second_hash, first_hash);
    restrict(&[ENTITY_TYPE_TURN, ENTITY_TYPE_PERSON]);
    let (status, refused) = keyed().await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused:#}");
    let refused = refused.to_string();
    assert!(refused.contains("board_document_unreadable"), "{refused}");
    assert!(!refused.contains(&first_hash), "{refused}");
}

/// F16 round 3 (Astra F4): a keyed board's replay re-admits each capability
/// its retrieval discovered, which no document it served names. Once its
/// reader, a delegated reader the disclosure clamp clears, reads no skill,
/// the replay is refused rather than naming it.
#[tokio::test]
async fn a_keyed_board_replays_no_capability_its_reader_no_longer_reads() {
    use oneiron::registry::{ENTITY_TYPE_SKILL, ENTITY_TYPE_TURN};
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal = seeded_test_entity_id(0x2516_0431);
    super::context_board_history::cleared_reader(
        &server,
        principal,
        seeded_test_entity_id(0x2516_0433),
    );
    let skill = seeded_test_entity_id(0x2516_0432);
    seed_board_skill(&server, skill, "keyedcapsneedle");
    let turn = put_authored_turn(&server, principal);
    let restrict = |types: &[u8]| {
        super::context_board_history::restrict_principal_read_types(&server, principal, types);
    };
    let keyed = || {
        let mut request = core_request_with_principal_ref(
            "POST",
            "/v1/core/context-board",
            "core:read,core:write",
            &principal.to_hex(),
            Some(&json!({
                "retrieval": {"query": "keyedcapsneedle", "limit": 1},
                "session": {"session_id": "caps-keyed"},
                "turn": {"id": turn.to_hex()}
            })),
        );
        request.headers_mut().insert(
            "Idempotency-Key",
            axum::http::HeaderValue::from_static("caps-keyed"),
        );
        route_json(server.clone(), request)
    };
    restrict(&[ENTITY_TYPE_TURN, ENTITY_TYPE_SKILL]);
    let (status, first) = keyed().await;
    assert_eq!(status, StatusCode::OK, "{first:#}");
    assert!(
        first["pack"]["capabilities"]
            .to_string()
            .contains(&skill.to_hex()),
        "{first:#}"
    );
    let (status, again) = keyed().await;
    assert_eq!(status, StatusCode::OK, "{again:#}");
    assert_eq!(again, first);

    restrict(&[ENTITY_TYPE_TURN]);
    let (status, refused) = keyed().await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused:#}");
    let refused = refused.to_string();
    assert!(refused.contains("board_document_unreadable"), "{refused}");
    assert!(!refused.contains(&skill.to_hex()), "{refused}");
}

/// F16 rounds 3 and 4 (Astra F5): a rider that counts outcomes past its cap
/// keeps the rows it counted. Its keyed board replays while each of them
/// still reads, so a lost response loses no outcome, and is refused once a
/// row it only counted no longer reads.
#[tokio::test]
async fn a_keyed_board_replays_no_count_of_a_row_its_reader_no_longer_reads() {
    use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
    let (_dir, server) = auth_test_server();
    let agent = seeded_test_entity_id(0x2516_0441);
    let own: Vec<_> = (0..17)
        .map(|outcome| {
            server
                .vault
                .park_run_proposal_for_test(
                    "rider-overflow",
                    agent,
                    oneiron::EntityId::now(),
                    format!("outcome {outcome}"),
                )
                .unwrap()
        })
        .collect();
    assert!(agent_board(&server, agent, "overflow").await.is_empty());
    settle_run(&server, "rider-overflow", "decline").await;
    let turn = put_authored_turn(&server, agent);
    super::context_board_history::restrict_principal_read_types(
        &server,
        agent,
        &[ENTITY_TYPE_TURN, ENTITY_TYPE_CLAIM],
    );
    let keyed = || {
        route_json(
            server.clone(),
            keyed_board(agent, turn, "overflow", "rider-overflow"),
        )
    };
    let (status, first) = keyed().await;
    assert_eq!(status, StatusCode::OK, "{first:#}");
    let changed = first["changed"].to_string();
    assert!(changed.contains("changed: +"), "{first:#}");
    let counted: Vec<_> = own
        .iter()
        .filter(|id| !changed.contains(&id.to_hex()))
        .collect();
    assert!(!counted.is_empty(), "{first:#}");
    let (status, again) = keyed().await;
    assert_eq!(status, StatusCode::OK, "{again:#}");
    assert_eq!(again, first);

    assert!(server.vault.delete_entity(counted[0]).unwrap());
    let (status, refused) = keyed().await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused:#}");
    assert!(
        refused.to_string().contains("board_document_unreadable"),
        "{refused:#}"
    );
}
