//! Owner ruling FACET-READ = A: a facet limits what a credential other than
//! the owner's reads, by one rule on MCP and on every lane door, and decides
//! where its births land (placement stays derived, ARCH-0028). A room's facet
//! is its project's slice facet; a message said there sits in it.

use super::*;
use crate::mcp::McpConnectorScope;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use std::collections::BTreeSet;

/// A vault with three facets (work, home, private), a project room in each
/// holding the owner and an agent, and one message the owner said in each.
struct Facets {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    owner: oneiron::EntityId,
    agent: oneiron::EntityId,
    work: Room,
    home: Room,
    private: Room,
}

#[derive(Clone, Copy)]
struct Room {
    facet: oneiron::EntityId,
    room: oneiron::EntityId,
    message: oneiron::EntityId,
}

fn facets() -> Facets {
    let (_dir, server) = interlocutor_test_server();
    let owner = seeded_test_entity_id(0x2614_0001);
    // The seeded manifest's agent ceiling names the first-party connector
    // actor; MCP resolves an agent connector only under one.
    let agent = oneiron::EntityId::from_bytes([0xE1; 16]).unwrap();
    for (id, kind) in [
        (owner, oneiron::registry::ENTITY_TYPE_PERSON),
        (agent, oneiron::registry::ENTITY_TYPE_PERSON),
    ] {
        server
            .vault
            .put_entity(
                &id,
                kind,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .expect("onboard person");
    }
    bind_room_owner(&server, owner);
    let room = |seed: u128| {
        let facet = seeded_test_entity_id(seed);
        server
            .vault
            .put_entity(
                &facet,
                oneiron::registry::ENTITY_TYPE_FACET,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"facet",
            )
            .expect("seed a facet");
        let root = server.vault.root_project().expect("root project");
        let project = seeded_test_entity_id(seed + 1);
        let mut roster =
            oneiron::workspace_roster::ProjectRecord::new(project, Some(root), root, owner)
                .unwrap();
        roster.slice.facet = Some(facet);
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
            .expect("onboard the agent into the project and its room");
        let message = oneiron::EntityId::now();
        server
            .vault
            .memory(owner, oneiron::EdgeActorClass::Human)
            .rooms_speak(&oneiron::memory::WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: Some(oneiron::EntityId::now().to_hex()),
                messages: vec![oneiron::memory::WitnessMessage {
                    id: Some(message.to_hex()),
                    author: oneiron::memory::WitnessAuthor::User,
                    message_type: "text".into(),
                    content: format!("said in facet {seed:x}"),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                }],
                occurred_at: 2,
            })
            .expect("speak");
        Room {
            facet,
            room,
            message,
        }
    };
    let (work, home, private) = (room(0x2614_0010), room(0x2614_0020), room(0x2614_0030));
    Facets {
        _dir,
        server,
        owner,
        agent,
        work,
        home,
        private,
    }
}

fn set(facets: &[oneiron::EntityId]) -> BTreeSet<oneiron::EntityId> {
    facets.iter().copied().collect()
}

impl Facets {
    /// Pairs `actor` at `class` under `scope` and registers its connector.
    async fn connector(
        &self,
        label: &str,
        actor: oneiron::EntityId,
        class: oneiron::EdgeActorClass,
        scope: &McpConnectorScope,
    ) {
        let token = pair_mcp_credential(&self.server, label, actor, class, scope);
        self.server
            .mcp_registry
            .lock()
            .await
            .register(
                &token,
                crate::mcp::McpConnectorActorRecord::new(actor, class, scope.clone()),
            )
            .expect("register connector");
    }

    /// The status and body `label` gets for `room`'s transcript.
    async fn transcript(&self, label: &str, room: oneiron::EntityId) -> (StatusCode, Value) {
        route_json(
            self.server.clone(),
            core_request_with_authz(
                "GET",
                &format!("/v1/core/conversations/{}/transcript", room.to_hex()),
                format!("Bearer {label}"),
                None,
            ),
        )
        .await
    }

    /// What `label` reads of each room on the lane: its transcript and its row
    /// in the conversation list. An unread room answers exactly as a missing
    /// one does.
    async fn lane_reads(&self, label: &str, room: Room) -> bool {
        let (missing_status, missing) = self.transcript(label, oneiron::EntityId::now()).await;
        let (status, body) = self.transcript(label, room.room).await;
        let (_, listed) = route_json(
            self.server.clone(),
            core_request_with_authz(
                "GET",
                "/v1/core/conversations",
                format!("Bearer {label}"),
                None,
            ),
        )
        .await;
        let listed = listed.to_string().contains(&room.room.to_hex());
        if status == StatusCode::OK {
            assert!(body.to_string().contains(&room.message.to_hex()), "{body}");
            assert!(listed, "a read room is listed");
            return true;
        }
        assert_eq!(status, missing_status, "{body}");
        assert_eq!(body["error"]["code"], missing["error"]["code"], "{body}");
        assert_eq!(body.get("narrowing"), missing.get("narrowing"), "{body}");
        assert!(!body.to_string().contains(&room.message.to_hex()));
        assert!(!listed, "an unread room is not listed");
        false
    }

    /// Whether MCP's ceiling admits `label` to the message said in `room`: a
    /// call that clears it is refused after, by the verb gate that cannot
    /// project a narrowed credential's bounds onto one task's detail.
    async fn mcp_admits(&self, label: &str, scope: &McpConnectorScope, room: Room) -> bool {
        let mut envelope = mcp_scoped_envelope(self.agent, "read_tasks", scope);
        envelope["actor"]["actor_class"] = json!("agent");
        envelope["actor"]["gate_actor_class"] = json!("agent");
        let refused = mcp_refusal(
            &self.server,
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                label,
                label,
                "describe",
                mcp_merge_args(
                    envelope,
                    json!({ "arguments": { "task_ref": room.message.to_hex() } }),
                ),
            ),
        )
        .await;
        let code = refused["error"]["data"]["error_code"].as_str();
        assert!(
            matches!(code, Some("mcp_scope_refused" | "mcp_scope_unprojectable")),
            "{label} must reach the ceiling: {refused}"
        );
        code == Some("mcp_scope_unprojectable")
    }
}

/// FACET-READ checks 1 and 5: an agent credential narrowed to work, on a
/// legacy one-facet registry row, reads the work room's message over MCP and
/// on the lane, and the private room's on neither. On main the lane refused
/// the credential outright and MCP judged a message by a `FacetOf` edge no
/// message carries.
#[tokio::test]
async fn a_work_agent_reads_work_alike_on_mcp_and_the_lane() {
    let vault = facets();
    let work = McpConnectorScope::scoped(None, Some(vault.work.facet));
    vault
        .connector(
            "fr-work",
            vault.agent,
            oneiron::EdgeActorClass::Agent,
            &work,
        )
        .await;
    assert!(vault.lane_reads("fr-work", vault.work).await);
    assert!(vault.mcp_admits("fr-work", &work, vault.work).await);
    for other in [vault.home, vault.private] {
        assert!(!vault.lane_reads("fr-work", other).await);
        assert!(!vault.mcp_admits("fr-work", &work, other).await);
    }
}

/// FACET-READ check 2: one credential over work and home reads both rooms and
/// not the private one, on both surfaces.
#[tokio::test]
async fn a_two_facet_agent_reads_both_and_not_a_third() {
    let vault = facets();
    let both = McpConnectorScope::with_facets(
        None,
        set(&[vault.work.facet, vault.home.facet]),
        Some(vault.home.facet),
    )
    .unwrap();
    vault
        .connector(
            "fr-both",
            vault.agent,
            oneiron::EdgeActorClass::Agent,
            &both,
        )
        .await;
    for (room, read) in [
        (vault.work, true),
        (vault.home, true),
        (vault.private, false),
    ] {
        assert_eq!(vault.lane_reads("fr-both", room).await, read);
        assert_eq!(vault.mcp_admits("fr-both", &both, room).await, read);
    }
}

/// FACET-READ check 3: the owner takes no facet limit. A link that would
/// narrow the owner's person is refused and says why, while an agent's is
/// issued; and a credential the owner narrowed itself still reads every
/// facet.
#[tokio::test]
async fn the_owner_takes_no_facet_limit() {
    let vault = facets();
    let mut work = Scope::top();
    work.facets = ScopeAxis::Some(BTreeSet::from([ScopeId(vault.work.facet)]));
    let link = |holder: oneiron::EntityId, class: &str| {
        route_json(
            vault.server.clone(),
            core_request_with_authz(
                "POST",
                "/v1/core/pairing/links",
                owner_bearer(),
                Some(&json!({
                    "scope": work, "lifetime_secs": 600,
                    "principal": { "holder_ref": holder.to_hex(), "actor_class": class },
                })),
            ),
        )
    };
    let (status, refused) = link(vault.owner, "human").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(refused.to_string().contains("scope.facets"), "{refused}");
    let (status, issued) = link(vault.agent, "agent").await;
    assert_eq!(status, StatusCode::OK, "{issued}");

    vault
        .connector(
            "fr-owner",
            vault.owner,
            oneiron::EdgeActorClass::Human,
            &McpConnectorScope::vault_wide(),
        )
        .await;
    attenuate_mcp_credential(
        &vault.server,
        "fr-owner",
        oneiron::authority::SlipCaveat {
            scope: Some(work),
            ..Default::default()
        },
    );
    for room in [vault.work, vault.home, vault.private] {
        assert!(vault.lane_reads("fr-owner", room).await);
    }
}

/// FACET-READ check 4: a TASK born under a {work, home} credential whose
/// write facet is home lands in home; in a session whose mode names work it
/// lands in work; a session naming private is refused, on MCP and on the
/// facade alike, and so is setting the session to private.
#[tokio::test]
async fn a_narrowed_birth_lands_in_its_write_facet_or_its_sessions() {
    let vault = facets();
    let member = seeded_test_entity_id(0x2614_0003);
    vault
        .server
        .vault
        .put_entity(
            &member,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"member",
        )
        .expect("onboard member");
    let both = McpConnectorScope::with_facets(
        None,
        set(&[vault.work.facet, vault.home.facet]),
        Some(vault.home.facet),
    )
    .unwrap();
    vault
        .connector("fr-write", member, oneiron::EdgeActorClass::Human, &both)
        .await;
    let session = |facet: oneiron::EntityId| {
        let session = oneiron::EntityId::now();
        vault
            .server
            .vault
            .batch()
            .put(
                &session,
                oneiron::registry::ENTITY_TYPE_SESSION,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&json!({ "facet_ref": facet.to_hex() })).unwrap(),
            )
            .commit()
            .unwrap();
        session
    };
    let (in_work, in_private) = (session(vault.work.facet), session(vault.private.facet));
    let unplaced = oneiron::EntityId::now();
    vault
        .server
        .vault
        .batch()
        .put(
            &unplaced,
            oneiron::registry::ENTITY_TYPE_SESSION,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&json!({})).unwrap(),
        )
        .commit()
        .unwrap();
    let landed = |task: &Value| {
        let task = task
            .as_str()
            .and_then(|task| oneiron::EntityId::from_hex(task).ok())
            .unwrap_or_else(|| panic!("a TASK was born: {task}"));
        [vault.work.facet, vault.home.facet, vault.private.facet]
            .into_iter()
            .filter(|facet| {
                vault
                    .server
                    .vault
                    .row_in_facets(&task, &ScopeAxis::Some(BTreeSet::from([ScopeId(*facet)])))
                    .unwrap()
            })
            .collect::<Vec<_>>()
    };
    let with_session = |mut request: Request<Body>, session: Option<oneiron::EntityId>| {
        if let Some(session) = session {
            request.headers_mut().insert(
                crate::api::write_facet::SESSION_HEADER,
                session.to_hex().parse().unwrap(),
            );
        }
        request
    };
    let mcp = |goal: &'static str, session: Option<oneiron::EntityId>| {
        route_json(
            vault.server.clone(),
            with_session(
                mcp_endpoint_call_request(
                    MCP_TOOL_FIRST_PATH,
                    "fr-write",
                    goal,
                    "tasks.create",
                    mcp_merge_args(
                        mcp_scoped_envelope(member, "write_tasks", &both),
                        json!({ "arguments": { "spec": { "goal": goal }, "label": goal } }),
                    ),
                ),
                session,
            ),
        )
    };
    let facade = |goal: &'static str, session: Option<oneiron::EntityId>| {
        route_json(
            vault.server.clone(),
            with_session(
                core_request_with_authz(
                    "POST",
                    "/v1/core/facade/tasks.create",
                    "Bearer fr-write".to_owned(),
                    Some(&json!({ "spec": { "goal": goal }, "label": goal })),
                ),
                session,
            ),
        )
    };

    let (_, created) = mcp("mcp-home", None).await;
    let output = &created["result"]["structuredContent"]["output"];
    assert_eq!(landed(&output["task_ref"]), [vault.home.facet], "{created}");
    let (_, created) = mcp("mcp-work", Some(in_work)).await;
    let output = &created["result"]["structuredContent"]["output"];
    assert_eq!(landed(&output["task_ref"]), [vault.work.facet], "{created}");
    let refused = mcp_refusal(
        &vault.server,
        with_session(
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                "fr-write",
                "mcp-private",
                "tasks.create",
                mcp_merge_args(
                    mcp_scoped_envelope(member, "write_tasks", &both),
                    json!({ "arguments": { "spec": { "goal": "mcp-private" } } }),
                ),
            ),
            Some(in_private),
        ),
    )
    .await;
    assert_mcp_structured_error(&refused, "mcp_scope_refused");

    let (status, created) = facade("facade-home", None).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(
        landed(&created["task_ref"]),
        [vault.home.facet],
        "{created}"
    );
    let (status, created) = facade("facade-work", Some(in_work)).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(
        landed(&created["task_ref"]),
        [vault.work.facet],
        "{created}"
    );
    let (status, refused) = facade("facade-private", Some(in_private)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    // Audit 2 L1: a session that names no facet places nothing either, and
    // refuses as one placed elsewhere does.
    let (status, unplaced_refusal) = facade("facade-unplaced", Some(unplaced)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{unplaced_refusal}");
    for field in ["code", "message"] {
        assert_eq!(unplaced_refusal["error"][field], refused["error"][field]);
    }

    let (status, refused) = route_json(
        vault.server.clone(),
        core_request_with_authz(
            "PATCH",
            &format!("/v1/core/sessions/{}", in_work.to_hex()),
            "Bearer fr-write".to_owned(),
            Some(&json!({ "mode": "direct", "facet_ref": vault.private.facet.to_hex() })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert_eq!(
        vault.server.vault.session_facet(in_work).unwrap(),
        Some(vault.work.facet)
    );
    // Audit 2 S1: the credential sets the mode only of a session placed in a
    // facet it reads. One placed elsewhere answers as a missing session and
    // keeps its facet.
    let patch = |session: oneiron::EntityId, facet: oneiron::EntityId| {
        route_json(
            vault.server.clone(),
            core_request_with_authz(
                "PATCH",
                &format!("/v1/core/sessions/{}", session.to_hex()),
                "Bearer fr-write".to_owned(),
                Some(&json!({ "mode": "direct", "facet_ref": facet.to_hex() })),
            ),
        )
    };
    let (missing_status, missing) = patch(oneiron::EntityId::now(), vault.work.facet).await;
    assert_ne!(missing_status, StatusCode::OK, "{missing}");
    for hidden in [in_private, unplaced] {
        let (status, body) = patch(hidden, vault.work.facet).await;
        assert_eq!(status, missing_status, "{body}");
        assert_eq!(body["error"]["code"], missing["error"]["code"], "{body}");
    }
    assert_eq!(
        vault.server.vault.session_facet(in_private).unwrap(),
        Some(vault.private.facet)
    );
    assert_eq!(vault.server.vault.session_facet(unplaced).unwrap(), None);
    let (status, body) = patch(in_work, vault.home.facet).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        vault.server.vault.session_facet(in_work).unwrap(),
        Some(vault.home.facet)
    );
}
