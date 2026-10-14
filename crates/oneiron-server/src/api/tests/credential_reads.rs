//! `/v1` doors read with a credential's key exactly as the facade's read lane
//! does: the owner's live, full credential reads as the owner, and any other
//! holder reads a relationship's words only on a live grant (ARCH-0006a rule
//! 2, DEC-0005 beam:D5). Unscoped words follow the credential's records.

use super::*;
use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};

const SPACED: &str = "lantern harbor credkey";
const UNSCOPED: &str = "kettle by the stove credkey";

/// A project room holding the owner and the vault's own agent. One message
/// was said in a relationship's space, one in none.
struct Room {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    owner: oneiron::EntityId,
    agent: oneiron::EntityId,
    room: oneiron::EntityId,
    space: oneiron::EntityId,
    spaced: oneiron::EntityId,
    unscoped: oneiron::EntityId,
}

fn room() -> Room {
    let (_dir, server) = interlocutor_test_server();
    let owner = seeded_test_entity_id(0x2401_0001);
    let agent = seeded_test_entity_id(0x2401_0002);
    server
        .vault
        .put_entity(
            &owner,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"room owner",
        )
        .expect("onboard person");
    bind_room_owner(&server, owner);
    let definition = oneiron::agent_def::AgentDefinition::new(
        "oneiron.agent.credkey",
        "Credential reader fixture",
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
    let project = seeded_test_entity_id(0x2401_0003);
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
    let space = seeded_test_entity_id(0x2401_0004);
    let (spaced, unscoped) = (oneiron::EntityId::now(), oneiron::EntityId::now());
    for (message, content, metadata, at) in [
        (spaced, SPACED, Some(json!({ "rel": space.to_hex() })), 2),
        (unscoped, UNSCOPED, None, 3),
    ] {
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
                    content: content.into(),
                    metadata,
                    is_visible: true,
                    order: 0,
                }],
                occurred_at: at,
            })
            .expect("speak");
    }
    Room {
        _dir,
        server,
        owner,
        agent,
        room,
        space,
        spaced,
        unscoped,
    }
}

impl Room {
    fn agent_recipe(&self, records: Option<&[oneiron::EntityId]>) -> String {
        let mut recipe = format!(
            "scope=core:read;principal_ref={};actor_class=agent",
            self.agent.to_hex()
        );
        if let Some(records) = records {
            let ids: Vec<_> = records.iter().map(oneiron::EntityId::to_hex).collect();
            recipe.push_str(&format!(";records={}", ids.join(",")));
        }
        recipe
    }

    /// Grants the agent its read of the spaced message's relationship.
    fn grant(&self, id: oneiron::EntityId) {
        self.server
            .vault
            .create_access_grant(
                &id,
                &AccessGrant {
                    principal_ref: self.agent,
                    scope: AccessGrantScope::Messages {
                        space_ref: self.space,
                    },
                    capability: AccessGrantCapability::MessagesRead,
                    authority_scope: oneiron::federation::Scope::top(),
                    status: AccessGrantStatus::Active,
                    created_at: 1,
                    revoked_at: None,
                    expires_at: None,
                },
            )
            .expect("grant the message's space");
    }

    /// What `recipe` reads of each message on `uri`: the spaced one, then the
    /// unscoped one.
    async fn reads(&self, recipe: &str, uri: &str) -> (bool, bool) {
        let request = match uri {
            "/v1/core/query" => json!({ "query": "credkey" }),
            _ => json!({
                "conversation_id": self.room.to_hex(),
                "query": "credkey",
                "limit": 20,
            }),
        };
        let (status, body) = route_json(
            self.server.clone(),
            core_request_with_authz("POST", uri, test_bearer(recipe), Some(&request)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        let body = body.to_string();
        let seen =
            |id: oneiron::EntityId, text: &str| body.contains(&id.to_hex()) || body.contains(text);
        (seen(self.spaced, SPACED), seen(self.unscoped, UNSCOPED))
    }
}

/// Sol R8 on #1388: a `/v1` key built straight from the slip read a
/// relationship's words with no grant. The vault's own agent reads them on a
/// plain route and in its room's context pack only while a `MessagesRead`
/// grant for the relationship is live, and loses them once it is revoked
/// while its credential stays live. Its unscoped words stay readable
/// throughout.
#[tokio::test]
async fn an_agent_reads_relationship_words_on_v1_only_on_a_live_grant() {
    let room = room();
    let recipe = room.agent_recipe(None);
    let doors = ["/v1/core/query", "/v1/core/context-pack"];
    for uri in doors {
        assert_eq!(
            room.reads(&recipe, uri).await,
            (false, true),
            "{uri}: no grant reads no relationship words"
        );
    }
    let grant = seeded_test_entity_id(0x2401_0005);
    room.grant(grant);
    for uri in doors {
        assert_eq!(
            room.reads(&recipe, uri).await,
            (true, true),
            "{uri}: a live grant reads the relationship's words"
        );
    }
    room.server
        .vault
        .revoke_access_grant(&grant, crate::api::params::unix_seconds_now())
        .expect("revoke the grant");
    for uri in doors {
        assert_eq!(
            room.reads(&recipe, uri).await,
            (false, true),
            "{uri}: a revoked grant reads no relationship words, the slip still live"
        );
    }
}

/// A grant is an extra condition: it never reads a row the credential's
/// records leave out, and an unscoped message the records name needs none.
#[tokio::test]
async fn a_grant_never_widens_a_credentials_records() {
    let room = room();
    let recipe = room.agent_recipe(Some(&[room.unscoped]));
    assert_eq!(room.reads(&recipe, "/v1/core/query").await, (false, true));
    room.grant(seeded_test_entity_id(0x2401_0006));
    assert_eq!(
        room.reads(&recipe, "/v1/core/query").await,
        (false, true),
        "the grant names the space, but the records do not name its message"
    );
}

/// The owner's own live, full credential reads as the owner on `/v1`, as on
/// the facade (#1388, ARCH-0057): a manifest grant that narrows the owner's
/// reads to TURNs narrows neither message. A narrower credential of the
/// owner's stays bounded by its lane, and a key built on the full credential
/// reads nothing once it is revoked.
#[tokio::test]
async fn the_owners_full_credential_reads_as_the_owner_on_v1() {
    let room = room();
    super::context_board_history::restrict_principal_read_types(
        &room.server,
        room.owner,
        &[oneiron::registry::ENTITY_TYPE_TURN],
    );
    let full = format!("principal_ref={};actor_class=human", room.owner.to_hex());
    let narrow = format!(
        "scope=core:read;principal_ref={};actor_class=human",
        room.owner.to_hex()
    );
    assert_eq!(room.reads(&full, "/v1/core/query").await, (true, true));
    assert_eq!(room.reads(&narrow, "/v1/core/query").await, (false, false));

    let auth = slip_credentials::authenticate(&room.server, &full);
    let lane = crate::api::scoped_read_for_core_auth(&room.server.vault, &auth).unwrap();
    let reads = [
        oneiron::claim::PointRead::id(room.spaced),
        oneiron::claim::PointRead::id(room.unscoped),
    ];
    assert!(
        lane.read(&reads, None)
            .unwrap()
            .value
            .iter()
            .all(Option::is_some)
    );
    slip_credentials::revoke(&room.server, &full);
    assert!(
        !matches!(lane.read(&reads, None), Ok(read) if read.value.iter().any(Option::is_some)),
        "a revoked owner credential reads nothing"
    );
    let (status, _) = route_json(
        room.server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/query",
            test_bearer(&full),
            Some(&json!({ "query": "credkey" })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Sol R1-004: the generated facade verbs ran on a `Memory` handle that
/// dropped the credential, so a narrower owner credential read the room as the
/// owner. Bound to its credential, it reads only what its lane admits: here a
/// manifest grant that reads conversations and turns, not messages.
#[tokio::test]
async fn a_narrower_owner_credential_stays_bounded_in_room_verbs() {
    let room = room();
    super::context_board_history::restrict_principal_read_types(
        &room.server,
        room.owner,
        &[
            oneiron::registry::ENTITY_TYPE_CONVERSATION,
            oneiron::registry::ENTITY_TYPE_TURN,
        ],
    );
    let messages = |recipe: String| {
        let server = room.server.clone();
        let request = json!({ "room_ref": room.room.to_hex() });
        async move {
            let (status, body) = route_json(
                server,
                core_request_with_authz(
                    "POST",
                    "/v1/core/facade/rooms.messages",
                    test_bearer(&recipe),
                    Some(&request),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body.to_string()
        }
    };
    let owner = room.owner.to_hex();
    let full = messages(format!("principal_ref={owner};actor_class=human")).await;
    assert!(full.contains(&room.spaced.to_hex()), "{full}");
    let narrow = messages(format!(
        "scope=core:read;principal_ref={owner};actor_class=human"
    ))
    .await;
    for message in [room.spaced, room.unscoped] {
        assert!(!narrow.contains(&message.to_hex()), "{narrow}");
    }
}

/// CodeRabbit on #1413: the campaign surface binds its handle as a person
/// whatever class the credential names, and the read lane judged the owner's
/// exemption by that bound class. So an agent-class credential held by the
/// owner's PERSON read a relationship's words on that handle with no grant,
/// while `/v1/core/query` withheld them. Both withhold them now, and the
/// owner's own person-class credential still reads them on both.
#[tokio::test]
async fn an_agent_class_credential_on_the_owners_person_is_not_the_owners() {
    let room = room();
    let owner = room.owner.to_hex();
    for (class, spaced) in [("agent", false), ("human", true)] {
        let recipe = format!("scope=core:read;principal_ref={owner};actor_class={class}");
        let auth = slip_credentials::authenticate(&room.server, &recipe);
        // Bound as `campaign::dispatch` binds it.
        let memory = crate::api::credential_memory(
            &room.server.vault,
            Some(&auth),
            room.owner,
            oneiron::EdgeActorClass::Human,
        );
        let messages = oneiron::task_verb::sdk::invoke(
            &memory,
            "rooms.messages",
            json!({ "room_ref": room.room.to_hex() }),
        )
        .expect("rooms.messages")
        .to_string();
        assert_eq!(
            (
                messages.contains(&room.spaced.to_hex()),
                messages.contains(&room.unscoped.to_hex())
            ),
            (spaced, true),
            "{class} on the campaign surface's handle: {messages}"
        );
        assert_eq!(
            room.reads(&recipe, "/v1/core/query").await,
            (spaced, true),
            "{class} on /v1/core/query"
        );
    }
}

/// Sol R1-005: a slip cut from the host root and handed to another key
/// (`attenuate_to`) still names the host, but no grant can name its holder.
/// It reads the unscoped words its records name, and no relationship's.
#[tokio::test]
async fn a_host_slip_handed_to_another_key_reads_no_relationship_words() {
    let room = room();
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(b"secret").unwrap();
    let mut slip = room.server.vault.ensure_host_root_slip(&issuer).unwrap();
    let holder = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32]);
    issuer
        .attenuate_to(
            &mut slip,
            oneiron::authority::SlipCaveat {
                records: Some([room.spaced.to_hex(), room.unscoped.to_hex()].into()),
                ..Default::default()
            },
            holder.verifying_key().to_bytes(),
        )
        .unwrap();
    let request = slip_credentials::bind_slip_request(
        &room.server,
        &slip,
        &holder,
        Request::builder()
            .method("POST")
            .uri("/v1/core/query")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "query": "credkey" }).to_string()))
            .unwrap(),
    );
    let (status, body) = route_json(room.server.clone(), request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let body = body.to_string();
    assert!(
        !body.contains(SPACED) && !body.contains(&room.spaced.to_hex()),
        "{body}"
    );
    assert!(
        body.contains(UNSCOPED) || body.contains(&room.unscoped.to_hex()),
        "{body}"
    );
}

/// Whether the agent's standing block, opened on its own credential, quotes
/// the claim said in a relationship's space.
async fn standing_quotes(
    server: &Arc<SyncServer>,
    agent: oneiron::EntityId,
    world: oneiron::EntityId,
) -> bool {
    let (status, body) = route_json(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/context-board",
            test_bearer(&format!(
                "scope=core:read;principal_ref={};actor_class=agent",
                agent.to_hex()
            )),
            Some(&json!({
                "standing": { "world_ref": world.to_hex(), "token_budget": 65_536 }
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["standing"]["compiled"]
        .as_str()
        .is_some_and(|compiled| compiled.contains("lantern-quiet"))
}

/// Sol R1-001: the standing prefix read an agent's standing claims with a key
/// built from its name alone, so under a manifest read grant a claim in a
/// relationship's space came back with no relationship grant. On the agent's
/// credential it needs a live `RelationshipClaimsRead` grant, and loses the
/// claim when that grant is revoked.
#[tokio::test]
async fn an_agents_standing_block_quotes_relationship_claims_only_on_a_live_grant() {
    let (_dir, server) = interlocutor_test_server();
    let agent = seeded_test_entity_id(0x2401_0011);
    let world = seeded_test_entity_id(0x2401_0012);
    let space = seeded_test_entity_id(0x2401_0013);
    for (id, kind) in [
        (agent, oneiron::registry::ENTITY_TYPE_PERSON),
        (world, oneiron::registry::ENTITY_TYPE_WORLD),
        (space, oneiron::registry::ENTITY_TYPE_RELATIONSHIP),
    ] {
        server
            .vault
            .put_entity(
                &id,
                kind,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"fixture",
            )
            .unwrap();
    }
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
        .open_standing_block(&owner, agent, world, "identity", 64)
        .unwrap();
    // The default policy's rules do not name the standing family, and an
    // undeclared predicate pends on the criticality floor.
    super::context_board_history::edit_vault_policy(&server, 199, |entries| {
        use rmpv::Value as Mp;
        let Some((_, Mp::Array(rules))) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("rules"))
        else {
            panic!("the vault policy carries rules");
        };
        rules.push(Mp::Map(vec![
            (Mp::from("prefix"), Mp::from("companion.standing.")),
            (
                Mp::from("axes"),
                Mp::Map(vec![
                    (Mp::from("criticality"), Mp::from("normal")),
                    (Mp::from("sensitivity"), Mp::from("normal")),
                ]),
            ),
        ]));
    });
    let mut claim = oneiron::ClaimBody::new(
        "companion.standing.tone",
        oneiron::ClaimSubject::Entity(agent),
        rmpv::Value::from("lantern-quiet"),
        0.9,
        oneiron::ClaimApprovalStatus::Approved,
        oneiron::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    claim.world = Some(world);
    claim.rel = Some(space);
    server
        .vault
        .put_claim(
            &seeded_test_entity_id(0x2401_0014),
            &claim,
            oneiron::TimeRange { start: 5, end: 5 },
            5,
        )
        .unwrap();
    super::context_board_history::restrict_principal_read_types(
        &server,
        agent,
        &[oneiron::registry::ENTITY_TYPE_CLAIM],
    );
    assert!(!standing_quotes(&server, agent, world).await);
    let grant = seeded_test_entity_id(0x2401_0015);
    server
        .vault
        .create_access_grant(
            &grant,
            &AccessGrant {
                principal_ref: agent,
                scope: AccessGrantScope::RelationshipClaims { space_ref: space },
                capability: AccessGrantCapability::RelationshipClaimsRead,
                authority_scope: oneiron::federation::Scope::top(),
                status: AccessGrantStatus::Active,
                created_at: 1,
                revoked_at: None,
                expires_at: None,
            },
        )
        .expect("grant the claim's relationship");
    assert!(standing_quotes(&server, agent, world).await);
    server
        .vault
        .revoke_access_grant(&grant, crate::api::params::unix_seconds_now())
        .expect("revoke the grant");
    assert!(!standing_quotes(&server, agent, world).await);
}

/// Sol R1-006..008: doors that read a record raw, under no credential key,
/// answered a credential whose records leave that record out: a room's roster
/// and its DAG, a campaign its holder owns, and a companion profile on a live
/// profile grant. Each now refuses the narrowed credential, as the room's
/// transcript and turns already did, and the holder's unnarrowed credential
/// still reads.
#[tokio::test]
async fn raw_doors_refuse_a_credential_whose_records_leave_the_record_out() {
    let room = room();
    let owner = room.owner.to_hex();
    oneiron::campaign::register_crm_pack(
        &room.server.vault,
        107,
        108,
        oneiron::registry::TypeByteFamily::Productivity,
    )
    .expect("register the CRM pack");
    let (status, created) = route_json(
        room.server.clone(),
        core_request_with_authz(
            "POST",
            "/campaigns",
            test_bearer(&format!("principal_ref={owner};actor_class=human")),
            Some(&json!({ "name": "credkey outreach" })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let campaign = created
        .pointer("/body/campaign_ref")
        .or_else(|| created.pointer("/body/record/campaign_ref"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no campaign_ref: {created}"))
        .to_owned();
    let (principal, person, persona) = (
        seeded_test_entity_id(0x2401_0021),
        seeded_test_entity_id(0x2401_0022),
        seeded_test_entity_id(0x2401_0023),
    );
    seed_companion_profile_access(
        &room.server,
        seeded_test_entity_id(0x2401_0024),
        principal,
        person,
        persona,
    );
    let profile = oneiron::PsychProfile::new(
        persona,
        "compact tier",
        "retrieval text tier",
        "Narrative profile tier.",
        vec![seeded_test_entity_id(0x2401_0025)],
        oneiron::psych_profile::PsychProfileConfidence::new(0.8, 0.7, 0.6).expect("confidence"),
    )
    .expect("profile");
    room.server
        .vault
        .put_psych_profile(&persona, &profile)
        .expect("put psych profile");

    let room_ref = room.room.to_hex();
    let doors = [
        (
            format!("/v1/core/conversations/{room_ref}/members"),
            room.agent_recipe(None),
        ),
        (
            format!("/v1/core/conversations/{room_ref}/records"),
            room.agent_recipe(None),
        ),
        (
            format!("/campaigns/{campaign}"),
            format!("scope=core:read;principal_ref={owner};actor_class=human"),
        ),
        (
            format!(
                "/v1/companion/profiles/{}?person_ref={}",
                persona.to_hex(),
                person.to_hex()
            ),
            format!(
                "scope=companion:profile:read;principal_ref={}",
                principal.to_hex()
            ),
        ),
    ];
    for (uri, recipe) in doors {
        let narrowed = format!("{recipe};records={}", room.unscoped.to_hex());
        for (recipe, expected) in [(recipe, StatusCode::OK), (narrowed, StatusCode::FORBIDDEN)] {
            let (status, body) = route_json(
                room.server.clone(),
                core_request_with_authz("GET", &uri, test_bearer(&recipe), None),
            )
            .await;
            assert_eq!(status, expected, "{uri} on {recipe}: {body}");
        }
    }
}

/// Astra #1413-001: the legacy `/api` reads admitted any full-scope slip and
/// then read under the server's own host root, so the vault's agent read a
/// relationship's words there that `/v1` withholds. They read under the
/// presented credential now: the agent's full-scope slip reads the spaced
/// message on neither door, and the host root and the bound owner still read
/// it.
#[tokio::test]
async fn legacy_api_reads_under_the_presented_credential() {
    let room = room();
    let agent = format!("principal_ref={};actor_class=agent", room.agent.to_hex());
    let owner = format!("principal_ref={};actor_class=human", room.owner.to_hex());
    let entity = |id: oneiron::EntityId, recipe: &str| {
        let request = core_request_with_authz(
            "GET",
            &format!("/api/entity/{}?view=full", id.to_hex()),
            test_bearer(recipe),
            None,
        );
        route_json(room.server.clone(), request)
    };
    // The agent's withheld read is the same 404 a missing row gets (Sol
    // R5 on the check: any other refusal would pass for the wrong reason),
    // and the same credential still reads the unscoped message.
    let (status, body) = entity(room.spaced, &agent).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{agent}: {body}");
    let (status, body) = entity(room.unscoped, &agent).await;
    assert!(
        status == StatusCode::OK && body.to_string().contains(UNSCOPED),
        "{agent}: {status} {body}"
    );
    for recipe in ["jti=owner-bearer", owner.as_str()] {
        let (status, body) = entity(room.spaced, recipe).await;
        assert!(
            status == StatusCode::OK && body.to_string().contains(SPACED),
            "{recipe}: {status} {body}"
        );
    }
    assert!(!room.reads(&agent, "/v1/core/query").await.0);
}

/// The reaction signal events `body` carries for `reaction`, sorted.
fn heard(body: &Value, reaction: oneiron::EntityId) -> Vec<String> {
    let mut events: Vec<String> = body["signals"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|signal| signal["reaction"] == reaction.to_hex())
        .map(|signal| signal["event"].as_str().unwrap_or_default().to_owned())
        .collect();
    events.sort();
    events
}

/// One turn of the room fixture: `message`, said by `author` at `at`.
fn room_turn(
    room: &Room,
    message: oneiron::EntityId,
    author: oneiron::memory::WitnessAuthor,
    content: &str,
    metadata: Value,
    at: u64,
) -> oneiron::memory::WitnessTurn {
    oneiron::memory::WitnessTurn {
        conversation_ref: room.room.to_hex(),
        turn_ref: Some(oneiron::EntityId::now().to_hex()),
        messages: vec![oneiron::memory::WitnessMessage {
            id: Some(message.to_hex()),
            author,
            message_type: "text".into(),
            content: content.into(),
            metadata: Some(metadata),
            is_visible: true,
            order: 0,
        }],
        occurred_at: at,
    }
}

/// Astra #1413-002: the signal feed admitted a reacted message under the
/// credential, but the reaction under the room's audience alone, so a
/// credential whose records leave the reaction out heard of it. Each signal
/// is admitted under the credential's own lane now, the reaction CLAIM
/// included, and a removal still reaches a credential that reads the
/// reaction. (Through the context pack, these narrowed credentials also sit
/// under a disclosure clamp that withholds this room's reaction from them,
/// so their lane's admission is checked directly.) A full-scope slip that is
/// not the owner's read the pack's feed raw; it reads it under its own key
/// too: once its grant reads no claim, it hears of no reaction.
#[tokio::test]
async fn reaction_signals_read_under_the_credential() {
    use oneiron::memory::WitnessAuthor;
    let room = room();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let owner = oneiron::WriteActor::new(room.owner, oneiron::EdgeActorClass::Human);
    // The agent answers the owner's mention: words of its own in the room.
    room.server
        .vault
        .bind_room_handle(room.room, "@credkey", room.agent)
        .expect("the agent's room handle");
    let (ask, words) = (oneiron::EntityId::now(), oneiron::EntityId::now());
    let asked = room
        .server
        .vault
        .memory(room.owner, oneiron::EdgeActorClass::Human)
        .rooms_speak(&room_turn(
            &room,
            ask,
            WitnessAuthor::User,
            "credkey for the agent",
            json!({ "room_mentions": ["@credkey"] }),
            4,
        ))
        .expect("the owner asks the agent");
    let asked = oneiron::EntityId::from_hex(
        asked
            .receipt_ref
            .strip_prefix("witness:")
            .expect("a witness receipt"),
    )
    .expect("the asked turn");
    // Membership reads nothing: the agent claims a turn it may read.
    room.server
        .vault
        .install_read_permit_for_test(oneiron::WriteActor::new(
            room.agent,
            oneiron::EdgeActorClass::Agent,
        ))
        .expect("read permit");
    let agent = room
        .server
        .vault
        .memory(room.agent, oneiron::EdgeActorClass::Agent);
    let claim = agent.rooms_claim(room.room, asked, 5);
    assert!(
        matches!(
            claim,
            Ok(oneiron::workspace_roster::RoomClaimOutcome::Claimed(_))
        ),
        "{claim:?}"
    );
    agent
        .rooms_speak(&room_turn(
            &room,
            words,
            WitnessAuthor::Companion,
            "agent kettle credkey",
            json!({ "room_reply_to": asked.to_hex() }),
            5,
        ))
        .expect("the agent answers");
    let reaction = room
        .server
        .vault
        .react(oneiron::reaction::ReactionInput {
            message: words,
            by: room.owner,
            glyph: "👀".to_owned(),
            occurred_at: now,
            actor: owner,
        })
        .expect("the owner reacts")
        .id;
    // The reaction's events in the agent's feed that `recipe`'s own lane
    // admits, as the context pack admits each signal.
    let admitted = |recipe: &str| {
        let auth = crate::test_credentials::authenticate(&room.server, recipe);
        let lane = crate::api::scoped_read_for_core_auth(&room.server.vault, &auth)
            .expect("the credential's lane");
        let mut events = Vec::new();
        for signal in room
            .server
            .vault
            .reactions_since(room.agent, 0)
            .expect("the agent's feed")
        {
            if signal.reaction == reaction
                && lane
                    .is_reaction_signal_readable_under(&signal, None)
                    .expect("signal admission")
            {
                events.push(signal.event().to_owned());
            }
        }
        events.sort();
        events
    };
    let left_out = room.agent_recipe(Some(&[words]));
    let named = room.agent_recipe(Some(&[words, reaction]));
    assert!(
        admitted(&left_out).is_empty(),
        "records that leave the reaction out admit none of it"
    );
    assert_eq!(admitted(&named), ["reaction.put"]);
    room.server
        .vault
        .remove_reaction(words, room.owner, "👀", owner)
        .expect("the owner removes the reaction");
    assert_eq!(
        admitted(&named),
        ["reaction.put", "reaction.revoked"],
        "a removal reaches a credential that reads the reaction"
    );
    assert!(admitted(&left_out).is_empty());

    let full = format!("principal_ref={};actor_class=agent", room.agent.to_hex());
    let signals = || {
        let request = json!({ "query": "credkey", "limit": 20, "signals_since": 0 });
        let (server, recipe) = (room.server.clone(), full.clone());
        async move {
            let (status, body) = route_json(
                server,
                core_request_with_authz(
                    "POST",
                    "/v1/core/context-pack",
                    test_bearer(&recipe),
                    Some(&request),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{recipe}: {body}");
            body
        }
    };
    assert_eq!(
        heard(&signals().await, reaction),
        ["reaction.put", "reaction.revoked"]
    );
    super::context_board_history::restrict_principal_read_types(
        &room.server,
        room.agent,
        &[
            oneiron::registry::ENTITY_TYPE_MESSAGE,
            oneiron::registry::ENTITY_TYPE_TURN,
        ],
    );
    let body = signals().await;
    assert!(
        heard(&body, reaction).is_empty(),
        "a grant that reads no claim hears of no reaction: {body}"
    );
}

/// The rulings' sweep after Astra #1413-002: a records listing's reaction
/// pills were read under the room's audience alone, so a reader whose grant
/// reads messages and turns but no claim still saw who reacted and how. A
/// pill counts only the reactions the caller's own key reads now; the owner's
/// still counts them all.
#[tokio::test]
async fn reaction_pills_read_under_the_credential() {
    let room = room();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    room.server
        .vault
        .react(oneiron::reaction::ReactionInput {
            message: room.unscoped,
            by: room.owner,
            glyph: "👀".to_owned(),
            occurred_at: now,
            actor: oneiron::WriteActor::new(room.owner, oneiron::EdgeActorClass::Human),
        })
        .expect("the owner reacts");
    let pill = |viewer: oneiron::EntityId, class: &'static str| {
        let recipe = format!("principal_ref={};actor_class={class}", viewer.to_hex());
        let uri = format!(
            "/v1/core/conversations/{}/records?with=reactions&viewer={}",
            room.room.to_hex(),
            viewer.to_hex()
        );
        let (server, unscoped) = (room.server.clone(), room.unscoped);
        async move {
            let (status, body) = route_json(
                server,
                core_request_with_authz("GET", &uri, test_bearer(&recipe), None),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{recipe}: {body}");
            let body = body.to_string();
            assert!(body.contains(&unscoped.to_hex()), "{recipe}: {body}");
            body.contains("👀")
        }
    };
    assert!(
        pill(room.agent, "agent").await,
        "a grant that reads claims sees the pill"
    );
    super::context_board_history::restrict_principal_read_types(
        &room.server,
        room.agent,
        &[
            oneiron::registry::ENTITY_TYPE_MESSAGE,
            oneiron::registry::ENTITY_TYPE_TURN,
        ],
    );
    assert!(
        !pill(room.agent, "agent").await,
        "a grant that reads no claim sees no pill"
    );
    assert!(pill(room.owner, "human").await, "the owner sees every pill");
}

/// Sol R5-003 on #1413 (the rulings' sweep): legacy discovery admitted any
/// full-scope slip and then counted, named and dated every row raw, so the
/// vault's agent learned of a relationship's message its own key withholds.
/// A credential short of the whole vault discovers only what its lane reads;
/// the owner's full credential and the host root still discover it all.
#[tokio::test]
async fn legacy_discovery_counts_only_what_the_credential_reads() {
    let room = room();
    let messages = |recipe: String| {
        let server = room.server.clone();
        async move {
            let (status, body) = route_json(
                server,
                core_request_with_authz("GET", "/api/core/discover", test_bearer(&recipe), None),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{recipe}: {body}");
            body["counts"][oneiron::registry::ENTITY_TYPE_MESSAGE.to_string()]
                .as_u64()
                .unwrap_or_default()
        }
    };
    let owner = messages(format!(
        "principal_ref={};actor_class=human",
        room.owner.to_hex()
    ))
    .await;
    assert!(owner >= 2, "the owner counts both messages: {owner}");
    assert_eq!(messages("jti=owner-bearer".to_owned()).await, owner);
    let agent = format!("principal_ref={};actor_class=agent", room.agent.to_hex());
    assert_eq!(
        messages(agent.clone()).await,
        owner - 1,
        "the agent counts no relationship message it cannot read"
    );
    room.grant(seeded_test_entity_id(0x2401_0032));
    assert_eq!(messages(agent).await, owner);
}
