//! engine-prs-15: a propose-only slip cannot take a public booking page
//! offline through MCP `claim_upsert`.

use super::*;
use oneiron::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BOOKING_PUBLIC_PAGE_PREDICATE,
    BOOKING_PUBLIC_PAGE_SCHEMA_VERSION, BookingEventTypeClaimValue, BookingPagePublication,
    ConstraintFieldConfig, EventTypeCard, EventTypeConfig, EventTypeKey, HostAvailabilityConfig,
    PublicBookingAvailability, RoutingMode, ThemeTokens, WeeklyWallWindow,
    encode_event_type_claim_value,
};
use oneiron::memory::ClaimInput;
use oneiron::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass};

fn config(host: oneiron::EntityId) -> EventTypeConfig {
    EventTypeConfig {
        key: EventTypeKey("intro".to_owned()),
        duration_min: 30,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 7 * 86_400,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: host,
            calendar_refs: vec![host],
            host_tz: "UTC".to_owned(),
            working_hours: (0..7)
                .map(|weekday| WeeklyWallWindow {
                    weekday,
                    start_minute: 0,
                    end_minute: 1_440,
                })
                .collect(),
            preferred_hours: Vec::new(),
        }],
        flex_windows: Vec::new(),
    }
}

fn publication(config: &EventTypeConfig, owner_display: &str) -> serde_json::Value {
    serde_json::to_value(BookingPagePublication {
        schema_version: BOOKING_PUBLIC_PAGE_SCHEMA_VERSION,
        published: true,
        event_config_hashes: [(
            "intro".to_owned(),
            oneiron::booking::booking_config_hash(config).expect("hash"),
        )]
        .into(),
        owner_display: owner_display.to_owned(),
        event_types: vec![EventTypeCard {
            key: EventTypeKey("intro".to_owned()),
            title: "Intro".to_owned(),
            duration_min: 30,
            description: "A first call".to_owned(),
        }],
        constraint_field: ConstraintFieldConfig {
            enabled: false,
            placeholder: String::new(),
        },
        theme: ThemeTokens(json!({})),
        landing: oneiron::booking::BookingLandingContent::default(),
        initial_availability: PublicBookingAvailability {
            event_type: EventTypeKey("intro".to_owned()),
            start_after_secs: 86_400,
            window_secs: 86_400,
            visitor_tz: "UTC".to_owned(),
        },
    })
    .expect("publication")
}

fn claim(predicate: &str, subject: oneiron::EntityId, value: serde_json::Value) -> ClaimInput {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    ClaimInput {
        id: None,
        predicate: predicate.to_owned(),
        subject_ref: subject.to_hex(),
        value,
        confidence: 1.0,
        source: "user_stated".to_owned(),
        world_ref: None,
        relationship_ref: None,
        scope: None,
        valid_from: Some(now - 60),
        valid_to: Some(now + 86_400),
        occurred_at: None,
        learned_at: None,
        salience: None,
    }
}

async fn public_page_status(server: &Arc<SyncServer>, page: oneiron::EntityId) -> StatusCode {
    let request = Request::builder()
        .method("GET")
        .uri(format!(
            "/public/booking/{}",
            crate::api::booking::booking_page_token(page)
        ))
        .extension(axum::extract::ConnectInfo(
            "127.0.0.1:43123"
                .parse::<std::net::SocketAddr>()
                .expect("peer"),
        ))
        .body(Body::empty())
        .expect("request");
    crate::build_app(Arc::clone(server))
        .oneshot(request)
        .await
        .expect("response")
        .status()
}

/// The owner's own slip, attenuated to read and propose, under a `proposed`
/// ceiling: what `token agent` mints for a propose-only connector. A no-id
/// revision of the live page's publication would move the page's public
/// address to a claim still awaiting review, so it needs write. The same
/// slip still proposes an ordinary claim.
#[tokio::test]
async fn a_propose_only_slip_cannot_take_a_public_booking_page_offline() {
    let (_dir, server) = auth_test_server();
    let owner = seeded_test_entity_id(0x0024_7101);
    let page = seeded_test_entity_id(0x0024_7102);
    let host = seeded_test_entity_id(0x0024_7103);
    for (id, kind, body) in [
        (
            owner,
            oneiron::registry::ENTITY_TYPE_PERSON,
            &b"page owner"[..],
        ),
        (host, oneiron::registry::ENTITY_TYPE_PERSON, &b"host"[..]),
        (
            page,
            oneiron::registry::ENTITY_TYPE_ASSET,
            &b"booking page"[..],
        ),
    ] {
        server
            .vault
            .put_entity(&id, kind, oneiron::TimeRange { start: 1, end: 1 }, 1, body)
            .expect("entity");
    }
    crate::test_credentials::bind_owner(&server.vault, "secret", owner);
    let config = config(host);
    server
        .vault
        .put_claim(
            &seeded_test_entity_id(0x0024_7104),
            &ClaimBody::new(
                BOOKING_EVENT_TYPE_PREDICATE,
                ClaimSubject::Entity(page),
                encode_event_type_claim_value(&BookingEventTypeClaimValue {
                    schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
                    page_ref: page,
                    config: config.clone(),
                })
                .expect("config value"),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )
            .expect("config claim"),
            oneiron::TimeRange { start: 1, end: 1 },
            1,
        )
        .expect("config");
    let published = server
        .vault
        .memory(owner, EdgeActorClass::Human)
        .claim_upsert(&claim(
            BOOKING_PUBLIC_PAGE_PREDICATE,
            page,
            publication(&config, "Host"),
        ))
        .expect("owner publishes");
    assert_eq!(published.approval, "auto");
    assert_eq!(public_page_status(&server, page).await, StatusCode::OK);

    let label = "booking-propose-only";
    let vault_wide = crate::mcp::McpConnectorScope::vault_wide();
    pair_mcp_credential(&server, label, owner, EdgeActorClass::Human, &vault_wide);
    let mut verbs = oneiron::federation::Scope::top();
    verbs.verbs = oneiron::federation::ScopeAxis::Some(
        ["core:read".to_owned(), "core:propose".to_owned()].into(),
    );
    let token = attenuate_mcp_credential(
        &server,
        label,
        oneiron::authority::SlipCaveat {
            scope: Some(verbs),
            ..Default::default()
        },
    );
    server
        .mcp_registry
        .lock()
        .await
        .register(
            &token,
            crate::mcp::McpConnectorActorRecord::new(owner, EdgeActorClass::Human, vault_wide),
        )
        .expect("register");
    oneiron::conversation_dag::test_support::put_test_policy_manifest(
        &server.vault,
        oneiron::write_envelope::WriteActor::new(owner, EdgeActorClass::Human),
        seeded_test_entity_id(0x0024_7105),
        &json!({
            "schema_version": "1.2", "pack_id": "propose-only-owner", "pack_version": "v1",
            "min_engine_version": "0.0.0",
            "defaults": { "criticality": "normal", "sensitivity": "normal" },
            "rules": [],
            "actor_ceilings": [{ "actor_class": "human", "actor_ref": owner.to_hex(),
                "ceiling": "proposed" }],
        }),
    )
    .expect("ceiling");
    assert!(
        server
            .vault
            .gate_actor_ceiling_is_proposed("human", &owner.to_hex())
            .expect("ceiling read"),
        "fixture check: the owner's live ceiling is `proposed`"
    );

    let upsert = |input: &ClaimInput| {
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            label,
            "upsert",
            oneiron::task_verb::sdk::AgentVerb::ClaimUpsert.as_str(),
            mcp_merge_args(
                mcp_endpoint_envelope(owner, "write_memory"),
                json!({"arguments": {"spec": input}}),
            ),
        )
    };
    let revision = claim(
        BOOKING_PUBLIC_PAGE_PREDICATE,
        page,
        publication(&config, "Someone else"),
    );
    let body = mcp_refusal(&server, upsert(&revision)).await;
    assert_eq!(
        body["error"]["data"]["error_code"], "mcp_auth_required",
        "{body}"
    );
    assert_eq!(
        public_page_status(&server, page).await,
        StatusCode::OK,
        "the live page stays up"
    );

    let (_, body) = route_json(
        Arc::clone(&server),
        upsert(&claim("profile.favorite_drink", owner, json!("sencha"))),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    assert_ne!(body["result"]["isError"], json!(true), "{body}");
}
