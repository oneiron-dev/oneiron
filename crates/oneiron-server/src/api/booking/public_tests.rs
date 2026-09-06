use super::fixture::*;
use super::*;

#[tokio::test]
async fn public_booking_render_requires_no_authentication() {
    let fixture = Fixture::new();
    let before = now_secs().expect("clock");
    let path = format!("/public/booking/{}", fixture.token);
    let response = fixture.route("GET", &path, Value::Null).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_inline(&response);
    let value: Value = serde_json::from_slice(&bytes(response).await).expect("page JSON");
    let expected = publication_input(fixture.page, true, 1, before + 86_400).value;
    for field in ["owner_display", "event_types", "constraint_field", "theme"] {
        assert_eq!(
            value["model"][field], expected[field],
            "owner field {field}"
        );
    }
    let model: BookingPageModel = serde_json::from_value(value["model"].clone()).expect("model");
    let oneiron::booking::RungProjection::Slots(mask) = &model.slots else {
        panic!("slots only")
    };
    assert!(!mask.slots.is_empty());
    assert!(mask.window_start_utc >= before + 86_400);
    assert_eq!(mask.window_end_utc - mask.window_start_utc, 86_400);
    assert!(
        mask.slots
            .iter()
            .all(|slot| slot.start_utc >= mask.window_start_utc
                && slot.end_utc <= mask.window_end_utc
                && slot.end_utc - slot.start_utc == 1_800)
    );
    let card: oneiron::lens::GeneratedUiCard =
        serde_json::from_value(value["card"].clone()).expect("existing card");
    assert_eq!(
        card,
        BookingPageLens::card_with_actions(
            &model,
            &PublicBookingPageToken(fixture.token.clone()),
            &[PublicBookingAction::Hold]
        )
        .expect("assembly")
    );
    assert!(card.render().is_ok());
    let authenticated_path = format!("/api/booking/{}/agent-instructions", fixture.token);
    assert_eq!(
        fixture
            .route("GET", &authenticated_path, Value::Null)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let context =
        public_http_transport_context(Ok(ConnectInfo("127.0.0.1:43123".parse().expect("peer"))))
            .expect("context");
    assert_eq!(context.authenticated_actor_ref, None);
    assert_eq!(context.transport, BookingTransport::PublicHttp);
    assert_eq!(
        context.source_ip,
        "127.0.0.1".parse::<IpAddr>().expect("IP")
    );
}

#[tokio::test]
async fn public_booking_token_does_not_reveal_entity_or_vault_ids() {
    let fixture = Fixture::new();
    assert!(EntityId::from_hex(&fixture.token).is_err());
    assert!(!fixture.token.contains(&fixture.page.to_hex()));
    let response = fixture
        .route(
            "GET",
            &format!("/public/booking/{}", fixture.token),
            Value::Null,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = serde_json::from_slice(&bytes(response).await).expect("actual served JSON");
    let wire = serde_json::to_string(&value).expect("wire");
    assert!(wire.contains(&fixture.token));
    for leak in [
        fixture.page.to_hex(),
        id(0x73).to_hex(),
        id(0x74).to_hex(),
        "vault_id".to_owned(),
        "page_ref".to_owned(),
        "EntityId".to_owned(),
    ] {
        assert!(!wire.contains(&leak), "leak: {leak}");
    }
    assert_eq!(
        value["card"]["actions"][0]["action"]["command"],
        "booking.hold"
    );
}

#[tokio::test]
async fn public_booking_unknown_token_is_non_oracular_404() {
    let fixture = Fixture::unpublished();
    let mut bodies = Vec::new();
    for token in [
        "invalid".to_owned(),
        "%FF".to_owned(),
        format!("bkp_{}", "00".repeat(16)),
        fixture.token.clone(),
        fixture.page.to_hex(),
    ] {
        let response = fixture
            .route("GET", &format!("/public/booking/{token}"), Value::Null)
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_inline(&response);
        bodies.push(bytes(response).await);
    }
    assert!(bodies.windows(2).all(|pair| pair[0] == pair[1]));
    // A publish-page INVITE grant must not turn into public-read authority.
    oneiron::booking::mint_publish_page_invite_grant(
        &fixture.server.vault,
        &oneiron::booking::PublishBookingPageGrantRequest {
            page_ref: fixture.page,
            publisher_principal: fixture.page,
            issued_at: 1,
        },
    )
    .expect("invite grant");
    let response = fixture
        .route(
            "GET",
            &format!("/public/booking/{}", fixture.token),
            Value::Null,
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(bytes(response).await, bodies[0]);
}

#[tokio::test]
async fn public_booking_disallowed_verb_is_404_or_405() {
    let fixture = Fixture::new();
    for verb in [
        "search",
        "read",
        "edit",
        "mcp",
        "connector",
        "shell",
        "booking.availability",
        "booking.book",
    ] {
        let response = fixture
            .route(
                "POST",
                &format!("/public/booking/{}/verbs/{verb}", fixture.token),
                json!({}),
            )
            .await;
        assert!(matches!(
            response.status(),
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ));
        assert_public_denial(response).await;
    }
    for suffix in [
        "artifact/secret",
        "api/entity/secret",
        "mcp",
        "verbs/search/extra",
    ] {
        let response = fixture
            .route(
                "GET",
                &format!("/public/booking/{}/{suffix}", fixture.token),
                Value::Null,
            )
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_public_denial(response).await;
    }
    let missing = fixture.route("GET", "/public/booking/", Value::Null).await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_public_denial(missing).await;
}

#[tokio::test]
async fn public_booking_response_never_redirects_or_downloads() {
    let fixture = Fixture::new();
    let path = format!("/public/booking/{}", fixture.token);
    for (method, suffix, body) in [
        ("GET", "", Value::Null),
        ("POST", "", json!({})),
        ("POST", "/verbs/booking.hold", json!({})),
        ("PUT", "", json!({})),
    ] {
        let response = fixture
            .route(method, &format!("{path}{suffix}"), body)
            .await;
        assert_inline(&response);
    }
    for response in [
        Json(json!({"ok": true})).into_response(),
        ApiError::bad_request("fixture refusal", None).into_response(),
        ApiError::invalid_state(Some("booking_slot_taken")).into_response(),
        (
            StatusCode::FOUND,
            [(LOCATION, "https://invalid.example/")],
            "redirect",
        )
            .into_response(),
        (
            [
                (CONTENT_TYPE, "application/octet-stream"),
                (CONTENT_DISPOSITION, "attachment"),
            ],
            "download",
        )
            .into_response(),
        ([(CONTENT_TYPE, "application/javascript")], "alert(1)").into_response(),
    ] {
        assert_inline(&public_booking_response(response).await);
    }
}

#[tokio::test]
async fn public_booking_publication_lifetime_and_revocation_are_non_oracular() {
    let fixture = Fixture::unpublished();
    let page_path = format!("/public/booking/{}", fixture.token);
    let unknown = fixture
        .route("GET", "/public/booking/unknown", Value::Null)
        .await;
    let refusal = bytes(unknown).await;
    let now = now_secs().expect("clock");
    // Each state is written by the actual owner facade, never a test resolver.
    for (published, from, until) in [
        (false, 1, now + 86_400),
        (true, 1, now),
        (true, now + 3_600, now + 86_400),
    ] {
        fixture.publish_page(fixture.page, published, from, until);
        for (method, suffix, body) in [
            ("GET", "", Value::Null),
            (
                "POST",
                "/verbs/booking.hold",
                serde_json::to_value(hold(
                    SelectedSlot {
                        start_utc: now + 86_400,
                        end_utc: now + 88_200,
                    },
                    "denied",
                    None,
                ))
                .expect("request"),
            ),
            ("POST", "/verbs/booking.confirm", json!({"malformed": true})),
        ] {
            let response = fixture
                .route(method, &format!("{page_path}{suffix}"), body)
                .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_inline(&response);
            assert_eq!(bytes(response).await, refusal);
        }
    }
    let claim = fixture.publish_page(fixture.page, true, 1, now + 86_400);
    assert_eq!(
        fixture.route("GET", &page_path, Value::Null).await.status(),
        StatusCode::OK
    );
    fixture
        .server
        .vault
        .memory(id(0x77), EdgeActorClass::Human)
        .claim_retract(&claim)
        .expect("owner revocation");
    for (method, suffix) in [("GET", ""), ("POST", "/verbs/booking.hold")] {
        let response = fixture
            .route(method, &format!("{page_path}{suffix}"), json!({}))
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(bytes(response).await, refusal);
    }
    // Neither the old superseded allow nor the retracted head can reappear.
    let rebuilt = Arc::new(
        SyncServer::new(fixture.server.vault.clone(), fixture.server.config.clone())
            .expect("rebuild server"),
    );
    let response = crate::build_app(rebuilt)
        .oneshot(
            Request::builder()
                .uri(&page_path)
                .extension(ConnectInfo(
                    "127.0.0.1:43123".parse::<SocketAddr>().expect("peer"),
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(bytes(response).await, refusal);
}

#[tokio::test]
async fn public_booking_only_owner_writes_publish_and_exact_presentation_updates_serve() {
    let fixture = Fixture::unpublished();
    let now = now_secs().expect("clock");
    let input = publication_input(fixture.page, true, 1, now + 86_400);
    let agent = fixture.server.vault.memory(id(0x77), EdgeActorClass::Agent);
    assert_eq!(
        agent
            .claim_upsert(&input)
            .expect_err("agent cannot publish")
            .code,
        oneiron::memory::MEMORY_CODE_FORBIDDEN
    );
    assert_eq!(
        agent
            .commit(std::slice::from_ref(&input))
            .expect("per-claim receipt")[0]
            .approval,
        "rejected"
    );
    let path = format!("/public/booking/{}", fixture.token);
    assert_eq!(
        fixture.route("GET", &path, Value::Null).await.status(),
        StatusCode::NOT_FOUND
    );
    fixture.publish_page(fixture.page, true, 1, now + 86_400);
    let mut changed = input;
    changed.value["owner_display"] = json!("Updated owner display");
    changed.value["event_types"][0]["title"] = json!("Updated event title");
    changed.value["constraint_field"]["placeholder"] = json!("Updated owner constraint");
    changed.value["theme"] = json!([null, {"unknown-replacement": "opaque"}]);
    let receipt = fixture
        .server
        .vault
        .memory(id(0x77), EdgeActorClass::Human)
        .claim_upsert(&changed)
        .expect("owner edits presentation");
    assert!(receipt.superseded_short_id.is_some());
    let response = fixture.route("GET", &path, Value::Null).await;
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = serde_json::from_slice(&bytes(response).await).expect("page");
    for field in ["owner_display", "event_types", "constraint_field", "theme"] {
        assert_eq!(value["model"][field], changed.value[field]);
    }
    // The same id as a HUMAN publication is not rewriteable as an agent head.
    changed.id = Some(
        oneiron::memory::resolve_entity_ref(&fixture.server.vault, &receipt.claim_short_id)
            .expect("claim id")
            .to_hex(),
    );
    assert!(agent.claim_upsert(&changed).is_err());
    assert!(agent.claim_retract(&receipt.claim_short_id).is_err());
    assert_eq!(
        fixture.route("GET", &path, Value::Null).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn public_booking_requires_real_peer_context_not_forwarding_headers() {
    let fixture = Fixture::new();
    let path = format!("/public/booking/{}", fixture.token);
    for (method, suffix, body) in [
        ("GET", "", Value::Null),
        (
            "POST",
            "/verbs/booking.hold",
            serde_json::to_value(hold(
                SelectedSlot {
                    start_utc: 10,
                    end_utc: 20,
                },
                "no-peer",
                None,
            ))
            .expect("request"),
        ),
    ] {
        let response = crate::build_app(fixture.server.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(format!("{path}{suffix}"))
                    .header(CONTENT_TYPE, "application/json")
                    .header("x-forwarded-for", "127.0.0.1")
                    .body(Body::from(serde_json::to_vec(&body).expect("body")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_inline(&response);
    }
    // A normal request carrying real peer context succeeds even with a forged
    // forwarding header. The once-only quota test pins which address is charged.
    assert_eq!(
        fixture.route("GET", &path, Value::Null).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn public_booking_render_admits_once_and_ignores_spoofed_source_ip() {
    use oneiron::booking::anti_abuse::observe_slot_list_request;
    for _ in 0..3 {
        // Amend after publication: both booking claim schemas are present.
        let fixture = Fixture::new();
        let limit = NonZeroU32::new(2).expect("limit");
        let scope = BookingRuleScope {
            page_ref: fixture.page,
            event_type: None,
        };
        let rule = BookingAntiAbuseRule::SlotListRate {
            per_minute_per_ip: limit,
            cache_ttl_secs: std::num::NonZeroU64::new(30).expect("TTL"),
        };
        apply_rule_amendment(
            &fixture.server.vault,
            0,
            BookingAntiAbuseRuleRow {
                row_id: booking_rule_row_id(&scope, &rule),
                scope,
                rule,
                version: 1,
                amended_at: 0,
                amended_by: fixture.page,
                owner_stamp_ref: None,
            },
            None,
        )
        .expect("rate rule");
        let now = now_secs().expect("clock");
        let response = fixture
            .route(
                "GET",
                &format!("/public/booking/{}", fixture.token),
                Value::Null,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        if now / 60 != now_secs().expect("clock") / 60 {
            continue;
        }
        let peer = booking_ip_hash("127.0.0.1");
        assert_eq!(
            observe_slot_list_request(&fixture.server.vault, &peer, limit, now).expect("one left"),
            BookingRateDecision::Allowed
        );
        assert!(matches!(
            observe_slot_list_request(&fixture.server.vault, &peer, limit, now).expect("spent"),
            BookingRateDecision::Exceeded { .. }
        ));
        let spoof = booking_ip_hash("198.51.100.7");
        for _ in 0..2 {
            assert_eq!(
                observe_slot_list_request(&fixture.server.vault, &spoof, limit, now)
                    .expect("untouched spoof"),
                BookingRateDecision::Allowed
            );
        }
        return;
    }
    panic!("could not observe render within one rate window");
}

#[tokio::test]
async fn public_booking_needs_live_surfaceable_publication_and_matching_configuration() {
    let fixture = Fixture::new();
    let path = format!("/public/booking/{}", fixture.token);
    let claim_ref =
        fixture.publish_page(fixture.page, true, 1, now_secs().expect("clock") + 86_400);
    let claim_id =
        oneiron::memory::resolve_entity_ref(&fixture.server.vault, &claim_ref).expect("claim id");
    let original = fixture
        .server
        .vault
        .get_claim(&claim_id)
        .expect("read")
        .expect("publication");
    let unknown = bytes(
        fixture
            .route("GET", "/public/booking/unknown", Value::Null)
            .await,
    )
    .await;
    for (approval, stale) in [
        (ClaimApprovalStatus::Proposed, false),
        (ClaimApprovalStatus::Rejected, false),
        (ClaimApprovalStatus::Auto, true),
    ] {
        // Existing low-level claim door models replicated/status-updated rows;
        // successful setup and publication still went through the owner facade.
        let mut body = original.clone();
        body.approval = approval;
        body.stale = stale;
        fixture
            .server
            .vault
            .put_claim(&claim_id, &body, TimeRange { start: 1, end: 1 }, 1)
            .expect("status");
        let response = fixture.route("GET", &path, Value::Null).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(bytes(response).await, unknown);
    }
    fixture
        .server
        .vault
        .put_claim(&claim_id, &original, TimeRange { start: 1, end: 1 }, 1)
        .expect("restore owner head");
    let mut config = fixture
        .server
        .vault
        .get_claim(&id(0x72))
        .expect("config")
        .expect("body");
    config.stale = true;
    fixture
        .server
        .vault
        .put_claim(&id(0x72), &config, TimeRange { start: 1, end: 1 }, 1)
        .expect("stale config");
    let response = fixture.route("GET", &path, Value::Null).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(bytes(response).await, unknown);
}
