//! BK-PERSONAL-LINKS through the real public router: a personal link serves
//! the page's own offer, names its recipient, books that recipient alone,
//! and dies on "not you?", on revocation and with its page. Every refusal is
//! the one public 404.

use super::fixture::*;
use super::*;
use oneiron::booking::{
    PersonalLinkEndReason, PersonalLinkMint, PersonalLinkRecipient, mint_personal_booking_link,
    personal_booking_links, revoke_personal_booking_link,
};

/// A token of the personal shape that was never minted.
const UNKNOWN_PERSONAL_TOKEN: &str =
    "bkr_0000000000000000000000000000000000000000000000000000000000000000";

fn mint(fixture: &Fixture, email: &str, name: &str) -> PersonalLinkMint {
    mint_personal_booking_link(
        &fixture.server.vault.memory(id(0x77), EdgeActorClass::Human),
        fixture.page,
        &PersonalLinkRecipient {
            email: email.to_owned(),
            name: name.to_owned(),
        },
        now_secs().expect("clock"),
    )
    .expect("the owner mints a personal link")
}

/// Status and body of one request through the public router.
async fn answer(fixture: &Fixture, method: &str, path: &str, body: Value) -> (StatusCode, Vec<u8>) {
    let response = fixture.route(method, path, body).await;
    let status = response.status();
    (status, bytes(response).await)
}

async fn page_json(fixture: &Fixture, token: &str) -> Value {
    let (status, body) = answer(
        fixture,
        "GET",
        &format!("/public/booking/{token}"),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "page {token}");
    serde_json::from_slice(&body).expect("page JSON")
}

fn availability_over(slot: &RankedSlot, session: &str) -> Value {
    serde_json::to_value(BookingAvailabilityInput {
        event_type: EventTypeKey("intro".to_owned()),
        window: TimeRange {
            start: slot.start_utc,
            end: slot.end_utc - 1,
        },
        visitor_tz: "UTC".to_owned(),
        constraint: None,
        session_ref: session.to_owned(),
    })
    .expect("availability body")
}

fn confirm_as(hold_token: String, session: &str, email: &str) -> Value {
    let mut request = confirm(hold_token, session);
    if let BookingOperationRequest::Book(BookingBookInput::Confirm(input)) = &mut request {
        email.clone_into(&mut input.booker_email);
    }
    serde_json::to_value(request).expect("confirm body")
}

/// The Finding notices addressed to `recipient` that a personal link wrote.
fn link_notices(fixture: &Fixture, recipient: EntityId) -> Vec<oneiron::inbox::NotificationBody> {
    let ids = fixture
        .server
        .vault
        .entities_by_type_page(oneiron::registry::ENTITY_TYPE_NOTIFICATION, None, 512)
        .expect("notification ids");
    ids.iter()
        .filter_map(|id| fixture.server.vault.get(id).expect("notification read"))
        .filter_map(|raw| oneiron::inbox::decode_notification_body(&raw).ok())
        .filter(|body| {
            body.source.producer == oneiron::booking::PERSONAL_LINK_NOTICE_PRODUCER
                && body.recipient.as_deref() == Some(recipient.to_hex().as_str())
        })
        .collect()
}

#[tokio::test]
async fn public_booking_personal_link_serves_only_its_recipient() {
    let fixture = Fixture::new();
    let minted = mint(&fixture, " A@Example.test ", "Ada");
    let token = minted.token.clone();
    assert!(token.starts_with("bkr_"));
    assert_eq!(token.len(), 68);
    assert!(!token.contains(&fixture.page.to_hex()));
    assert_eq!(minted.link.recipient.email, "a@example.test");
    assert_eq!(minted.link.page_ref, fixture.page);

    // The page's own offer, naming who it is for; its actions carry the
    // personal token so the visitor's book stays under the lock.
    let shared = page_json(&fixture, &fixture.token).await;
    let personal = page_json(&fixture, &token).await;
    assert_eq!(
        personal["recipient"],
        json!({"name": "Ada", "email": "a@example.test"})
    );
    assert!(shared.get("recipient").is_none());
    // The slots are solved per render; the offer itself is the page's.
    for field in [
        "owner_display",
        "event_types",
        "constraint_field",
        "theme",
        "landing",
    ] {
        assert_eq!(personal["model"][field], shared["model"][field], "{field}");
    }
    let card = personal["card"].to_string();
    assert!(card.contains(&token));
    assert!(!card.contains(&fixture.token));

    // Availability and hold through the link.
    let slots = fixture.slots().await;
    let (status, body) = answer(
        &fixture,
        "POST",
        &format!("/public/booking/{token}/availability"),
        availability_over(&slots[0], "ada"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let BookingOperationResponse::Availability { slots: offered, .. } =
        serde_json::from_slice(&body).expect("availability")
    else {
        panic!("availability")
    };
    assert_eq!(
        offered.first().map(|slot| slot.start_utc),
        Some(slots[0].start_utc)
    );
    let held = fixture
        .dispatch_at(
            &token,
            "booking.hold",
            hold(selected(&slots[0]), "ada", None),
        )
        .await
        .expect("hold through the personal link");
    let BookingOperationResponse::Book(BookingBookResult::Held { hold_token, .. }) = held else {
        panic!("held, got {held:?}")
    };

    // Another recipient gets exactly what a dead link gets.
    let confirm_path = format!("/public/booking/{token}/verbs/booking.confirm");
    let stranger = answer(
        &fixture,
        "POST",
        &confirm_path,
        confirm_as(hold_token.clone(), "ada", "b@example.test"),
    )
    .await;
    let unknown = answer(
        &fixture,
        "POST",
        &format!("/public/booking/{UNKNOWN_PERSONAL_TOKEN}/verbs/booking.confirm"),
        confirm_as(hold_token.clone(), "ada", "b@example.test"),
    )
    .await;
    assert_eq!(stranger.0, StatusCode::NOT_FOUND);
    assert_eq!(stranger, unknown);

    // The recipient books, however the address is spelled.
    let (status, body) = answer(
        &fixture,
        "POST",
        &confirm_path,
        confirm_as(hold_token, "ada", "A@EXAMPLE.test"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(matches!(
        serde_json::from_slice(&body).expect("confirm"),
        BookingOperationResponse::Book(BookingBookResult::Confirmed { .. })
    ));

    // "not you?" ends the link and tells its minter.
    assert!(link_notices(&fixture, id(0x77)).is_empty());
    let (status, body) = answer(
        &fixture,
        "POST",
        &format!("/public/booking/{token}/not-you"),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).expect("void"),
        json!({"voided": true})
    );
    let notices = link_notices(&fixture, id(0x77));
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].kind, oneiron::inbox::NotificationKind::Finding);
    assert_eq!(
        notices[0].source.result.as_deref(),
        Some(minted.link.link_ref.as_str())
    );
    assert_eq!(notices[0].subject_refs, vec![fixture.page.to_hex()]);

    // From then on the link is a dead link on every route.
    let dead_page = answer(
        &fixture,
        "GET",
        &format!("/public/booking/{token}"),
        Value::Null,
    )
    .await;
    let unknown_page = answer(
        &fixture,
        "GET",
        &format!("/public/booking/{UNKNOWN_PERSONAL_TOKEN}"),
        Value::Null,
    )
    .await;
    assert_eq!(dead_page.0, StatusCode::NOT_FOUND);
    assert_eq!(dead_page, unknown_page);
    let (status, _) = answer(
        &fixture,
        "POST",
        &format!("/public/booking/{token}/availability"),
        availability_over(&slots[1], "ada"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        fixture
            .dispatch_at(
                &token,
                "booking.hold",
                hold(selected(&slots[1]), "ada-2", None)
            )
            .await
            .expect_err("a voided link holds nothing"),
        StatusCode::NOT_FOUND
    );
    let again = answer(
        &fixture,
        "POST",
        &format!("/public/booking/{token}/not-you"),
        Value::Null,
    )
    .await;
    assert_eq!(again, unknown_page);
    assert_eq!(link_notices(&fixture, id(0x77)).len(), 1);

    // The page itself still serves.
    let _ = page_json(&fixture, &fixture.token).await;
}

#[tokio::test]
async fn a_personal_link_ends_with_its_revocation_and_its_page() {
    let fixture = Fixture::new();
    let owner = || fixture.server.vault.memory(id(0x77), EdgeActorClass::Human);
    let first = mint(&fixture, "a@example.test", "Ada");
    let second = mint(&fixture, "c@example.test", "Cy");
    let unknown_page = answer(
        &fixture,
        "GET",
        &format!("/public/booking/{UNKNOWN_PERSONAL_TOKEN}"),
        Value::Null,
    )
    .await;
    assert_eq!(unknown_page.0, StatusCode::NOT_FOUND);

    // A revoked link is a dead link; its sibling is untouched.
    let now = now_secs().expect("clock");
    assert!(revoke_personal_booking_link(&owner(), &first.link.link_ref, now).expect("revoke"));
    assert!(
        !revoke_personal_booking_link(&owner(), &first.link.link_ref, now)
            .expect("a second revoke ends nothing")
    );
    for (method, suffix) in [("GET", ""), ("POST", "/not-you")] {
        let dead = answer(
            &fixture,
            method,
            &format!("/public/booking/{}{suffix}", first.token),
            Value::Null,
        )
        .await;
        assert_eq!(dead, unknown_page, "{method} {suffix}");
    }
    let _ = page_json(&fixture, &second.token).await;
    let links = personal_booking_links(&fixture.server.vault, fixture.page).expect("links");
    assert_eq!(links.len(), 2);
    let ended = |link_ref: &str| {
        links
            .iter()
            .find(|link| link.link_ref == link_ref)
            .expect("listed")
            .ended
            .map(|end| end.reason)
    };
    assert_eq!(
        ended(&first.link.link_ref),
        Some(PersonalLinkEndReason::Revoked)
    );
    assert_eq!(ended(&second.link.link_ref), None);
    assert!(link_notices(&fixture, id(0x77)).is_empty());

    // "not you?" answers personal links only.
    let page_void = answer(
        &fixture,
        "POST",
        &format!("/public/booking/{}/not-you", fixture.token),
        Value::Null,
    )
    .await;
    assert_eq!(page_void.0, StatusCode::NOT_FOUND);

    // The link serves only while its page is published.
    let until = now_secs().expect("clock") + 86_400;
    fixture.publish_page(fixture.page, false, 1, until);
    let hidden = answer(
        &fixture,
        "GET",
        &format!("/public/booking/{}", second.token),
        Value::Null,
    )
    .await;
    assert_eq!(hidden, unknown_page);
    assert!(
        mint_personal_booking_link(
            &owner(),
            fixture.page,
            &PersonalLinkRecipient {
                email: "d@example.test".to_owned(),
                name: "Di".to_owned(),
            },
            now_secs().expect("clock"),
        )
        .is_err(),
        "no link to an unpublished page"
    );
    fixture.publish_page(fixture.page, true, 1, until);
    let _ = page_json(&fixture, &second.token).await;
}

/// One owner verb through the facade, as `principal` holding an owner-grade
/// human credential: status and JSON body (`null` for an empty one).
async fn facade_verb(
    fixture: &Fixture,
    principal: EntityId,
    verb: &str,
    body: Value,
) -> (StatusCode, Value) {
    let recipe = format!("principal_ref={};actor_class=human", principal.to_hex());
    let (slip, key) = crate::test_credentials::credential(&fixture.server, &recipe);
    let request = crate::test_credentials::bind_slip_request(
        &fixture.server,
        &slip,
        &key,
        Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header(CONTENT_TYPE, "application/json")
            .extension(ConnectInfo(
                "127.0.0.1:43123".parse::<SocketAddr>().expect("peer"),
            ))
            .body(Body::from(body.to_string()))
            .expect("request"),
    );
    let response = crate::build_app(fixture.server.clone())
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let body = bytes(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// The fixture with its page published by the vault's own owner, the actor
/// an owner door's proof admits: the embedded owner, bound to the host key
/// again (the fixture moved that binding to its stand-in owner `id(0x77)`)
/// and publishing the page in its own name.
fn fixture_of_the_vault_owner() -> (Fixture, EntityId) {
    let fixture = Fixture::new();
    let owner = fixture.owner_actor();
    crate::test_credentials::bind_owner(&fixture.server.vault, "owner-fixture-secret", owner);
    let memory = fixture.server.vault.memory(owner, EdgeActorClass::Human);
    let receipt = memory
        .claim_upsert(&publication_input(
            fixture.page,
            true,
            1,
            now_secs().expect("clock") + 86_400,
        ))
        .expect("the vault owner publishes the page");
    if receipt.approval == "proposed" {
        memory
            .confirm_booking_publication(&receipt.claim_short_id, now_secs().expect("clock"))
            .expect("the vault owner confirms the revision");
    }
    (fixture, owner)
}

#[tokio::test]
async fn the_owner_mints_lists_and_revokes_personal_links_through_its_verbs() {
    let (fixture, owner) = fixture_of_the_vault_owner();
    let page_ref = fixture.page.to_hex();
    let _ = page_json(&fixture, &fixture.token).await;

    // Only the owner mints.
    let (status, _) = facade_verb(
        &fixture,
        id(0x78),
        "vault.booking.personal_link.mint",
        json!({"page_ref": page_ref, "recipient_email": "a@example.test", "recipient_name": "Ada"}),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "a non-owner mints nothing");

    let (status, minted) = facade_verb(
        &fixture,
        owner,
        "vault.booking.personal_link.mint",
        json!({"page_ref": page_ref, "recipient_email": "A@Example.test", "recipient_name": "Ada"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    let token = minted["token"].as_str().expect("token").to_owned();
    let link_ref = minted["link"]["link_ref"]
        .as_str()
        .expect("link_ref")
        .to_owned();
    assert!(token.starts_with("bkr_"));
    assert_eq!(minted["link"]["recipient_email"], "a@example.test");
    assert_eq!(minted["link"]["page_ref"], page_ref.as_str());
    assert!(minted["link"]["ended_at"].is_null());

    // The minted link serves its page, naming its recipient.
    let page = page_json(&fixture, &token).await;
    assert_eq!(page["recipient"]["name"], "Ada");

    // The list names it without its token.
    let (status, listed) = facade_verb(
        &fixture,
        owner,
        "vault.booking.personal_link.list",
        json!({"page_ref": page_ref}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed["links"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed["links"][0]["link_ref"], link_ref.as_str());
    assert!(!listed.to_string().contains(&token));

    // Revoked, it is a dead link, and the list says why.
    let (status, revoked) = facade_verb(
        &fixture,
        owner,
        "vault.booking.personal_link.revoke",
        json!({"link_ref": link_ref}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    assert_eq!(revoked, json!({"revoked": true}));
    let (status, _) = answer(
        &fixture,
        "GET",
        &format!("/public/booking/{token}"),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, listed) = facade_verb(
        &fixture,
        owner,
        "vault.booking.personal_link.list",
        json!({"page_ref": page_ref}),
    )
    .await;
    assert_eq!(listed["links"][0]["ended_reason"], "revoked");
}
