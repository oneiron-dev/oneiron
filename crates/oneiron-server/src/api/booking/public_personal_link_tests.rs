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

/// The vault's embedded owner mints, the actor the fixture publishes its
/// page as (H149).
fn mint(fixture: &Fixture, email: &str, name: &str) -> PersonalLinkMint {
    mint_personal_booking_link(
        &fixture
            .server
            .vault
            .memory(fixture.owner_actor(), EdgeActorClass::Human),
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
        duration_min: None,
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
    assert!(link_notices(&fixture, fixture.owner_actor()).is_empty());
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
    let notices = link_notices(&fixture, fixture.owner_actor());
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
    assert_eq!(link_notices(&fixture, fixture.owner_actor()).len(), 1);

    // The page itself still serves.
    let _ = page_json(&fixture, &fixture.token).await;
}

#[tokio::test]
async fn a_personal_link_ends_with_its_revocation_and_its_page() {
    let fixture = Fixture::new();
    let owner = || {
        fixture
            .server
            .vault
            .memory(fixture.owner_actor(), EdgeActorClass::Human)
    };
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
    assert!(link_notices(&fixture, fixture.owner_actor()).is_empty());

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
    let credential = owner_credential(fixture, principal);
    facade_verb_as(fixture, &credential, verb, body, None).await
}

/// An owner-grade human credential of `principal`.
fn owner_credential(
    fixture: &Fixture,
    principal: EntityId,
) -> (
    oneiron::authority::CapabilitySlip,
    ed25519_dalek::SigningKey,
) {
    let recipe = format!("principal_ref={};actor_class=human", principal.to_hex());
    crate::test_credentials::credential(&fixture.server, &recipe)
}

/// [`facade_verb`] on one `credential`, naming `invocation` when given, its
/// request polled on the engine's stack (`test_engine_stack`): the facade's
/// generated dispatch does not fit a test thread's.
async fn facade_verb_as(
    fixture: &Fixture,
    (slip, key): &(
        oneiron::authority::CapabilitySlip,
        ed25519_dalek::SigningKey,
    ),
    verb: &str,
    body: Value,
    invocation: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("/v1/core/facade/{verb}"))
        .header(CONTENT_TYPE, "application/json")
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43123))));
    if let Some(invocation) = invocation {
        request = request.header("x-oneiron-invocation", invocation);
    }
    let request = crate::test_credentials::bind_slip_request(
        &fixture.server,
        slip,
        key,
        request.body(Body::from(body.to_string())).expect("request"),
    );
    let app = crate::build_app(fixture.server.clone());
    let (status, body) = crate::test_engine_stack::on_engine_stack(async move {
        let response = app.oneshot(request).await.expect("response");
        let status = response.status();
        (status, bytes(response).await)
    })
    .await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// The fixture with its page published by the vault's own owner, the actor
/// an owner door's proof admits: the embedded owner the rooted server binds
/// to the host key at genesis (H149), as the fixture publishes.
fn fixture_of_the_vault_owner() -> (Fixture, EntityId) {
    let fixture = Fixture::new();
    let owner = fixture.owner_actor();
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

/// A confirm carries the personal link it came through to every writer
/// (#8304 review round 1): a link that ends while the confirm waits, on its
/// email domain lookup or its turn, stops the confirm before it books, and
/// its caller gets exactly the 404 a dead link gets. The control: the same
/// snapshot books while its link lives.
#[tokio::test]
async fn a_personal_link_ended_mid_confirm_books_nothing() {
    let fixture = Fixture::new();
    let slots = fixture.slots().await;
    assert!(slots.len() > 1);
    let link = mint(&fixture, "ada@example.test", "Ada");
    let mut holds = Vec::new();
    for (slot, session) in [(&slots[0], "ada"), (&slots[1], "ada-again")] {
        let held = fixture
            .dispatch_at(
                &link.token,
                "booking.hold",
                hold(selected(slot), session, None),
            )
            .await
            .expect("hold through the personal link");
        let BookingOperationResponse::Book(BookingBookResult::Held { hold_token, .. }) = held
        else {
            panic!("held, got {held:?}")
        };
        holds.push((hold_token, session));
    }
    let confirm_input = |hold_token: &str, session: &str| {
        let BookingOperationRequest::Book(BookingBookInput::Confirm(mut input)) =
            confirm(hold_token.to_owned(), session)
        else {
            panic!("confirm")
        };
        "ada@example.test".clone_into(&mut input.booker_email);
        input
    };

    // The confirm's admission resolves the link: the snapshot it carries.
    let (authority, _, resolved) =
        public_attempt_authority(&fixture.server, &link.token, &ReadDestination::on_device())
            .expect("live link");
    assert_eq!(
        authority.personal_link_ref.as_deref(),
        resolved.as_ref().map(|resolved| resolved.link_ref.as_str())
    );
    let booked = super::super::execute_confirm(
        &fixture.server,
        fixture.page,
        confirm_input(&holds[0].0, holds[0].1),
        now_secs().expect("clock"),
        Some(authority.clone()),
    )
    .await
    .expect("the snapshot books while its link lives");
    assert!(matches!(
        booked.0,
        BookingOperationResponse::Book(BookingBookResult::Confirmed { .. })
    ));

    // While the next confirm waits, the minter revokes the link.
    assert!(
        revoke_personal_booking_link(
            &fixture
                .server
                .vault
                .memory(fixture.owner_actor(), EdgeActorClass::Human),
            &link.link.link_ref,
            now_secs().expect("clock"),
        )
        .expect("revoke")
    );

    // That confirm's writes then run on the snapshot taken before it.
    let refused = super::super::execute_confirm(
        &fixture.server,
        fixture.page,
        confirm_input(&holds[1].0, holds[1].1),
        now_secs().expect("clock"),
        Some(authority),
    )
    .await;
    let Err(error) = refused else {
        panic!("a confirm through a revoked link booked")
    };
    let answered = dead_link_or(&fixture.server, &link.token, error).into_response();
    let unknown = answer(
        &fixture,
        "POST",
        &format!("/public/booking/{UNKNOWN_PERSONAL_TOKEN}/verbs/booking.confirm"),
        confirm_as("hold".to_owned(), "ada", "ada@example.test"),
    )
    .await;
    assert_eq!((answered.status(), bytes(answered).await), unknown);
}

/// [`answer`] as a visitor on this device sends it: from loopback, with no
/// proxy forwarding header (the fixture's own requests carry one, so they
/// come from off this device).
async fn answer_on_this_device(
    fixture: &Fixture,
    method: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Vec<u8>) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(CONTENT_TYPE, "application/json")
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43125))))
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    let response = crate::build_app(fixture.server.clone())
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    (status, bytes(response).await)
}

/// DEC-0005 (census L5-29) on the personal-link path: a personal link opens
/// the page's own publication and configuration rows, so the off-device
/// judge runs on it as on the page token. With the page's event-type
/// configuration born again in a world the owner keeps on this machine, a
/// visitor off this device meets the one 404 through the link (its page,
/// its availability and its "not you?"), which names no world, and the
/// refused "not you?" ends nothing. On this device the link still serves
/// the page. A personal-link path that skips the judge answers the kept
/// configuration's page off this device.
#[tokio::test]
async fn a_personal_link_off_this_device_meets_no_kept_page() {
    let fixture = Fixture::new();
    let vault = &fixture.server.vault;
    let minted = mint(&fixture, "ada@example.test", "Ada");
    let token = minted.token.clone();
    let slots = fixture.slots().await;
    let page = format!("/public/booking/{token}");
    let _ = page_json(&fixture, &token).await;

    // As in `public_availability_off_this_device_ignores_a_kept_configuration`:
    // the configuration's copy is born in a kept world and the base claim
    // retires, so the page reads the world's configuration.
    let world = EntityId::now();
    vault
        .put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            TimeRange { start: 1, end: 1 },
            1,
            b"world",
        )
        .expect("world");
    let mut body = vault.get_claim(&id(0x72)).expect("read").expect("config");
    body.world = Some(world);
    let kept = EntityId::now();
    vault
        .put_claim(&kept, &body, TimeRange { start: 1, end: 1 }, 1)
        .expect("configuration born in the world");
    vault
        .retract_claim(&id(0x72), 1)
        .expect("the base configuration retires");
    vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&fixture.server),
            world,
            true,
        )
        .expect("keep the world on this machine");
    crate::test_credentials::bind_owner(vault, "owner-fixture-secret", fixture.owner_actor());
    assert!(
        vault
            .device_local_keeps_for(&kept, &oneiron::claim::CallerLocality::OffDevice.into())
            .expect("world judge"),
        "the kept world holds the configuration from a caller off this device"
    );

    let (status, here) = answer_on_this_device(&fixture, "GET", &page, Value::Null).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "on this device the link still serves its page: {}",
        String::from_utf8_lossy(&here)
    );

    for (method, path, request) in [
        ("GET", page.clone(), Value::Null),
        (
            "POST",
            format!("{page}/availability"),
            availability_over(&slots[0], "ada"),
        ),
        ("POST", format!("{page}/not-you"), Value::Null),
    ] {
        let (status, away) = answer(&fixture, method, &path, request).await;
        let away = String::from_utf8_lossy(&away).into_owned();
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{method} {path}: a personal link served a page a kept world shapes off this device: {away}"
        );
        assert!(!away.contains(&world.to_hex()), "the miss names no world");
    }
    assert!(
        oneiron::booking::resolve_personal_booking_link(vault, &token)
            .expect("link read")
            .is_some(),
        "a refused \"not you?\" ends no link"
    );
}

const MINT_VERB: &str = "vault.booking.personal_link.mint";

/// Review round 2 of #8571 (P1, the one-time token): no invocation claim
/// keeps a mint's reply. The same owner request again under the same
/// invocation runs the mint again and is never answered the first reply's
/// token: a fresh token and link, beside the first. A claim that kept the
/// reply answers the first token twice.
#[tokio::test]
async fn a_minted_token_is_never_answered_again_under_its_invocation() {
    let (fixture, owner) = fixture_of_the_vault_owner();
    let credential = owner_credential(&fixture, owner);
    let invocation = EntityId::now().to_hex();
    let body = json!({
        "page_ref": fixture.page.to_hex(),
        "recipient_email": "a@example.test",
        "recipient_name": "Ada",
    });
    let (status, first) = facade_verb_as(
        &fixture,
        &credential,
        MINT_VERB,
        body.clone(),
        Some(&invocation),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, again) =
        facade_verb_as(&fixture, &credential, MINT_VERB, body, Some(&invocation)).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    let first_token = first["token"].as_str().expect("first token");
    let again_token = again["token"].as_str().expect("second token");
    assert_ne!(
        first_token, again_token,
        "the first mint's token was answered again under its invocation"
    );
    assert_ne!(first["link"]["link_ref"], again["link"]["link_ref"]);
    let links = personal_booking_links(&fixture.server.vault, fixture.page).expect("links");
    assert_eq!(links.len(), 2, "each run minted its own link: {links:?}");
    for token in [first_token, again_token] {
        assert_eq!(page_json(&fixture, token).await["recipient"]["name"], "Ada");
    }
}

/// A hook sandbox whose first run asks and every later run does nothing.
#[cfg(feature = "code-sandbox-wasmtime")]
#[derive(Default)]
struct AskOnceRuntime {
    runs: std::sync::atomic::AtomicUsize,
}

#[cfg(feature = "code-sandbox-wasmtime")]
impl oneiron::runtime_hooks::HookBodyRuntime for AskOnceRuntime {
    fn run_hook(
        &self,
        _body: &str,
        _input_json: &str,
        _context: &mut oneiron::runtime_hooks::HookRunContext,
        _read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> oneiron::Result<oneiron::runtime_hooks::HookBodyRun> {
        let outcome = if self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            json!({"kind": "ask", "question": "May this link be minted?"})
        } else {
            json!({"kind": "nothing"})
        };
        Ok(oneiron::runtime_hooks::HookBodyRun {
            outcome_json: outcome.to_string(),
            fuel_used: None,
            host_calls: 1,
        })
    }
}

/// The owner puts a pack whose one pre-hook asks before every mint; answers
/// the hook's binding claim.
#[cfg(feature = "code-sandbox-wasmtime")]
fn bind_mint_ask(vault: &oneiron::Vault, owner: EntityId) -> EntityId {
    const PACK: &str = "example.mintask";
    const HOOK: &str = "ask-before-mint";
    vault
        .prepare_install_signing()
        .expect("install signing keys");
    let proof = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("owner proof");
    let files = vec![
        oneiron::skill_hub::HubFile::new(
            "PACK.md",
            format!(
                "---\nname: {PACK}\ndescription: Personal link mint ask fixture.\nversion: 1.0.0\nkind: capability\nhooks: [\"{HOOK}\"]\n---\nA pack whose one pre-hook asks before a personal link is minted.\n"
            ),
        ),
        oneiron::skill_hub::HubFile::new(
            format!("hooks/{HOOK}/HOOK.md"),
            format!(
                "---\nname: {HOOK}\nversion: 1.0.0\nverbs: [\"{MINT_VERB}\"]\nphase: pre\noutcomes: [\"ask\"]\n---\n{HOOK} asks before a personal link is minted.\n"
            ),
        ),
        oneiron::skill_hub::HubFile::new(
            format!("hooks/{HOOK}/body.js"),
            "return { kind: \"ask\", question: \"May this link be minted?\" };\n",
        ),
    ];
    match vault
        .put_pack(&proof, files)
        .expect("the owner puts the pack")
    {
        oneiron::skill_hub::pack_catalog::PackInstallDisposition::Installed(receipt) => {
            assert_eq!(receipt.pack_name, PACK);
        }
        other => panic!("the owner's put installs the pack: {other:?}"),
    }
    let (binding, row) = vault
        .pack_hook_bindings()
        .expect("list bindings")
        .into_iter()
        .find(|(_, row)| row.pack == PACK && row.hook == HOOK)
        .expect("the owner's hook binds");
    assert!(row.enabled, "the new binding runs");
    binding
}

/// Review round 2 of #8571 (P1, the one-time token, its hook leg): an
/// owner's pre-hook that asks before a mint saves no credential to run the
/// mint on. Once the owner answers proceed, settlement's drain runs nothing
/// and mints nothing, so no ask row keeps a token; the caller's own retry
/// under the same invocation mints, and its token goes to that retry alone.
/// A drain that runs the mint saves its whole answer, the raw token in it,
/// in the ask's row for the retry. The host's check runs in the hook
/// sandbox's build alone, as serve installs it.
#[cfg(feature = "code-sandbox-wasmtime")]
#[tokio::test]
async fn a_mint_a_hook_asked_runs_only_on_its_callers_retry() {
    let (fixture, owner) = fixture_of_the_vault_owner();
    let vault = Arc::clone(&fixture.server.vault);
    vault
        .install_hook_runtime(Arc::new(AskOnceRuntime::default()))
        .expect("the vault runs its verb hooks on the test sandbox");
    // The host's check for a settled ask, as serve installs it, on the
    // engine-stack runtime whose blocking threads run the drain below.
    let server = Arc::clone(&fixture.server);
    crate::test_engine_stack::on_engine_stack(async move {
        server.vault().install_verb_ask_credential_check(Arc::new(
            crate::credential_resume::ServerVerbAskCredentialCheck::new(
                &server,
                tokio::runtime::Handle::current(),
            ),
        ));
    })
    .await;
    let binding = bind_mint_ask(&vault, owner);
    let credential = owner_credential(&fixture, owner);
    let invocation = EntityId::now().to_hex();
    let body = json!({
        "page_ref": fixture.page.to_hex(),
        "recipient_email": "a@example.test",
        "recipient_name": "Ada",
    });

    let (status, held) = facade_verb_as(
        &fixture,
        &credential,
        MINT_VERB,
        body.clone(),
        Some(&invocation),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "the hook asks first: {held}");
    assert_eq!(held["error"]["code"], json!("verb_hook_pending"), "{held}");
    let ask = EntityId::from_hex(held["error"]["hook"]["ask"].as_str().expect("ask handle"))
        .expect("a 32-hex ask handle");
    let mut word = oneiron::task_verb::TaskAskWord::new(binding);
    word.option = Some(oneiron::task_verb::TaskAskOptionId::new("proceed").expect("option"));
    vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_answer(&oneiron::task_verb::TaskAskHandle { group_ref: ask }, &word)
        .expect("the owner answers proceed");

    let drained = {
        let vault = Arc::clone(&vault);
        crate::test_engine_stack::on_engine_stack(async move {
            tokio::task::spawn_blocking(move || vault.drain_verb_asks())
                .await
                .expect("the drain pass ends")
        })
        .await
        .expect("the drain pass")
    };
    assert_eq!(drained, 0, "settlement's drain ran the mint");
    assert!(
        personal_booking_links(&vault, fixture.page)
            .expect("links")
            .is_empty(),
        "no link is minted before the caller's retry"
    );

    let (status, minted) =
        facade_verb_as(&fixture, &credential, MINT_VERB, body, Some(&invocation)).await;
    assert_eq!(status, StatusCode::OK, "the retry mints: {minted}");
    let token = minted["token"].as_str().expect("token");
    assert!(token.starts_with("bkr_"));
    assert_eq!(
        personal_booking_links(&vault, fixture.page)
            .expect("links")
            .len(),
        1
    );
}

/// Review round 2 of #8571 (P1, the slot read's final check): the check a
/// slot answer ends in (on the cached and the solved path, and in a
/// constraint turn, the public one and the facade's alike) needs the
/// snapshot's personal link still live, as every writer's does. A link the
/// owner revokes while its slots are read answers the one 404, with the page
/// still published. A check that reads only the publication lets the slots
/// through.
#[tokio::test]
async fn a_personal_link_revoked_mid_read_answers_no_slots() {
    let fixture = Fixture::new();
    let link = mint(&fixture, "ada@example.test", "Ada");
    let (authority, _, _) =
        public_attempt_authority(&fixture.server, &link.token, &ReadDestination::on_device())
            .expect("live link");
    assert_eq!(
        authority.personal_link_ref.as_deref(),
        Some(link.link.link_ref.as_str())
    );
    super::super::public_availability::recheck(&fixture.server, Some(&authority))
        .expect("a live link's read stands");

    assert!(
        revoke_personal_booking_link(
            &fixture
                .server
                .vault
                .memory(fixture.owner_actor(), EdgeActorClass::Human),
            &link.link.link_ref,
            now_secs().expect("clock"),
        )
        .expect("revoke")
    );
    let Err(refused) =
        super::super::public_availability::recheck(&fixture.server, Some(&authority))
    else {
        panic!("a read through a revoked link kept its slots")
    };
    assert_eq!(refused.into_response().status(), StatusCode::NOT_FOUND);
    // The page itself still serves through its own token.
    let _ = page_json(&fixture, &fixture.token).await;
}
