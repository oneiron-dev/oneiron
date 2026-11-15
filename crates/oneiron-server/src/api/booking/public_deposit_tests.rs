//! BK-DEPOSITS PR 3: a deposit event type through the real public router and
//! the signed Stripe webhook, against a loopback fake of Stripe's API.
//!
//! The brief's proof test: publish an `intro` event type that asks a
//! deposit; hold a slot (the hold opens the checkout, and its lease extends
//! the hold to the checkout window); confirm before payment is refused;
//! Stripe's signed webhook says the card is authorized; confirm answers the
//! reschedule and cancel tokens, and the deposit is captured. Beside it: the
//! webhook refuses a bad signature, a stale timestamp and a live-mode event;
//! a confirm that beats the webhook reads Stripe's own word; a live key never
//! reaches Stripe. The Astra money review's cases (15 Nov): a hold opens a
//! payment only under the terms the visitor read; a void that finds the
//! payment captured refunds it; a refund Stripe holds pending stays owed
//! and is never made twice.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Form, Path as AxumPath, Query, State as AxumState};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use hmac::{Hmac, Mac};
use oneiron::booking::agent_api::{BookingDepositCheckout, SelectedSlot};
use oneiron::booking::lifecycle::{DepositState, booking_deposit_for_payment};
use oneiron::booking::{DepositRefundRule, DepositTerms};
use oneiron::secret_custody::PaymentCredentialRelease;
use sha2::Sha256;

use super::fixture::*;
use super::*;
use crate::booking_deposit::settle::settle_deposits_once;
use crate::booking_deposit::webhook::STRIPE_DEPOSIT_WEBHOOK_PATH;
use crate::booking_deposit::{
    DEPOSIT_EFFECTOR, STRIPE_PUBLISHABLE_KEY_NAME, STRIPE_SECRET_KEY_NAME,
    STRIPE_WEBHOOK_SECRET_NAME,
};

const SECRET_KEY: &str = "sk_test_fixture";
const PUBLISHABLE_KEY: &str = "pk_test_fixture";
const WEBHOOK_SECRET: &str = "whsec_fixture";

fn deposit_terms() -> DepositTerms {
    DepositTerms {
        amount_minor: 5_000,
        currency: "jpy".to_owned(),
        refund: DepositRefundRule::default(),
    }
}

/// A full refund on any cancel before the start, so a fixture slot's
/// cancel releases the whole deposit.
fn any_notice_terms() -> DepositTerms {
    DepositTerms {
        refund: DepositRefundRule {
            full_refund_notice_secs: 0,
            late_cancel_refund_percent: 0,
        },
        ..deposit_terms()
    }
}

/// One PaymentIntent the fake holds.
#[derive(Clone)]
struct FakeIntent {
    amount: u64,
    currency: String,
    capture_method: String,
    status: String,
}

/// What the fake Stripe saw and holds.
#[derive(Default)]
struct FakeStripe {
    intents: BTreeMap<String, FakeIntent>,
    by_idempotency_key: BTreeMap<String, String>,
    /// `(method and path, form, Idempotency-Key)` of every call.
    calls: Vec<(String, BTreeMap<String, String>, Option<String>)>,
    /// Every `Authorization` header it was sent.
    bearers: Vec<String>,
    /// The next capture is taken, and its reply lost: Stripe answers 500.
    lose_capture_reply: bool,
    /// The status a new refund gets; `succeeded` when unset.
    refund_status: Option<String>,
    refunds: Vec<FakeRefund>,
}

/// One refund the fake holds.
#[derive(Clone)]
struct FakeRefund {
    id: String,
    payment_intent: String,
    amount: u64,
    status: String,
    settle_key: Option<String>,
}

fn refund_json(refund: &FakeRefund) -> Value {
    json!({
        "id": refund.id,
        "object": "refund",
        "amount": refund.amount,
        "payment_intent": refund.payment_intent,
        "status": refund.status,
        "metadata": refund
            .settle_key
            .as_ref()
            .map_or_else(|| json!({}), |key| json!({ "oneiron_settle_key": key })),
    })
}

fn stripe_error(status: StatusCode, code: &str) -> (StatusCode, axum::Json<Value>) {
    (
        status,
        axum::Json(json!({ "error": { "code": code, "message": code } })),
    )
}

type Shared = Arc<Mutex<FakeStripe>>;

fn intent_json(id: &str, intent: &FakeIntent) -> Value {
    json!({
        "id": id,
        "object": "payment_intent",
        "client_secret": format!("{id}_secret_fixture"),
        "status": intent.status,
        "amount": intent.amount,
        "amount_capturable": if intent.status == "requires_capture" { intent.amount } else { 0 },
        "amount_received": if intent.status == "succeeded" { intent.amount } else { 0 },
        "currency": intent.currency,
        "livemode": false,
    })
}

fn observe(
    stripe: &Shared,
    call: String,
    headers: &HeaderMap,
    form: BTreeMap<String, String>,
) -> Option<String> {
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut stripe = stripe.lock().expect("fake stripe");
    if let Some(bearer) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
    {
        stripe.bearers.push(bearer.to_owned());
    }
    stripe.calls.push((call, form, key.clone()));
    key
}

async fn create_intent(
    AxumState(stripe): AxumState<Shared>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> axum::Json<Value> {
    let key = observe(
        &stripe,
        "POST /v1/payment_intents".to_owned(),
        &headers,
        form.clone(),
    );
    let mut stripe = stripe.lock().expect("fake stripe");
    if let Some(id) = key
        .as_ref()
        .and_then(|key| stripe.by_idempotency_key.get(key))
        .cloned()
    {
        let intent = stripe.intents[&id].clone();
        return axum::Json(intent_json(&id, &intent));
    }
    let id = format!("pi_fixture{}", stripe.intents.len() + 1);
    let intent = FakeIntent {
        amount: form["amount"].parse().expect("amount"),
        currency: form["currency"].clone(),
        capture_method: form["capture_method"].clone(),
        status: "requires_payment_method".to_owned(),
    };
    stripe.intents.insert(id.clone(), intent.clone());
    if let Some(key) = key {
        stripe.by_idempotency_key.insert(key, id.clone());
    }
    axum::Json(intent_json(&id, &intent))
}

async fn read_intent(
    AxumState(stripe): AxumState<Shared>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> axum::Json<Value> {
    observe(
        &stripe,
        format!("GET /v1/payment_intents/{id}"),
        &headers,
        BTreeMap::new(),
    );
    let stripe = stripe.lock().expect("fake stripe");
    axum::Json(intent_json(&id, &stripe.intents[&id]))
}

async fn move_intent(
    AxumState(stripe): AxumState<Shared>,
    headers: HeaderMap,
    AxumPath((id, movement)): AxumPath<(String, String)>,
    Form(form): Form<BTreeMap<String, String>>,
) -> (StatusCode, axum::Json<Value>) {
    observe(
        &stripe,
        format!("POST /v1/payment_intents/{id}/{movement}"),
        &headers,
        form,
    );
    let mut stripe = stripe.lock().expect("fake stripe");
    let lose_reply = movement == "capture" && std::mem::take(&mut stripe.lose_capture_reply);
    let intent = stripe.intents.get_mut(&id).expect("known intent");
    if movement == "cancel" && intent.status == "succeeded" {
        // Stripe cancels no captured payment.
        return stripe_error(StatusCode::BAD_REQUEST, "payment_intent_unexpected_state");
    }
    intent.status = if movement == "capture" {
        "succeeded"
    } else {
        "canceled"
    }
    .to_owned();
    if lose_reply {
        return stripe_error(StatusCode::INTERNAL_SERVER_ERROR, "api_error");
    }
    let intent = intent.clone();
    (StatusCode::OK, axum::Json(intent_json(&id, &intent)))
}

async fn refund(
    AxumState(stripe): AxumState<Shared>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> axum::Json<Value> {
    observe(
        &stripe,
        "POST /v1/refunds".to_owned(),
        &headers,
        form.clone(),
    );
    let mut stripe = stripe.lock().expect("fake stripe");
    let refund = FakeRefund {
        id: format!("re_fixture{}", stripe.refunds.len() + 1),
        payment_intent: form["payment_intent"].clone(),
        amount: form["amount"].parse().expect("refund amount"),
        status: stripe
            .refund_status
            .clone()
            .unwrap_or_else(|| "succeeded".to_owned()),
        settle_key: form.get("metadata[oneiron_settle_key]").cloned(),
    };
    stripe.refunds.push(refund.clone());
    axum::Json(refund_json(&refund))
}

async fn list_refunds(
    AxumState(stripe): AxumState<Shared>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> axum::Json<Value> {
    observe(
        &stripe,
        "GET /v1/refunds".to_owned(),
        &headers,
        query.clone(),
    );
    let stripe = stripe.lock().expect("fake stripe");
    let data: Vec<Value> = stripe
        .refunds
        .iter()
        .filter(|refund| Some(&refund.payment_intent) == query.get("payment_intent"))
        .map(refund_json)
        .collect();
    axum::Json(json!({ "object": "list", "data": data, "has_more": false }))
}

/// A loopback Stripe on this runtime; its origin.
async fn fake_stripe() -> (Shared, String) {
    let stripe = Shared::default();
    let app = axum::Router::new()
        .route("/v1/payment_intents", post(create_intent))
        .route("/v1/payment_intents/{id}", get(read_intent))
        .route("/v1/payment_intents/{id}/{movement}", post(move_intent))
        .route("/v1/refunds", post(refund).get(list_refunds))
        .with_state(Arc::clone(&stripe));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake stripe port");
    let origin = format!(
        "http://{}",
        listener.local_addr().expect("fake stripe address")
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("fake stripe");
    });
    (stripe, origin)
}

/// Stores one deposit secret, bound to the deposit door, as the owner does.
/// The value field is crate-private, so the record goes through the one
/// public body codec, as `server/housekeeping_tests.rs` writes one.
fn register_deposit_secret(vault: &oneiron::Vault, name: &str, value: &str) {
    use rmpv::Value as Mp;
    let band = |min: u64, max: u64| {
        Mp::Map(vec![
            (Mp::from("min"), Mp::from(min)),
            (Mp::from("max"), Mp::from(max)),
        ])
    };
    let floor = Mp::Map(vec![
        (Mp::from("portable"), band(0, 2)),
        (Mp::from("device_bound"), band(0, 2)),
        (Mp::from("cross_vault"), band(0, 0)),
        (Mp::from("rotation_max_age_secs"), Mp::Nil),
        (Mp::from("env_bindings"), Mp::Map(vec![])),
    ]);
    let binding = Mp::Map(vec![
        (Mp::from("effector"), Mp::from(DEPOSIT_EFFECTOR)),
        (Mp::from("tier_ceiling"), Mp::from(0_u64)),
        (Mp::from("scopes"), Mp::Array(vec![Mp::from("read")])),
    ]);
    let body = Mp::Map(vec![
        (
            Mp::from("schema_version"),
            Mp::from(u64::from(
                oneiron::secret_record::SECRET_CUSTODY_SCHEMA_VERSION,
            )),
        ),
        (Mp::from("name"), Mp::from(name)),
        (Mp::from("class"), Mp::from("custody-portable")),
        (Mp::from("device_only"), Mp::from(false)),
        (
            Mp::from("value_bytes"),
            Mp::Binary(value.as_bytes().to_vec()),
        ),
        (Mp::from("status"), Mp::from("active")),
        (Mp::from("registered_at"), Mp::from(1_u64)),
        (Mp::from("rotated_at"), Mp::Nil),
        (Mp::from("rotation_generation"), Mp::from(0_u64)),
        (Mp::from("bindings"), Mp::Array(vec![binding])),
        (Mp::from("manifest_ref"), Mp::from("")),
        (Mp::from("declared_paths"), Mp::Array(vec![])),
        (Mp::from("policy_floor_snapshot"), floor),
        (Mp::from("model_reveal_allowed"), Mp::from(false)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("custody body");
    let record =
        oneiron::secret_custody::decode_secret_custody_body(&bytes).expect("custody record");
    vault
        .register_secret(record)
        .expect("register a deposit secret");
}

/// A published page whose `intro` event type asks a 5000 jpy deposit, its
/// deposits pointed at the fake Stripe, with the owner's three secrets
/// stored. The test host proves no runner fence, so it lifts the payment
/// credential withholding, as a self-hoster's serve flag does.
async fn deposit_fixture(secret_key: &str) -> (Fixture, Shared) {
    deposit_fixture_with(deposit_terms(), secret_key).await
}

/// [`deposit_fixture`] for an event type that asks `terms`.
async fn deposit_fixture_with(terms: DepositTerms, secret_key: &str) -> (Fixture, Shared) {
    let mut fixture = Fixture::with_config(EventTypeConfig {
        deposit: Some(terms),
        ..fixture_config()
    });
    let (stripe, origin) = fake_stripe().await;
    Arc::get_mut(&mut fixture.server)
        .expect("the fixture alone holds its server")
        .booking_deposit_stripe_base = origin;
    let vault = &fixture.server.vault;
    vault.set_payment_credential_release(PaymentCredentialRelease {
        runner_fence_proven: false,
        withholding_lifted: true,
    });
    register_deposit_secret(vault, STRIPE_SECRET_KEY_NAME, secret_key);
    register_deposit_secret(vault, STRIPE_PUBLISHABLE_KEY_NAME, PUBLISHABLE_KEY);
    register_deposit_secret(vault, STRIPE_WEBHOOK_SECRET_NAME, WEBHOOK_SECRET);
    (fixture, stripe)
}

/// The signed webhook delivery of one PaymentIntent event, as Stripe sends
/// it; its HTTP status.
async fn deliver_event(
    fixture: &Fixture,
    event: &Value,
    signed_at: u64,
    secret: &str,
) -> StatusCode {
    let body = serde_json::to_vec(event).expect("event body");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("mac key");
    mac.update(format!("{signed_at}.").as_bytes());
    mac.update(&body);
    let signature: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let request = Request::builder()
        .method("POST")
        .uri(STRIPE_DEPOSIT_WEBHOOK_PATH)
        .header(CONTENT_TYPE, "application/json")
        .header("stripe-signature", format!("t={signed_at},v1={signature}"))
        .extension(ConnectInfo(
            "127.0.0.1:43124".parse::<SocketAddr>().expect("peer"),
        ))
        .body(Body::from(body))
        .expect("request");
    crate::build_app(fixture.server.clone())
        .oneshot(request)
        .await
        .expect("response")
        .status()
}

fn capturable_event(event_id: &str, payment_id: &str, livemode: bool) -> Value {
    json!({
        "id": event_id,
        "object": "event",
        "type": "payment_intent.amount_capturable_updated",
        "livemode": livemode,
        "data": { "object": {
            "id": payment_id,
            "object": "payment_intent",
            "amount_capturable": 5_000,
            "currency": "jpy",
            "status": "requires_capture"
        } }
    })
}

/// The visitor's Stripe.js authorizes the card: the intent waits for capture.
fn authorize_card(stripe: &Shared, payment_id: &str) {
    stripe
        .lock()
        .expect("fake stripe")
        .intents
        .get_mut(payment_id)
        .expect("known intent")
        .status = "requires_capture".to_owned();
}

/// A hold that carries the deposit terms the visitor read on the card.
fn hold_shown(
    slot: SelectedSlot,
    session: &str,
    shown: Option<DepositTerms>,
) -> BookingOperationRequest {
    let BookingOperationRequest::Book(BookingBookInput::Hold(mut input)) =
        hold(slot, session, None)
    else {
        panic!("the fixture's hold is a hold")
    };
    input.deposit_terms = shown;
    BookingOperationRequest::Book(BookingBookInput::Hold(input))
}

/// The PaymentIntent a checkout's client secret belongs to.
fn payment_of(checkout: &BookingDepositCheckout) -> String {
    checkout
        .client_secret
        .split("_secret_")
        .next()
        .expect("client secret")
        .to_owned()
}

/// Hold under `terms`, the card authorized, confirm: the payment and the
/// booking's cancel token.
async fn paid_booking(
    fixture: &Fixture,
    stripe: &Shared,
    slot: SelectedSlot,
    session: &str,
    terms: &DepositTerms,
) -> (String, String) {
    let held = fixture
        .dispatch(
            "booking.hold",
            hold_shown(slot, session, Some(terms.clone())),
        )
        .await
        .expect("hold");
    let BookingOperationResponse::Book(BookingBookResult::Held {
        hold_token,
        deposit: Some(checkout),
        ..
    }) = held
    else {
        panic!("a deposit hold answers its checkout")
    };
    let payment_id = payment_of(&checkout);
    authorize_card(stripe, &payment_id);
    let confirmed = fixture
        .dispatch("booking.confirm", confirm(hold_token, session))
        .await
        .expect("confirm after the authorization");
    let BookingOperationResponse::Book(BookingBookResult::Confirmed { cancel_token, .. }) =
        confirmed
    else {
        panic!("confirmed")
    };
    (payment_id, cancel_token)
}

/// The POST /v1/refunds calls the fake saw.
fn refund_posts(stripe: &Shared) -> usize {
    stripe
        .lock()
        .expect("fake stripe")
        .calls
        .iter()
        .filter(|(call, _, _)| call == "POST /v1/refunds")
        .count()
}

fn deposit_state(fixture: &Fixture, payment_id: &str) -> DepositState {
    booking_deposit_for_payment(&fixture.server.vault, payment_id)
        .expect("read")
        .expect("the deposit exists")
        .state
}

#[tokio::test]
async fn public_booking_deposit_event_holds_checkout_window_and_confirms_only_after_payment() {
    let (fixture, stripe) = deposit_fixture(SECRET_KEY).await;
    let slots = fixture.slots().await;
    let slot = selected(&slots[0]);

    let before = now_secs().expect("clock");
    let held = fixture
        .dispatch(
            "booking.hold",
            hold_shown(slot, "deposit-visitor", Some(deposit_terms())),
        )
        .await
        .expect("the deposit event type's hold opens its checkout");
    let BookingOperationResponse::Book(BookingBookResult::Held {
        hold_token,
        expires_at,
        deposit: Some(checkout),
        ..
    }) = held
    else {
        panic!("a deposit hold answers its checkout")
    };
    let window = oneiron::booking::lifecycle::DEPOSIT_CHECKOUT_WINDOW_SECS;
    assert!(
        expires_at >= before + window && expires_at <= now_secs().expect("clock") + window,
        "the payment's lease extends the hold to the checkout window"
    );
    assert_eq!(checkout.amount_minor, 5_000);
    assert_eq!(checkout.currency, "jpy");
    assert_eq!(checkout.publishable_key, PUBLISHABLE_KEY);
    let payment_id = checkout
        .client_secret
        .split("_secret_")
        .next()
        .expect("client secret")
        .to_owned();
    {
        let stripe = stripe.lock().expect("fake stripe");
        let intent = &stripe.intents[&payment_id];
        assert_eq!((intent.amount, intent.currency.as_str()), (5_000, "jpy"));
        assert_eq!(
            intent.capture_method, "manual",
            "authorize now, capture at confirm"
        );
        assert!(
            stripe
                .bearers
                .iter()
                .all(|bearer| bearer == "Bearer sk_test_fixture"),
            "every call carries the owner's test key"
        );
    }

    let early = fixture
        .dispatch(
            "booking.confirm",
            confirm(hold_token.clone(), "deposit-visitor"),
        )
        .await;
    assert_eq!(
        early,
        Err(StatusCode::BAD_REQUEST),
        "confirm before payment is refused"
    );
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::AwaitingAuthorization
    );

    // The webhook refuses what Stripe did not sign, a stale delivery and live
    // mode, and changes nothing.
    let now = now_secs().expect("clock");
    let authorized = capturable_event("evt_fixture_1", &payment_id, false);
    assert_eq!(
        deliver_event(&fixture, &authorized, now, "whsec_wrong").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        deliver_event(&fixture, &authorized, now - 600, WEBHOOK_SECRET).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        deliver_event(
            &fixture,
            &capturable_event("evt_fixture_live", &payment_id, true),
            now,
            WEBHOOK_SECRET
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::AwaitingAuthorization
    );

    // Stripe's signed word that the card is authorized, delivered twice.
    authorize_card(&stripe, &payment_id);
    for _ in 0..2 {
        assert_eq!(
            deliver_event(&fixture, &authorized, now, WEBHOOK_SECRET).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Authorized
    );

    let confirmed = fixture
        .dispatch("booking.confirm", confirm(hold_token, "deposit-visitor"))
        .await
        .expect("confirm after the authorization");
    let BookingOperationResponse::Book(BookingBookResult::Confirmed {
        reschedule_token,
        cancel_token,
    }) = confirmed
    else {
        panic!("confirmed")
    };
    assert_eq!(reschedule_token.len(), 64);
    assert_eq!(cancel_token.len(), 64);
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Captured {
            amount_minor: 5_000
        },
        "the deposit is captured at confirm"
    );
    let stripe = stripe.lock().expect("fake stripe");
    let captures: Vec<_> = stripe
        .calls
        .iter()
        .filter(|(call, _, _)| call.ends_with("/capture"))
        .collect();
    assert_eq!(captures.len(), 1, "captured once");
    let (_, form, key) = captures[0];
    assert_eq!(
        form.get("amount_to_capture").map(String::as_str),
        Some("5000")
    );
    assert!(key.is_some(), "the capture carries an idempotency key");
}

#[tokio::test]
async fn a_confirm_that_beats_the_webhook_reads_stripes_word() {
    let (fixture, stripe) = deposit_fixture(SECRET_KEY).await;
    let slots = fixture.slots().await;
    let held = fixture
        .dispatch(
            "booking.hold",
            hold_shown(selected(&slots[1]), "fast-visitor", Some(deposit_terms())),
        )
        .await
        .expect("hold");
    let BookingOperationResponse::Book(BookingBookResult::Held {
        hold_token,
        deposit: Some(checkout),
        ..
    }) = held
    else {
        panic!("a deposit hold answers its checkout")
    };
    let payment_id = payment_of(&checkout);
    authorize_card(&stripe, &payment_id);
    fixture
        .dispatch("booking.confirm", confirm(hold_token, "fast-visitor"))
        .await
        .expect("the confirm reads the authorization from Stripe itself");
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Captured {
            amount_minor: 5_000
        }
    );
}

#[tokio::test]
async fn a_live_stripe_key_never_reaches_stripe() {
    let (fixture, stripe) = deposit_fixture("sk_live_fixture").await;
    let slots = fixture.slots().await;
    let held = fixture
        .dispatch(
            "booking.hold",
            hold_shown(selected(&slots[2]), "live-visitor", Some(deposit_terms())),
        )
        .await;
    assert_eq!(
        held,
        Err(StatusCode::CONFLICT),
        "deposits run in test mode only"
    );
    assert!(
        stripe.lock().expect("fake stripe").calls.is_empty(),
        "no request left with a live key"
    );
}

#[tokio::test]
async fn a_hold_opens_a_payment_only_under_the_terms_the_visitor_read() {
    let (fixture, stripe) = deposit_fixture(SECRET_KEY).await;
    let slots = fixture.slots().await;
    // The card the visitor read before the owner changed the refund rule.
    let stale = DepositTerms {
        refund: DepositRefundRule {
            full_refund_notice_secs: 2 * 3_600,
            late_cancel_refund_percent: 50,
        },
        ..deposit_terms()
    };
    for (session, shown) in [("terms-unread", None), ("terms-stale", Some(stale))] {
        let held = fixture
            .dispatch(
                "booking.hold",
                hold_shown(selected(&slots[0]), session, shown),
            )
            .await;
        assert_eq!(
            held,
            Err(StatusCode::CONFLICT),
            "{session}: no checkout under terms the visitor did not read"
        );
    }
    assert!(
        stripe.lock().expect("fake stripe").calls.is_empty(),
        "no payment was created"
    );

    let held = fixture
        .dispatch(
            "booking.hold",
            hold_shown(selected(&slots[0]), "terms-read", Some(deposit_terms())),
        )
        .await
        .expect("the live terms open the checkout");
    assert!(
        matches!(
            held,
            BookingOperationResponse::Book(BookingBookResult::Held {
                deposit: Some(_),
                ..
            })
        ),
        "a deposit hold answers its checkout: {held:?}"
    );
}

#[tokio::test]
async fn a_void_that_finds_the_payment_captured_refunds_it() {
    let terms = any_notice_terms();
    let (fixture, stripe) = deposit_fixture_with(terms.clone(), SECRET_KEY).await;
    let slots = fixture.slots().await;
    // Stripe takes the confirm's capture, and its reply is lost.
    stripe.lock().expect("fake stripe").lose_capture_reply = true;
    let (payment_id, cancel_token) =
        paid_booking(&fixture, &stripe, selected(&slots[0]), "lost-reply", &terms).await;
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::CaptureDue {
            amount_minor: 5_000
        },
        "the lost reply leaves the capture owed"
    );
    assert_eq!(
        stripe.lock().expect("fake stripe").intents[&payment_id].status,
        "succeeded"
    );

    // The visitor cancels in time for a full refund: the deposit turns void.
    fixture
        .dispatch("booking.cancel", cancel(cancel_token, "cancel-lost-reply"))
        .await
        .expect("cancel");
    assert_eq!(deposit_state(&fixture, &payment_id), DepositState::VoidDue);

    let base = fixture.server.booking_deposit_stripe_base().to_owned();
    let now = now_secs().expect("clock");
    for pass in 0..2 {
        let drain =
            settle_deposits_once(&fixture.server.vault, &base, now + pass).expect("settle pass");
        assert_eq!(drain.failed, 0, "pass {pass}: no move fails for good");
    }
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Refunded {
            amount_minor: 5_000
        },
        "the void found the 5000 captured, and it went back to the visitor"
    );
    assert_eq!(refund_posts(&stripe), 1, "refunded once");
}

#[tokio::test]
async fn a_refund_stripe_holds_pending_stays_owed_and_is_made_once() {
    let terms = any_notice_terms();
    let (fixture, stripe) = deposit_fixture_with(terms.clone(), SECRET_KEY).await;
    let slots = fixture.slots().await;
    let (payment_id, cancel_token) = paid_booking(
        &fixture,
        &stripe,
        selected(&slots[0]),
        "pending-refund",
        &terms,
    )
    .await;
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Captured {
            amount_minor: 5_000
        }
    );
    fixture
        .dispatch(
            "booking.cancel",
            cancel(cancel_token, "cancel-pending-refund"),
        )
        .await
        .expect("cancel");
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::RefundDue {
            amount_minor: 5_000
        }
    );

    stripe.lock().expect("fake stripe").refund_status = Some("pending".to_owned());
    let base = fixture.server.booking_deposit_stripe_base().to_owned();
    let now = now_secs().expect("clock");
    for at in [now, now + 60] {
        let drain = settle_deposits_once(&fixture.server.vault, &base, at).expect("settle pass");
        assert_eq!(drain.failed, 0, "a pending refund never fails for good");
        assert_eq!(drain.refunded, 0, "a pending refund is no refund");
        assert_eq!(
            deposit_state(&fixture, &payment_id),
            DepositState::RefundDue {
                amount_minor: 5_000
            },
            "the refund stays owed while Stripe holds it"
        );
    }

    // Stripe finishes the refund; the next ask finds it by its key.
    stripe.lock().expect("fake stripe").refunds[0].status = "succeeded".to_owned();
    let drain =
        settle_deposits_once(&fixture.server.vault, &base, now + 3_601).expect("settle pass");
    assert_eq!(drain.refunded, 1);
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Refunded {
            amount_minor: 5_000
        }
    );
    assert_eq!(
        refund_posts(&stripe),
        1,
        "the pending refund was never made twice"
    );
}
