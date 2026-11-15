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
//! reaches Stripe.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Form, Path as AxumPath, State as AxumState};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use hmac::{Hmac, Mac};
use oneiron::booking::lifecycle::{DepositState, booking_deposit_for_payment};
use oneiron::booking::{DepositRefundRule, DepositTerms};
use oneiron::secret_custody::PaymentCredentialRelease;
use sha2::Sha256;

use super::fixture::*;
use super::*;
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

fn deposit_config() -> EventTypeConfig {
    EventTypeConfig {
        deposit: Some(deposit_terms()),
        ..fixture_config()
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
) -> axum::Json<Value> {
    observe(
        &stripe,
        format!("POST /v1/payment_intents/{id}/{movement}"),
        &headers,
        form,
    );
    let mut stripe = stripe.lock().expect("fake stripe");
    let intent = stripe.intents.get_mut(&id).expect("known intent");
    intent.status = if movement == "capture" {
        "succeeded"
    } else {
        "canceled"
    }
    .to_owned();
    let intent = intent.clone();
    axum::Json(intent_json(&id, &intent))
}

async fn refund(
    AxumState(stripe): AxumState<Shared>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> axum::Json<Value> {
    observe(&stripe, "POST /v1/refunds".to_owned(), &headers, form);
    axum::Json(json!({ "id": "re_fixture", "status": "succeeded" }))
}

/// A loopback Stripe on this runtime; its origin.
async fn fake_stripe() -> (Shared, String) {
    let stripe = Shared::default();
    let app = axum::Router::new()
        .route("/v1/payment_intents", post(create_intent))
        .route("/v1/payment_intents/{id}", get(read_intent))
        .route("/v1/payment_intents/{id}/{movement}", post(move_intent))
        .route("/v1/refunds", post(refund))
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
/// public body codec, as `api/tests/owner_surfaces.rs` writes one.
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
        (Mp::from("schema_version"), Mp::from(1_u64)),
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
    let mut fixture = Fixture::with_config(deposit_config());
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
        .dispatch("booking.hold", hold(slot, "deposit-visitor", None))
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
            hold(selected(&slots[1]), "fast-visitor", None),
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
    let payment_id = checkout
        .client_secret
        .split("_secret_")
        .next()
        .expect("client secret")
        .to_owned();
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
            hold(selected(&slots[2]), "live-visitor", None),
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
