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
//! and is never made twice. The Muse Spark blind review's case (16 Nov): a
//! refund owed while the key is withheld waits, and runs once it is back.
//! The fake lists a payment's refunds as Stripe does, newest first and a page
//! at a time, so a refund past the first page is found
//! (FIX [BK-DEPOSIT-REFUND-LIST-ONE-PAGE]). Sol's blind review of #9862: a
//! page of refunds with full metadata is still read, and a refund the list
//! names twice is never counted twice.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Form, Path as AxumPath, Query, State as AxumState};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use hmac::{Hmac, Mac};
use oneiron::booking::agent_api::{BookingDepositCheckout, SelectedSlot};
use oneiron::booking::lifecycle::{
    BookingDepositSettlementDrain, DepositState, booking_deposit_for_payment,
};
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

/// Half the deposit back on any cancel: every cancel comes later than the
/// longest notice a rule may ask.
fn late_cancel_half_terms() -> DepositTerms {
    DepositTerms {
        refund: DepositRefundRule {
            full_refund_notice_secs: 366 * 86_400,
            late_cancel_refund_percent: 50,
        },
        ..deposit_terms()
    }
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
    /// Every read of a PaymentIntent answers 500 while set: an outage.
    fail_intent_reads: bool,
    /// Every capture and cancel of a PaymentIntent answers 403 while set: a
    /// restricted key without the permission.
    refuse_intent_moves: bool,
    /// Every new refund answers 403 while set: a restricted key without the
    /// permission.
    refuse_refunds: bool,
    /// A cursor fault, once: the page asked from after this refund lists the
    /// payment's refunds from the start again.
    restart_refund_list_after: Option<String>,
    /// Every refund list answers without `has_more` while set: a reply that
    /// does not say whether more refunds follow.
    omit_refund_list_has_more: bool,
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
    /// The metadata the refund carries besides the settle key.
    metadata: BTreeMap<String, String>,
}

fn refund_json(refund: &FakeRefund) -> Value {
    let mut metadata = refund.metadata.clone();
    if let Some(key) = &refund.settle_key {
        metadata.insert("oneiron_settle_key".to_owned(), key.clone());
    }
    json!({
        "id": refund.id,
        "object": "refund",
        "amount": refund.amount,
        "payment_intent": refund.payment_intent,
        "status": refund.status,
        "metadata": metadata,
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
) -> (StatusCode, axum::Json<Value>) {
    observe(
        &stripe,
        format!("GET /v1/payment_intents/{id}"),
        &headers,
        BTreeMap::new(),
    );
    let stripe = stripe.lock().expect("fake stripe");
    if stripe.fail_intent_reads {
        return stripe_error(StatusCode::INTERNAL_SERVER_ERROR, "api_error");
    }
    (
        StatusCode::OK,
        axum::Json(intent_json(&id, &stripe.intents[&id])),
    )
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
    if stripe.refuse_intent_moves {
        // The key may not move a PaymentIntent: nothing of the fake changes.
        return stripe_error(StatusCode::FORBIDDEN, "permission_denied");
    }
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
) -> (StatusCode, axum::Json<Value>) {
    observe(
        &stripe,
        "POST /v1/refunds".to_owned(),
        &headers,
        form.clone(),
    );
    let mut stripe = stripe.lock().expect("fake stripe");
    if stripe.refuse_refunds {
        // The key may not refund: the fake holds no new refund.
        return stripe_error(StatusCode::FORBIDDEN, "permission_denied");
    }
    let refund = FakeRefund {
        id: format!("re_fixture{}", stripe.refunds.len() + 1),
        payment_intent: form["payment_intent"].clone(),
        amount: form["amount"].parse().expect("refund amount"),
        status: stripe
            .refund_status
            .clone()
            .unwrap_or_else(|| "succeeded".to_owned()),
        settle_key: form.get("metadata[oneiron_settle_key]").cloned(),
        metadata: BTreeMap::new(),
    };
    stripe.refunds.push(refund.clone());
    (StatusCode::OK, axum::Json(refund_json(&refund)))
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
    let mut stripe = stripe.lock().expect("fake stripe");
    let restarted = query.contains_key("starting_after")
        && stripe.restart_refund_list_after.as_ref() == query.get("starting_after");
    if restarted {
        stripe.restart_refund_list_after = None;
    }
    // Stripe lists a payment's refunds newest first, at most `limit` (10 when
    // unset) to a page, from the refund after `starting_after`.
    let limit = query
        .get("limit")
        .map_or(10, |limit| limit.parse().expect("refund list limit"));
    let listed: Vec<&FakeRefund> = stripe
        .refunds
        .iter()
        .rev()
        .filter(|refund| Some(&refund.payment_intent) == query.get("payment_intent"))
        .collect();
    let start = query
        .get("starting_after")
        .filter(|_| !restarted)
        .map_or(0, |after| {
            listed
                .iter()
                .position(|refund| &refund.id == after)
                .expect("starting_after names a listed refund")
                + 1
        });
    let data: Vec<Value> = listed[start..]
        .iter()
        .take(limit)
        .copied()
        .map(refund_json)
        .collect();
    let has_more = listed.len() > start + data.len();
    if stripe.omit_refund_list_has_more {
        return axum::Json(json!({ "object": "list", "data": data }));
    }
    axum::Json(json!({ "object": "list", "data": data, "has_more": has_more }))
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

/// One settle pass at `at`, run off the runtime as the settle worker runs it
/// (booking_deposit/settle.rs spawn_deposit_settlement): the Stripe client
/// blocks, and the fake Stripe answers on this runtime.
async fn run_settle_pass(fixture: &Fixture, at: u64) -> BookingDepositSettlementDrain {
    let vault = Arc::clone(&fixture.server.vault);
    let base = fixture.server.booking_deposit_stripe_base().to_owned();
    tokio::task::spawn_blocking(move || {
        settle_deposits_once(&vault, &base, at).expect("settle pass")
    })
    .await
    .expect("the settle pass ran")
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

    let now = now_secs().expect("clock");
    for pass in 0..2 {
        let drain = run_settle_pass(&fixture, now + pass).await;
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
async fn a_refused_void_whose_payment_read_fails_runs_again() {
    let terms = any_notice_terms();
    let (fixture, stripe) = deposit_fixture_with(terms.clone(), SECRET_KEY).await;
    let slots = fixture.slots().await;
    // Stripe takes the confirm's capture, and its reply is lost.
    stripe.lock().expect("fake stripe").lose_capture_reply = true;
    let (payment_id, cancel_token) = paid_booking(
        &fixture,
        &stripe,
        selected(&slots[0]),
        "read-outage",
        &terms,
    )
    .await;
    fixture
        .dispatch("booking.cancel", cancel(cancel_token, "cancel-read-outage"))
        .await
        .expect("cancel");
    assert_eq!(deposit_state(&fixture, &payment_id), DepositState::VoidDue);

    // Stripe refuses the void (the payment is captured), and the read that
    // would say so fails: every row of the deposit waits for a retry.
    stripe.lock().expect("fake stripe").fail_intent_reads = true;
    // Every pass runs an hour behind the wall clock: a row requeued for a
    // later instant is claimed only once it is due by the vault's own clock.
    let now = now_secs().expect("clock") - 3_601;
    let drain = run_settle_pass(&fixture, now).await;
    assert_eq!(drain.failed, 0, "an outage fails no move for good");
    assert!(drain.retrying > 0, "the void runs again later");
    assert_eq!(deposit_state(&fixture, &payment_id), DepositState::VoidDue);

    // The outage ends; the retry finds the capture and owes it back.
    stripe.lock().expect("fake stripe").fail_intent_reads = false;
    for pass in 1..3 {
        let drain = run_settle_pass(&fixture, now + 300 + pass).await;
        assert_eq!(drain.failed, 0, "pass {pass}: no move fails for good");
    }
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Refunded {
            amount_minor: 5_000
        },
        "the retried void found the 5000 captured, and it went back to the visitor"
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
    // The passes run up to the wall clock, never past it: a row requeued for
    // a later instant is claimed only once it is due by the vault's own clock.
    let now = now_secs().expect("clock") - 3_601;
    for at in [now, now + 60] {
        let drain = run_settle_pass(&fixture, at).await;
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
    let drain = run_settle_pass(&fixture, now + 3_601).await;
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

/// A setup failure (here the host withholds the owner's key, L8-60) makes no
/// Stripe call. The refund it holds up stays owed past the settle row's
/// tries, and runs once the key is back (Muse Spark blind review of #8231,
/// 16 Nov).
#[tokio::test]
async fn a_refund_owed_while_the_key_is_withheld_waits_and_runs_once_it_is_back() {
    let terms = any_notice_terms();
    let (fixture, stripe) = deposit_fixture_with(terms.clone(), SECRET_KEY).await;
    let slots = fixture.slots().await;
    let (payment_id, cancel_token) = paid_booking(
        &fixture,
        &stripe,
        selected(&slots[0]),
        "withheld-key",
        &terms,
    )
    .await;
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Captured {
            amount_minor: 5_000
        }
    );

    // The owner marks the key a payment credential, and the host withholds
    // payment credentials: its runner fence is unproven and the serve flag
    // is off.
    let vault = &fixture.server.vault;
    let secret = vault
        .resolve_secret_ref(STRIPE_SECRET_KEY_NAME)
        .expect("resolve the secret key")
        .expect("the secret key is stored");
    vault
        .set_secret_payment_mark(
            &crate::test_credentials::embedded_owner(vault),
            &secret,
            Some(true),
        )
        .expect("the owner's payment mark");
    vault.set_payment_credential_release(PaymentCredentialRelease {
        runner_fence_proven: false,
        withholding_lifted: false,
    });
    fixture
        .dispatch(
            "booking.cancel",
            cancel(cancel_token, "cancel-withheld-key"),
        )
        .await
        .expect("cancel");
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::RefundDue {
            amount_minor: 5_000
        }
    );

    // More passes than a settle row's tries, each past the row's longest
    // wait: the refund stays owed, and no request reaches Stripe. The last
    // pass runs at the wall clock and the earlier ones behind it: a row
    // requeued for a later instant is claimed only once it is due by the
    // vault's own clock.
    let calls_before = stripe.lock().expect("fake stripe").calls.len();
    let now = now_secs().expect("clock") - 10 * 3_601;
    for pass in 0..10_u64 {
        let drain = run_settle_pass(&fixture, now + pass * 3_601).await;
        assert_eq!(
            drain.failed, 0,
            "pass {pass}: a withheld key fails no move for good"
        );
        assert_eq!(drain.refunded, 0, "pass {pass}: no refund without the key");
    }
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::RefundDue {
            amount_minor: 5_000
        },
        "the refund stays owed while the key is withheld"
    );
    assert_eq!(
        stripe.lock().expect("fake stripe").calls.len(),
        calls_before,
        "a withheld key makes no Stripe call"
    );

    // The self-hoster lifts the withholding: the next pass makes the refund.
    vault.set_payment_credential_release(PaymentCredentialRelease {
        runner_fence_proven: false,
        withholding_lifted: true,
    });
    let drain = run_settle_pass(&fixture, now + 10 * 3_601).await;
    assert_eq!(
        drain.refunded, 1,
        "the owed refund runs once the key is back"
    );
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Refunded {
            amount_minor: 5_000
        }
    );
    assert_eq!(refund_posts(&stripe), 1, "refunded once");
}

/// A restricted key without the permission to capture is refused with a 403 on
/// every capture, the confirm's own among them: the booking stands and its
/// capture stays owed past the settle rows' tries. It runs once the owner
/// gives the key the permission (FIX [BK-DEPOSIT-SETTLE-OUTAGE-STRANDS-MOVE]).
#[tokio::test]
async fn a_capture_a_restricted_key_may_not_make_stays_owed_and_lands_once_the_key_may() {
    let terms = deposit_terms();
    let (fixture, stripe) = deposit_fixture(SECRET_KEY).await;
    let slots = fixture.slots().await;
    // Stripe refuses every capture from here on, the confirm's own included.
    stripe.lock().expect("fake stripe").refuse_intent_moves = true;
    let (payment_id, _) = paid_booking(
        &fixture,
        &stripe,
        selected(&slots[0]),
        "restricted-key",
        &terms,
    )
    .await;
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::CaptureDue {
            amount_minor: terms.amount_minor
        },
        "the refused capture leaves the deposit owed"
    );

    let capture_posts = || {
        stripe
            .lock()
            .expect("fake stripe")
            .calls
            .iter()
            .filter(|(call, _, _)| call.ends_with("/capture"))
            .count()
    };

    // Four passes, each an hour and a second after the last, the last one
    // now. A settle row is claimed only once it is due by the vault's own
    // clock, so no pass may run ahead of that clock: the earlier ones run
    // behind it. In the first three every ask is refused again: a live row
    // asks Stripe, no move fails for good, and the capture stays owed.
    let now = now_secs().expect("clock");
    let pass_at = |pass: u64| now - (3 - pass) * 3_601;
    for pass in 0..3_u64 {
        let asked_before = capture_posts();
        let drain = run_settle_pass(&fixture, pass_at(pass)).await;
        assert_eq!(
            drain.failed, 0,
            "pass {pass}: a refused capture fails no move for good"
        );
        assert!(
            capture_posts() > asked_before,
            "pass {pass}: a live settle row asked Stripe for the capture again"
        );
        assert_eq!(
            deposit_state(&fixture, &payment_id),
            DepositState::CaptureDue {
                amount_minor: terms.amount_minor
            },
            "pass {pass}: the capture stays owed"
        );
    }
    assert_eq!(
        stripe.lock().expect("fake stripe").intents[&payment_id].status,
        "requires_capture",
        "a refused capture takes nothing"
    );

    // The owner gives the key the permission: the next pass captures, once.
    let refused_captures = capture_posts();
    stripe.lock().expect("fake stripe").refuse_intent_moves = false;
    let drain = run_settle_pass(&fixture, pass_at(3)).await;
    assert_eq!(
        drain.captured, 1,
        "the owed capture runs once the key may capture"
    );
    assert_eq!(drain.failed, 0, "the landing pass fails no move");
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Captured {
            amount_minor: terms.amount_minor
        }
    );
    assert_eq!(
        stripe.lock().expect("fake stripe").intents[&payment_id].status,
        "succeeded",
        "Stripe captured the payment"
    );
    assert_eq!(
        capture_posts() - refused_captures,
        1,
        "the capture was made once"
    );
}

/// A deposit whose late cancel owes half of it back, the payment it was
/// captured on, and its fixture.
async fn half_refund_owed(session: &str) -> (Fixture, Shared, String) {
    let terms = late_cancel_half_terms();
    let (fixture, stripe) = deposit_fixture_with(terms.clone(), SECRET_KEY).await;
    let slots = fixture.slots().await;
    let (payment_id, cancel_token) =
        paid_booking(&fixture, &stripe, selected(&slots[0]), session, &terms).await;
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Captured {
            amount_minor: 5_000
        }
    );
    fixture
        .dispatch(
            "booking.cancel",
            cancel(cancel_token, &format!("cancel-{session}")),
        )
        .await
        .expect("cancel");
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::RefundDue {
            amount_minor: 2_500
        },
        "a late cancel owes half the deposit back"
    );
    (fixture, stripe, payment_id)
}

/// A refund a person made in the Stripe dashboard, under no settle key.
fn refund_by_hand(id: &str, payment_id: &str, amount: u64, status: &str) -> FakeRefund {
    FakeRefund {
        id: id.to_owned(),
        payment_intent: payment_id.to_owned(),
        amount,
        status: status.to_owned(),
        settle_key: None,
        metadata: BTreeMap::new(),
    }
}

/// The owner's key may not refund, so the owed refund stays owed and its
/// settle row lives on. The owner then refunds by hand in the Stripe
/// dashboard and repairs the key: the hand refund stands as the deposit's
/// refund, and the row makes no second one
/// (FIX [BK-DEPOSIT-REFUND-AFTER-HAND-REFUND-PAID-TWICE]).
#[tokio::test]
async fn a_refund_the_owner_made_by_hand_is_not_made_again_once_the_key_may_refund() {
    let (fixture, stripe, payment_id) = half_refund_owed("hand-refund").await;

    // Two passes an hour and a second apart, the second one now: a settle
    // row is claimed only once it is due by the vault's own clock. In the
    // first, Stripe refuses the refund: every live settle row of the deposit
    // asked, and the refund stays owed.
    stripe.lock().expect("fake stripe").refuse_refunds = true;
    let now = now_secs().expect("clock");
    let drain = run_settle_pass(&fixture, now - 3_601).await;
    assert_eq!(drain.failed, 0, "a refused refund fails no move for good");
    assert_eq!(drain.refunded, 0, "a refused refund is no refund");
    let refused_posts = refund_posts(&stripe);
    assert!(
        refused_posts > 0,
        "a live settle row asked Stripe for the refund"
    );
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::RefundDue {
            amount_minor: 2_500
        },
        "the refused refund stays owed"
    );

    // The owner refunds the half by hand, then gives the key the permission.
    {
        let mut stripe = stripe.lock().expect("fake stripe");
        stripe.refunds.push(refund_by_hand(
            "re_by_hand",
            &payment_id,
            2_500,
            "succeeded",
        ));
        stripe.refuse_refunds = false;
    }
    let drain = run_settle_pass(&fixture, now).await;
    assert_eq!(drain.failed, 0, "the landing pass fails no move");
    assert_eq!(
        drain.refunded, 1,
        "the hand refund stands as the deposit's refund"
    );
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Refunded {
            amount_minor: 2_500
        }
    );
    assert_eq!(
        refund_posts(&stripe),
        refused_posts,
        "no refund was asked once the payment held the hand refund"
    );
    assert_eq!(
        stripe.lock().expect("fake stripe").refunds.len(),
        1,
        "the payment holds the hand refund alone"
    );
}

/// A hand refund short of what is owed is never topped up by the settle row:
/// it asks Stripe for no refund, and the refund stays owed. Once the owner's
/// own refunds cover what is owed the row waits while Stripe holds one of
/// them, and ends when Stripe has made them all.
#[tokio::test]
async fn a_hand_refund_short_of_what_is_owed_is_never_topped_up_by_the_settle_row() {
    let (fixture, stripe, payment_id) = half_refund_owed("short-hand-refund").await;
    let owed = DepositState::RefundDue {
        amount_minor: 2_500,
    };

    // Three passes an hour and a second apart, the last one now.
    let now = now_secs().expect("clock");
    let pass_at = |pass: u64| now - (2 - pass) * 3_601;

    // The owner refunded 1000 of the 2500 by hand.
    stripe
        .lock()
        .expect("fake stripe")
        .refunds
        .push(refund_by_hand(
            "re_by_hand_1",
            &payment_id,
            1_000,
            "succeeded",
        ));
    let drain = run_settle_pass(&fixture, pass_at(0)).await;
    assert_eq!(
        drain.failed, 0,
        "a short hand refund fails no move for good"
    );
    assert_eq!(drain.refunded, 0, "the row adds no refund of its own");
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        owed,
        "the refund stays owed while 1500 is missing"
    );

    // The owner refunds the missing 1500 by hand; Stripe still holds it.
    stripe
        .lock()
        .expect("fake stripe")
        .refunds
        .push(refund_by_hand(
            "re_by_hand_2",
            &payment_id,
            1_500,
            "pending",
        ));
    let drain = run_settle_pass(&fixture, pass_at(1)).await;
    assert_eq!(drain.failed, 0, "a held hand refund fails no move for good");
    assert_eq!(drain.refunded, 0, "a refund Stripe holds is no refund yet");
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        owed,
        "the refund stays owed while Stripe holds a part of it"
    );

    // Stripe finishes the second hand refund: the two cover what is owed.
    stripe.lock().expect("fake stripe").refunds[1].status = "succeeded".to_owned();
    let drain = run_settle_pass(&fixture, pass_at(2)).await;
    assert_eq!(drain.failed, 0, "the landing pass fails no move");
    assert_eq!(
        drain.refunded, 1,
        "the hand refunds stand as the deposit's refund"
    );
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Refunded {
            amount_minor: 2_500
        }
    );
    assert_eq!(
        refund_posts(&stripe),
        0,
        "the settle row never asked Stripe for a refund"
    );
}

/// Stripe ends the settle row's own refund failed, so the refund stays owed
/// and the row makes no second one under its key. The owner then refunds by
/// hand: the failed refund paid nothing back and hides nothing, so the hand
/// refund stands as the deposit's refund and the row ends (second review of
/// #9037, 16 Nov).
#[tokio::test]
async fn a_hand_refund_stands_once_the_rows_own_refund_ended_failed() {
    let (fixture, stripe, payment_id) = half_refund_owed("failed-keyed-refund").await;
    let owed = DepositState::RefundDue {
        amount_minor: 2_500,
    };

    // Three passes an hour and a second apart, the last one now.
    let now = now_secs().expect("clock");
    let pass_at = |pass: u64| now - (2 - pass) * 3_601;

    // The row asks for the refund, and Stripe ends it failed.
    stripe.lock().expect("fake stripe").refund_status = Some("failed".to_owned());
    let drain = run_settle_pass(&fixture, pass_at(0)).await;
    assert_eq!(drain.failed, 0, "a failed refund fails no move for good");
    assert_eq!(drain.refunded, 0, "a failed refund is no refund");
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        owed,
        "the failed refund stays owed"
    );
    {
        let mut stripe = stripe.lock().expect("fake stripe");
        assert_eq!(
            stripe.refunds.len(),
            1,
            "guard: the payment holds the one refund the row asked for"
        );
        assert_eq!(stripe.refunds[0].status, "failed");
        assert!(
            stripe.refunds[0].settle_key.is_some(),
            "guard: the failed refund carries the row's key"
        );
        // From here on Stripe would make a new refund succeed.
        stripe.refund_status = None;
    }

    // The next pass finds the failed refund under its key and asks for no
    // second one.
    let drain = run_settle_pass(&fixture, pass_at(1)).await;
    assert_eq!(drain.failed, 0, "the failed refund fails no move for good");
    assert_eq!(drain.refunded, 0, "the row makes no second refund");
    assert_eq!(deposit_state(&fixture, &payment_id), owed);
    assert_eq!(
        refund_posts(&stripe),
        1,
        "the refund was asked for once, under the row's key"
    );

    // The owner refunds the half by hand.
    stripe
        .lock()
        .expect("fake stripe")
        .refunds
        .push(refund_by_hand(
            "re_by_hand",
            &payment_id,
            2_500,
            "succeeded",
        ));
    let drain = run_settle_pass(&fixture, pass_at(2)).await;
    assert_eq!(drain.failed, 0, "the landing pass fails no move");
    assert_eq!(
        drain.refunded, 1,
        "the hand refund stands as the deposit's refund"
    );
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Refunded {
            amount_minor: 2_500
        }
    );
    assert_eq!(
        refund_posts(&stripe),
        1,
        "no refund was asked once the payment held the hand refund"
    );
}

/// Stripe lists a payment's refunds at most 100 to a page, newest first. The
/// settle row's own refund, still pending behind 100 refunds the owner tried
/// by hand and Stripe failed, sits on the second page: the next pass reads
/// every page, finds it under its key and makes no second one, which Stripe's
/// one-day key would not stop (FIX [BK-DEPOSIT-REFUND-LIST-ONE-PAGE]).
#[tokio::test]
async fn a_pending_refund_past_the_first_page_of_refunds_is_not_made_again() {
    let terms = any_notice_terms();
    let (fixture, stripe) = deposit_fixture_with(terms.clone(), SECRET_KEY).await;
    let slots = fixture.slots().await;
    let (payment_id, cancel_token) = paid_booking(
        &fixture,
        &stripe,
        selected(&slots[0]),
        "refund-past-first-page",
        &terms,
    )
    .await;
    fixture
        .dispatch(
            "booking.cancel",
            cancel(cancel_token, "cancel-refund-past-first-page"),
        )
        .await
        .expect("cancel");
    let owed = DepositState::RefundDue {
        amount_minor: 5_000,
    };
    assert_eq!(deposit_state(&fixture, &payment_id), owed);

    // Three passes an hour and a second apart, the last one now.
    let now = now_secs().expect("clock");
    let pass_at = |pass: u64| now - (2 - pass) * 3_601;

    // The row asks for the refund, and Stripe holds it pending.
    stripe.lock().expect("fake stripe").refund_status = Some("pending".to_owned());
    let drain = run_settle_pass(&fixture, pass_at(0)).await;
    assert_eq!(drain.failed, 0, "a pending refund never fails for good");
    assert_eq!(drain.refunded, 0, "a pending refund is no refund");
    assert_eq!(refund_posts(&stripe), 1, "guard: the row asked once");

    // The owner tries 100 refunds by hand, and Stripe fails each one: the
    // row's own refund is now the 101st, on the second page.
    {
        let mut stripe = stripe.lock().expect("fake stripe");
        for attempt in 1..=100 {
            stripe.refunds.push(refund_by_hand(
                &format!("re_by_hand_{attempt}"),
                &payment_id,
                5_000,
                "failed",
            ));
        }
        stripe.refund_status = None;
    }
    let drain = run_settle_pass(&fixture, pass_at(1)).await;
    assert_eq!(
        refund_posts(&stripe),
        1,
        "the pending refund past the first page was never made twice"
    );
    assert_eq!(drain.failed, 0, "a pending refund never fails for good");
    assert_eq!(drain.refunded, 0, "a pending refund is no refund");
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        owed,
        "the refund stays owed while Stripe holds it"
    );
    assert!(
        stripe
            .lock()
            .expect("fake stripe")
            .calls
            .iter()
            .any(|(call, query, _)| call == "GET /v1/refunds"
                && query.contains_key("starting_after")),
        "guard: the pass read the second page"
    );

    // Stripe finishes the row's refund; the next pass finds it by its key.
    {
        let mut stripe = stripe.lock().expect("fake stripe");
        assert!(
            stripe.refunds[0].settle_key.is_some(),
            "guard: the first refund is the row's own"
        );
        stripe.refunds[0].status = "succeeded".to_owned();
    }
    let drain = run_settle_pass(&fixture, pass_at(2)).await;
    assert_eq!(drain.failed, 0);
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
        "the refund was asked for once, under the row's key"
    );
}

/// A refund may carry 50 metadata pairs of up to 500 characters each, so a
/// page of 100 refunds can pass 256 KiB. The settle row's own refund, behind
/// 100 failed hand refunds that each carry full metadata, is still found on
/// the second page once Stripe has made it (Sol blind review of #9862,
/// round 1).
#[tokio::test]
async fn a_refund_behind_a_page_of_refunds_with_full_metadata_is_found() {
    let terms = any_notice_terms();
    let (fixture, stripe) = deposit_fixture_with(terms.clone(), SECRET_KEY).await;
    let slots = fixture.slots().await;
    let (payment_id, cancel_token) = paid_booking(
        &fixture,
        &stripe,
        selected(&slots[0]),
        "refund-behind-full-metadata",
        &terms,
    )
    .await;
    fixture
        .dispatch(
            "booking.cancel",
            cancel(cancel_token, "cancel-refund-behind-full-metadata"),
        )
        .await
        .expect("cancel");
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::RefundDue {
            amount_minor: 5_000
        }
    );

    // Two passes an hour and a second apart, the second one now. In the
    // first, the row asks for the refund, and Stripe holds it pending.
    let now = now_secs().expect("clock");
    stripe.lock().expect("fake stripe").refund_status = Some("pending".to_owned());
    let drain = run_settle_pass(&fixture, now - 3_601).await;
    assert_eq!(drain.refunded, 0, "a pending refund is no refund");
    assert_eq!(refund_posts(&stripe), 1, "guard: the row asked once");

    // The owner tries 100 refunds by hand, each noted in full metadata, and
    // Stripe fails each one. Then Stripe makes the row's own refund.
    {
        let mut stripe = stripe.lock().expect("fake stripe");
        let full_metadata: BTreeMap<String, String> = (0..50)
            .map(|pair| (format!("owner_note_{pair:02}"), "n".repeat(500)))
            .collect();
        for attempt in 1..=100 {
            let mut refund =
                refund_by_hand(&format!("re_noted_{attempt}"), &payment_id, 5_000, "failed");
            refund.metadata = full_metadata.clone();
            stripe.refunds.push(refund);
        }
        let first_page: Vec<Value> = stripe.refunds[1..].iter().map(refund_json).collect();
        assert!(
            serde_json::to_vec(&first_page).expect("page").len() > 256 * 1024,
            "guard: the first page of refunds passes 256 KiB"
        );
        assert!(
            stripe.refunds[0].settle_key.is_some(),
            "guard: the first refund is the row's own"
        );
        stripe.refunds[0].status = "succeeded".to_owned();
        stripe.refund_status = None;
    }
    let drain = run_settle_pass(&fixture, now).await;
    assert_eq!(
        drain.refunded, 1,
        "the row's own refund is found behind the full first page"
    );
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        DepositState::Refunded {
            amount_minor: 5_000
        }
    );
    assert_eq!(
        refund_posts(&stripe),
        1,
        "the refund was asked for once, under the row's key"
    );
}

/// A list that names one refund on two pages never counts it twice. The half
/// the owner refunded by hand, read twice, would cover the whole refund owed
/// and end the row with half of it never paid back: the pass refuses the
/// list instead, and the refund stays owed (Sol blind review of #9862,
/// round 1).
#[tokio::test]
async fn a_refund_the_list_names_twice_is_not_counted_twice() {
    let terms = any_notice_terms();
    let (fixture, stripe) = deposit_fixture_with(terms.clone(), SECRET_KEY).await;
    let slots = fixture.slots().await;
    let (payment_id, cancel_token) = paid_booking(
        &fixture,
        &stripe,
        selected(&slots[0]),
        "refund-listed-twice",
        &terms,
    )
    .await;
    fixture
        .dispatch(
            "booking.cancel",
            cancel(cancel_token, "cancel-refund-listed-twice"),
        )
        .await
        .expect("cancel");
    let owed = DepositState::RefundDue {
        amount_minor: 5_000,
    };
    assert_eq!(deposit_state(&fixture, &payment_id), owed);

    // The owner tries 200 refunds by hand, which Stripe fails, then refunds
    // half by hand. Newest first, that half leads the first page; the second
    // page ends on re_failed_2, and the page asked from after it lists from
    // the start again, once.
    {
        let mut stripe = stripe.lock().expect("fake stripe");
        for attempt in 1..=200 {
            stripe.refunds.push(refund_by_hand(
                &format!("re_failed_{attempt}"),
                &payment_id,
                5_000,
                "failed",
            ));
        }
        stripe.refunds.push(refund_by_hand(
            "re_paid_half",
            &payment_id,
            2_500,
            "succeeded",
        ));
        stripe.restart_refund_list_after = Some("re_failed_2".to_owned());
    }
    let drain = run_settle_pass(&fixture, now_secs().expect("clock")).await;
    assert!(
        stripe
            .lock()
            .expect("fake stripe")
            .restart_refund_list_after
            .is_none(),
        "guard: the list started again after re_failed_2"
    );
    assert_eq!(drain.refunded, 0, "half paid back is not the refund owed");
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        owed,
        "the refund stays owed"
    );
    assert_eq!(
        refund_posts(&stripe),
        0,
        "no refund is made on a list that names a refund twice"
    );
}

/// A list that names the row's own refund twice on one page is refused, even
/// when the row's refund comes first: every id on a page is checked before
/// any refund on it counts, so no repeat is read past. The row stays owed,
/// and the pass makes no second refund (Sol blind review of #9862, round 2).
#[tokio::test]
async fn a_page_that_names_the_rows_own_refund_twice_is_refused() {
    let terms = any_notice_terms();
    let (fixture, stripe) = deposit_fixture_with(terms.clone(), SECRET_KEY).await;
    let slots = fixture.slots().await;
    let (payment_id, cancel_token) = paid_booking(
        &fixture,
        &stripe,
        selected(&slots[0]),
        "own-refund-listed-twice",
        &terms,
    )
    .await;
    fixture
        .dispatch(
            "booking.cancel",
            cancel(cancel_token, "cancel-own-refund-listed-twice"),
        )
        .await
        .expect("cancel");
    let owed = DepositState::RefundDue {
        amount_minor: 5_000,
    };
    assert_eq!(deposit_state(&fixture, &payment_id), owed);

    // Two passes an hour and a second apart, the second one now. In the
    // first, the row asks for the refund, and Stripe holds it pending.
    let now = now_secs().expect("clock");
    stripe.lock().expect("fake stripe").refund_status = Some("pending".to_owned());
    let drain = run_settle_pass(&fixture, now - 3_601).await;
    assert_eq!(drain.refunded, 0, "a pending refund is no refund");
    assert_eq!(refund_posts(&stripe), 1, "guard: the row asked once");

    // Stripe makes the row's refund, and its list names that refund twice
    // on the one page.
    {
        let mut stripe = stripe.lock().expect("fake stripe");
        assert!(
            stripe.refunds[0].settle_key.is_some(),
            "guard: the first refund is the row's own"
        );
        stripe.refunds[0].status = "succeeded".to_owned();
        let repeat = stripe.refunds[0].clone();
        stripe.refunds.push(repeat);
        stripe.refund_status = None;
    }
    let drain = run_settle_pass(&fixture, now).await;
    assert_eq!(
        drain.refunded, 0,
        "a list that names a refund twice settles nothing"
    );
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        owed,
        "the refund stays owed"
    );
    assert_eq!(
        refund_posts(&stripe),
        1,
        "no second refund is made on a list that names a refund twice"
    );
}

/// A refund page that does not say whether more refunds follow is refused,
/// never read as the list's end. Behind 100 refunds the owner tried by hand
/// and Stripe failed, the row's own pending refund sits on the second page:
/// a pass that took the first page for the whole list would make a second
/// refund under the row's key, which Stripe dedupes for a day only (Sol
/// blind review of #9862, round 2).
#[tokio::test]
async fn a_refund_page_that_omits_has_more_makes_no_refund() {
    let terms = any_notice_terms();
    let (fixture, stripe) = deposit_fixture_with(terms.clone(), SECRET_KEY).await;
    let slots = fixture.slots().await;
    let (payment_id, cancel_token) = paid_booking(
        &fixture,
        &stripe,
        selected(&slots[0]),
        "refund-page-omits-has-more",
        &terms,
    )
    .await;
    fixture
        .dispatch(
            "booking.cancel",
            cancel(cancel_token, "cancel-refund-page-omits-has-more"),
        )
        .await
        .expect("cancel");
    let owed = DepositState::RefundDue {
        amount_minor: 5_000,
    };
    assert_eq!(deposit_state(&fixture, &payment_id), owed);

    // Two passes an hour and a second apart, the second one now. In the
    // first, the row asks for the refund, and Stripe holds it pending.
    let now = now_secs().expect("clock");
    stripe.lock().expect("fake stripe").refund_status = Some("pending".to_owned());
    let drain = run_settle_pass(&fixture, now - 3_601).await;
    assert_eq!(drain.refunded, 0, "a pending refund is no refund");
    assert_eq!(refund_posts(&stripe), 1, "guard: the row asked once");

    // The owner tries 100 refunds by hand, and Stripe fails each one: the
    // row's own refund is now the 101st, on the second page. Stripe's pages
    // stop saying whether more follow.
    {
        let mut stripe = stripe.lock().expect("fake stripe");
        for attempt in 1..=100 {
            stripe.refunds.push(refund_by_hand(
                &format!("re_by_hand_{attempt}"),
                &payment_id,
                5_000,
                "failed",
            ));
        }
        stripe.omit_refund_list_has_more = true;
        stripe.refund_status = None;
    }
    let drain = run_settle_pass(&fixture, now).await;
    assert_eq!(
        refund_posts(&stripe),
        1,
        "no second refund is made on a page that omits has_more"
    );
    assert_eq!(drain.refunded, 0, "a pending refund is no refund");
    assert_eq!(
        deposit_state(&fixture, &payment_id),
        owed,
        "the refund stays owed"
    );
}
