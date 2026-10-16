//! Rule five at the owner's booking windows: an authenticated caller past one
//! waits for it to open and is served, never answered "retry after". Time is
//! paused, so the booking clock moves only as the runtime's clock does.

use axum::http::header::AUTHORIZATION;

use super::fixture::*;
use super::*;
use crate::wire_telemetry::LimitRow;

fn install(fixture: &Fixture, rule: BookingAntiAbuseRule) {
    let scope = BookingRuleScope {
        page_ref: fixture.page,
        event_type: None,
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
}

fn per_minute(limit: u32) -> NonZeroU32 {
    NonZeroU32::new(limit).expect("positive")
}

/// The fixture, its booking clock starting at the wall clock and moving with
/// the runtime's paused time from here.
fn fixture_on_the_runtime_clock() -> Fixture {
    let mut fixture = Fixture::new();
    let server = Arc::get_mut(&mut fixture.server).expect("the fixture alone holds its server");
    server.booking_test_now_secs = Some(now_secs().expect("clock"));
    server.booking_test_clock_from = Some(tokio::time::Instant::now());
    fixture
}

/// One request on the private booking route `route`, under the owner
/// credential `jti`, from the loopback peer.
async fn owner(fixture: &Fixture, jti: &str, route: &str, body: impl serde::Serialize) -> Response {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/booking/{}/{route}", fixture.token))
        .header(
            AUTHORIZATION,
            format!("{}jti={jti}", crate::test_credentials::RECIPE_PREFIX),
        )
        .header(CONTENT_TYPE, "application/json")
        .extension(ConnectInfo(
            "127.0.0.1:43123".parse::<SocketAddr>().expect("peer"),
        ))
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    let request = crate::test_credentials::bind_request(&fixture.server, request);
    crate::build_app(fixture.server.clone())
        .oneshot(request)
        .await
        .expect("response")
}

async fn served(response: Response) -> BookingOperationResponse {
    let status = response.status();
    let body = bytes(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "served, not refused: {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).expect("operation response")
}

/// A listing of a window `nth` hours on, so no two listings ask the same.
fn listing(nth: u64) -> BookingAvailabilityInput {
    let now = now_secs().expect("clock");
    BookingAvailabilityInput {
        event_type: EventTypeKey("intro".to_owned()),
        window: TimeRange {
            start: now + 86_400 + nth * 3_600,
            end: now + 3 * 86_400 + nth * 3_600,
        },
        visitor_tz: "UTC".to_owned(),
        constraint: None,
        session_ref: format!("turn-{nth}"),
    }
}

fn asked(fixture: &Fixture) -> bool {
    fixture
        .server
        .wire_telemetry
        .limit_questions()
        .latest(LimitRow::BookingWindows)
        .is_some()
}

fn book_input(request: BookingOperationRequest) -> BookingBookInput {
    let BookingOperationRequest::Book(input) = request else {
        panic!("a book request")
    };
    input
}

/// Past the owner's slot-list, hold and book windows (one a minute each), the
/// second request of each kind waits for its window to open and is served.
#[tokio::test(start_paused = true)]
async fn an_authenticated_caller_past_each_booking_window_waits_and_is_served() {
    let fixture = fixture_on_the_runtime_clock();
    let slots = fixture.slots().await;
    assert!(slots.len() > 1);
    install(
        &fixture,
        BookingAntiAbuseRule::SlotListRate {
            per_minute_per_ip: per_minute(1),
            cache_ttl_secs: std::num::NonZeroU64::new(30).expect("TTL"),
        },
    );
    install(
        &fixture,
        BookingAntiAbuseRule::HoldRate {
            max_active_per_session: 1,
            per_minute_per_ip: per_minute(1),
        },
    );
    install(
        &fixture,
        BookingAntiAbuseRule::BookRate {
            per_minute_per_ip: per_minute(1),
            max_active_future_per_email: 2,
        },
    );

    for nth in 0..2 {
        served(owner(&fixture, "agent", "availability", listing(nth)).await).await;
    }
    let mut holds = Vec::new();
    for (nth, slot) in slots.iter().take(2).enumerate() {
        let session = format!("turn-hold-{nth}");
        let request = book_input(hold(selected(slot), &session, None));
        let held = served(owner(&fixture, "agent", "book", request).await).await;
        let BookingOperationResponse::Book(BookingBookResult::Held { hold_token, .. }) = held
        else {
            panic!("held, got {held:?}")
        };
        holds.push((hold_token, session));
    }
    for (token, session) in holds {
        let request = book_input(confirm(token, &session));
        let confirmed = served(owner(&fixture, "agent", "book", request).await).await;
        assert!(
            matches!(
                confirmed,
                BookingOperationResponse::Book(BookingBookResult::Confirmed { .. })
            ),
            "confirmed, got {confirmed:?}"
        );
    }
    assert!(asked(&fixture), "each window's crossing asks");
}

/// Rule five at the booking windows row: `callers` listings on one
/// credential, past a window of half as many a minute, all complete and the
/// row asks. It runs on a paused runtime of its own.
pub(crate) fn cross_the_booking_windows(callers: usize) -> crate::admission::Crossing {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let fixture = fixture_on_the_runtime_clock();
        install(
            &fixture,
            BookingAntiAbuseRule::SlotListRate {
                per_minute_per_ip: per_minute(u32::try_from(callers / 2).expect("callers")),
                cache_ttl_secs: std::num::NonZeroU64::new(30).expect("TTL"),
            },
        );
        let listings = (0_u64..)
            .take(callers)
            .map(|nth| owner(&fixture, "agent", "availability", listing(nth)));
        let responses = futures_util::future::join_all(listings).await;
        crate::admission::Crossing {
            refused: responses
                .iter()
                .filter(|response| response.status() != StatusCode::OK)
                .count(),
            asked: asked(&fixture),
        }
    })
}
