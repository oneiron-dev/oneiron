//! Booking admission charges the client the connection proves (C7): its own
//! peer, or the client a configured trusted proxy names. A forwarding header
//! from anyone else mints no budget.

use axum::http::header::AUTHORIZATION;
use oneiron::booking::anti_abuse::observe_slot_list_request;

use super::fixture::*;
use super::*;

const LIMIT: u32 = 2;

fn install_slot_list_rate(fixture: &Fixture) {
    let scope = BookingRuleScope {
        page_ref: fixture.page,
        event_type: None,
    };
    let rule = BookingAntiAbuseRule::SlotListRate {
        per_minute_per_ip: NonZeroU32::new(LIMIT).expect("limit"),
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
}

/// One availability listing over the real router from `peer`, carrying
/// `forwarded` as its `X-Forwarded-For`. `owner` takes the authenticated route
/// with an owner credential; otherwise the anonymous public one. Each call
/// asks for a different window, so no cached listing answers it.
async fn list(fixture: &Fixture, peer: &str, forwarded: &str, owner: bool, nth: u64) {
    let now = now_secs().expect("clock");
    let input = BookingAvailabilityInput {
        event_type: EventTypeKey("intro".to_owned()),
        window: TimeRange {
            start: now + 86_400 + nth * 3_600,
            end: now + 3 * 86_400 + nth * 3_600,
        },
        visitor_tz: "UTC".to_owned(),
        constraint: None,
        session_ref: format!("client-address-{nth}"),
    };
    let (path, mut request) = if owner {
        let request = Request::builder().header(
            AUTHORIZATION,
            format!(
                "{}jti=booking-owner",
                crate::test_credentials::RECIPE_PREFIX
            ),
        );
        ("/api/booking", request)
    } else {
        ("/public/booking", Request::builder())
    };
    request = request
        .method("POST")
        .uri(format!("{path}/{}/availability", fixture.token))
        .header(CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", forwarded)
        .extension(ConnectInfo(SocketAddr::new(
            peer.parse().expect("peer"),
            43_123,
        )));
    let request = request
        .body(Body::from(serde_json::to_vec(&input).expect("body")))
        .expect("request");
    let request = crate::test_credentials::bind_request(&fixture.server, request);
    let response = crate::build_app(fixture.server.clone())
        .oneshot(request)
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK, "{peer} {forwarded}");
}

/// Whether `address` was charged one listing this minute: one more fits under
/// [`LIMIT`] and the next is refused. An untouched address fits two more.
fn charged_once(fixture: &Fixture, address: &str, now: u64) -> bool {
    let key = booking_ip_hash(address);
    let limit = NonZeroU32::new(LIMIT).expect("limit");
    let observe =
        || observe_slot_list_request(&fixture.server.vault, &key, limit, now).expect("observe");
    let first = observe();
    let second = observe();
    assert_eq!(first, BookingRateDecision::Allowed, "{address} over budget");
    matches!(second, BookingRateDecision::Exceeded { .. })
}

#[tokio::test]
async fn authenticated_booking_charges_the_connection_not_a_forwarding_header() {
    for _ in 0..3 {
        let fixture = Fixture::new();
        install_slot_list_rate(&fixture);
        let now = now_secs().expect("clock");
        list(&fixture, "203.0.113.9", "198.51.100.7", true, 0).await;
        if now / 60 != now_secs().expect("clock") / 60 {
            continue;
        }
        assert!(
            charged_once(&fixture, "203.0.113.9", now),
            "the connection pays"
        );
        assert!(
            !charged_once(&fixture, "198.51.100.7", now),
            "a header from an untrusted peer mints no budget"
        );
        return;
    }
    panic!("could not list within one rate window");
}

// Trusted proxies are new with the resolver; below this line has no before.

#[tokio::test]
async fn trusted_proxy_chain_charges_each_client_behind_it() {
    for _ in 0..3 {
        let fixture = Fixture::behind(vec!["10.0.0.0/8".parse().expect("proxy block")]);
        install_slot_list_rate(&fixture);
        let now = now_secs().expect("clock");
        // Right to left past every trusted hop: the client-supplied entry to
        // the left of the first untrusted one is never read.
        list(&fixture, "10.0.0.2", "192.0.2.50, 198.51.100.7", false, 0).await;
        list(&fixture, "10.0.0.2", "198.51.100.8, 10.0.0.3", false, 1).await;
        // A chain the proxy did not write legibly charges the proxy itself.
        list(&fixture, "10.0.0.2", "not-an-address", false, 2).await;
        // A peer outside the trusted block is charged as itself.
        list(&fixture, "203.0.113.9", "198.51.100.9", false, 3).await;
        // The authenticated route reads the same chain.
        list(&fixture, "10.0.0.2", "198.51.100.10", true, 4).await;
        if now / 60 != now_secs().expect("clock") / 60 {
            continue;
        }
        for charged in [
            "198.51.100.7",
            "198.51.100.8",
            "10.0.0.2",
            "203.0.113.9",
            "198.51.100.10",
        ] {
            assert!(charged_once(&fixture, charged, now), "{charged} pays");
        }
        for untouched in ["192.0.2.50", "10.0.0.3", "198.51.100.9"] {
            assert!(
                !charged_once(&fixture, untouched, now),
                "{untouched} is not charged"
            );
        }
        return;
    }
    panic!("could not list within one rate window");
}
