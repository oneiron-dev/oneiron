//! Booking admission charges the client the connection proves (C7): its own
//! peer, or the client a configured trusted proxy names. A forwarding header
//! from anyone else mints no budget.

use axum::http::HeaderValue;
use axum::http::header::AUTHORIZATION;
use oneiron::booking::anti_abuse::observe_slot_list_request;

use super::fixture::*;
use super::*;
use crate::managed::UnixPeer;

const LIMIT: u32 = 3;

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

/// Who a connection comes from, as the listener records it.
#[derive(Clone, Copy)]
enum Peer {
    Tcp(&'static str),
    /// The managed supervisor on its kernel-verified socket.
    Supervisor,
    /// A connection the listener recorded no peer for.
    Unrecorded,
}

/// One availability listing over the real router from `peer`, carrying each
/// of `forwarded` as an `X-Forwarded-For` field. `owner` takes the
/// authenticated route with an owner credential; otherwise the anonymous
/// public one. Each call asks for a different window, so no cached listing
/// answers it.
async fn list(
    fixture: &Fixture,
    peer: Peer,
    forwarded: &[&[u8]],
    owner: bool,
    nth: u64,
) -> StatusCode {
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
        .header(CONTENT_TYPE, "application/json");
    for field in forwarded {
        let field = HeaderValue::from_bytes(field).expect("field value");
        request = request.header("x-forwarded-for", field);
    }
    request = match peer {
        Peer::Tcp(ip) => request.extension(ConnectInfo(SocketAddr::new(
            ip.parse().expect("peer"),
            43_123,
        ))),
        Peer::Supervisor => request.extension(ConnectInfo(UnixPeer::verified_for_test())),
        Peer::Unrecorded => request,
    };
    let request = request
        .body(Body::from(serde_json::to_vec(&input).expect("body")))
        .expect("request");
    let request = crate::test_credentials::bind_request(&fixture.server, request);
    crate::build_app(fixture.server.clone())
        .oneshot(request)
        .await
        .expect("response")
        .status()
}

/// How many listings `address` was charged this minute: the rest of
/// [`LIMIT`] is spent until a listing is refused.
fn spent(fixture: &Fixture, address: &str, now: u64) -> u32 {
    let key = booking_ip_hash(address);
    let limit = NonZeroU32::new(LIMIT).expect("limit");
    let left = (0..=LIMIT)
        .take_while(|_| {
            observe_slot_list_request(&fixture.server.vault, &key, limit, now).expect("observe")
                == BookingRateDecision::Allowed
        })
        .count();
    LIMIT - u32::try_from(left).expect("count")
}

/// Whether the clock is still in the rate window `then` was in.
fn same_minute(then: u64) -> bool {
    then / 60 == now_secs().expect("clock") / 60
}

#[tokio::test]
async fn authenticated_booking_charges_the_connection_not_a_forwarding_header() {
    for _ in 0..3 {
        let fixture = Fixture::new();
        install_slot_list_rate(&fixture);
        let now = now_secs().expect("clock");
        // One caller rotating the header it sends.
        for (nth, forwarded) in ["198.51.100.7", "198.51.100.8"].into_iter().enumerate() {
            let peer = Peer::Tcp("203.0.113.9");
            let status = list(&fixture, peer, &[forwarded.as_bytes()], true, nth as u64).await;
            assert_eq!(status, StatusCode::OK);
        }
        if !same_minute(now) {
            continue;
        }
        assert_eq!(
            spent(&fixture, "203.0.113.9", now),
            2,
            "the connection pays"
        );
        for named in ["198.51.100.7", "198.51.100.8"] {
            assert_eq!(spent(&fixture, named, now), 0, "{named} minted no budget");
        }
        return;
    }
    panic!("could not list within one rate window");
}

/// The managed supervisor is one loopback caller to booking, on either route,
/// whatever forwarding header it passes on.
#[tokio::test]
async fn the_managed_supervisor_is_charged_as_loopback_and_its_header_unread() {
    for owner in [true, false] {
        supervisor_listing_charges_loopback(owner).await;
    }
}

async fn supervisor_listing_charges_loopback(owner: bool) {
    for _ in 0..3 {
        let fixture = Fixture::new();
        install_slot_list_rate(&fixture);
        let now = now_secs().expect("clock");
        let forwarded = "198.51.100.7".as_bytes();
        let status = list(&fixture, Peer::Supervisor, &[forwarded], owner, 0).await;
        assert_eq!(status, StatusCode::OK, "owner route: {owner}");
        if !same_minute(now) {
            continue;
        }
        assert_eq!(
            spent(&fixture, "198.51.100.7", now),
            0,
            "owner route: {owner}"
        );
        assert_eq!(spent(&fixture, "127.0.0.1", now), 1, "owner route: {owner}");
        return;
    }
    panic!("could not list within one rate window");
}

/// A connection with no recorded peer is refused on the authenticated route,
/// never pooled under a header's address or loopback.
#[tokio::test]
async fn authenticated_booking_refuses_a_connection_with_no_peer() {
    let fixture = Fixture::new();
    install_slot_list_rate(&fixture);
    let now = now_secs().expect("clock");
    let status = list(
        &fixture,
        Peer::Unrecorded,
        &["198.51.100.7".as_bytes()],
        true,
        0,
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    for address in ["198.51.100.7", "127.0.0.1"] {
        assert_eq!(spent(&fixture, address, now), 0, "{address}");
    }
}

// Trusted proxies are new with the resolver; below this line has no before.

#[tokio::test]
async fn trusted_proxy_chain_charges_each_client_behind_it() {
    for _ in 0..3 {
        let fixture = Fixture::behind(vec!["10.0.0.0/8".parse().expect("proxy block")]);
        install_slot_list_rate(&fixture);
        let now = now_secs().expect("clock");
        let proxy = Peer::Tcp("10.0.0.2");
        // Right to left past every trusted hop: the client-supplied entry to
        // the left of the first untrusted one is never read. Two clients
        // behind one proxy are charged apart.
        let listings: [(Peer, &[&str], bool); 6] = [
            (proxy, &["192.0.2.50, 198.51.100.7"], false),
            (proxy, &["198.51.100.8, 10.0.0.3"], false),
            // Repeated fields are one chain, oldest field first.
            (proxy, &["192.0.2.51", "198.51.100.9"], false),
            // A chain the proxy did not write legibly charges the proxy itself.
            (proxy, &["not-an-address"], false),
            // A peer outside the trusted block is charged as itself.
            (Peer::Tcp("203.0.113.9"), &["198.51.100.10"], false),
            // The authenticated route reads the same chain.
            (proxy, &["198.51.100.11"], true),
        ];
        for (nth, (peer, forwarded, owner)) in listings.into_iter().enumerate() {
            let forwarded: Vec<&[u8]> = forwarded.iter().copied().map(str::as_bytes).collect();
            let status = list(&fixture, peer, &forwarded, owner, nth as u64).await;
            assert_eq!(status, StatusCode::OK);
        }
        if !same_minute(now) {
            continue;
        }
        for charged in [
            "198.51.100.7",
            "198.51.100.8",
            "198.51.100.9",
            "10.0.0.2",
            "203.0.113.9",
            "198.51.100.11",
        ] {
            assert_eq!(spent(&fixture, charged, now), 1, "{charged} pays once");
        }
        for untouched in ["192.0.2.50", "10.0.0.3", "192.0.2.51", "198.51.100.10"] {
            assert_eq!(spent(&fixture, untouched, now), 0, "{untouched}");
        }
        return;
    }
    panic!("could not list within one rate window");
}

/// C7 review r1 (Sol F1, Wonder F1): a client behind a proxy that appends to
/// the incoming header could put a byte that is not text in its own part of
/// the chain. That once made the whole chain unreadable and charged the
/// proxy, a second budget. The walk now stops only where it reaches such an
/// entry, so the client the proxy appended still pays.
#[tokio::test]
async fn an_illegible_entry_left_of_the_client_never_moves_its_charge() {
    for _ in 0..3 {
        let fixture = Fixture::behind(vec!["10.0.0.0/8".parse().expect("proxy block")]);
        install_slot_list_rate(&fixture);
        let now = now_secs().expect("clock");
        let proxy = Peer::Tcp("10.0.0.2");
        let one_field: &[&[u8]] = &[b"place\xffholder, 198.51.100.7".as_slice()];
        let earlier_field: &[&[u8]] = &[b"place\xffholder".as_slice(), b"198.51.100.8"];
        for (nth, forwarded) in [one_field, earlier_field].into_iter().enumerate() {
            let status = list(&fixture, proxy, forwarded, false, nth as u64).await;
            assert_eq!(status, StatusCode::OK);
        }
        if !same_minute(now) {
            continue;
        }
        assert_eq!(spent(&fixture, "198.51.100.7", now), 1);
        assert_eq!(spent(&fixture, "198.51.100.8", now), 1);
        assert_eq!(
            spent(&fixture, "10.0.0.2", now),
            0,
            "the proxy pays nothing"
        );
        return;
    }
    panic!("could not list within one rate window");
}
