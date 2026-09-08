//! Guard behavior tests for booking anti-abuse enforcement.

use axum::extract::State;
use oneiron::booking::anti_abuse::{
    BookingRuleScope, booking_anti_abuse_rules, booking_email_hash, booking_ip_hash,
    slot_list_rate_knobs,
};

use super::tests_support::tests::*;
use super::{
    BookingHttpDisposition, cached_slot_list_body, enforce_book, enforce_hold, enforce_slot_list,
    remember_slot_list_body,
};

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[tokio::test]
    async fn honeypot_and_fast_submit_are_silent_200_without_writes() {
        let (_dir, server) = test_server();
        install_defaults(&server);

        let mut honeypot = facts();
        honeypot.honeypot_nonempty = true;
        let mut fast = facts();
        fast.submitted_at_millis = fast.started_at_millis + 30;

        let first = enforce_book(State(server.clone()), honeypot.clone())
            .await
            .expect("honeypot guard answers");
        let second = enforce_book(State(server.clone()), fast.clone())
            .await
            .expect("floor guard answers");
        assert_eq!(first, BookingHttpDisposition::SilentOk);
        assert_eq!(
            first, second,
            "both bot signals must be one indistinguishable 200 shape"
        );
        let third = enforce_book(State(server.clone()), honeypot)
            .await
            .expect("repeat honeypot");
        let fourth = enforce_book(State(server.clone()), fast)
            .await
            .expect("repeat fast");
        assert_eq!(third, fourth);
        assert_eq!(third, first);

        // No booking-side write: the same IP still holds its entire 10/min
        // book budget, so none of the four silent rejections spent a token.
        let mut legit = facts();
        legit.honeypot_nonempty = false;
        for _ in 0..10 {
            let disposition = enforce_book(State(server.clone()), legit.clone())
                .await
                .expect("legit book");
            assert_eq!(disposition, BookingHttpDisposition::Continue);
        }
        let eleventh = enforce_book(State(server.clone()), legit)
            .await
            .expect("budget exhaustion");
        assert!(
            matches!(eleventh, BookingHttpDisposition::RetryAfter { .. }),
            "the live counter proves the budget is exactly ten and the silent calls spent none: {eleventh:?}"
        );

        // And no rule churn: the ten seeded rows are all that exists.
        let rows = booking_anti_abuse_rules(
            &server.vault,
            &BookingRuleScope {
                page_ref: page(),
                event_type: Some(event()),
            },
        )
        .expect("rows");
        assert_eq!(rows.len(), 10);
    }

    #[tokio::test]
    async fn slot_list_ignores_default_form_timestamps_but_spends_its_ip_quota() {
        let (_dir, server) = test_server();
        install_defaults(&server);

        // Listing has no form submission. The ordinary zero defaults must not
        // accidentally trip the book-only submit-floor rule.
        let mut listing = facts();
        listing.started_at_millis = 0;
        listing.submitted_at_millis = 0;
        listing.email_hash = None;

        let first = enforce_slot_list(State(server.clone()), listing.clone(), false)
            .await
            .expect("ordinary slot list");
        assert_eq!(first, BookingHttpDisposition::Continue);
        assert_ne!(first, BookingHttpDisposition::SilentOk);

        for _ in 0..119 {
            assert_eq!(
                enforce_slot_list(State(server.clone()), listing.clone(), false)
                    .await
                    .expect("slot-list quota"),
                BookingHttpDisposition::Continue
            );
        }
        let exhausted = enforce_slot_list(State(server.clone()), listing, false)
            .await
            .expect("slot-list exhaustion");
        assert!(
            matches!(exhausted, BookingHttpDisposition::RetryAfter { .. }),
            "an ordinary listing consumes the endpoint quota: {exhausted:?}"
        );
    }

    #[tokio::test]
    async fn slot_list_limit_is_ip_scoped_and_cache_is_30_to_60_seconds() {
        let (_dir, server) = test_server();
        install_defaults(&server);

        let mut ip_one = facts();
        ip_one.ip_hash = booking_ip_hash("203.0.113.60");
        ip_one.email_hash = None;
        // 120 allowed, the 121st limited — in ONE sixty-second window.
        for _ in 0..120 {
            let disposition = enforce_slot_list(State(server.clone()), ip_one.clone(), false)
                .await
                .expect("slot list");
            assert_eq!(disposition, BookingHttpDisposition::Continue);
        }
        let limited = enforce_slot_list(State(server.clone()), ip_one.clone(), false)
            .await
            .expect("limit answer");
        let BookingHttpDisposition::RetryAfter { seconds } = limited else {
            panic!("the 121st listing must be rate limited: {limited:?}");
        };
        assert!((1..=60).contains(&seconds), "Retry-After inside the window");

        // The limit is IP-scoped: a fresh address keeps its own budget.
        let mut ip_two = facts();
        ip_two.ip_hash = booking_ip_hash("203.0.113.61");
        ip_two.email_hash = None;
        let disposition = enforce_slot_list(State(server.clone()), ip_two, false)
            .await
            .expect("fresh ip");
        assert_eq!(disposition, BookingHttpDisposition::Continue);

        // The response cache discharges requests without spending quota —
        // which is exactly how a page can survive the 120/min envelope.
        let body = b"{\"slots\":[1,2,3]}".to_vec();
        assert!(
            remember_slot_list_body(&server, &page(), Some(&event()), &body).expect("cache write"),
            "the slot-list rule supplies the cache TTL"
        );
        assert_eq!(
            cached_slot_list_body(&server, &page(), Some(&event())).expect("cache read"),
            Some(body.clone())
        );
        // The spent IP keeps answering from cache — no quota movement.
        let cached = enforce_slot_list(State(server.clone()), ip_one.clone(), true)
            .await
            .expect("cached answer");
        assert_eq!(cached, BookingHttpDisposition::Continue);

        // The cache is scope-keyed: another page is a miss, not a leak.
        assert_eq!(
            cached_slot_list_body(&server, &other_page(), Some(&event())).expect("other page"),
            None
        );

        // The window itself: the rule's TTL sits inside the ratified band,
        // and out-of-band writes refuse at the engine door (engine-side test
        // covers 29s/61s); here the adapter accepts only the rule's TTL.
        let rows = booking_anti_abuse_rules(
            &server.vault,
            &BookingRuleScope {
                page_ref: page(),
                event_type: Some(event()),
            },
        )
        .expect("rows");
        let (rate, ttl) = slot_list_rate_knobs(&rows, &page(), &Some(event())).expect("slot knobs");
        assert_eq!(rate.get(), 120);
        assert!(
            (30..=60).contains(&ttl.get()),
            "cache window inside the ratified 30-60s band"
        );
        assert_eq!(ttl.get(), 45, "the owner-configured TTL is what applied");
    }

    #[tokio::test]
    async fn book_limit_uses_combined_ip_email_key() {
        let (_dir, server) = test_server();
        install_defaults(&server);

        // One corporate NAT address, two distinct people behind it.
        let nat_ip = booking_ip_hash("192.0.2.10");
        let mut alice = facts();
        alice.ip_hash = nat_ip;
        alice.email_hash = Some(booking_email_hash("alice@example.org"));
        let mut bob = facts();
        bob.ip_hash = nat_ip;
        bob.email_hash = Some(booking_email_hash("bob@example.org"));

        // Ten Alice bookings pass; the eleventh Alice booking limits.
        for _ in 0..10 {
            let disposition = enforce_book(State(server.clone()), alice.clone())
                .await
                .expect("alice book");
            assert_eq!(disposition, BookingHttpDisposition::Continue);
        }
        let limited = enforce_book(State(server.clone()), alice.clone())
            .await
            .expect("alice limit");
        assert!(
            matches!(limited, BookingHttpDisposition::RetryAfter { .. }),
            "ten alice bookings exhaust her combined IP+email bucket: {limited:?}"
        );

        // Bob behind the SAME NAT keeps an independent bucket: the combined
        // key never collapses two people onto one minute budget.
        let bob_first = enforce_book(State(server.clone()), bob.clone())
            .await
            .expect("bob book");
        assert_eq!(bob_first, BookingHttpDisposition::Continue);

        // The per-email active-future quota is likewise per person: Alice at
        // her cap is asked to correct, Bob under his cap proceeds.
        let mut alice_capped = alice.clone();
        alice_capped.active_future_bookings_for_email = 1;
        alice_capped.email_hash = alice.email_hash;
        let capped = enforce_book(State(server.clone()), alice_capped)
            .await
            .expect("alice cap");
        let BookingHttpDisposition::PromptCorrection { body } = capped else {
            panic!("Alice at her email cap prompts a correction: {capped:?}");
        };
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("correction json");
        assert_eq!(parsed["field"], "email");

        let bob_open = enforce_book(State(server.clone()), bob)
            .await
            .expect("bob under cap");
        assert_eq!(bob_open, BookingHttpDisposition::Continue);
    }

    #[tokio::test]
    async fn hold_limit_enforces_one_active_per_session_and_ip_cap() {
        let (_dir, server) = test_server();
        install_defaults(&server);

        // One active hold per session: a session already squatting retries.
        let mut squatting = facts();
        squatting.active_holds_for_session = 1;
        let session_ip = squatting.ip_hash;
        let blocked = enforce_hold(State(server.clone()), squatting)
            .await
            .expect("session cap");
        assert_eq!(
            blocked,
            BookingHttpDisposition::RetryAfter { seconds: 60 },
            "the session squatter retries, never a hard denial"
        );

        // The verdict path spent no per-IP budget: thirty more holds from
        // that same address still pass inside the window.
        let mut free = facts();
        free.ip_hash = session_ip;
        free.active_holds_for_session = 0;
        for _ in 0..30 {
            let disposition = enforce_hold(State(server.clone()), free.clone())
                .await
                .expect("hold");
            assert_eq!(disposition, BookingHttpDisposition::Continue);
        }
        let limited = enforce_hold(State(server.clone()), free)
            .await
            .expect("ip cap");
        assert!(
            matches!(limited, BookingHttpDisposition::RetryAfter { .. }),
            "the configured per-IP hold cap binds: {limited:?}"
        );

        // The cap is per IP: another address is untouched.
        let mut elsewhere = facts();
        elsewhere.ip_hash = booking_ip_hash("203.0.113.200");
        elsewhere.active_holds_for_session = 0;
        let disposition = enforce_hold(State(server.clone()), elsewhere)
            .await
            .expect("fresh ip");
        assert_eq!(disposition, BookingHttpDisposition::Continue);
    }
}
