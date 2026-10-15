//! Guard behavior tests for booking anti-abuse enforcement.

use axum::extract::State;

use super::tests_support::tests::*;
use super::{BookingHttpDisposition, enforce_slot_list};

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

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
}
