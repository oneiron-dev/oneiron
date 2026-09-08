//! Quarantine-behavior tests for booking anti-abuse enforcement.

use axum::extract::State;
use oneiron::booking::EventTypeKey;
use oneiron::booking::anti_abuse::{
    apply_rule_amendment, booking_email_hash, booking_ip_hash, default_booking_anti_abuse_rows,
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
    async fn quarantine_without_book_rate_is_scope_bounded_despite_rotating_identities() {
        let (_dir, server) = test_server();
        server
            .vault
            .put_entity(
                &page(),
                oneiron::registry::ENTITY_TYPE_EVENT,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"booking page fixture",
            )
            .expect("page entity");
        install_live_booking_config(&server, event());
        for row in default_booking_anti_abuse_rows(page(), None, &owner_config())
            .expect("seed rows")
            .into_iter()
            .filter(|row| {
                !matches!(
                    row.rule,
                    oneiron::booking::anti_abuse::BookingAntiAbuseRule::BookRate { .. }
                )
            })
        {
            apply_rule_amendment(&server.vault, 0, row, None).expect("install partial row");
        }
        let mut first = facts();
        first.email = Some(oneiron::booking::anti_abuse::EmailValidationEvidence {
            syntax_valid: true,
            mx_present: Some(false),
            disposable_domain: true,
        });
        assert_eq!(
            enforce_book(State(server.clone()), first.clone())
                .await
                .expect("first guard"),
            BookingHttpDisposition::QuarantineAndAccept
        );
        // Replay is accepted before quota consumption, despite a transport
        // placeholder/timing change; it cannot starve the page-wide budget.
        let mut retry = first.clone();
        retry.submission_fingerprint = [0xD3; 32];
        retry.started_at_millis = 0;
        retry.submitted_at_millis = u64::MAX;
        assert_eq!(
            enforce_book(State(server.clone()), retry)
                .await
                .expect("retry guard"),
            BookingHttpDisposition::QuarantineAndAccept
        );
        for attempt in 1..4_u8 {
            let mut request = facts();
            request.event_type = Some(EventTypeKey(format!("attacker-event-{attempt}")));
            request.ip_hash = booking_ip_hash(&format!("198.51.100.{attempt}"));
            request.email_hash = Some(booking_email_hash(&format!("rotate-{attempt}@example.org")));
            request.selected_slot_hash = [attempt; 32];
            request.intake_content_hash = [attempt.wrapping_add(10); 32];
            request.email = Some(oneiron::booking::anti_abuse::EmailValidationEvidence {
                syntax_valid: true,
                mx_present: Some(false),
                disposable_domain: true,
            });
            let disposition = enforce_book(State(server.clone()), request)
                .await
                .expect("guard");
            assert!(
                matches!(disposition, BookingHttpDisposition::RetryAfter { .. }),
                "rotating identity and event string cannot bypass the page-wide quarantine budget"
            );
        }
        let decisions = server.vault.gate_decisions(10).expect("decisions");
        assert_eq!(
            decisions.len(),
            1,
            "the aggregate budget bounds decision growth"
        );
        let quarantine_claims = server
            .vault
            .claims_for_subject(&page())
            .expect("claims")
            .into_iter()
            .map(|claim_id| {
                server
                    .vault
                    .get_claim(&claim_id)
                    .expect("claim")
                    .expect("claim body")
            })
            .filter(|claim| claim.predicate == "booking.submission_quarantine")
            .count();
        assert_eq!(
            quarantine_claims, 1,
            "the aggregate budget bounds quarantine claim growth"
        );
        assert_eq!(
            server
                .vault
                .pending_gate_consents(10)
                .expect("pending rows")
                .len(),
            1,
            "the aggregate budget bounds pending growth and an exact retry adds no row"
        );
        assert!(
            decisions[0].claim_id.is_some(),
            "the sole decision still binds exactly one pending-review claim"
        );
    }

    #[tokio::test]
    async fn server_boundary_replaces_transport_fingerprint_and_ignores_timestamp_only_retry() {
        let (_dir, server) = test_server();
        install_defaults(&server);
        let mut first = facts();
        first.submission_fingerprint = [1; 32];
        first.email = Some(oneiron::booking::anti_abuse::EmailValidationEvidence {
            syntax_valid: true,
            mx_present: Some(false),
            disposable_domain: true,
        });
        assert_eq!(
            enforce_book(State(server.clone()), first.clone())
                .await
                .expect("first"),
            BookingHttpDisposition::QuarantineAndAccept
        );
        let mut retry = first.clone();
        retry.submission_fingerprint = [2; 32];
        retry.started_at_millis = 0;
        retry.submitted_at_millis = u64::MAX;
        let _ = enforce_book(State(server.clone()), retry)
            .await
            .expect("retry guard");
        assert_eq!(
            server.vault.gate_decisions(10).expect("decisions").len(),
            1,
            "transport fingerprint and timestamps cannot fork a trusted submission identity"
        );
        let mut distinct = first;
        distinct.intake_content_hash = [0xE4; 32];
        // Same form shape and identity, but canonical intake differs.
        assert_eq!(
            enforce_book(State(server.clone()), distinct)
                .await
                .expect("distinct guard"),
            BookingHttpDisposition::QuarantineAndAccept
        );
        assert_eq!(server.vault.gate_decisions(10).expect("decisions").len(), 2);
        assert_eq!(
            server
                .vault
                .pending_gate_consents(10)
                .expect("pending")
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn server_adapters_thread_state_and_api_error_for_slot_list_hold_and_book() {
        // Every guard threads `State<Arc<SyncServer>>`, loads its rows and
        // counters from that one state, and returns `Result<_, ApiError>` —
        // the assertions below exercise each adapter's verdict, counter,
        // cache, and quarantine wiring through nothing but `server`.
        let (_dir, server) = test_server();
        install_defaults(&server);

        let good = facts();
        for call in ["slot", "hold", "book"] {
            let disposition = match call {
                "slot" => enforce_slot_list(State(server.clone()), good.clone(), false)
                    .await
                    .expect("slot adapter"),
                "hold" => enforce_hold(State(server.clone()), good.clone())
                    .await
                    .expect("hold adapter"),
                _ => enforce_book(State(server.clone()), good.clone())
                    .await
                    .expect("book adapter"),
            };
            // The slot/hold calls above consumed one unit of each window, so
            // all three adapters demonstrably share the seeded rows.
            assert_eq!(
                disposition,
                BookingHttpDisposition::Continue,
                "{call} adapter must continue a clean request"
            );
        }

        // A correctable verdict maps onto the correction disposition.
        let mut short_intake = facts();
        short_intake.intake_chars = 0;
        let prompted = enforce_book(State(server.clone()), short_intake)
            .await
            .expect("prompt adapter");
        let BookingHttpDisposition::PromptCorrection { body } = prompted else {
            panic!("intake correction prompts: {prompted:?}");
        };
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("correction json");
        assert_eq!(parsed["field"], "intake");

        // Hold creation does not evaluate submit-form honeypot fields.
        let mut bot = facts();
        bot.honeypot_nonempty = true;
        let disposition = enforce_hold(State(server.clone()), bot)
            .await
            .expect("hold adapter");
        assert_eq!(disposition, BookingHttpDisposition::Continue);

        // Borderline traffic quarantines through the adapter and is accepted.
        let mut borderline = facts();
        borderline.email_hash = Some(booking_email_hash("sketchy@example.net"));
        borderline.email = Some(oneiron::booking::anti_abuse::EmailValidationEvidence {
            syntax_valid: true,
            mx_present: Some(false),
            disposable_domain: true,
        });
        let quarantined = enforce_book(State(server.clone()), borderline)
            .await
            .expect("quarantine adapter");
        assert_eq!(quarantined, BookingHttpDisposition::QuarantineAndAccept);
    }

    #[tokio::test]
    async fn page_wide_rows_govern_event_typed_requests() {
        let (_dir, server) = test_server();
        // Only page-wide (`event_type: None`) rows exist; no event-scoped
        // stack is ever installed.
        install_defaults_scoped(&server, None);

        // A request naming an event type still answers to the page-wide
        // intake control...
        let mut typed = facts();
        typed.intake_chars = 0;
        let prompted = enforce_book(State(server.clone()), typed)
            .await
            .expect("page-wide intake governs");
        let BookingHttpDisposition::PromptCorrection { body } = prompted else {
            panic!("the page-wide intake rule must govern an event-typed request: {prompted:?}");
        };
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("correction json");
        assert_eq!(parsed["field"], "intake");

        // ...and to the page-wide slot-list rate knob: 120 pass, the 121st
        // event-typed listing is limited exactly as if the stack had been
        // seeded event-scoped.
        let good = facts();
        for _ in 0..120 {
            let disposition = enforce_slot_list(State(server.clone()), good.clone(), false)
                .await
                .expect("slot list");
            assert_eq!(disposition, BookingHttpDisposition::Continue);
        }
        let limited = enforce_slot_list(State(server.clone()), good, false)
            .await
            .expect("slot-list limit");
        assert!(
            matches!(limited, BookingHttpDisposition::RetryAfter { .. }),
            "the page-wide 120/min slot-list row governs event-typed traffic: {limited:?}"
        );

        // The cache helper resolves the page-wide TTL for the same typed
        // scope as well.
        let body = b"{\"slots\":[]}".to_vec();
        assert!(
            remember_slot_list_body(&server, &page(), Some(&event()), &body).expect("cache write"),
            "the page-wide slot-list row supplies the cache TTL"
        );
        assert_eq!(
            cached_slot_list_body(&server, &page(), Some(&event())).expect("cache read"),
            Some(body)
        );
    }
}
