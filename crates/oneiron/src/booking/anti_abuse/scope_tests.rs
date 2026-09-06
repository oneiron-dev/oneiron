//! Rule-scope discrimination on pages with both booking claim schemas.

use super::*;
use crate::EdgeActorClass;
use crate::booking::{
    BOOKING_PUBLIC_PAGE_PREDICATE, BOOKING_PUBLIC_PAGE_SCHEMA_VERSION, BookingPagePublication,
    ConstraintFieldConfig, EventTypeCard, PublicBookingAvailability, ThemeTokens,
    decode_event_type_claim_value, load_public_booking_page,
};
use crate::memory::ClaimInput;

fn published_page(vault: &Vault) -> BookingPagePublication {
    install_page_and_config(vault, id(PAGE), &EventTypeKey("intro-call".to_owned()));
    vault
        .put_entity(
            &id(OWNER),
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"booking owner fixture",
        )
        .expect("owner entity");
    let publication = BookingPagePublication {
        schema_version: BOOKING_PUBLIC_PAGE_SCHEMA_VERSION,
        published: true,
        owner_display: "Fixture owner".to_owned(),
        event_types: vec![EventTypeCard {
            key: EventTypeKey("intro-call".to_owned()),
            title: "Fixture event".to_owned(),
            duration_min: u32::from(DEFAULT_INTRO_DURATION_MIN),
            description: "Fixture description".to_owned(),
        }],
        constraint_field: ConstraintFieldConfig {
            enabled: false,
            placeholder: String::new(),
        },
        theme: ThemeTokens(serde_json::json!({"owner-data": [null, 7]})),
        initial_availability: PublicBookingAvailability {
            event_type: EventTypeKey("intro-call".to_owned()),
            start_after_secs: 10,
            window_secs: 3_600,
            visitor_tz: "UTC".to_owned(),
        },
    };
    // Force the legitimate publication ahead of the configuration in the
    // validator's sorted scan. Random claim IDs can hide the original bug.
    assert!(id(0x01) < id(0x57));
    let receipt = vault
        .memory(id(OWNER), EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: Some(id(0x01).to_hex()),
            predicate: BOOKING_PUBLIC_PAGE_PREDICATE.to_owned(),
            subject_ref: id(PAGE).to_hex(),
            value: serde_json::to_value(&publication).expect("publication JSON"),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            world_ref: None,
            scope: None,
            valid_from: Some(100),
            valid_to: Some(200),
            occurred_at: None,
            learned_at: None,
            salience: None,
        })
        .expect("normal owner publication write");
    assert_eq!(receipt.approval, "auto");
    assert_eq!(
        load_public_booking_page(vault, id(PAGE), 150).expect("live publication"),
        Some(publication.clone())
    );
    publication
}

fn scoped_row(event_type: Option<EventTypeKey>) -> BookingAntiAbuseRuleRow {
    let mut row = seed_rule(&BookingAntiAbuseRule::RequiredIntake {
        min_chars: nz16(10),
    });
    row.scope.event_type = event_type;
    row.row_id = booking_rule_row_id(&row.scope, &row.rule);
    row
}

#[test]
fn rule_activation_and_amendment_accept_mixed_publication_and_event_configuration() {
    for event_type in [None, Some(EventTypeKey("intro-call".to_owned()))] {
        let (_dir, vault) = open_vault();
        let publication = published_page(&vault);
        let row = scoped_row(event_type);
        let first =
            apply_rule_amendment(&vault, 0, row.clone(), None).expect("activate after publication");
        assert_eq!(first.stored, row);
        let tighter = BookingAntiAbuseRuleRow {
            version: 2,
            rule: BookingAntiAbuseRule::RequiredIntake {
                min_chars: nz16(20),
            },
            ..row
        };
        let outcome = apply_rule_amendment(&vault, 1, tighter.clone(), None)
            .expect("amend after publication");
        assert_eq!(outcome.stored, tighter);
        assert!(outcome.owner_notice_required);
        assert_eq!(
            booking_anti_abuse_rules(&vault, &tighter.scope).expect("stored rule"),
            vec![tighter]
        );
        assert_eq!(
            booking_anti_abuse_notices(&vault).expect("notices").len(),
            2
        );
        assert_eq!(
            load_public_booking_page(&vault, id(PAGE), 150).expect("unchanged publication"),
            Some(publication)
        );
    }
}

#[test]
fn publication_does_not_replace_a_live_matching_event_configuration_for_rule_scope() {
    for event_type in [None, Some(EventTypeKey("intro-call".to_owned()))] {
        let (_dir, vault) = open_vault();
        published_page(&vault);
        let row = scoped_row(event_type);
        let original = vault.get_claim(&id(0x57)).expect("read").expect("config");
        for (approval, lifecycle, stale) in [
            (
                ClaimApprovalStatus::Proposed,
                ClaimLifecycleStatus::Active,
                false,
            ),
            (
                ClaimApprovalStatus::Rejected,
                ClaimLifecycleStatus::Active,
                false,
            ),
            (
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
                true,
            ),
            (
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Superseded,
                false,
            ),
            (
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Retracted,
                false,
            ),
        ] {
            let mut body = original.clone();
            body.approval = approval;
            body.lifecycle = lifecycle;
            body.stale = stale;
            vault
                .put_claim(&id(0x57), &body, TimeRange { start: 1, end: 1 }, 1)
                .expect("configuration status");
            assert_rejected_without_activation(&vault, row.clone());
        }
        if row.scope.event_type.is_some() {
            let mut body = original;
            let mut value = decode_event_type_claim_value(&body.value).expect("valid config");
            value.config.key = EventTypeKey("different-event".to_owned());
            body.value = encode_event_type_claim_value(&value).expect("mismatched config");
            vault
                .put_claim(&id(0x57), &body, TimeRange { start: 1, end: 1 }, 1)
                .expect("different event");
            assert_rejected_without_activation(&vault, row);
        }
    }
}

#[test]
fn malformed_true_event_configuration_still_denies_rule_activation_and_amendment() {
    for event_type in [None, Some(EventTypeKey("intro-call".to_owned()))] {
        for defect in ["shape", "schema_version", "duration"] {
            for expected_version in [0, 1] {
                let (_dir, vault) = open_vault();
                published_page(&vault);
                let mut row = scoped_row(event_type.clone());
                if expected_version == 1 {
                    apply_rule_amendment(&vault, 0, row.clone(), None)
                        .expect("initial valid activation");
                    row.version = 2;
                }
                let before = booking_anti_abuse_rules(&vault, &row.scope).expect("prior rules");
                let notices = booking_anti_abuse_notices(&vault).expect("prior notices");
                let mut body = vault.get_claim(&id(0x57)).expect("read").expect("config");
                let mut value = decode_event_type_claim_value(&body.value).expect("valid config");
                match defect {
                    "shape" => body.value = rmpv::Value::Nil,
                    "schema_version" => {
                        value.schema_version = BOOKING_EVENT_TYPE_SCHEMA_VERSION + 1;
                        body.value = encode_event_type_claim_value(&value).expect("encode");
                    }
                    "duration" => {
                        value.config.duration_min = 0;
                        body.value = encode_event_type_claim_value(&value).expect("encode");
                    }
                    _ => unreachable!("fixture defect"),
                }
                assert_eq!(body.predicate, BOOKING_EVENT_TYPE_PREDICATE);
                assert!(
                    vault
                        .put_claim(&id(0x57), &body, TimeRange { start: 1, end: 1 }, 1)
                        .is_err(),
                    "malformed event configuration must fail the write door"
                );
                // The ordinary write rejects these bytes. Inject a corrupt
                // stored body while retaining its existing claim-of edge to
                // prove the amendment read path also fails closed.
                let encoded = crate::claim::encode_claim_body(&body).expect("encode body");
                let raw = crate::test_util::entity_record(
                    crate::registry::ENTITY_TYPE_CLAIM,
                    TimeRange { start: 1, end: 1 },
                    1,
                    &encoded,
                );
                vault
                    .with_write_txn(|wtxn| {
                        vault.store.entities.put(wtxn, id(0x57).as_bytes(), &raw)?;
                        Ok(())
                    })
                    .expect("inject malformed stored configuration");
                let stored = vault
                    .get_claim(&id(0x57))
                    .expect("readable claim")
                    .expect("body");
                assert_eq!(stored.predicate, BOOKING_EVENT_TYPE_PREDICATE);
                assert!(decode_event_type_claim_value(&stored.value).is_err());
                let scope = row.scope.clone();
                assert!(
                    matches!(
                        apply_rule_amendment(&vault, expected_version, row, None),
                        Err(BookingError::InvalidConstraint(message))
                            if message.contains("InvalidBookingPage: rule scope has malformed event configuration")
                    ),
                    "{defect} must fail closed"
                );
                assert_eq!(
                    booking_anti_abuse_rules(&vault, &scope).expect("rules"),
                    before
                );
                assert_eq!(
                    booking_anti_abuse_notices(&vault).expect("notices"),
                    notices
                );
            }
        }
    }
}
