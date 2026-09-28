use super::*;
use crate::VaultConfig;
use crate::booking::{
    BookingSnippetCopy, EventTypeKey, PublicBookingPageToken, RankedSlot, SlotMask,
    booking_intake_stages, booking_reminders, booking_shortlist, booking_slots_snippet,
    repeat_no_show_offer,
};
use crate::calendar::EventOutcome;
use crate::test_util::{entity, open_test_vault_with, put_policy_manifest_bytes};

fn row(
    scope: BookingPolicyScope,
    holder_ref: Option<String>,
    policy: BookingConversionPolicy,
) -> BookingConversionPolicyRow {
    BookingConversionPolicyRow {
        scope,
        holder_ref,
        policy,
    }
}

#[test]
fn nested_policy_narrows_and_holder_override_stays_inside_vault_cap() {
    let holder = entity(0x72).to_hex();
    let nested = BookingConversionPolicy {
        max_visible_slots: 2,
        max_preconfirm_fields: 1,
        max_snippet_times: 1,
        repeat_no_show_at: 1,
        reminder_leads_secs: vec![7_200],
        reminder_action: ReminderAction::Neutral,
        ..BookingConversionPolicy::default()
    };
    let requested = BookingConversionPolicy {
        max_visible_slots: 4,
        max_preconfirm_fields: 2,
        max_snippet_times: 2,
        repeat_no_show_at: 2,
        reminder_leads_secs: vec![86_400, 7_200],
        ..BookingConversionPolicy::default()
    };
    let rows = vec![
        row(BookingPolicyScope::Nested, None, nested),
        row(BookingPolicyScope::Holder, Some(holder.clone()), requested),
    ];
    let without = resolve_booking_conversion_rows(&rows, None).expect("nested");
    assert_eq!(without.max_visible_slots, 2);
    assert_eq!(without.max_preconfirm_fields, 1);
    assert_eq!(without.reminder_leads_secs, [7_200]);
    let matched = resolve_booking_conversion_rows(&rows, Some(&holder)).expect("holder");
    assert_eq!(matched.max_visible_slots, 4);
    assert_eq!(matched.max_preconfirm_fields, 2);
    assert_eq!(matched.reminder_leads_secs, [86_400, 7_200]);
    let narrower_vault = BookingConversionPolicy {
        max_visible_slots: 3,
        max_snippet_times: 1,
        ..BookingConversionPolicy::default()
    };
    let mut capped_rows = rows;
    capped_rows.push(row(BookingPolicyScope::Vault, None, narrower_vault.clone()));
    let capped = resolve_booking_conversion_rows(&capped_rows, Some(&holder)).expect("vault cap");
    assert_eq!(capped.max_visible_slots, 3);
    assert_eq!(capped.max_snippet_times, 1);
    let nested_only = BookingConversionPolicy {
        precedence: BookingPolicyPrecedence::NestedNarrowing,
        ..narrower_vault
    };
    capped_rows.pop();
    capped_rows.push(row(BookingPolicyScope::Vault, None, nested_only));
    assert_eq!(
        resolve_booking_conversion_rows(&capped_rows, Some(&holder))
            .unwrap()
            .max_visible_slots,
        2
    );
    let widened = BookingConversionPolicy {
        max_visible_slots: 7,
        max_snippet_times: 3,
        ..BookingConversionPolicy::default()
    };
    capped_rows.pop();
    capped_rows.push(row(BookingPolicyScope::Vault, None, widened.clone()));
    let wide =
        resolve_booking_conversion_rows(&[row(BookingPolicyScope::Vault, None, widened)], None)
            .expect("owner vault row replaces shipped UX default");
    assert_eq!((wide.max_visible_slots, wide.max_snippet_times), (7, 3));
    assert_eq!(
        resolve_booking_conversion_rows(&capped_rows, Some(&holder))
            .expect("owner vault choice can widen shipped UX default")
            .max_visible_slots,
        4
    );
}

#[test]
fn trusted_manifest_rows_change_actual_conversion_answers() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().expect("default id"),
        &crate::gate::default_policy_manifest(),
    )
    .expect("shipped manifest");
    let shipped = vault
        .booking_conversion_policy(None)
        .expect("shipped default");
    let default_hash = {
        let txn = vault.store.env.read_txn().expect("default snapshot");
        crate::gate::resolve_policy_manifest(&vault.store, &txn)
            .expect("default resolved")
            .read_frontier_hash()
            .expect("frontier")
    };
    assert_eq!(
        (
            shipped.max_visible_slots,
            shipped.max_preconfirm_fields,
            shipped.max_snippet_times
        ),
        (5, 3, 2)
    );
    let holder = entity(0x74).to_hex();
    let nested = BookingConversionPolicy {
        max_visible_slots: 1,
        max_preconfirm_fields: 1,
        max_snippet_times: 1,
        repeat_no_show_at: 1,
        reminder_leads_secs: vec![7_200],
        reminder_action: ReminderAction::Neutral,
        ..shipped
    };
    let holder_row = BookingConversionPolicy {
        max_visible_slots: 4,
        max_preconfirm_fields: 2,
        max_snippet_times: 2,
        ..shipped
    };
    let rows = vec![
        row(BookingPolicyScope::Nested, None, nested),
        row(BookingPolicyScope::Holder, Some(holder.clone()), holder_row),
    ];
    let manifest = serde_json::json!({
        "schema_version": crate::gate::POLICY_SCHEMA_VERSION,
        "pack_id": "booking-conversion-owner-test",
        "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [], "actor_ceilings": [],
        "booking_conversion": rows,
    });
    let bytes = rmp_serde::to_vec_named(&manifest).expect("manifest");
    let encoded = rmpv::decode::read_value(&mut bytes.as_slice()).expect("wire");
    let rmpv::Value::Map(entries) = &encoded else {
        panic!("map");
    };
    let rows = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("booking_conversion"))
        .unwrap()
        .1
        .as_array()
        .unwrap();
    for row in rows {
        let json: serde_json::Value = rmpv::ext::from_value(row.clone())
            .unwrap_or_else(|error| panic!("row JSON decode: {error:?}; value: {row:?}"));
        let decoded: BookingConversionPolicyRow = serde_json::from_value(json).expect("typed row");
        decoded.validate().expect("valid row");
    }
    put_policy_manifest_bytes(&vault, entity(0x48), &bytes).expect("owner-authored row");
    let txn = vault.store.env.read_txn().expect("read");
    let view = crate::gate::resolve_policy_manifest(&vault.store, &txn).expect("resolve");
    assert!(
        !view.is_fail_closed(),
        "manifest diagnostic: {:?}",
        view.diagnostics()
    );
    assert_ne!(
        view.read_frontier_hash().expect("policy hash"),
        default_hash
    );
    drop(txn);
    let resolved = vault
        .booking_conversion_policy(None)
        .expect("nested resolved");
    assert_eq!(resolved.max_visible_slots, 1);
    assert_eq!(resolved.max_preconfirm_fields, 1);
    assert_eq!(resolved.reminder_leads_secs, [7_200]);
    assert_eq!(
        booking_reminders(200_000, 0, &resolved).unwrap()[0].action,
        ReminderAction::Neutral
    );
    let chosen = vault
        .booking_conversion_policy(Some(&holder))
        .expect("holder resolved");
    assert_eq!(chosen.max_visible_slots, 4);
    assert_eq!(chosen.max_preconfirm_fields, 2);
    assert_eq!(
        booking_reminders(200_000, 0, &chosen).unwrap()[0].action,
        ReminderAction::RescheduleFirst
    );

    let slots = vec![
        RankedSlot {
            start_utc: 200_000,
            end_utc: 201_800,
            rank: 1.0,
        },
        RankedSlot {
            start_utc: 203_600,
            end_utc: 205_400,
            rank: 0.5,
        },
    ];
    assert_eq!(
        booking_shortlist(&slots, 1, &resolved)
            .unwrap()
            .visible
            .len(),
        1
    );
    assert!(booking_shortlist(&slots, 2, &resolved).is_err());
    let fields = vec!["name".to_owned(), "purpose".to_owned()];
    assert_eq!(
        booking_intake_stages(&fields, 1, &resolved)
            .unwrap()
            .after_confirm,
        ["purpose"]
    );
    assert_eq!(booking_reminders(200_000, 0, &resolved).unwrap().len(), 1);
    assert_eq!(
        repeat_no_show_offer(&[EventOutcome::NoShow], true, &resolved),
        crate::booking::RepeatNoShowOffer::ConfirmLink
    );
    let mask = SlotMask {
        event_type: EventTypeKey("intro".into()),
        window_start_utc: 199_000,
        window_end_utc: 210_000,
        slots,
        flex_used: false,
    };
    let token = PublicBookingPageToken(format!("bkp_{}", "ab".repeat(16)));
    let face = format!("https://book.example.org/schedule/{}", token.0);
    assert!(
        booking_slots_snippet(
            &mask,
            &[200_000, 203_600],
            "UTC",
            &token,
            &face,
            BookingSnippetCopy {
                introduction: "Available:",
                optional_link_label: "More"
            },
            &resolved
        )
        .is_err()
    );
    assert!(
        booking_slots_snippet(
            &mask,
            &[200_000],
            "UTC",
            &token,
            &face,
            BookingSnippetCopy {
                introduction: "Available:",
                optional_link_label: "More"
            },
            &resolved
        )
        .is_ok()
    );
    // A malformed owner row cannot silently fall back to the shipped limit.
    let mut malformed = manifest;
    malformed["booking_conversion"][0]["policy"]["repeat_no_show_at"] = serde_json::json!(0);
    put_policy_manifest_bytes(
        &vault,
        entity(0x48),
        &rmp_serde::to_vec_named(&malformed).expect("malformed wire"),
    )
    .expect("store malformed fixture");
    assert!(vault.booking_conversion_policy(None).is_err());
}
