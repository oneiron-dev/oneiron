use super::*;
use crate::booking::{BookingConversionPolicy, EventTypeKey};

fn slot(start_utc: u64, rank: f32) -> RankedSlot {
    RankedSlot {
        start_utc,
        end_utc: start_utc + 1800,
        rank,
    }
}

#[test]
fn shortlist_is_a_ranked_prefix_with_one_recommended_slot_and_see_more() {
    let slots: Vec<_> = (0..9)
        .map(|i| slot(1_800_000_000 + i * 3600, 9.0 - i as f32))
        .collect();
    for visible_count in 3..=5 {
        let shortlist =
            booking_shortlist(&slots, visible_count, &BookingConversionPolicy::default()).unwrap();
        assert_eq!(shortlist.recommended, Some(slots[0].clone()));
        assert_eq!(shortlist.visible, slots[..visible_count].to_vec());
        assert_eq!(shortlist.more_count, 9 - visible_count);
    }
    let empty = booking_shortlist(&[], 3, &BookingConversionPolicy::default()).unwrap();
    assert!(empty.recommended.is_none() && empty.visible.is_empty());
    assert_eq!(empty.more_count, 0);
    assert_eq!(
        booking_shortlist(&slots, 0, &BookingConversionPolicy::default()),
        Err(ConversionError::InvalidConfig)
    );
    assert_eq!(
        booking_shortlist(&slots, 6, &BookingConversionPolicy::default()),
        Err(ConversionError::InvalidConfig)
    );
    assert_eq!(
        booking_shortlist(&[slot(1, f32::NAN)], 3, &BookingConversionPolicy::default()),
        Err(ConversionError::InvalidSlots)
    );
    assert_eq!(
        booking_shortlist(
            &[slots[1].clone(), slots[0].clone()],
            3,
            &BookingConversionPolicy::default()
        ),
        Err(ConversionError::InvalidSlots),
        "a reversed mask must not advertise its lower-ranked first slot as recommended"
    );
}

#[test]
fn snippet_link_hints_only_live_exact_solver_slots() {
    let event = EventTypeKey("consultation&60".to_owned());
    let slots = [slot(1_800_000_000, 1.0), slot(1_800_003_600, 0.9)];
    let query = "event_type=consultation%2660&start_utc=1800000000&end_utc=1800001800&visitor_tz=Europe%2FLondon";
    let hint = parse_booking_slot_link(Some(query)).expect("complete link context");
    assert_eq!(hint.event_type, event);
    assert_eq!(hint.visitor_tz, "Europe/London");
    assert_eq!(
        booking_suggested_slot(&slots, &hint),
        Some(slots[0].clone())
    );
    let stale = BookingSlotLinkHint {
        end_utc: 1_800_001_801,
        ..hint
    };
    assert_eq!(booking_suggested_slot(&slots, &stale), None);
    for invalid in [
        "start_utc=1800000000&end_utc=1800001800",
        "event_type=consultation%2660&start_utc=1800000000&end_utc=1800001800&visitor_tz=Europe%2FLondon&redirect=bad",
        "event_type=consultation&60&start_utc=1800000000&end_utc=1800001800&visitor_tz=Europe%2FLondon",
        "event_type=consultation%2660&start_utc=1800001800&end_utc=1800001800&visitor_tz=Europe%2FLondon",
    ] {
        assert_eq!(parse_booking_slot_link(Some(invalid)), None);
    }
}

#[test]
fn intake_keeps_all_later_fields_out_of_the_confirm_step() {
    let keys: Vec<String> = ["name", "email", "purpose", "preparation", "other"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let one = booking_intake_stages(&keys, 1, &BookingConversionPolicy::default())
        .expect("one pre-confirm field is a permitted owner/UI choice");
    assert_eq!(one.after_confirm, keys[1..]);
    let stages = booking_intake_stages(&keys, 3, &BookingConversionPolicy::default()).unwrap();
    assert_eq!(stages.before_confirm, keys[..3]);
    assert_eq!(stages.after_confirm, keys[3..]);
    assert!(booking_intake_stages(&keys, 4, &BookingConversionPolicy::default()).is_err());
    assert!(
        booking_intake_stages(
            &["same".into(), "same".into()],
            2,
            &BookingConversionPolicy::default()
        )
        .is_err()
    );
}

#[test]
fn two_reminders_are_reschedule_first_and_never_backfilled() {
    use crate::calendar::outcome::EventOutcome::{CancelledPreStart, Held, NoShow, Unknown};

    let policy = BookingConversionPolicy {
        reminder_leads_secs: vec![86_400, 3_600],
        ..BookingConversionPolicy::default()
    };
    let plan = booking_reminders(1_000_000, 100, &policy).unwrap();
    assert_eq!(
        plan,
        vec![
            BookingReminder {
                due_utc: 913_600,
                action: ReminderAction::RescheduleFirst,
                step: ReminderStep(0)
            },
            BookingReminder {
                due_utc: 996_400,
                action: ReminderAction::RescheduleFirst,
                step: ReminderStep(1)
            },
        ]
    );
    assert_eq!(
        booking_reminders(1_000_000, 913_600, &policy).unwrap(),
        plan[1..]
    );
    assert!(booking_reminders(10, 11, &policy).unwrap().is_empty());
    let malformed = BookingConversionPolicy {
        reminder_leads_secs: vec![3_600, 86_400],
        ..BookingConversionPolicy::default()
    };
    assert!(booking_reminders(1_000_000, 0, &malformed).is_err());
    assert_eq!(
        repeat_no_show_offer(&[NoShow, NoShow], false, &policy),
        RepeatNoShowOffer::Ordinary
    );
    assert_eq!(
        repeat_no_show_offer(&[NoShow, Unknown], true, &policy),
        RepeatNoShowOffer::Ordinary
    );
    assert_eq!(
        repeat_no_show_offer(&[Held, Unknown, CancelledPreStart], true, &policy),
        RepeatNoShowOffer::Ordinary
    );
    assert_eq!(
        repeat_no_show_offer(&[Unknown, NoShow, Held, NoShow], true, &policy),
        RepeatNoShowOffer::ConfirmLink
    );
}

#[test]
fn zone_labels_are_per_party_and_no_unknown_zone_becomes_utc() {
    let winter = crate::calendar::tz::wall_to_utc(
        &crate::calendar::tz::WallTime {
            y: 2026,
            mo: 1,
            d: 15,
            h: 9,
            mi: 0,
            s: 0,
        },
        "Europe/London",
    )
    .unwrap();
    let summer = crate::calendar::tz::wall_to_utc(
        &crate::calendar::tz::WallTime {
            y: 2026,
            mo: 7,
            d: 15,
            h: 9,
            mi: 0,
            s: 0,
        },
        "Europe/London",
    )
    .unwrap();
    assert_eq!(summer - winter, 181 * 86400 - 3600);
    for utc in [winter, summer] {
        let (visitor, host, locked) = booking_display_zones(
            utc,
            "Europe/London",
            "America/New_York",
            MeetingLocation::Remote,
            false,
        )
        .unwrap();
        assert_eq!(
            visitor.local,
            "2026-01-15 09:00".replace("01-15", if utc == winter { "01-15" } else { "07-15" })
        );
        assert_eq!(visitor.zone, "Europe/London");
        assert_eq!(host.zone, "America/New_York");
        assert_ne!(visitor.local, host.local);
        assert!(!locked);
    }
    assert_eq!(
        booking_zoned_time(winter, "Madeup/Unknown"),
        Err(ConversionError::InvalidZone)
    );
    assert_eq!(
        booking_display_zones(
            winter,
            "Europe/London",
            "UTC",
            MeetingLocation::Remote,
            true
        ),
        Err(ConversionError::InvalidConfig)
    );
    assert!(
        booking_display_zones(
            winter,
            "Europe/London",
            "UTC",
            MeetingLocation::Physical,
            true
        )
        .unwrap()
        .2
    );
}

#[test]
fn legislation_date_does_not_inherit_a_neighbouring_region_rule() {
    // Mexico City abolished seasonal changes in 2022. In 2026 it remains
    // UTC-6 across the US spring/fall transitions; a US region bucket is wrong.
    let wall = crate::calendar::tz::WallTime {
        y: 2026,
        mo: 7,
        d: 15,
        h: 9,
        mi: 0,
        s: 0,
    };
    let mexico = crate::calendar::tz::wall_to_utc(&wall, "America/Mexico_City").unwrap();
    let chicago = crate::calendar::tz::wall_to_utc(&wall, "America/Chicago").unwrap();
    assert_eq!(mexico, chicago + 3_600);
    assert_eq!(
        booking_zoned_time(mexico, "America/Mexico_City")
            .unwrap()
            .local,
        "2026-07-15 09:00"
    );
    // British Columbia's permanent UTC-7 starts at the 2026-11-01
    // transition. Vancouver must not inherit the US Pacific fallback.
    let bc_after = crate::calendar::tz::WallTime {
        y: 2026,
        mo: 11,
        d: 2,
        h: 9,
        mi: 0,
        s: 0,
    };
    assert_eq!(
        crate::calendar::tz::wall_to_utc(&bc_after, "America/Vancouver"),
        Ok(1_793_635_200)
    );
}

#[test]
fn copy_paste_times_use_the_host_page_and_distinguish_a_dst_fold() {
    use crate::calendar::tz::{WallTime, wall_to_utc};

    let first = wall_to_utc(
        &WallTime {
            y: 2026,
            mo: 11,
            d: 1,
            h: 1,
            mi: 30,
            s: 0,
        },
        "America/New_York",
    )
    .expect("fold");
    let mask = crate::booking::SlotMask {
        event_type: EventTypeKey("consultation&60".to_owned()),
        window_start_utc: first - 60,
        window_end_utc: first + 5_400,
        slots: [first, first + 3_600]
            .into_iter()
            .map(|start_utc| RankedSlot {
                start_utc,
                end_utc: start_utc + 1_800,
                rank: 0.5,
            })
            .collect(),
        flex_used: false,
    };
    let token = PublicBookingPageToken(format!("bkp_{}", "ab".repeat(16)));
    let page = format!("https://book.example.org/schedule/{}", token.0);
    let text = booking_slots_snippet(
        &mask,
        &[first, first + 3_600],
        "America/New_York",
        &token,
        &page,
        BookingSnippetCopy {
            introduction: "Available:",
            optional_link_label: "Or see all slots",
        },
        &BookingConversionPolicy::default(),
    )
    .expect("human-facing message");
    assert!(text.starts_with("Available:\n"));
    assert_eq!(text.matches(&page).count(), 3);
    assert!(!text.contains("/public/booking/"));
    let links: Vec<_> = text
        .lines()
        .skip(1)
        .take(2)
        .map(|line| {
            let (label, href) = line.split_once("](").expect("link");
            (label.to_owned(), href.trim_end_matches(')').to_owned())
        })
        .collect();
    assert!(
        links
            .iter()
            .all(|(label, _)| label.contains("01:30 America/New_York"))
    );
    assert_ne!(
        links[0].0, links[1].0,
        "UTC labels distinguish the two 01:30s"
    );
    assert_ne!(links[0].1, links[1].1);
    for ((_, href), start) in links.iter().zip([first, first + 3_600]) {
        let hint = crate::booking::booking_snippet_selection_from_url(href, &token)
            .expect("host page consumes its own link");
        assert_eq!(hint.event_type, mask.event_type);
        assert_eq!(hint.start_utc, start);
        assert_eq!(hint.end_utc, start + 1_800);
    }
    for bad in [
        "http://book.example.org/schedule/invalid".to_owned(),
        format!("https://book.example.org/public/booking/{}", token.0),
        "https://user@book.example.org/schedule/invalid".to_owned(),
    ] {
        assert!(
            booking_slots_snippet(
                &mask,
                &[first],
                "UTC",
                &token,
                &bad,
                BookingSnippetCopy {
                    introduction: "Intro",
                    optional_link_label: "Link"
                },
                &BookingConversionPolicy::default()
            )
            .is_err()
        );
    }
    assert!(
        booking_slots_snippet(
            &mask,
            &[first],
            "Missing/Zone",
            &token,
            &page,
            BookingSnippetCopy {
                introduction: "Intro",
                optional_link_label: "Link"
            },
            &BookingConversionPolicy::default(),
        )
        .is_err()
    );
    assert!(
        booking_slots_snippet(
            &mask,
            &[],
            "UTC",
            &token,
            &page,
            BookingSnippetCopy {
                introduction: "Intro",
                optional_link_label: "Link"
            },
            &BookingConversionPolicy::default()
        )
        .is_err()
    );
}
