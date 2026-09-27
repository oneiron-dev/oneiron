//! BK-07 host-facing conversion contracts across the merged booking packs.

use oneiron::booking::{
    EventTypeKey, MeetingLocation, PublicBookingPageToken, RankedSlot, SlotMask,
    booking_display_zones, booking_shortlist, booking_slot_preview, booking_slots_snippet,
    booking_snippet_links, booking_snippet_selection_from_url, booking_suggested_slot,
    parse_booking_slot_link,
};

fn mask() -> SlotMask {
    SlotMask {
        event_type: EventTypeKey("consultation&60".to_owned()),
        window_start_utc: 1_800_000_000,
        window_end_utc: 1_800_030_000,
        slots: vec![
            RankedSlot {
                start_utc: 1_800_003_600,
                end_utc: 1_800_007_200,
                rank: 1.0,
            },
            RankedSlot {
                start_utc: 1_800_014_400,
                end_utc: 1_800_018_000,
                rank: 0.9,
            },
        ],
        flex_used: false,
    }
}

#[test]
fn conversion_preview_and_shortlist_keep_the_solver_choice() {
    let mask = mask();
    let preview = booking_slot_preview(&mask);
    let shortlist = booking_shortlist(&mask.slots, 3).expect("ranked shortlist");
    assert_eq!(preview.recommended_start_utc, Some(mask.slots[0].start_utc));
    assert_eq!(shortlist.recommended, Some(mask.slots[0].clone()));
    assert_eq!(shortlist.visible, mask.slots);
    assert_eq!(shortlist.more_count, 0);
    assert!(booking_shortlist(&mask.slots, 2).is_err());
}

#[test]
fn public_face_and_engine_json_snippets_have_distinct_validated_hint_protocols() {
    let mask = mask();
    let token = PublicBookingPageToken(format!("bkp_{}", "ab".repeat(16)));
    let face = format!("https://book.example.org/schedule/{}", token.0);
    let face_link = booking_snippet_links(
        &mask,
        &[mask.slots[0].start_utc],
        "Europe/London",
        &token,
        &face,
    )
    .expect("host public-face link")
    .pop()
    .unwrap();
    let face_hint = booking_snippet_selection_from_url(&face_link.href, &token)
        .expect("host can read its own link");
    assert_eq!(face_hint.event_type, mask.event_type);
    assert_eq!(face_hint.start_utc, mask.slots[0].start_utc);
    assert!(
        parse_booking_slot_link(face_link.href.split_once('?').map(|(_, query)| query)).is_none()
    );

    let snippet = booking_slots_snippet(
        "https://book.example.org",
        &token,
        &mask.event_type,
        &mask.slots[..1],
        "Europe/London",
        "Available:",
        "All slots",
    )
    .expect("engine route link");
    let href = snippet
        .lines()
        .nth(1)
        .unwrap()
        .split_once("](")
        .unwrap()
        .1
        .trim_end_matches(')');
    let strict_hint = parse_booking_slot_link(href.split_once('?').map(|(_, query)| query))
        .expect("engine route can read its own query");
    assert_eq!(strict_hint.event_type, mask.event_type);
    assert_eq!(
        booking_suggested_slot(&mask.slots, &strict_hint),
        Some(mask.slots[0].clone())
    );
    assert!(booking_snippet_selection_from_url(href, &token).is_none());
}

#[test]
fn remote_meeting_zone_cannot_be_locked_or_silently_defaulted() {
    let start = mask().slots[0].start_utc;
    let (visitor, host, locked) = booking_display_zones(
        start,
        "Europe/London",
        "America/New_York",
        MeetingLocation::Remote,
        false,
    )
    .expect("both parties have labels");
    assert_eq!(visitor.zone, "Europe/London");
    assert_eq!(host.zone, "America/New_York");
    assert!(!locked);
    assert!(
        booking_display_zones(
            start,
            "Europe/London",
            "America/New_York",
            MeetingLocation::Remote,
            true,
        )
        .is_err()
    );
    assert!(
        booking_display_zones(
            start,
            "Not/AZone",
            "America/New_York",
            MeetingLocation::Physical,
            false,
        )
        .is_err()
    );
}
