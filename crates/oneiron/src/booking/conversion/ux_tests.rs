use super::*;
use crate::booking::{BookingConversionPolicy, EventTypeKey};

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
