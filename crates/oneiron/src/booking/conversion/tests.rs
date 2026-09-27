use super::*;
use crate::booking::EventTypeKey;

fn mask() -> SlotMask {
    SlotMask {
        event_type: EventTypeKey("intro".to_owned()),
        window_start_utc: 1_794_050_000,
        window_end_utc: 1_794_100_000,
        slots: (0..7)
            .map(|i| RankedSlot {
                start_utc: 1_794_050_000 + i * 3_600,
                end_utc: 1_794_051_800 + i * 3_600,
                rank: if i == 2 { 1.0 } else { 0.5 },
            })
            .collect(),
        flex_used: false,
    }
}

#[test]
fn preview_highlights_best_visible_and_leaves_full_mask_available() {
    let mask = mask();
    let preview = booking_slot_preview(&mask);
    assert_eq!(preview.visible, mask.slots[..5]);
    assert_eq!(preview.recommended_start_utc, Some(mask.slots[2].start_utc));
    assert_eq!(preview.remaining_count, 2);
    assert_eq!(mask.slots.len(), 7);
    let mut empty = mask;
    empty.slots.clear();
    assert_eq!(booking_slot_preview(&empty).recommended_start_utc, None);
    assert_eq!(booking_slot_preview(&empty).remaining_count, 0);
}

#[test]
fn landing_content_rejects_unbounded_copy_unsafe_assets_and_duplicate_intake() {
    let good = BookingLandingContent {
        photo_path: Some("/assets/host.jpg".to_owned()),
        intro: "Owner introduction".to_owned(),
        faq: vec![BookingFaq {
            question: "Why?".into(),
            answer: "Owner answer".into(),
        }],
        prep_path: Some("/assets/prep.pdf".to_owned()),
        preconfirm_field_keys: vec!["role".into(), "topic".into()],
    };
    good.validate().expect("owner data");
    for path in [
        "//evil.example/a",
        "https://evil.example/a",
        "/../secret",
        "/public/booking/bkp_test",
        "/photo?redirect=evil",
        "/x\\file",
    ] {
        let mut invalid = good.clone();
        invalid.photo_path = Some(path.to_owned());
        assert!(invalid.validate().is_err(), "{path}");
    }
    let mut invalid = good.clone();
    invalid.intro = "x".repeat(2049);
    assert!(invalid.validate().is_err());
    let mut invalid = good.clone();
    invalid.preconfirm_field_keys.push("role".into());
    assert!(invalid.validate().is_err());
    let mut invalid = good;
    invalid.faq[0].question.clear();
    assert!(invalid.validate().is_err());
}

#[test]
fn snippet_requires_solved_slots_and_explicit_real_zone() {
    let mask = mask();
    let page = PublicBookingPageToken(format!("bkp_{}", "ab".repeat(16)));
    let selected = [mask.slots[0].start_utc, mask.slots[2].start_utc];
    let url = format!("https://book.example.test/{}", page.0);
    let links =
        booking_snippet_links(&mask, &selected, "America/Vancouver", &page, &url).expect("links");
    assert_eq!(links.len(), 2);
    assert!(
        links
            .iter()
            .all(|link| link.label.contains(" America/Vancouver (")
                && link.label.ends_with(" UTC)")
                && link.href == url)
    );
    for rejected in [
        vec![],
        vec![selected[0], selected[0]],
        vec![1],
        vec![selected[0], selected[1], mask.slots[3].start_utc],
    ] {
        assert!(booking_snippet_links(&mask, &rejected, "America/Vancouver", &page, &url).is_err());
    }
    assert!(booking_snippet_links(&mask, &selected[..1], "Not/AZone", &page, &url).is_err());
    for bad in [
        "http://book.example.test/bkp_bad",
        "https://evil@example.test/bkp_bad",
        "https://book.example.test/public/booking/bkp_bad",
    ] {
        assert!(booking_snippet_links(&mask, &selected[..1], "UTC", &page, bad).is_err());
    }
    assert!(
        booking_snippet_links(
            &mask,
            &selected[..1],
            "UTC",
            &PublicBookingPageToken("bkp_../evil".into()),
            &url
        )
        .is_err()
    );
}

#[test]
fn snippet_disambiguates_the_two_instants_in_a_fall_back_fold() {
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
    let mut mask = mask();
    mask.window_start_utc = first - 60;
    mask.window_end_utc = first + 5_400;
    mask.slots = [first, first + 3_600]
        .into_iter()
        .map(|start_utc| RankedSlot {
            start_utc,
            end_utc: start_utc + 1_800,
            rank: 0.5,
        })
        .collect();
    let token = PublicBookingPageToken(format!("bkp_{}", "ab".repeat(16)));
    let url = format!("https://book.example.test/{}", token.0);
    let links = booking_snippet_links(
        &mask,
        &[first, first + 3_600],
        "America/New_York",
        &token,
        &url,
    )
    .expect("links");
    assert!(links[0].label.contains("01:30 America/New_York"));
    assert!(links[1].label.contains("01:30 America/New_York"));
    assert_ne!(
        links[0].label, links[1].label,
        "UTC instants distinguish fold"
    );
}
