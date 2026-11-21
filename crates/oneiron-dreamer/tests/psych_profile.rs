//! Pure public-API checks for the Psych Mirror profile policy: the band
//! floor, the round-robin slot fill and canon's confidence formula
//! (ARCH-0025 #conf, #scour:A56).

use oneiron_dreamer::psych_profile::{
    Candidate, ClaimSource, RESTRICTED_BAND, SOURCE_SLOTS, admits_band, confidence, fill_slots,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    slot_fill: Vec<SlotFillCase>,
    confidence: Vec<ConfidenceCase>,
}

#[derive(Deserialize)]
struct SlotFillCase {
    case: String,
    ranked: Vec<Candidate>,
    slots: Vec<usize>,
}

#[derive(Deserialize)]
struct ConfidenceCase {
    case: String,
    sources: Vec<SourceRun>,
    confidence: f32,
}

/// `count` claims in a row from one source.
#[derive(Deserialize)]
struct SourceRun {
    source: Option<ClaimSource>,
    count: usize,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/psych_profile.json")).expect("fixture parses")
}

fn candidate(predicate: &str) -> Candidate {
    Candidate {
        predicate: predicate.to_owned(),
        band: Some(0),
        source: Some(ClaimSource::UserStated),
    }
}

#[test]
fn only_bands_below_the_restricted_band_are_read() {
    assert_eq!(RESTRICTED_BAND, 3);
    for band in 0..RESTRICTED_BAND {
        assert!(admits_band(Some(band)), "band {band}");
    }
    for band in [RESTRICTED_BAND, RESTRICTED_BAND + 1, u8::MAX] {
        assert!(!admits_band(Some(band)), "band {band}");
    }
    assert!(!admits_band(None), "a claim that carries no band");
}

#[test]
fn slots_fill_round_robin_across_predicates_in_rank_order() {
    for case in fixture().slot_fill {
        assert_eq!(fill_slots(&case.ranked), case.slots, "case {}", case.case);
    }
}

#[test]
fn fifty_slots_cap_the_fill() {
    // Three predicates of 30 claims each, ranked one group after another.
    let ranked: Vec<Candidate> = ["trait.openness", "value.security", "habit.sleep"]
        .into_iter()
        .flat_map(|predicate| (0..30).map(move |_| candidate(predicate)))
        .collect();
    let slots = fill_slots(&ranked);
    assert_eq!(SOURCE_SLOTS, 50);
    assert_eq!(slots.len(), SOURCE_SLOTS);
    assert_eq!(slots[..6], [0, 30, 60, 1, 31, 61]);
    assert_eq!(slots[48..], [16, 46]);
    let per_group = [0..30, 30..60, 60..90].map(|group| {
        slots
            .iter()
            .filter(|position| group.contains(*position))
            .count()
    });
    assert_eq!(per_group, [17, 17, 16]);
}

#[test]
fn fewer_admitted_claims_than_slots_are_all_read() {
    let mut ranked: Vec<Candidate> = (0..40).map(|_| candidate("trait.openness")).collect();
    ranked.push(Candidate {
        band: Some(RESTRICTED_BAND),
        ..candidate("value.security")
    });
    assert_eq!(fill_slots(&ranked), (0..40).collect::<Vec<usize>>());
}

#[test]
fn confidence_blends_density_and_source_quality_sixty_forty() {
    for case in fixture().confidence {
        let sources = case
            .sources
            .iter()
            .flat_map(|run| std::iter::repeat_n(run.source, run.count));
        let got = confidence(sources);
        assert!(
            (got - case.confidence).abs() < 1e-6,
            "case {}: got {got}, want {}",
            case.case,
            case.confidence
        );
    }
}

#[test]
fn a_profile_scores_the_claims_it_read() {
    let ranked: Vec<Candidate> = (0..60)
        .map(|_| Candidate {
            source: Some(ClaimSource::Observed),
            ..candidate("trait.openness")
        })
        .collect();
    let read = fill_slots(&ranked);
    assert_eq!(read.len(), SOURCE_SLOTS);
    let got = confidence(read.iter().map(|&position| ranked[position].source));
    assert!((got - 0.92).abs() < 1e-6, "got {got}");
}
