//! A sufficiency card reads unknown, not worse, when the comparison is not
//! like for like: the set or rubric version moved, or the canary diverged
//! (ARCH-0053 #eval-sufficiency; FIX 4732). A like-for-like comparison below
//! the margin still reads worse.

use std::collections::BTreeMap;

use oneiron::skill_optimize::{
    SufficiencyInput, SufficiencyVerdict, UnknownReason, sufficiency_card,
};

/// Eight families, retest noise 0.05, and a paired interval wholly below
/// minus the margin: a clearly worse, like-for-like comparison.
fn below_margin() -> SufficiencyInput {
    SufficiencyInput {
        families: 8,
        floor_slices: BTreeMap::from([("core".to_owned(), 8)]),
        min_families_per_slice: 3,
        retest_noise: Some(0.05),
        owner_margin: None,
        paired_interval: Some((-0.30, -0.20)),
        detectable_effect: Some(0.10),
        set_changed: false,
        rubric_changed: false,
        canary_diverged: Some(false),
    }
}

fn verdict(input: SufficiencyInput) -> SufficiencyVerdict {
    let card = sufficiency_card(input).expect("read the card");
    assert!(!card.approves(), "no card below the margin approves");
    assert_eq!(card.margin, Some(0.05));
    card.verdict
}

#[test]
fn like_for_like_below_margin_reads_worse() {
    assert_eq!(verdict(below_margin()), SufficiencyVerdict::Worse);
}

#[test]
fn changed_set_below_margin_reads_unknown() {
    let input = SufficiencyInput {
        set_changed: true,
        ..below_margin()
    };
    assert_eq!(
        verdict(input),
        SufficiencyVerdict::Unknown(vec![UnknownReason::SetChanged])
    );
}

#[test]
fn changed_rubric_below_margin_reads_unknown() {
    let input = SufficiencyInput {
        rubric_changed: true,
        ..below_margin()
    };
    assert_eq!(
        verdict(input),
        SufficiencyVerdict::Unknown(vec![UnknownReason::RubricChanged])
    );
}

#[test]
fn diverged_canary_below_margin_reads_unknown() {
    let input = SufficiencyInput {
        canary_diverged: Some(true),
        ..below_margin()
    };
    assert_eq!(
        verdict(input),
        SufficiencyVerdict::Unknown(vec![UnknownReason::CanaryDiverged])
    );
}

#[test]
fn every_moved_part_below_margin_is_listed() {
    let input = SufficiencyInput {
        set_changed: true,
        rubric_changed: true,
        canary_diverged: Some(true),
        ..below_margin()
    };
    assert_eq!(
        verdict(input),
        SufficiencyVerdict::Unknown(vec![
            UnknownReason::SetChanged,
            UnknownReason::RubricChanged,
            UnknownReason::CanaryDiverged,
        ])
    );
}

/// An unmeasured canary or a thin floor slice is not a moved comparison: a
/// clearly worse interval still reads worse.
#[test]
fn unmeasured_canary_or_thin_slice_below_margin_reads_worse() {
    let no_canary = SufficiencyInput {
        canary_diverged: None,
        ..below_margin()
    };
    assert_eq!(verdict(no_canary), SufficiencyVerdict::Worse);
    let thin_slice = SufficiencyInput {
        floor_slices: BTreeMap::from([("rare".to_owned(), 1)]),
        ..below_margin()
    };
    assert_eq!(verdict(thin_slice), SufficiencyVerdict::Worse);
}

#[test]
fn changed_set_above_margin_reads_unknown() {
    let input = SufficiencyInput {
        paired_interval: Some((0.01, 0.20)),
        set_changed: true,
        ..below_margin()
    };
    let card = sufficiency_card(input).expect("read the card");
    assert!(!card.approves());
    assert_eq!(
        card.verdict,
        SufficiencyVerdict::Unknown(vec![UnknownReason::SetChanged])
    );
}
