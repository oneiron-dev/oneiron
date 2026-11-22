//! These tests cover draft spans, gaps, and input refusals (FIX [BROWSER-CRATE-RUNS-NO-TEST]).
//! They exercise the rule tier with plain history and page values.

use oneiron_browser::{
    BatchStep, BatchStopCause, BrowserError, DraftGap, DraftGapKind, DraftInput, DraftOutcome,
    DraftOutput, DraftPage, DraftStep, DraftTypeRef, ExpectInput, FieldSpec, ReplayAction,
    draft_from_steps,
};
use serde_json::{Value, json};

const SHOP: &str = "https://shop.example";
const OTHER: &str = "https://other.example";
const FORM: &str = "https://shop.example/form";
const BUTTON: &str = "e-button";

/// An ordinary check that requires neither handle resolution nor custody.
fn ready() -> ExpectInput {
    ExpectInput {
        role: Some("heading".to_owned()),
        name: Some("Ready".to_owned()),
        ..Default::default()
    }
}

/// A subgoal and a check, with default bounds and press policy.
fn input() -> DraftInput {
    DraftInput {
        subgoal: "Fill form".to_owned(),
        postcondition: vec![ready()],
        ..Default::default()
    }
}

/// The shop page, with no secret handles known to its checks.
fn page() -> DraftPage {
    DraftPage {
        url: FORM.to_owned(),
        origin: Some(SHOP.to_owned()),
        ..Default::default()
    }
}

/// A history entry that acted on the shop page in the main tab.
fn step(seq: u64, verb: &str, action: Result<ReplayAction, DraftGapKind>) -> DraftStep {
    DraftStep {
        seq,
        verb: verb.to_owned(),
        tab: Some("main".to_owned()),
        result_tab: Some("main".to_owned()),
        source_url: Some(FORM.to_owned()),
        source_origin: Some(SHOP.to_owned()),
        result_url: FORM.to_owned(),
        result_origin: Some(SHOP.to_owned()),
        requested_origin: None,
        target_name: None,
        effect_class: None,
        action,
        outcome: DraftOutcome::Ok,
    }
}

/// An opening that asked for the form on `origin` and landed there.
fn open(seq: u64, origin: &str) -> DraftStep {
    let url = format!("{origin}/form");
    DraftStep {
        source_url: None,
        source_origin: None,
        result_origin: Some(origin.to_owned()),
        requested_origin: Some(origin.to_owned()),
        result_url: url.clone(),
        ..step(seq, "open", Ok(ReplayAction::Open { url }))
    }
}

/// A click at a recorded locator.
fn click(seq: u64, locator: &str) -> DraftStep {
    step(
        seq,
        "click",
        Ok(ReplayAction::Click {
            locator: locator.to_owned(),
        }),
    )
}

/// A Fill that recorded the whole field it was given.
fn fill(seq: u64, field: FieldSpec) -> DraftStep {
    step(
        seq,
        "fill",
        Ok(ReplayAction::Fill {
            locator: "e-fill".to_owned(),
            field,
        }),
    )
}

/// The exact gap expected at an entry of the history.
fn at(seq: u64, verb: &str, gap: DraftGapKind) -> DraftGap {
    DraftGap {
        seq: Some(seq),
        verb: Some(verb.to_owned()),
        gap,
    }
}

/// A gap on the input or span rather than on a history entry.
fn input_gap(gap: DraftGapKind) -> DraftGap {
    DraftGap {
        seq: None,
        verb: None,
        gap,
    }
}

/// Batch steps lack Rust equality, so compare their whole serialized values.
fn assert_steps(draft: &DraftOutput, expected: Value) {
    let actual = serde_json::to_value(&draft.proposal.steps).expect("proposal steps serialize");
    assert_eq!(actual, expected);
}

#[test]
fn the_default_span_is_the_latest_contiguous_run_on_the_open_page_origin() {
    use DraftGapKind::UnrecordedNavigation;

    let steps = [
        open(1, OTHER),
        open(3, SHOP),
        DraftStep {
            source_url: None,
            source_origin: None,
            result_url: String::new(),
            result_origin: None,
            ..step(4, "unrecorded", Err(UnrecordedNavigation))
        },
        click(5, BUTTON),
        open(7, OTHER),
    ];
    let got = draft_from_steps(&input(), &steps, &page()).expect("the page's latest run drafts");

    assert_eq!((got.after_seq, got.through_seq), (1, 5));
    assert_eq!(got.origin.as_deref(), Some(SHOP));
    assert_steps(
        &got,
        json!([{"step":"open", "url":FORM}, {"step":"click", "ref":BUTTON}]),
    );
    assert_eq!(got.gaps, [at(4, "unrecorded", UnrecordedNavigation)]);
}

#[test]
fn explicit_bounds_exclude_after_include_through_and_allow_equal_bounds() {
    let steps = [
        open(1, SHOP),
        open(3, SHOP),
        click(5, "e-end"),
        click(7, "e-out"),
    ];
    let input = DraftInput {
        after_seq: Some(1),
        through_seq: Some(5),
        ..input()
    };
    let got = draft_from_steps(&input, &steps, &page()).expect("both bounds name history entries");

    assert_eq!((got.after_seq, got.through_seq), (1, 5));
    assert_steps(
        &got,
        json!([{"step":"open", "url":FORM}, {"step":"click", "ref":"e-end"}]),
    );
    assert_eq!(got.origin.as_deref(), Some(SHOP));
    assert!(got.gaps.is_empty());
    assert!(got.complete);

    let input = DraftInput {
        after_seq: Some(3),
        through_seq: Some(3),
        ..input
    };
    let got = draft_from_steps(&input, &steps, &page()).expect("equal named bounds are valid");
    assert_eq!((got.after_seq, got.through_seq), (3, 3));
    assert!(got.proposal.steps.is_empty());
    assert_eq!(got.gaps, [input_gap(DraftGapKind::EmptySpan)]);
}

#[test]
fn an_after_seq_past_the_last_entry_is_refused_before_other_errors() {
    let input = DraftInput {
        after_seq: Some(5),
        through_seq: Some(4),
        ..input()
    };
    let error = draft_from_steps(&input, &[open(3, SHOP)], &page())
        .expect_err("after_seq names a future entry");
    assert_eq!(
        error,
        BrowserError::Input(
            "after_seq 5 names no entry of this session's history yet: its last is 3".to_owned()
        )
    );

    let input = DraftInput {
        after_seq: Some(1),
        through_seq: None,
        ..input
    };
    let error = draft_from_steps(&input, &[], &page()).expect_err("an empty history ends at zero");
    assert_eq!(
        error,
        BrowserError::Input(
            "after_seq 1 names no entry of this session's history yet: its last is 0".to_owned()
        )
    );
}

#[test]
fn a_through_seq_past_the_last_entry_is_refused_as_input() {
    let input = DraftInput {
        through_seq: Some(4),
        ..input()
    };
    let error = draft_from_steps(&input, &[open(3, SHOP)], &page())
        .expect_err("through_seq names a future entry");
    assert_eq!(
        error,
        BrowserError::Input(
            "through_seq 4 names no entry of this session's history yet: its last is 3".to_owned()
        )
    );
}

#[test]
fn an_after_seq_past_through_seq_is_refused_as_input() {
    let input = DraftInput {
        after_seq: Some(3),
        through_seq: Some(1),
        ..input()
    };
    let steps = [open(1, SHOP), click(3, BUTTON)];
    let error = draft_from_steps(&input, &steps, &page()).expect_err("the bounds are inverted");
    assert_eq!(
        error,
        BrowserError::Input(
            "after_seq 3 is past through_seq 1: a span runs after the first through the second"
                .to_owned()
        )
    );
}

#[test]
fn an_outcome_gap_preserves_a_replayable_action_and_suppresses_only_a_stopped_no_action() {
    use BatchStopCause::{LocatorMissing, PressNeeded, TakenOver};
    use DraftGapKind::{Failed, NoAction, NoEffect, UnrecordedNavigation};

    let steps = [
        open(1, SHOP),
        DraftStep {
            outcome: DraftOutcome::NoEffect,
            ..click(2, "e-no-effect")
        },
        DraftStep {
            outcome: DraftOutcome::NoEffect,
            ..step(3, "type", Err(NoAction))
        },
        DraftStep {
            outcome: DraftOutcome::Failed {
                cause: LocatorMissing,
            },
            ..click(4, "e-failed")
        },
        DraftStep {
            outcome: DraftOutcome::Failed { cause: PressNeeded },
            ..step(5, "click", Err(NoAction))
        },
        DraftStep {
            outcome: DraftOutcome::Failed { cause: TakenOver },
            ..step(6, "record", Err(UnrecordedNavigation))
        },
    ];
    let got =
        draft_from_steps(&input(), &steps, &page()).expect("outcomes are reported in the draft");

    assert_steps(
        &got,
        json!([
            {"step":"open", "url":FORM},
            {"step":"click", "ref":"e-no-effect"},
            {"step":"click", "ref":"e-failed"},
        ]),
    );
    assert_eq!(
        got.gaps,
        [
            at(2, "click", NoEffect),
            at(3, "type", NoEffect),
            at(3, "type", NoAction),
            at(
                4,
                "click",
                Failed {
                    cause: LocatorMissing
                }
            ),
            at(5, "click", Failed { cause: PressNeeded }),
            at(6, "record", Failed { cause: TakenOver }),
            at(6, "record", UnrecordedNavigation),
        ]
    );
    assert!(!got.complete);
}

#[test]
fn a_marked_stop_at_the_excluded_boundary_reports_its_failure() {
    use BatchStopCause::{LocatorMissing, PressNeeded};
    use DraftGapKind::{Failed, NoAction};

    let input = DraftInput {
        after_seq: Some(1),
        ..input()
    };
    let steps = [
        DraftStep {
            outcome: DraftOutcome::Failed { cause: PressNeeded },
            ..click(1, "e-excluded")
        },
        open(2, SHOP),
        DraftStep {
            outcome: DraftOutcome::Failed {
                cause: LocatorMissing,
            },
            ..click(3, BUTTON)
        },
        DraftStep {
            outcome: DraftOutcome::Marked {
                seq: 1,
                cause: PressNeeded,
            },
            ..step(4, "type", Err(NoAction))
        },
    ];
    let got = draft_from_steps(&input, &steps, &page())
        .expect("the span contains the stop, not its effect");

    assert_steps(
        &got,
        json!([{"step":"open", "url":FORM}, {"step":"click", "ref":BUTTON}]),
    );
    assert_eq!(
        got.gaps,
        [
            at(
                3,
                "click",
                Failed {
                    cause: LocatorMissing
                }
            ),
            at(4, "type", Failed { cause: PressNeeded })
        ]
    );
}

#[test]
fn an_unwritten_generated_fill_is_retained_but_makes_the_draft_incomplete() {
    let generated = || FieldSpec {
        generate: true,
        instruction: Some("write an answer".to_owned()),
        ..Default::default()
    };
    let fields = [
        generated(),
        FieldSpec {
            supplied: Some(String::new()),
            ..generated()
        },
        FieldSpec {
            template: Some("text".to_owned()),
            ..generated()
        },
        FieldSpec {
            secret: Some("sc5".to_owned()),
            ..Default::default()
        },
    ];
    let mut steps = vec![open(1, SHOP)];
    steps.extend(
        (2..)
            .zip(fields.iter())
            .map(|(seq, field)| fill(seq, field.clone())),
    );
    let got =
        draft_from_steps(&input(), &steps, &page()).expect("Fills are retained even with a gap");

    assert!(matches!(got.proposal.steps.first(), Some(BatchStep::Open { url }) if url == FORM));
    let fills = &got.proposal.steps[1..];
    assert_eq!(fills.len(), fields.len());
    for (batch, expected) in fills.iter().zip(fields) {
        assert!(
            matches!(batch, BatchStep::Fill { target, field } if target == "e-fill" && *field == expected)
        );
    }
    assert!(got.slot_candidates.is_empty());
    assert!(got.proposal.params.is_empty());
    assert!(got.proposal.args.is_empty());
    assert_eq!(got.gaps, [at(2, "fill", DraftGapKind::GeneratedFill)]);
    assert!(!got.complete);
}

#[test]
fn an_empty_draft_reports_input_gaps_in_order_without_inventing_an_opening() {
    use DraftGapKind::{EmptySpan, NoLiveOrigin, NoPostcondition, NoSubgoal};

    let page = DraftPage {
        url: "about:blank".to_owned(),
        ..Default::default()
    };
    let input = DraftInput {
        subgoal: " \t".to_owned(),
        type_ref: Some(DraftTypeRef {
            node_id: "forms.fill".to_owned(),
            tree_version: 2,
        }),
        ..Default::default()
    };
    let got = draft_from_steps(&input, &[], &page).expect("empty input still yields a draft");

    assert_eq!((got.after_seq, got.through_seq), (0, 0));
    assert_eq!((got.origin.as_deref(), got.site.as_deref()), (None, None));
    assert_eq!(got.proposal.subgoal, " \t");
    assert!(got.proposal.steps.is_empty());
    assert!(got.proposal.params.is_empty());
    assert!(got.proposal.postcondition.is_empty());
    assert!(got.proposal.args.is_empty());
    assert!(got.proposal.replay_args.is_empty());
    assert!(got.proposal.secret_args.is_empty());
    assert!(got.proposal.candidate.is_none());
    assert!(got.proposal.supersedes.is_none());
    assert!(got.proposal.seed.is_none());
    assert!(got.proposal.snapshot_bounds.is_none());
    assert!(got.slot_candidates.is_empty());
    assert!(!got.complete);
    assert_eq!(
        got.gaps,
        [
            input_gap(NoSubgoal),
            input_gap(NoLiveOrigin),
            input_gap(EmptySpan),
            input_gap(NoPostcondition)
        ]
    );

    let input = DraftInput {
        after_seq: Some(1),
        through_seq: Some(1),
        ..input
    };
    let got = draft_from_steps(&input, &[open(1, SHOP)], &page)
        .expect("an explicit span does not need a live origin");
    assert_eq!((got.after_seq, got.through_seq), (1, 1));
    assert_eq!(
        got.gaps,
        [
            input_gap(NoSubgoal),
            input_gap(EmptySpan),
            input_gap(NoPostcondition)
        ]
    );
}

#[test]
fn a_missing_opening_uses_page_site_but_an_invalid_open_url_does_not_fall_back() {
    let explicit = DraftInput {
        through_seq: Some(1),
        ..input()
    };
    let steps = [DraftStep {
        result_origin: None,
        result_url: String::new(),
        ..click(1, BUTTON)
    }];
    let got =
        draft_from_steps(&explicit, &steps, &page()).expect("the click supplies a source origin");

    assert_eq!((got.after_seq, got.through_seq), (0, 1));
    assert_eq!(got.origin.as_deref(), Some(SHOP));
    assert_eq!(got.site.as_deref(), Some("shop.example"));
    assert_steps(&got, json!([{"step":"click", "ref":BUTTON}]));
    assert_eq!(got.gaps, [at(1, "click", DraftGapKind::MissingOpening)]);
    assert!(!got.complete);

    let url = "https://{{name}}/";
    let steps = [DraftStep {
        requested_origin: None,
        action: Ok(ReplayAction::Open {
            url: url.to_owned(),
        }),
        ..open(1, SHOP)
    }];
    let got = draft_from_steps(&input(), &steps, &page())
        .expect("drafting does not validate a program's site");
    assert_eq!(got.site, None);
    assert_eq!(got.origin.as_deref(), Some(SHOP));
    assert!(got.gaps.is_empty());
    assert!(got.complete);
}
