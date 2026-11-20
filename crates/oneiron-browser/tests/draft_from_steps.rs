//! These tests hold the rule-tier draft contract (FIX [BROWSER-CRATE-RUNS-NO-TEST]).
//! They build proposals from plain history and page values, without a browser or a store.

use oneiron_browser::{
    BatchStopCause, DraftGap, DraftGapKind, DraftInput, DraftOutcome, DraftOutput, DraftPage,
    DraftStep, EFFECT_ACCOUNT, EFFECT_DESTRUCTIVE, EFFECT_PAY, EFFECT_PUBLISH, EFFECT_SEND,
    EFFECT_UNKNOWN, ExpectInput, OperandGap, PressedThrough, ReplayAction, SecretKind,
    SlotCandidate, SlotField, TypeOperand, draft_from_steps,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const SHOP: &str = "https://shop.example";
const OTHER: &str = "https://other.example";
const THIRD: &str = "http://third.example:8080";
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

/// A check that expects a secret in the named target.
fn secret_check(target: &str, secret: &str) -> ExpectInput {
    ExpectInput {
        target: Some(target.to_owned()),
        secret: Some(secret.to_owned()),
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

/// A Type with its operand and clear flag as recorded.
fn type_at(seq: u64, locator: &str, operand: TypeOperand, clear: bool) -> DraftStep {
    step(
        seq,
        "type",
        Ok(ReplayAction::Type {
            locator: locator.to_owned(),
            operand,
            clear,
        }),
    )
}

/// A Type with a literal operand, which may be empty.
fn literal(seq: u64, text: &str, clear: bool) -> DraftStep {
    type_at(
        seq,
        "e-type",
        TypeOperand::Literal {
            text: text.to_owned(),
        },
        clear,
    )
}

/// A Select whose option may be empty.
fn select(seq: u64, locator: &str, option: &str) -> DraftStep {
    step(
        seq,
        "select",
        Ok(ReplayAction::Select {
            locator: locator.to_owned(),
            option: option.to_owned(),
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

/// The expected entry in an ordered list of presses taken.
fn pressed(seq: u64, class: &str) -> PressedThrough {
    PressedThrough {
        seq,
        effect_class: class.to_owned(),
    }
}

/// A complete expected slot candidate, including both kinds of position.
fn candidate(step: usize, seq: u64, field: SlotField, literal: &str, name: &str) -> SlotCandidate {
    SlotCandidate {
        step,
        seq,
        field,
        literal: literal.to_owned(),
        suggested_param: name.to_owned(),
    }
}

/// Batch steps lack Rust equality, so compare their whole serialized values.
fn assert_steps(draft: &DraftOutput, expected: Value) {
    let actual = serde_json::to_value(&draft.proposal.steps).expect("proposal steps serialize");
    assert_eq!(actual, expected);
}

#[test]
fn typed_secrets_reuse_only_the_same_kind_and_handle_across_steps_and_checks() {
    use SecretKind::{Card, Cvv, Otp, Password};

    let input = DraftInput {
        postcondition: vec![ready(), secret_check("e-verify", "sc7")],
        ..input()
    };
    let page = DraftPage {
        secrets: BTreeMap::from([("sc7".to_owned(), Password)]),
        ..page()
    };
    let mut steps = vec![open(1, SHOP)];
    steps.extend(
        [
            (2, "e-a", Password, "sc7", true),
            (3, "e-b", Password, "sc7", false),
            (4, "e-c", Password, "sc8", true),
            (5, "e-d", Otp, "sc7", false),
            (6, "e-card", Card, "sc9", false),
            (7, "e-cvv", Cvv, "sc10", false),
        ]
        .map(|(seq, locator, kind, handle, clear)| {
            type_at(
                seq,
                locator,
                TypeOperand::Secret {
                    kind,
                    handle: handle.to_owned(),
                },
                clear,
            )
        }),
    );
    let got = draft_from_steps(&input, &steps, &page).expect("the typed operands draft");

    assert_steps(
        &got,
        json!([
            {"step":"open", "url":FORM},
            {"step":"type", "ref":"e-a", "secret":"{{password}}", "clear":true},
            {"step":"type", "ref":"e-b", "secret":"{{password}}", "clear":false},
            {"step":"type", "ref":"e-c", "secret":"{{password_2}}", "clear":true},
            {"step":"type", "ref":"e-d", "secret":"{{otp}}", "clear":false},
            {"step":"type", "ref":"e-card", "secret":"{{card}}", "clear":false},
            {"step":"type", "ref":"e-cvv", "secret":"{{cvv}}", "clear":false},
        ]),
    );
    assert_eq!(
        got.proposal.params,
        ["password", "password_2", "otp", "card", "cvv"]
    );
    assert_eq!(
        got.proposal.args,
        BTreeMap::from(
            [
                ("password", "sc7"),
                ("password_2", "sc8"),
                ("otp", "sc7"),
                ("card", "sc9"),
                ("cvv", "sc10"),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
        )
    );
    assert_eq!(
        got.proposal.postcondition,
        [ready(), secret_check("e-verify", "{{password}}")]
    );
    assert!(got.slot_candidates.is_empty());
    assert!(got.proposal.replay_args.is_empty());
    assert!(got.proposal.secret_args.is_empty());
    assert!(got.complete);
}

#[test]
fn a_withheld_secret_has_no_value_and_only_a_known_unbound_secret_keeps_its_step() {
    use OperandGap::{NoCustody, Refused, Unbound, UnknownKind};
    use SecretKind::{Card, Otp, Password};

    let withheld = [
        (2, "e-a", Some(Password), Unbound, true),
        (3, "e-b", Some(Password), Unbound, false),
        (4, "e-c", Some(Card), NoCustody, false),
        (5, "e-d", None, Unbound, false),
        (6, "e-e", Some(Otp), Refused, false),
        (7, "e-f", None, UnknownKind, false),
    ];
    let mut steps = vec![open(1, SHOP)];
    steps.extend(withheld.map(|(seq, locator, kind, cause, clear)| {
        type_at(seq, locator, TypeOperand::Withheld { kind, cause }, clear)
    }));
    let got = draft_from_steps(&input(), &steps, &page()).expect("withheld operands yield gaps");

    assert_steps(
        &got,
        json!([
            {"step":"open", "url":FORM},
            {"step":"type", "ref":"e-a", "secret":"{{password}}", "clear":true},
            {"step":"type", "ref":"e-b", "secret":"{{password_2}}", "clear":false},
        ]),
    );
    assert_eq!(got.proposal.params, ["password", "password_2"]);
    assert!(got.proposal.args.is_empty());
    assert!(got.slot_candidates.is_empty());
    assert_eq!(
        got.gaps,
        withheld.map(|(seq, _, kind, cause, _)| {
            at(seq, "type", DraftGapKind::SecretWithheld { kind, cause })
        })
    );
    assert!(!got.complete);
}

#[test]
fn unknown_check_refs_take_priority_over_unknown_secrets_and_checks_keep_input_order() {
    use DraftGapKind::{CheckSecretWithheld, CheckUnknownRef};

    let page = DraftPage {
        secrets: BTreeMap::from([("sc1".to_owned(), SecretKind::Otp)]),
        ..page()
    };
    let steps = [open(1, SHOP)];
    let bad_checks = || [secret_check("hAb:007", "sc2"), secret_check("e-y", "sc2")];
    let [bad_ref, bad_secret] = bad_checks();
    let input = DraftInput {
        postcondition: vec![ready(), bad_ref, bad_secret, secret_check("e-x", "sc1")],
        ..input()
    };
    let got = draft_from_steps(&input, &steps, &page).expect("invalid checks yield gaps");
    let unknown_secret = |check| {
        input_gap(CheckSecretWithheld {
            check,
            cause: OperandGap::UnknownKind,
        })
    };
    assert_eq!(
        got.proposal.postcondition,
        [ready(), secret_check("e-x", "{{otp}}")]
    );
    assert_eq!(got.proposal.params, ["otp"]);
    assert_eq!(
        got.proposal.args,
        BTreeMap::from([("otp".to_owned(), "sc1".to_owned())])
    );
    assert_eq!(
        got.gaps,
        [input_gap(CheckUnknownRef { check: 1 }), unknown_secret(2)]
    );

    let input = DraftInput {
        postcondition: Vec::from(bad_checks()),
        ..input
    };
    let got = draft_from_steps(&input, &steps, &page).expect("all checks may be dropped");
    assert!(got.proposal.postcondition.is_empty());
    assert_eq!(
        got.gaps,
        [input_gap(CheckUnknownRef { check: 0 }), unknown_secret(1)]
    );
}

#[test]
fn candidate_names_take_four_ascii_words_and_skip_secret_names_and_earlier_suggestions() {
    let input = DraftInput {
        postcondition: vec![secret_check("e-verify", "sc1")],
        ..input()
    };
    let page = DraftPage {
        secrets: BTreeMap::from([("sc1".to_owned(), SecretKind::Password)]),
        ..page()
    };
    let mut steps = vec![open(1, SHOP)];
    steps.extend(
        [
            (2, Some("Password")),
            (3, Some("Password 2")),
            (4, Some("Password")),
            (5, Some("Å9--CITY / BOX New LAST")),
            (6, Some("世界")),
            (7, None),
        ]
        .map(|(seq, name)| DraftStep {
            target_name: name.map(str::to_owned),
            ..type_at(
                seq,
                "e-field",
                TypeOperand::Literal {
                    text: "x".to_owned(),
                },
                false,
            )
        }),
    );
    steps.push(select(8, "e-choice", "value"));
    let got = draft_from_steps(&input, &steps, &page).expect("literal names can be suggested");

    assert_eq!(
        got.slot_candidates,
        [
            candidate(1, 2, SlotField::Text, "x", "password_2"),
            candidate(2, 3, SlotField::Text, "x", "password_2_2"),
            candidate(3, 4, SlotField::Text, "x", "password_3"),
            candidate(4, 5, SlotField::Text, "x", "text_9_city_box_new"),
            candidate(5, 6, SlotField::Text, "x", "text"),
            candidate(6, 7, SlotField::Text, "x", "text_2"),
            candidate(7, 8, SlotField::Choice, "value", "option"),
        ]
    );
    assert_eq!(got.proposal.params, ["password"]);
}

#[test]
fn literals_are_unchanged_and_candidates_use_emitted_step_indices() {
    let steps = [
        open(1, SHOP),
        step(2, "click_at", Err(DraftGapKind::NoAction)),
        literal(3, "", true),
        select(4, "e-select", ""),
        literal(5, " x ", false),
        select(6, "e-select", " x "),
        literal(7, " x ", true),
        click(8, BUTTON),
    ];
    let got =
        draft_from_steps(&input(), &steps, &page()).expect("literal actions draft around a gap");

    assert_steps(
        &got,
        json!([
            {"step":"open", "url":FORM},
            {"step":"type", "ref":"e-type", "text":"", "clear":true},
            {"step":"select", "ref":"e-select", "option":""},
            {"step":"type", "ref":"e-type", "text":" x ", "clear":false},
            {"step":"select", "ref":"e-select", "option":" x "},
            {"step":"type", "ref":"e-type", "text":" x ", "clear":true},
            {"step":"click", "ref":BUTTON},
        ]),
    );
    assert_eq!(
        got.slot_candidates,
        [
            candidate(3, 5, SlotField::Text, " x ", "text"),
            candidate(4, 6, SlotField::Choice, " x ", "option"),
            candidate(5, 7, SlotField::Text, " x ", "text_2"),
        ]
    );
    assert_eq!(got.gaps, [at(2, "click_at", DraftGapKind::NoAction)]);
    assert!(!got.complete);
}

#[test]
fn a_known_press_ends_the_proposal_before_the_press_but_keeps_span_bounds() {
    for class in [EFFECT_SEND, EFFECT_PAY, EFFECT_PUBLISH, EFFECT_DESTRUCTIVE] {
        let steps = [
            open(1, SHOP),
            DraftStep {
                effect_class: Some(EFFECT_ACCOUNT.to_owned()),
                ..click(2, "e-account")
            },
            DraftStep {
                effect_class: Some(class.to_owned()),
                tab: None,
                outcome: DraftOutcome::Failed {
                    cause: BatchStopCause::PressNeeded,
                },
                ..click(3, "e-press")
            },
            click(4, "e-after"),
        ];
        let got =
            draft_from_steps(&input(), &steps, &page()).expect("a known press cuts the draft");

        assert_steps(
            &got,
            json!([
                {"step":"open", "url":FORM},
                {"step":"click", "ref":"e-account"},
            ]),
        );
        let gap = DraftGapKind::PrePress {
            effect_class: class.to_owned(),
        };
        assert_eq!(got.gaps, [at(3, "click", gap)]);
        assert!(got.pressed_through.is_empty());
        assert_eq!((got.after_seq, got.through_seq), (0, 4));
    }
}

#[test]
fn an_unknown_press_stops_before_even_an_unrecordable_action_and_is_incomplete() {
    let steps = [
        open(1, SHOP),
        DraftStep {
            effect_class: Some(EFFECT_UNKNOWN.to_owned()),
            ..step(2, "click_at", Err(DraftGapKind::NoAction))
        },
        click(3, BUTTON),
    ];
    let got = draft_from_steps(&input(), &steps, &page()).expect("an unknown press cuts the draft");

    assert_steps(&got, json!([{"step":"open", "url":FORM}]));
    assert_eq!(got.gaps, [at(2, "click_at", DraftGapKind::UnknownPress)]);
    assert!(got.pressed_through.is_empty());
    assert_eq!((got.after_seq, got.through_seq), (0, 3));
    assert!(!got.complete);
}

#[test]
fn past_press_records_all_matched_presses_in_order_even_without_an_action() {
    let input = DraftInput {
        past_press: true,
        ..input()
    };
    let account = DraftStep {
        effect_class: Some(EFFECT_ACCOUNT.to_owned()),
        ..click(2, "e-account")
    };
    let send = DraftStep {
        effect_class: Some(EFFECT_SEND.to_owned()),
        ..click(3, "e-send")
    };
    let unknown = DraftStep {
        effect_class: Some(EFFECT_UNKNOWN.to_owned()),
        ..step(4, "click_at", Err(DraftGapKind::NoAction))
    };
    let custom = DraftStep {
        effect_class: Some("custom.effect".to_owned()),
        ..click(5, "e-custom")
    };
    let pay = DraftStep {
        effect_class: Some(EFFECT_PAY.to_owned()),
        ..click(6, "e-pay")
    };
    let mut steps = vec![open(1, SHOP), account, send, unknown, custom, pay];
    let got =
        draft_from_steps(&input, &steps, &page()).expect("past_press takes classified presses");

    let replay = || {
        json!([
            {"step":"open", "url":FORM},
            {"step":"click", "ref":"e-account"},
            {"step":"click", "ref":"e-send"},
            {"step":"click", "ref":"e-custom"},
            {"step":"click", "ref":"e-pay"},
        ])
    };
    assert_steps(&got, replay());
    assert_eq!(
        got.pressed_through,
        [
            pressed(3, EFFECT_SEND),
            pressed(4, EFFECT_UNKNOWN),
            pressed(6, EFFECT_PAY)
        ]
    );
    assert_eq!(got.gaps, [at(4, "click_at", DraftGapKind::NoAction)]);
    assert!(!got.complete);

    steps.retain(|step| step.seq != 4);
    let got = draft_from_steps(&input, &steps, &page()).expect("a gapless press history drafts");
    assert_steps(&got, replay());
    assert_eq!(
        got.pressed_through,
        [pressed(3, EFFECT_SEND), pressed(6, EFFECT_PAY)]
    );
    assert!(got.gaps.is_empty());
    assert!(got.complete);
}

#[test]
fn opening_redirect_keeps_its_requested_url_and_later_foreign_origins_are_ordered() {
    let input = DraftInput {
        after_seq: Some(0),
        through_seq: Some(4),
        ..input()
    };
    let page = DraftPage {
        url: format!("{OTHER}/page"),
        origin: Some(OTHER.to_owned()),
        ..Default::default()
    };
    let opening_url = " HTTPS://user@Shop.Example:0443?form ";
    let later_url = format!("{THIRD}/form");
    let steps = [
        DraftStep {
            requested_origin: Some(SHOP.to_owned()),
            action: Ok(ReplayAction::Open {
                url: opening_url.to_owned(),
            }),
            ..open(1, OTHER)
        },
        DraftStep {
            requested_origin: Some(THIRD.to_owned()),
            action: Ok(ReplayAction::Open {
                url: later_url.clone(),
            }),
            ..open(2, OTHER)
        },
        DraftStep {
            source_url: Some(later_url.clone()),
            source_origin: Some(THIRD.to_owned()),
            ..click(3, "e-third")
        },
        DraftStep {
            source_url: Some(format!("{OTHER}/form")),
            source_origin: Some(OTHER.to_owned()),
            ..click(4, "e-other")
        },
    ];
    let got = draft_from_steps(&input, &steps, &page).expect("redirects draft with their context");

    assert_eq!(got.origin.as_deref(), Some(OTHER));
    assert_eq!(got.site.as_deref(), Some("shop.example:0443"));
    assert_steps(
        &got,
        json!([
            {"step":"open", "url":opening_url},
            {"step":"open", "url":later_url},
            {"step":"click", "ref":"e-third"},
            {"step":"click", "ref":"e-other"},
        ]),
    );
    let foreign = |origin: &str| DraftGapKind::ForeignOrigin {
        origin: Some(origin.to_owned()),
    };
    assert_eq!(
        got.gaps,
        [
            at(2, "open", foreign(THIRD)),
            at(3, "click", foreign(THIRD)),
            at(4, "click", foreign(SHOP))
        ]
    );
    assert!(!got.complete);
}

#[test]
fn only_replayable_steps_check_context_and_a_rejected_step_can_switch_the_front_tab() {
    use DraftGapKind::{MissingContext, NoAction, TabChange};

    let steps = [
        open(1, SHOP),
        DraftStep {
            tab: None,
            result_tab: Some("second".to_owned()),
            source_url: None,
            source_origin: None,
            ..step(2, "switch", Err(NoAction))
        },
        DraftStep {
            tab: Some("second".to_owned()),
            result_tab: None,
            source_url: None,
            source_origin: None,
            ..click(3, "e-second")
        },
        click(4, "e-main"),
        DraftStep {
            tab: None,
            ..click(5, "e-no-tab")
        },
        DraftStep {
            source_url: None,
            ..click(6, "e-no-source-url")
        },
    ];
    let got =
        draft_from_steps(&input(), &steps, &page()).expect("the tab history drafts with gaps");

    assert_steps(
        &got,
        json!([
            {"step":"open", "url":FORM},
            {"step":"click", "ref":"e-second"},
            {"step":"click", "ref":"e-main"},
            {"step":"click", "ref":"e-no-tab"},
            {"step":"click", "ref":"e-no-source-url"},
        ]),
    );
    assert_eq!(
        got.gaps,
        [
            at(2, "switch", NoAction),
            at(3, "click", MissingContext),
            at(4, "click", TabChange),
            at(5, "click", MissingContext),
        ]
    );
}
