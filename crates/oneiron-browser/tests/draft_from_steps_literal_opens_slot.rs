//! These tests cover FIX [BROWSER-DRAFT-LITERAL-TEXT-WITH-SLOT-BRACES-READS-AS-A-SLOT].
//! Drafts keep recorded text that opens a slot, but report that replay needs a parameter.

use oneiron_browser::{
    BatchStep, BrowserError, DraftGap, DraftGapKind, DraftInput, DraftOutcome, DraftOutput,
    DraftPage, DraftStep, ExpectInput, FieldSpec, ReplayAction, SecretKind, TextReference,
    TypeOperand, WorkflowProgram, draft_from_steps,
};
use serde_json::{Value, json};

const SHOP: &str = "https://shop.example";
const FORM: &str = "https://shop.example/form";
const GREETING: &str = "Dear {{first_name}},";
const GREETING_LOCATOR: &str = "e-greeting";

/// A subgoal and an ordinary postcondition with no live handles or slots.
fn input() -> DraftInput {
    DraftInput {
        subgoal: "Fill the form".to_owned(),
        postcondition: vec![ExpectInput {
            role: Some("heading".to_owned()),
            name: Some("Ready".to_owned()),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// The shop page in front at the end of the span.
fn page() -> DraftPage {
    DraftPage {
        url: FORM.to_owned(),
        origin: Some(SHOP.to_owned()),
        ..Default::default()
    }
}

/// A successful entry that stays on the shop page in the same tab.
fn step(seq: u64, verb: &str, action: ReplayAction) -> DraftStep {
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
        action: Ok(action),
        outcome: DraftOutcome::Ok,
    }
}

/// An opening on the shop origin with the requested URL as recorded.
fn open(seq: u64, url: &str) -> DraftStep {
    DraftStep {
        source_url: None,
        source_origin: None,
        requested_origin: Some(SHOP.to_owned()),
        result_url: url.to_owned(),
        ..step(
            seq,
            "open",
            ReplayAction::Open {
                url: url.to_owned(),
            },
        )
    }
}

/// A click at its recorded locator.
fn click(seq: u64, locator: &str) -> DraftStep {
    step(
        seq,
        "click",
        ReplayAction::Click {
            locator: locator.to_owned(),
        },
    )
}

/// A type with its recorded locator and operand.
fn type_at(seq: u64, locator: &str, operand: TypeOperand) -> DraftStep {
    step(
        seq,
        "type",
        ReplayAction::Type {
            locator: locator.to_owned(),
            operand,
            clear: true,
        },
    )
}

/// A type that entered literal text.
fn literal(seq: u64, locator: &str, text: &str) -> DraftStep {
    type_at(
        seq,
        locator,
        TypeOperand::Literal {
            text: text.to_owned(),
        },
    )
}

/// A Fill with the field it recorded.
fn fill(seq: u64, field: FieldSpec) -> DraftStep {
    step(
        seq,
        "fill",
        ReplayAction::Fill {
            locator: "e-fill".to_owned(),
            field,
        },
    )
}

/// The literal-slot-opening gap at a history entry.
fn at(seq: u64, verb: &str) -> DraftGap {
    DraftGap {
        seq: Some(seq),
        verb: Some(verb.to_owned()),
        gap: DraftGapKind::LiteralOpensSlot,
    }
}

/// The same greeting draft for the gap and repair tests.
fn greeting_draft() -> DraftOutput {
    let typed = DraftStep {
        target_name: Some("Greeting message".to_owned()),
        ..literal(4, GREETING_LOCATOR, GREETING)
    };
    draft_from_steps(&input(), &[open(1, FORM), typed], &page()).expect("the greeting drafts")
}

/// Compares batch steps by their whole serialized values.
fn assert_steps(steps: &[BatchStep], expected: Value) {
    let serialized = serde_json::to_value(steps).expect("batch steps serialize");
    assert_eq!(serialized, expected);
}

/// Checks that the full greeting batch contains the original text.
fn assert_greeting_steps(steps: &[BatchStep]) {
    assert_steps(
        steps,
        json!([
            {"step":"open", "url":FORM},
            {"step":"type", "ref":GREETING_LOCATOR, "text":GREETING, "clear":true},
        ]),
    );
}

/// Checks the whole candidate list, including each candidate's wire field name.
fn assert_candidates(draft: &DraftOutput, expected: Value) {
    let serialized =
        serde_json::to_value(&draft.slot_candidates).expect("slot candidates serialize");
    assert_eq!(serialized, expected);
}

/// Checks the greeting draft and its one candidate before any repair.
fn assert_greeting_draft(draft: &DraftOutput) {
    assert_eq!(draft.gaps, [at(4, "type")]);
    assert!(!draft.complete);
    assert_greeting_steps(&draft.proposal.steps);
    assert_candidates(
        draft,
        json!([
            {"step":1, "seq":4, "field":"text", "literal":GREETING, "suggested_param":"greeting_message"},
        ]),
    );
}

#[test]
fn a_typed_slot_literal_is_flagged_and_kept_with_its_candidate() {
    assert_greeting_draft(&greeting_draft());
}

#[test]
fn a_select_option_that_opens_a_slot_is_flagged_and_kept_with_its_candidate() {
    let option = "Choose {{size}}";
    let select = step(
        2,
        "select",
        ReplayAction::Select {
            locator: "e-size".to_owned(),
            option: option.to_owned(),
        },
    );
    let draft = draft_from_steps(&input(), &[open(1, FORM), select], &page())
        .expect("the select drafts even with a gap");
    assert_eq!(draft.gaps, [at(2, "select")]);
    assert!(!draft.complete);
    assert_steps(
        &draft.proposal.steps,
        json!([
            {"step":"open", "url":FORM},
            {"step":"select", "ref":"e-size", "option":option},
        ]),
    );
    assert_candidates(
        &draft,
        json!([
            {"step":1, "seq":2, "field":"option", "literal":option, "suggested_param":"option"},
        ]),
    );
}

#[test]
fn a_slot_in_the_opening_query_is_flagged_without_losing_the_url_or_site() {
    let url = "https://shop.example/form?search={{term}}";
    let draft = draft_from_steps(&input(), &[open(7, url)], &page())
        .expect("the opening query drafts even with a gap");
    assert_eq!(draft.gaps, [at(7, "open")]);
    assert!(!draft.complete);
    assert_eq!(draft.site.as_deref(), Some("shop.example"));
    assert_steps(&draft.proposal.steps, json!([{"step":"open", "url":url}]));
}

#[test]
fn a_click_locator_that_opens_a_slot_is_flagged_and_kept() {
    let locator = "e-review-{{item}}";
    let draft = draft_from_steps(&input(), &[open(1, FORM), click(2, locator)], &page())
        .expect("the click locator drafts even with a gap");
    assert_eq!(draft.gaps, [at(2, "click")]);
    assert!(!draft.complete);
    assert_steps(
        &draft.proposal.steps,
        json!([{"step":"open", "url":FORM}, {"step":"click", "ref":locator}]),
    );
}

#[test]
fn a_fill_field_that_opens_a_slot_is_flagged_and_kept() {
    let text = "Answer {{detail}}";
    let supplied = "Recorded answer";
    let cases = [
        (
            FieldSpec {
                supplied: Some(text.to_owned()),
                ..Default::default()
            },
            json!({"supplied":text}),
        ),
        (
            FieldSpec {
                references: vec![TextReference {
                    id: "answer".to_owned(),
                    text: text.to_owned(),
                }],
                ..Default::default()
            },
            json!({"references":[{"id":"answer", "text":text}]}),
        ),
        (
            FieldSpec {
                supplied: Some(supplied.to_owned()),
                template: Some(text.to_owned()),
                ..Default::default()
            },
            json!({"supplied":supplied, "template":text}),
        ),
        (
            FieldSpec {
                supplied: Some(supplied.to_owned()),
                instruction: Some(text.to_owned()),
                ..Default::default()
            },
            json!({"supplied":supplied, "instruction":text}),
        ),
    ];
    for (field, expected) in cases {
        let draft = draft_from_steps(&input(), &[open(1, FORM), fill(2, field)], &page())
            .expect("the field drafts even with a gap");
        assert_eq!(draft.gaps, [at(2, "fill")], "field: {expected}");
        assert!(!draft.complete);
        assert_steps(
            &draft.proposal.steps,
            json!([
                {"step":"open", "url":FORM},
                {"step":"fill", "ref":"e-fill", "field":expected},
            ]),
        );
    }
}

#[test]
fn an_unclosed_slot_opening_is_flagged_and_kept() {
    let text = "Total {{ due";
    let draft = draft_from_steps(
        &input(),
        &[open(1, FORM), literal(2, "e-total", text)],
        &page(),
    )
    .expect("the unclosed opening drafts even with a gap");
    assert_eq!(draft.gaps, [at(2, "type")]);
    assert!(!draft.complete);
    assert_steps(
        &draft.proposal.steps,
        json!([
            {"step":"open", "url":FORM},
            {"step":"type", "ref":"e-total", "text":text, "clear":true},
        ]),
    );
}

#[test]
fn two_slot_openings_in_one_entry_give_it_one_gap() {
    let locator = "e-message-{{field}}";
    let text = "Message {{body}}";
    let draft = draft_from_steps(
        &input(),
        &[open(1, FORM), literal(2, locator, text)],
        &page(),
    )
    .expect("the entry with two openings drafts");
    assert_eq!(draft.gaps, [at(2, "type")]);
    assert!(!draft.complete);
    assert_steps(
        &draft.proposal.steps,
        json!([
            {"step":"open", "url":FORM},
            {"step":"type", "ref":locator, "text":text, "clear":true},
        ]),
    );
}

#[test]
fn brace_text_without_a_slot_opening_leaves_the_draft_complete() {
    for text in ["{", "}}", "{ {", r#"{"a":{"b":1}}"#] {
        let draft = draft_from_steps(
            &input(),
            &[open(1, FORM), literal(2, "e-note", text)],
            &page(),
        )
        .expect("ordinary brace text drafts unchanged");
        assert!(draft.gaps.is_empty(), "text {text:?}: {:?}", draft.gaps);
        assert!(draft.complete);
        assert_steps(
            &draft.proposal.steps,
            json!([
                {"step":"open", "url":FORM},
                {"step":"type", "ref":"e-note", "text":text, "clear":true},
            ]),
        );
    }
}

#[test]
fn a_secret_slot_written_by_the_draft_leaves_it_complete() {
    let typed = type_at(
        2,
        "e-password",
        TypeOperand::Secret {
            kind: SecretKind::Password,
            handle: "sc7".to_owned(),
        },
    );
    let draft = draft_from_steps(&input(), &[open(1, FORM), typed], &page())
        .expect("the known secret operand drafts as a slot");
    assert!(draft.gaps.is_empty());
    assert!(draft.complete);
    assert!(draft.slot_candidates.is_empty());
    assert_eq!(draft.proposal.params, ["password"]);
    assert_steps(
        &draft.proposal.steps,
        json!([
            {"step":"open", "url":FORM},
            {"step":"type", "ref":"e-password", "secret":"{{password}}", "clear":true},
        ]),
    );
}

#[test]
fn the_literal_opens_slot_gap_has_a_stable_wire_form() {
    let gap = at(4, "type");
    let wire = json!({"seq":4, "verb":"type", "gap":{"why":"literal_opens_slot"}});
    assert_eq!(
        serde_json::to_value(&gap).expect("the gap serializes"),
        wire
    );
    let decoded: DraftGap = serde_json::from_value(wire).expect("the wire gap decodes");
    assert_eq!(decoded, gap);
}

#[test]
fn the_flagged_literal_cannot_fill_until_it_is_bound_as_an_argument() {
    let draft = greeting_draft();
    assert_greeting_draft(&draft);

    let mut program = WorkflowProgram {
        subgoal: draft.proposal.subgoal,
        params: draft.proposal.params,
        secret_params: Vec::new(),
        steps: draft.proposal.steps,
        postcondition: draft.proposal.postcondition,
    };
    let mut args = draft.proposal.args;
    assert_eq!(
        program
            .fill(&args)
            .expect_err("the recorded slot is not a parameter"),
        BrowserError::Input("slot {{first_name}} is no parameter".to_owned()),
    );
    let candidate = draft
        .slot_candidates
        .into_iter()
        .next()
        .expect("the typed literal has a candidate");
    let BatchStep::Type { text, .. } = &mut program.steps[candidate.step] else {
        panic!("the candidate points to the type step");
    };
    let name = candidate.suggested_param;
    *text = Some(format!("{{{{{name}}}}}"));
    program.params.push(name.clone());
    args.insert(name, candidate.literal);

    let (filled_steps, _) = program
        .fill(&args)
        .expect("the argument is inserted without another fill");
    assert_greeting_steps(&filled_steps);
}

#[test]
fn only_the_entries_that_open_slots_get_gaps_in_history_order() {
    let locator = "e-review-{{item}}";
    let text = "Note {{detail}}";
    let steps = [
        open(1, FORM),
        click(3, locator),
        literal(7, "e-note", text),
        click(9, "e-save"),
    ];
    let draft =
        draft_from_steps(&input(), &steps, &page()).expect("the span drafts around its gaps");
    assert_eq!(draft.gaps, [at(3, "click"), at(7, "type")]);
    assert!(!draft.complete);
    assert_steps(
        &draft.proposal.steps,
        json!([
            {"step":"open", "url":FORM},
            {"step":"click", "ref":locator},
            {"step":"type", "ref":"e-note", "text":text, "clear":true},
            {"step":"click", "ref":"e-save"},
        ]),
    );
}
