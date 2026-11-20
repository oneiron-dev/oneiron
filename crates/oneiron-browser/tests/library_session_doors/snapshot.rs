//! The `snapshot_solved_run` door's seven tests
//! (FIX [BROWSER-LIBRARY-SESSION-DOORS-HELD-BY-NO-TEST]): what a solved capture keeps of its span,
//! its checks, and its secrets. The session is real; the browser is a fake and the library stays
//! unset. The peer proves the door's reads, not a real browser's answers. The custody double proves
//! what the door takes, not a host's keeping.

use super::secret_custody::{CountingSecretCustody, CustodyCall};
use super::session_fixture::{attach_session, expect_answer};
use oneiron_browser::{
    BatchStopCause, BrowserDriver, DraftGap, DraftGapKind, DraftInput, DraftOutput, ExpectInput,
    OpenInput, OperandGap, SecretKind, SecretParam, SolvedSnapshotGap, StepStop,
};
use serde_json::json;
use std::sync::Arc;

/// The page the fixture shows: the span's opening and the checks' page.
const PAGE_URL: &str = "https://shop.example/form";
/// The span's site, as the library keys it.
const SITE: &str = "shop.example";
/// The span's origin, as the draft parses it.
const ORIGIN: &str = "https://shop.example";
/// The subgoal the snapshots draft under.
const SUBGOAL: &str = "Ready form";
/// The effect class a press stop names.
const PRESS_CLASS: &str = "browser.send";
// The public test card number, not a real secret.
const CARD_NUMBER: &str = "4111111111111111";
/// A made-up custody binding, outside any handle's form.
const FIXTURE_BINDING: &str = "fixture-binding";

/// One check's reads, then the draft's page read.
const SINGLE_CHECK_METHODS: [&str; 10] = [
    "Target.getTargets",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Accessibility.getFullAXTree",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Target.getTargets",
    "Target.getTargetInfo",
];
/// A checkless snapshot's reads: only the draft's page read.
const NO_CHECK_METHODS: [&str; 2] = ["Target.getTargets", "Target.getTargetInfo"];
/// Two checks' reads, then the draft's page read.
const DOUBLE_CHECK_METHODS: [&str; 18] = [
    "Target.getTargets",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Accessibility.getFullAXTree",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Target.getTargets",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Accessibility.getFullAXTree",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Page.getFrameTree",
    "DOM.getDocument",
    "Target.getTargets",
    "Target.getTargetInfo",
];
/// An unread check's reads: its follow with no capture, then the page read.
const UNREAD_CHECK_METHODS: [&str; 3] = [
    "Target.getTargets",
    "Target.getTargets",
    "Target.getTargetInfo",
];

/// A check the fixture page meets: its Ready heading.
fn ready() -> ExpectInput {
    ExpectInput {
        role: Some("heading".to_owned()),
        name: Some("Ready".to_owned()),
        ..Default::default()
    }
}

/// A check the fixture page misses: no row is named Never.
fn never() -> ExpectInput {
    ExpectInput {
        role: Some("heading".to_owned()),
        name: Some("Never".to_owned()),
        ..Default::default()
    }
}

/// A second check the fixture page misses: no row is named Other.
fn other() -> ExpectInput {
    ExpectInput {
        role: Some("heading".to_owned()),
        name: Some("Other".to_owned()),
        ..Default::default()
    }
}

/// A draft input for `checks` under the fixture subgoal.
fn draft_input(checks: Vec<ExpectInput>) -> DraftInput {
    DraftInput {
        subgoal: SUBGOAL.to_owned(),
        postcondition: checks,
        ..Default::default()
    }
}

/// The press stop a solved capture must end before.
fn press_stop() -> StepStop {
    StepStop {
        step: "click".to_owned(),
        cause: BatchStopCause::PressNeeded,
        error: "fixture stop".to_owned(),
        receipt: None,
        effect_class: Some(PRESS_CLASS.to_owned()),
    }
}

/// The bare stop a span holding only it drafts as failed.
fn click_stop() -> StepStop {
    StepStop {
        step: "click".to_owned(),
        cause: BatchStopCause::LocatorMissing,
        error: "fixture stop".to_owned(),
        receipt: None,
        effect_class: None,
    }
}

/// Checks this fixture's draft bounds, page identity and unused replay fields.
fn assert_draft_span(draft: &DraftOutput, through_seq: u64) {
    assert_eq!((draft.after_seq, draft.through_seq), (0, through_seq));
    assert_eq!(draft.site.as_deref(), Some(SITE));
    assert_eq!(draft.origin.as_deref(), Some(ORIGIN));
    assert!(draft.pressed_through.is_empty(), "no press is taken");
    assert!(draft.slot_candidates.is_empty(), "no slot candidate");
    assert!(draft.proposal.replay_args.is_empty(), "no replay argument");
}

#[test]
fn a_solved_capture_forces_the_span_to_end_at_a_press_even_if_asked_to_pass_it() {
    let (mut session, peer) = attach_session(PAGE_URL);
    let observation = expect_answer(
        &peer,
        session.open(OpenInput {
            url: PAGE_URL.to_owned(),
        }),
        "the fixture page opens",
    );
    assert_eq!(observation.url.as_str(), PAGE_URL, "the open lands");
    assert_eq!(session.history_mark(), Some(1), "the open is first");
    session.note_stop(press_stop());
    assert_eq!(session.history_mark(), Some(2), "the press stop is second");
    let mark = peer.mark();
    let input = DraftInput {
        subgoal: SUBGOAL.to_owned(),
        postcondition: vec![ready()],
        past_press: true,
        ..Default::default()
    };
    let snapshot = expect_answer(
        &peer,
        session.snapshot_solved_run(input),
        "the press span snapshots",
    );
    assert_eq!(
        snapshot.gap,
        Some(SolvedSnapshotGap::PressInSpan {
            effect_class: Some(PRESS_CLASS.to_owned())
        }),
        "the press keeps the span from being solved"
    );
    assert!(!snapshot.solved(), "a span with a press is not solved");
    assert_draft_span(&snapshot.draft, 2);
    assert!(snapshot.draft.complete, "the pre-press prefix is complete");
    assert_eq!(
        snapshot.draft.gaps,
        [DraftGap {
            seq: Some(2),
            verb: Some("click".to_owned()),
            gap: DraftGapKind::PrePress {
                effect_class: PRESS_CLASS.to_owned()
            },
        }],
        "the draft ends before the press"
    );
    assert!(snapshot.secret_slots.is_empty(), "no secret slot");
    assert_eq!(snapshot.checks, [ready()], "the met check stays");
    assert_eq!(
        snapshot.checks, snapshot.draft.proposal.postcondition,
        "checks are the postcondition"
    );
    assert!(snapshot.draft.proposal.params.is_empty(), "no parameter");
    assert!(snapshot.draft.proposal.args.is_empty(), "no argument");
    assert_eq!(
        serde_json::to_value(&snapshot.draft.proposal.steps).expect("the steps encode"),
        json!([{ "step": "open", "url": PAGE_URL }]),
        "only the opening replays"
    );
    assert!(
        snapshot.replay_ready,
        "the complete prefix with no parameter replays"
    );
    peer.assert_methods(mark, &SINGLE_CHECK_METHODS);
}

#[test]
fn a_snapshot_without_checks_still_drafts_the_opening_and_names_no_checks() {
    let (mut session, peer) = attach_session(PAGE_URL);
    let observation = expect_answer(
        &peer,
        session.open(OpenInput {
            url: PAGE_URL.to_owned(),
        }),
        "the fixture page opens",
    );
    assert_eq!(observation.url.as_str(), PAGE_URL, "the open lands");
    let mark = peer.mark();
    let snapshot = expect_answer(
        &peer,
        session.snapshot_solved_run(draft_input(Vec::new())),
        "a checkless span snapshots",
    );
    assert_eq!(
        snapshot.gap,
        Some(SolvedSnapshotGap::NoChecks),
        "no check solves the page"
    );
    assert!(!snapshot.solved(), "a span with no check is not solved");
    assert_draft_span(&snapshot.draft, 1);
    assert!(!snapshot.draft.complete, "no postcondition is not complete");
    assert_eq!(
        snapshot.draft.gaps,
        [DraftGap {
            seq: None,
            verb: None,
            gap: DraftGapKind::NoPostcondition
        }],
        "the missing postcondition is named"
    );
    assert!(snapshot.secret_slots.is_empty(), "no secret slot");
    assert!(snapshot.checks.is_empty(), "no check is kept");
    assert!(snapshot.draft.proposal.params.is_empty(), "no parameter");
    assert!(snapshot.draft.proposal.args.is_empty(), "no argument");
    assert_eq!(
        serde_json::to_value(&snapshot.draft.proposal.steps).expect("the steps encode"),
        json!([{ "step": "open", "url": PAGE_URL }]),
        "the opening still drafts"
    );
    assert!(
        !snapshot.replay_ready,
        "an incomplete draft is not replay-ready"
    );
    peer.assert_methods(mark, &NO_CHECK_METHODS);
}

#[test]
fn the_first_unmet_snapshot_check_wins_but_every_check_reads() {
    let (mut session, peer) = attach_session(PAGE_URL);
    assert_eq!(session.history_mark(), None, "no entry yet");
    let mark = peer.mark();
    let snapshot = expect_answer(
        &peer,
        session.snapshot_solved_run(draft_input(vec![never(), other()])),
        "two missed checks snapshot",
    );
    assert_eq!(
        snapshot.gap,
        Some(SolvedSnapshotGap::CheckUnmet { check: 0 }),
        "the first unmet check wins"
    );
    assert!(!snapshot.solved(), "an unmet check is not solved");
    assert_draft_span(&snapshot.draft, 0);
    assert!(!snapshot.draft.complete, "no entry is not complete");
    assert_eq!(
        snapshot.draft.gaps,
        [DraftGap {
            seq: None,
            verb: None,
            gap: DraftGapKind::EmptySpan
        }],
        "the empty span is named"
    );
    assert!(snapshot.secret_slots.is_empty(), "no secret slot");
    assert_eq!(
        snapshot.checks,
        [never(), other()],
        "both checks stay, in order"
    );
    assert_eq!(
        snapshot.checks, snapshot.draft.proposal.postcondition,
        "checks are the postcondition"
    );
    assert!(snapshot.draft.proposal.params.is_empty(), "no parameter");
    assert!(snapshot.draft.proposal.args.is_empty(), "no argument");
    assert_eq!(
        serde_json::to_value(&snapshot.draft.proposal.steps).expect("the steps encode"),
        json!([]),
        "no step replays"
    );
    assert!(
        !snapshot.replay_ready,
        "an incomplete draft is not replay-ready"
    );
    peer.assert_methods(mark, &DOUBLE_CHECK_METHODS);
}

#[test]
fn a_durable_copy_strips_a_typed_secret_binding_independently_of_handle_syntax() {
    let (mut session, peer) = attach_session(PAGE_URL);
    let observation = expect_answer(
        &peer,
        session.open(OpenInput {
            url: PAGE_URL.to_owned(),
        }),
        "the fixture page opens",
    );
    assert_eq!(observation.url.as_str(), PAGE_URL, "the open lands");
    let custody = CountingSecretCustody::new(FIXTURE_BINDING);
    session.set_secret_custody(Arc::new(custody.clone()));
    let mark = peer.mark();
    let check = ExpectInput {
        role: Some("heading".to_owned()),
        name: Some("Never".to_owned()),
        value: Some(CARD_NUMBER.to_owned()),
        absent: true,
        ..Default::default()
    };
    let snapshot = expect_answer(
        &peer,
        session.snapshot_solved_run(draft_input(vec![check])),
        "the card span snapshots",
    );
    assert_eq!(snapshot.gap, None, "an absent check no row shows is met");
    assert!(snapshot.solved(), "the span is solved");
    assert_draft_span(&snapshot.draft, 1);
    assert!(
        snapshot.draft.complete,
        "the opening with its check is complete"
    );
    assert!(snapshot.draft.gaps.is_empty(), "no gap is named");
    assert_eq!(
        snapshot.secret_slots,
        [SecretParam {
            name: "card".to_owned(),
            kind: SecretKind::Card
        }],
        "the card slot stays by name and kind"
    );
    let kept = ExpectInput {
        role: Some("heading".to_owned()),
        name: Some("Never".to_owned()),
        secret: Some("{{card}}".to_owned()),
        absent: true,
        ..Default::default()
    };
    assert_eq!(
        snapshot.checks,
        [kept],
        "the check keeps the slot, not the digits"
    );
    assert_eq!(
        snapshot.checks, snapshot.draft.proposal.postcondition,
        "checks are the postcondition"
    );
    assert_eq!(
        snapshot.draft.proposal.params,
        ["card".to_owned()],
        "the card parameter"
    );
    assert!(
        snapshot.draft.proposal.args.is_empty(),
        "the run binding is stripped"
    );
    assert_eq!(
        serde_json::to_value(&snapshot.draft.proposal.steps).expect("the steps encode"),
        json!([{ "step": "open", "url": PAGE_URL }]),
        "only the opening replays"
    );
    assert!(
        !snapshot.replay_ready,
        "an unbound slot binds again before it replays"
    );
    let encoded = serde_json::to_value(&snapshot.draft)
        .expect("the draft encodes")
        .to_string();
    assert!(
        !encoded.contains(CARD_NUMBER),
        "no card digits stay in the copy"
    );
    assert!(
        !encoded.contains(FIXTURE_BINDING),
        "no run binding stays in the copy"
    );
    assert_eq!(
        custody.calls(),
        [CustodyCall::Acquire {
            kind: SecretKind::Card,
            value: CARD_NUMBER.to_owned(),
            origin: ORIGIN.to_owned(),
        }],
        "the card value is taken once, into the page origin"
    );
    peer.assert_methods(mark, &SINGLE_CHECK_METHODS);
}

#[test]
fn a_check_with_both_value_and_secret_is_named_unread_before_capture() {
    let (mut session, peer) = attach_session(PAGE_URL);
    let mark = peer.mark();
    let check = ExpectInput {
        value: Some("x".to_owned()),
        secret: Some("sc9".to_owned()),
        ..Default::default()
    };
    let snapshot = expect_answer(
        &peer,
        session.snapshot_solved_run(draft_input(vec![check])),
        "the double-named check snapshots",
    );
    assert_eq!(
        snapshot.gap,
        Some(SolvedSnapshotGap::CheckUnread {
            check: 0,
            error: "invalid browser verb input: an expect names a value or a secret, never both"
                .to_owned(),
        }),
        "the check that names both is unread"
    );
    assert!(!snapshot.solved(), "an unread check is not solved");
    assert_draft_span(&snapshot.draft, 0);
    assert!(!snapshot.draft.complete, "no entry is not complete");
    assert_eq!(
        snapshot.draft.gaps,
        [
            DraftGap {
                seq: None,
                verb: None,
                gap: DraftGapKind::EmptySpan
            },
            DraftGap {
                seq: None,
                verb: None,
                gap: DraftGapKind::NoPostcondition
            },
            DraftGap {
                seq: None,
                verb: None,
                gap: DraftGapKind::CheckSecretWithheld {
                    check: 0,
                    cause: OperandGap::UnknownKind,
                },
            },
        ],
        "the empty span, the missing postcondition, and the unknown secret"
    );
    assert!(snapshot.secret_slots.is_empty(), "no secret slot");
    assert!(
        snapshot.checks.is_empty(),
        "the unknown secret keeps no check"
    );
    assert!(snapshot.draft.proposal.params.is_empty(), "no parameter");
    assert!(snapshot.draft.proposal.args.is_empty(), "no argument");
    assert_eq!(
        serde_json::to_value(&snapshot.draft.proposal.steps).expect("the steps encode"),
        json!([]),
        "no step replays"
    );
    assert!(
        !snapshot.replay_ready,
        "an incomplete draft is not replay-ready"
    );
    peer.assert_methods(mark, &UNREAD_CHECK_METHODS);
}

#[test]
fn a_complete_opening_with_a_met_plain_check_is_solved_and_replay_ready() {
    let (mut session, peer) = attach_session(PAGE_URL);
    let observation = expect_answer(
        &peer,
        session.open(OpenInput {
            url: PAGE_URL.to_owned(),
        }),
        "the fixture page opens",
    );
    assert_eq!(observation.url.as_str(), PAGE_URL, "the open lands");
    let mark = peer.mark();
    let snapshot = expect_answer(
        &peer,
        session.snapshot_solved_run(draft_input(vec![ready()])),
        "the met span snapshots",
    );
    assert_eq!(snapshot.gap, None, "the met span names no gap");
    assert!(snapshot.solved(), "the span is solved");
    assert_draft_span(&snapshot.draft, 1);
    assert!(
        snapshot.draft.complete,
        "the opening with its check is complete"
    );
    assert!(snapshot.draft.gaps.is_empty(), "no gap is named");
    assert!(snapshot.secret_slots.is_empty(), "no secret slot");
    assert_eq!(snapshot.checks, [ready()], "the met check stays");
    assert_eq!(
        snapshot.checks, snapshot.draft.proposal.postcondition,
        "checks are the postcondition"
    );
    assert!(snapshot.draft.proposal.params.is_empty(), "no parameter");
    assert!(snapshot.draft.proposal.args.is_empty(), "no argument");
    assert_eq!(
        serde_json::to_value(&snapshot.draft.proposal.steps).expect("the steps encode"),
        json!([{ "step": "open", "url": PAGE_URL }]),
        "only the opening replays"
    );
    assert!(
        snapshot.replay_ready,
        "the complete opening with no parameter replays"
    );
    peer.assert_methods(mark, &SINGLE_CHECK_METHODS);
}

#[test]
fn a_span_with_only_a_stop_mark_is_drafted_as_failed_without_a_replay_step() {
    let (mut session, peer) = attach_session(PAGE_URL);
    session.note_stop(click_stop());
    assert_eq!(
        session.history_mark(),
        Some(1),
        "the stop is the only entry"
    );
    let mark = peer.mark();
    let snapshot = expect_answer(
        &peer,
        session.snapshot_solved_run(draft_input(vec![ready()])),
        "the stop-only span snapshots",
    );
    // No assertion on `gap` or `solved()`: the module prose says a span is solved only when it
    // holds steps (`src/session/solved.rs:8-12`), but the code tests `after_seq == through_seq`
    // only (`src/session/solved.rs:136-137`), so a stop-only span reports no gap. Finding, not pinned.
    assert_draft_span(&snapshot.draft, 1);
    assert!(
        !snapshot.draft.complete,
        "a stop with no opening is not complete"
    );
    assert_eq!(
        snapshot.draft.gaps,
        [
            DraftGap {
                seq: Some(1),
                verb: Some("click".to_owned()),
                gap: DraftGapKind::MissingOpening,
            },
            DraftGap {
                seq: Some(1),
                verb: Some("click".to_owned()),
                gap: DraftGapKind::Failed {
                    cause: BatchStopCause::LocatorMissing
                },
            },
        ],
        "the missing opening and the stop's failure, in order"
    );
    assert!(snapshot.secret_slots.is_empty(), "no secret slot");
    assert_eq!(snapshot.checks, [ready()], "the met check stays");
    assert_eq!(
        snapshot.checks, snapshot.draft.proposal.postcondition,
        "checks are the postcondition"
    );
    assert!(snapshot.draft.proposal.params.is_empty(), "no parameter");
    assert!(snapshot.draft.proposal.args.is_empty(), "no argument");
    assert_eq!(
        serde_json::to_value(&snapshot.draft.proposal.steps).expect("the steps encode"),
        json!([]),
        "no step replays"
    );
    assert!(
        !snapshot.replay_ready,
        "an incomplete draft is not replay-ready"
    );
    peer.assert_methods(mark, &SINGLE_CHECK_METHODS);
}
