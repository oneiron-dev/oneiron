//! The `library_draft` door's five tests
//! (FIX [BROWSER-LIBRARY-SESSION-DOORS-HELD-BY-NO-TEST]): a minted check keeps
//! its row's locator, a plain value on a secret field binds through custody, an
//! unknown secret is dropped with its own gap, and stops draft as failed without
//! inventing replay steps. The session is real; the browser is a fake, the library
//! stays unset, and the door sends only the live page read. Secrets here are
//! fabricated: a made-up passphrase and a made-up custody binding.

use super::secret_custody::{CountingSecretCustody, CustodyCall};
use super::session_fixture::{attach_session, expect_answer};
use oneiron_browser::{
    BatchStep, BatchStopCause, BrowserDriver, DraftGap, DraftGapKind, DraftInput, ExpectInput,
    ObserveInput, OpenInput, OperandGap, SecretKind, StepStop, is_live_handle,
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The fixture page every draft here leaves open.
const PAGE_URL: &str = "https://shop.example/form";

/// The origin of [`PAGE_URL`], as a draft keeps it.
const ORIGIN: &str = "https://shop.example";

/// A check the fixture page meets: its Ready heading.
fn ready() -> ExpectInput {
    ExpectInput {
        role: Some("heading".to_owned()),
        name: Some("Ready".to_owned()),
        ..Default::default()
    }
}

/// A draft of `postcondition` for the Ready form.
fn draft_input(postcondition: Vec<ExpectInput>) -> DraftInput {
    DraftInput {
        subgoal: "Ready form".to_owned(),
        postcondition,
        ..Default::default()
    }
}

/// A stop the session notes, on the census's form: a click that found no row.
fn click_stop(receipt: Option<u64>) -> StepStop {
    StepStop {
        step: "click".to_owned(),
        cause: BatchStopCause::LocatorMissing,
        error: "fixture stop".to_owned(),
        receipt,
        effect_class: None,
    }
}

#[test]
fn a_draft_keeps_a_minted_checks_locator_without_reading_the_check() {
    let (mut session, peer) = attach_session(PAGE_URL);
    let observed = expect_answer(
        &peer,
        session.observe(ObserveInput::default()),
        "the fixture page reads",
    );
    let row = observed
        .rows
        .first()
        .expect("the fixture page shows its heading");
    assert_eq!(row.name, "Ready", "the setup mints the Ready row");
    let handle = row.target.clone();
    let locator = row.locator.clone();
    assert!(
        is_live_handle(&handle),
        "the minted ref has a live handle's form"
    );
    assert!(
        is_live_handle("h00000000:999"),
        "the unknown ref has a live handle's form"
    );
    assert!(
        session.handle_info("h00000000:999").is_none(),
        "the unknown ref was never minted"
    );
    let mark = peer.mark();
    let output = expect_answer(
        &peer,
        session.library_draft(draft_input(vec![
            ExpectInput {
                target: Some(handle),
                ..Default::default()
            },
            ExpectInput {
                target: Some("h00000000:999".to_owned()),
                ..Default::default()
            },
        ])),
        "a draft with one minted and one unknown ref answers",
    );
    assert_eq!(output.after_seq, 0, "an empty trail starts at zero");
    assert_eq!(output.through_seq, 0, "an empty trail ends at zero");
    assert_eq!(
        output.site,
        Some("shop.example".to_owned()),
        "the open page names the site"
    );
    assert_eq!(
        output.origin,
        Some(ORIGIN.to_owned()),
        "the open page names the origin"
    );
    assert!(
        !output.complete,
        "a draft that drops a check is not complete"
    );
    assert!(
        output.proposal.steps.is_empty(),
        "an empty trail proposes no step"
    );
    assert_eq!(
        output.proposal.postcondition,
        [ExpectInput {
            target: Some(locator),
            ..Default::default()
        }],
        "the minted check keeps its row's locator"
    );
    assert!(
        output.proposal.params.is_empty(),
        "no secret names a parameter"
    );
    assert!(output.proposal.args.is_empty(), "no secret binds a value");
    assert!(
        output.slot_candidates.is_empty(),
        "no literal stands for a slot"
    );
    assert!(
        output.pressed_through.is_empty(),
        "no press stands to take past"
    );
    assert_eq!(
        output.gaps,
        [
            DraftGap {
                seq: None,
                verb: None,
                gap: DraftGapKind::EmptySpan,
            },
            DraftGap {
                seq: None,
                verb: None,
                gap: DraftGapKind::CheckUnknownRef { check: 1 },
            },
        ],
        "the empty span, then the unknown ref at its own index"
    );
    peer.assert_methods(mark, &["Target.getTargets", "Target.getTargetInfo"]);
}

#[test]
fn a_plain_secret_field_check_is_bound_through_custody_without_rechecking_the_page() {
    let (mut session, peer) = attach_session(PAGE_URL);
    peer.show_password_field();
    let observed = expect_answer(
        &peer,
        session.observe(ObserveInput::default()),
        "the page with a password field reads",
    );
    let row = observed
        .rows
        .iter()
        .find(|row| {
            row.secret
                .as_ref()
                .is_some_and(|secret| secret.kind == SecretKind::Password)
        })
        .expect("the setup mints the password row");
    let handle = row.target.clone();
    let locator = row.locator.clone();
    assert!(
        is_live_handle(&handle),
        "the password ref has a live handle's form"
    );
    let custody = CountingSecretCustody::new("sc7");
    session.set_secret_custody(Arc::new(custody.clone()));
    let mark = peer.mark();
    let output = expect_answer(
        &peer,
        session.library_draft(draft_input(vec![ExpectInput {
            target: Some(handle),
            value: Some("fixture-passphrase".to_owned()),
            ..Default::default()
        }])),
        "a plain value on a secret field drafts",
    );
    assert_eq!(
        custody.calls(),
        [CustodyCall::Acquire {
            kind: SecretKind::Password,
            value: "fixture-passphrase".to_owned(),
            origin: ORIGIN.to_owned(),
        }],
        "the exact passphrase binds once, through custody alone"
    );
    assert_eq!(
        output.proposal.params,
        vec!["password".to_owned()],
        "the secret names its password slot"
    );
    assert_eq!(
        output.proposal.args,
        BTreeMap::from([("password".to_owned(), "sc7".to_owned())]),
        "the slot binds the custody handle"
    );
    assert!(
        output.proposal.replay_args.is_empty(),
        "a draft holds no replay value"
    );
    assert_eq!(
        output.proposal.postcondition,
        [ExpectInput {
            target: Some(locator),
            secret: Some("{{password}}".to_owned()),
            ..Default::default()
        }],
        "the check keeps the locator and the slot, never the passphrase"
    );
    let proposal = serde_json::to_string(&output.proposal).expect("the proposal serializes");
    assert!(
        !proposal.contains("fixture-passphrase"),
        "no literal passphrase reaches the proposal: {proposal}"
    );
    assert!(!output.complete, "a draft over no step is not complete");
    assert_eq!(
        output.gaps,
        [DraftGap {
            seq: None,
            verb: None,
            gap: DraftGapKind::EmptySpan,
        }],
        "only the empty span keeps it from replaying"
    );
    peer.assert_methods(mark, &["Target.getTargets", "Target.getTargetInfo"]);
}

#[test]
fn an_unknown_secret_check_is_dropped_with_its_own_gap_and_index() {
    let (mut session, peer) = attach_session(PAGE_URL);
    let mark = peer.mark();
    let output = expect_answer(
        &peer,
        session.library_draft(draft_input(vec![
            ready(),
            ExpectInput {
                secret: Some("sc9".to_owned()),
                ..Default::default()
            },
        ])),
        "a draft with an unknown secret answers",
    );
    assert_eq!(
        output.proposal.postcondition,
        [ready()],
        "only the plain check survives"
    );
    assert!(
        output.proposal.params.is_empty(),
        "no secret names a parameter"
    );
    assert!(output.proposal.args.is_empty(), "no secret binds a value");
    assert!(
        !output.complete,
        "a draft that drops a check is not complete"
    );
    assert_eq!(
        output.gaps,
        [
            DraftGap {
                seq: None,
                verb: None,
                gap: DraftGapKind::EmptySpan,
            },
            DraftGap {
                seq: None,
                verb: None,
                gap: DraftGapKind::CheckSecretWithheld {
                    check: 1,
                    cause: OperandGap::UnknownKind,
                },
            },
        ],
        "the empty span, then the unknown secret at its own index"
    );
    peer.assert_methods(mark, &["Target.getTargets", "Target.getTargetInfo"]);
}

#[test]
fn an_effect_stop_mark_is_drafted_as_failed_without_inventing_a_replay_action() {
    let (mut session, peer) = attach_session(PAGE_URL);
    session.note_stop(click_stop(None));
    assert_eq!(
        session.history_mark(),
        Some(1),
        "the stop is the first entry"
    );
    let mark = peer.mark();
    let output = expect_answer(
        &peer,
        session.library_draft(draft_input(vec![ready()])),
        "a draft over one stop answers",
    );
    assert_eq!(output.after_seq, 0, "the span starts before the stop");
    assert_eq!(output.through_seq, 1, "the span ends with the stop");
    assert_eq!(
        output.site,
        Some("shop.example".to_owned()),
        "the open page names the site"
    );
    assert_eq!(
        output.origin,
        Some(ORIGIN.to_owned()),
        "the open page names the origin"
    );
    assert!(
        output.proposal.steps.is_empty(),
        "a stop invents no replay step"
    );
    assert_eq!(
        output.proposal.postcondition,
        [ready()],
        "the check survives the failed span"
    );
    assert!(!output.complete, "a failed span is not complete");
    assert_eq!(
        output.gaps,
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
                    cause: BatchStopCause::LocatorMissing,
                },
            },
        ],
        "no opening, then the stop's own failure, both at the stop"
    );
    peer.assert_methods(mark, &["Target.getTargets", "Target.getTargetInfo"]);
}

#[test]
fn a_stop_that_names_an_effect_marks_that_effect_failed_in_the_draft() {
    let (mut session, peer) = attach_session("about:blank");
    let opened = expect_answer(
        &peer,
        session.open(OpenInput {
            url: PAGE_URL.to_owned(),
        }),
        "the fixture page opens",
    );
    let landed = opened
        .receipt
        .as_ref()
        .expect("the open leaves its receipt")
        .seq;
    assert_eq!(landed, 1, "the open is the first entry");
    session.note_stop(click_stop(Some(landed)));
    assert_eq!(session.history_mark(), Some(2), "the stop follows the open");
    let mark = peer.mark();
    let output = expect_answer(
        &peer,
        session.library_draft(draft_input(vec![ready()])),
        "a draft over an open and its stop answers",
    );
    assert_eq!(output.after_seq, 0, "the span starts before the open");
    assert_eq!(output.through_seq, 2, "the span ends with the stop");
    assert_eq!(
        serde_json::to_value(&output.proposal.steps).expect("the proposed steps encode"),
        serde_json::to_value(&[BatchStep::Open {
            url: PAGE_URL.to_owned(),
        }])
        .expect("the opening encodes"),
        "the open stands as the one proposed step"
    );
    assert_eq!(
        output.proposal.postcondition,
        [ready()],
        "the check survives the failed span"
    );
    assert!(
        !output.complete,
        "a span with a failed effect is not complete"
    );
    assert_eq!(
        output.gaps,
        [DraftGap {
            seq: Some(landed),
            verb: Some("open".to_owned()),
            gap: DraftGapKind::Failed {
                cause: BatchStopCause::LocatorMissing,
            },
        }],
        "exactly the open's failure, never a second gap at the stop"
    );
    peer.assert_methods(mark, &["Target.getTargets", "Target.getTargetInfo"]);
}
