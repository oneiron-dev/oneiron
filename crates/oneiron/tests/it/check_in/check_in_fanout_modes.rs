//! ROLES-CHECKIN PR 1 (ARCH-0082 #build): fan-out admission is the first
//! caller of check-in, and the rename changes no behaviour. The same matrix
//! runs on main (the old fan-out mode type) and on the PR head (CheckInMode):
//! for each mode token, classifier answer and width, the plan proceeds or
//! pauses as before, the classifier is asked as often as before, and the same
//! rows are surfaced.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test check_in_fanout_modes`.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::fanout_admission::{AdmissionOutcome, Classifier, admit_one};

const THRESHOLD: u32 = 10;
const NARROW: u32 = 3;
const WIDE: u32 = 40;

fn outcome(outcome: &'static str, classifier_calls: usize, rows: usize) -> AdmissionOutcome {
    AdmissionOutcome {
        outcome,
        classifier_calls,
        rows,
    }
}

#[test]
fn fanout_admission_by_mode_is_unchanged() {
    use Classifier::{Allow, Fails, SurfaceHuman};
    let cases = [
        // `manual` (AlwaysAsk) pauses at any width and never asks the classifier.
        ("manual", Allow, NARROW, outcome("paused", 0, 1)),
        ("manual", Allow, WIDE, outcome("paused", 0, 1)),
        // `auto` (AskWhenUnsure) asks the classifier at any width.
        ("auto", Allow, NARROW, outcome("proceed", 1, 0)),
        // Above the threshold the allow clears the width check: no row.
        ("auto", Allow, WIDE, outcome("proceed", 1, 0)),
        ("auto", SurfaceHuman, NARROW, outcome("paused", 1, 1)),
        ("auto", SurfaceHuman, WIDE, outcome("paused", 1, 1)),
        // A failing classifier is not authority to start: it pauses.
        ("auto", Fails, NARROW, outcome("paused", 1, 1)),
        // `full-access` (NeverAsk) proceeds and never asks the classifier.
        ("full-access", Allow, NARROW, outcome("proceed", 0, 0)),
        // Above the threshold it leaves a non-blocking width-question row.
        ("full-access", Allow, WIDE, outcome("proceed", 0, 1)),
        ("full-access", Fails, WIDE, outcome("proceed", 0, 1)),
    ];
    for (mode, classifier, total, expected) in cases {
        let got = admit_one(mode, classifier, total, THRESHOLD)
            .unwrap_or_else(|error| panic!("{mode} {classifier:?} {total}: {error}"));
        assert_eq!(got, expected, "{mode} {classifier:?} total {total}");
    }
}

#[test]
fn unknown_mode_token_is_refused() {
    assert!(admit_one("always_ask", Classifier::Allow, NARROW, THRESHOLD).is_err());
}
