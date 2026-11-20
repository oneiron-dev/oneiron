//! The reveal ask window setting: a longer window lets the owner answer after an hour, the default still ends after an hour, and zero is refused.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test reveal_ask_window_setting`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::test_doors::reveal_ask_window::{answer_reveal_after, set_reveal_window};

#[test]
fn a_longer_reveal_window_lets_the_owner_answer_after_an_hour() {
    let run = answer_reveal_after(Some(7200), 3601).expect("the door runs");
    assert_eq!(run.window_secs, 7200, "the filed ask keeps its window");
    assert_eq!(
        run.answer,
        Ok(()),
        "the owner answers inside the longer window"
    );
}

#[test]
fn the_default_reveal_window_still_ends_after_an_hour() {
    let run = answer_reveal_after(None, 3601).expect("the door runs");
    assert_eq!(run.window_secs, 3600, "the default window is an hour");
    let text = run.answer.expect_err("the ask past its window is refused");
    assert!(
        text.contains("this reveal's ask has expired"),
        "the expiry error: {text}"
    );
    let run = answer_reveal_after(None, 3599).expect("the door runs");
    assert_eq!(
        run.answer,
        Ok(()),
        "the owner answers inside the default window"
    );
}

#[test]
fn a_reveal_window_of_zero_is_refused() {
    let error = set_reveal_window(0).expect_err("a zero window is refused");
    assert!(
        error.to_string().contains("at least one second"),
        "the floor error: {error}"
    );
    assert!(set_reveal_window(1).is_ok(), "a one-second window stands");
}
