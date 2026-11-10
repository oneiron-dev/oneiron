//! The shared timestamp bound must agree with JavaScript's safe integers.

use oneiron_remote::{check_unix_seconds, stamp_occurred_at};

#[test]
fn unix_seconds_refuse_non_whole_non_finite_and_unsafe_numbers() {
    for number in [
        -1.0,
        1_700_000_000.9,
        9_007_199_254_740_992.0,
        9_007_199_254_740_994.0,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ] {
        for error in [
            check_unix_seconds("learned_at", number).expect_err("invalid timestamp"),
            stamp_occurred_at(Some(number)).expect_err("invalid witness timestamp"),
        ] {
            assert_eq!(error.code, "BAD_REQUEST");
            assert!(!error.suggestions.is_empty());
        }
    }
}
