//! Red/green for PLAN-UC-04 stage 6.4a (FIX TRAINING-PIN-NAN-DISAGREES): a training or drafter
//! pin refuses a non-finite float.
//!
//! A pin is the BLAKE3 of a value's sorted JSON. That JSON writes a NaN or an infinity as
//! `null`, so before this change a value holding one had a pin, the same pin as the value
//! with a `null` in its place. The Python training worker (`scripts/training_pack/worker.py`,
//! `_float_text`) refuses such a value before it hashes, so it could never agree with that
//! pin. Now the engine refuses it too, with `InvalidConfig`; every value the worker accepts
//! keeps its pin (`tests/fingerprint_keep_training_pins.rs`).
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test training_pin_non_finite`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;

use oneiron::Error;
use oneiron::test_doors::fingerprint_keep_training_pins as door;
use serde::Serialize;

/// A plan-like record whose tolerance is a float, as `TrainingPlan.export_logit_tolerance`.
#[derive(Serialize)]
struct Tolerance {
    harness: &'static str,
    export_logit_tolerance: f64,
}

/// An evaluation-like record whose metrics are floats, as `HeldOutResult.metrics`.
#[derive(Serialize)]
struct Metrics {
    passed: bool,
    metrics: BTreeMap<String, f64>,
}

/// A record whose float sits behind a tagged variant.
#[derive(Serialize)]
enum Measure {
    Score { value: f32 },
    Pair(f64, f64),
}

/// One shape: a name and a value of any serde shape.
fn shape<T: Serialize + 'static>(
    name: &'static str,
    value: T,
) -> (&'static str, Box<dyn erased::Pinned>) {
    (name, Box::new(value))
}

/// `value` as an f32: a NaN or an infinity stays one, and a finite value beyond the f32
/// range becomes the nearest finite f32.
fn as_f32(value: f64) -> f32 {
    #[allow(clippy::cast_possible_truncation)]
    let narrow = value as f32;
    if value.is_finite() {
        narrow.clamp(f32::MIN, f32::MAX)
    } else {
        narrow
    }
}

/// Takes the pin of every shape below with `bad` in its float slot, and returns each result
/// with the shape's name.
fn pins_with(
    bad: f64,
    pin: fn(&dyn erased::Pinned) -> oneiron::Result<[u8; 32]>,
) -> Vec<(&'static str, oneiron::Result<[u8; 32]>)> {
    let bad_f32 = as_f32(bad);
    let shapes = vec![
        shape("a bare f64", bad),
        shape("a bare f32", bad_f32),
        shape(
            "a struct field",
            Tolerance {
                harness: "h",
                export_logit_tolerance: bad,
            },
        ),
        shape(
            "a map value",
            Metrics {
                passed: true,
                metrics: BTreeMap::from([("loss".to_owned(), 0.25), ("auc".to_owned(), bad)]),
            },
        ),
        shape("an option", Some(bad)),
        shape("a list element", vec![1.0, 2.5, bad]),
        shape("a tuple element", ("plan", 3_u64, bad)),
        shape("a struct variant", Measure::Score { value: bad_f32 }),
        shape("a tuple variant", Measure::Pair(0.5, bad)),
        shape("a nested list", vec![vec![0.0], vec![bad]]),
    ];
    shapes
        .into_iter()
        .map(|(name, value)| (name, pin(value.as_ref())))
        .collect()
}

/// Lets one list hold values of many types and pass each to a generic door.
mod erased {
    use serde::Serialize;

    pub(crate) trait Pinned {
        fn training_pin(&self) -> oneiron::Result<[u8; 32]>;
        fn drafter_pin(&self) -> oneiron::Result<[u8; 32]>;
    }

    impl<T: Serialize> Pinned for T {
        fn training_pin(&self) -> oneiron::Result<[u8; 32]> {
            super::door::training_pin(self)
        }

        fn drafter_pin(&self) -> oneiron::Result<[u8; 32]> {
            super::door::drafter_pin(self)
        }
    }
}

fn training(value: &dyn erased::Pinned) -> oneiron::Result<[u8; 32]> {
    value.training_pin()
}

fn drafter(value: &dyn erased::Pinned) -> oneiron::Result<[u8; 32]> {
    value.drafter_pin()
}

fn assert_refused(
    kind: &str,
    pin: fn(&dyn erased::Pinned) -> oneiron::Result<[u8; 32]>,
    message: &str,
) {
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -f64::NAN] {
        for (shape, result) in pins_with(bad, pin) {
            match result {
                Err(Error::InvalidConfig(reason)) => assert_eq!(
                    reason, message,
                    "{kind} pin of {shape} holding {bad}: refused for another reason"
                ),
                Err(other) => panic!("{kind} pin of {shape} holding {bad}: refused as {other:?}"),
                Ok(pin) => panic!(
                    "{kind} pin of {shape} holding {bad}: took the pin {}, which the worker \
                     cannot recompute",
                    blake3::Hash::from(pin).to_hex()
                ),
            }
        }
    }
}

#[test]
fn a_training_pin_refuses_a_non_finite_float() {
    assert_refused(
        "training",
        training,
        "training pin holds a non-finite number, which has no JSON form",
    );
}

#[test]
fn a_drafter_pin_refuses_a_non_finite_float() {
    assert_refused(
        "drafter",
        drafter,
        "drafter pin holds a non-finite number, which has no JSON form",
    );
}

#[test]
fn finite_floats_and_nulls_keep_their_pins() {
    // Every finite float has a pin, and so has the `null` a NaN used to share a pin with.
    for good in [
        0.0,
        -0.0,
        1.5,
        -2.25e-7,
        f64::MAX,
        f64::MIN,
        f64::MIN_POSITIVE,
        5e-324,
    ] {
        for (shape, result) in pins_with(good, training) {
            assert!(
                result.is_ok(),
                "training pin of {shape} holding {good}: {result:?}"
            );
        }
        for (shape, result) in pins_with(good, drafter) {
            assert!(
                result.is_ok(),
                "drafter pin of {shape} holding {good}: {result:?}"
            );
        }
    }
    let null: Option<f64> = None;
    let unit = ();
    for value in [
        &null as &dyn erased::Pinned,
        &unit,
        &serde_json::Value::Null,
    ] {
        assert!(value.training_pin().is_ok());
        assert!(value.drafter_pin().is_ok());
    }
    // A pin still refuses a value with no sorted JSON, with the message it always gave.
    let keyed_by_pairs = BTreeMap::from([((1_u8, 2_u8), 3_u8)]);
    assert!(matches!(
        door::training_pin(&keyed_by_pairs),
        Err(Error::InvalidConfig(reason)) if reason == "training pin encoding failed"
    ));
    assert!(matches!(
        door::drafter_pin(&keyed_by_pairs),
        Err(Error::InvalidConfig(reason)) if reason == "drafter pin encoding failed"
    ));
}
