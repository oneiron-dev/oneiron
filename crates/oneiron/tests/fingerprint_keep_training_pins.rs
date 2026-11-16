//! K-proof (oracle) for PLAN-UC-04 stage 6.4a: the training and drafter pins keep their
//! bytes.
//!
//! Both pins now start through the fingerprint crate's K door (`purposes::training_pack::PIN`
//! and `purposes::drafter::PIN`, plain BLAKE3 with no tag) in one helper,
//! `training_pack::pin::pin_digest`. Runs, corpus splits, role swaps and drafter versions
//! store the pins, dispatch, completion, promotion and serving compare them, and the Python
//! training worker takes several again. So each must give main's bytes for every value that
//! has a pin; `tests/training_pin_non_finite.rs` covers the values that no longer have one.
//!
//! `base_training_pack` and `base_drafter` hold main's lines at 41c9d7ffe245, copied by range (each
//! range is named above its copy; the generator is
//! `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from them only in
//! indentation. The few lines around the copies are the imports main's lines name, the
//! `crate::llm` path they call (the same public fn as the engine's `llm` module), and a
//! wrapper for each private fn.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_training_pins`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use oneiron::test_doors::fingerprint_keep_training_pins as door;
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};
use serde::Serialize;
use serde_json::json;

/// The path main's `hash_json` names (`crate::llm::canonical_json_bytes`).
mod llm {
    pub(crate) use oneiron::llm::canonical_json_bytes;
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
mod base_training_pack {
    use oneiron::{Error, Result};
    use serde::Serialize;

    // main 41c9d7ffe245: crates/oneiron/src/training_pack/mod.rs:62-64
    fn invalid(reason: &str) -> Error {
        Error::InvalidConfig(reason.into())
    }

    // main 41c9d7ffe245: crates/oneiron/src/training_pack/mod.rs:70-74
    fn hash_json(value: &impl Serialize) -> Result<[u8; 32]> {
        let bytes = crate::llm::canonical_json_bytes(value)
            .map_err(|_| invalid("training pin encoding failed"))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    /// Main's training pin, which is private there.
    pub(crate) fn main_training_pin(value: &impl Serialize) -> Result<[u8; 32]> {
        hash_json(value)
    }
}

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
mod base_drafter {
    use oneiron::{Error, Result};
    use serde::Serialize;

    // main 41c9d7ffe245: crates/oneiron/src/drafter/mod.rs:138-140
    fn invalid(reason: &str) -> Error {
        Error::InvalidConfig(reason.into())
    }

    // main 41c9d7ffe245: crates/oneiron/src/drafter/mod.rs:142-146
    fn hash_json(value: &impl Serialize) -> Result<[u8; 32]> {
        let bytes = crate::llm::canonical_json_bytes(value)
            .map_err(|_| invalid("drafter pin encoding failed"))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    /// Main's drafter pin, which is private there.
    pub(crate) fn main_drafter_pin(value: &impl Serialize) -> Result<[u8; 32]> {
        hash_json(value)
    }
}

/// Lets one list hold values of many types and take each one's pins on main and the head.
mod erased {
    use serde::Serialize;

    pub(crate) trait Pinned {
        fn head_training(&self) -> oneiron::Result<[u8; 32]>;
        fn main_training(&self) -> oneiron::Result<[u8; 32]>;
        fn head_drafter(&self) -> oneiron::Result<[u8; 32]>;
        fn main_drafter(&self) -> oneiron::Result<[u8; 32]>;
        fn sorted_json(&self) -> Option<Vec<u8>>;
    }

    impl<T: Serialize> Pinned for T {
        fn head_training(&self) -> oneiron::Result<[u8; 32]> {
            super::door::training_pin(self)
        }

        fn main_training(&self) -> oneiron::Result<[u8; 32]> {
            super::base_training_pack::main_training_pin(self)
        }

        fn head_drafter(&self) -> oneiron::Result<[u8; 32]> {
            super::door::drafter_pin(self)
        }

        fn main_drafter(&self) -> oneiron::Result<[u8; 32]> {
            super::base_drafter::main_drafter_pin(self)
        }

        fn sorted_json(&self) -> Option<Vec<u8>> {
            oneiron::llm::canonical_json_bytes(self).ok()
        }
    }
}

use erased::Pinned;

/// A plan-like record whose fields are declared out of name order.
#[derive(Serialize)]
struct Plan {
    zeta: u8,
    alpha: String,
    middle: Option<f64>,
    list: Vec<u32>,
    #[serde(rename = "Upper")]
    upper: bool,
}

#[derive(Serialize)]
enum Shape {
    Unit,
    Newtype(String),
    Tuple(u8, f64),
    Struct { b: i64, a: Vec<String> },
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Tagged {
    Probe {
        input: serde_json::Value,
        logit: f64,
    },
    Empty {},
}

#[derive(Serialize)]
#[serde(untagged)]
enum Loose {
    Number(f64),
    Text(String),
}

#[derive(Serialize)]
struct Wrapped(u64);

/// One case: a name and a value of any serde shape.
fn case<T: Serialize + 'static>(name: &'static str, value: T) -> (&'static str, Box<dyn Pinned>) {
    (name, Box::new(value))
}

/// Every case: values of each serde shape, finite floats at their edges, strings that JSON
/// escapes, maps in more than one order, the tuple shapes the custody pins hash, and values
/// with no sorted JSON (a map whose keys are not strings or numbers).
#[allow(clippy::too_many_lines)]
fn cases() -> Vec<(&'static str, Box<dyn Pinned>)> {
    let long = "x".repeat(5000);
    let mut hashed = HashMap::new();
    hashed.insert("b".to_owned(), 2_u8);
    hashed.insert("a".to_owned(), 1_u8);
    hashed.insert("c".to_owned(), 3_u8);
    let checkpoint_files = vec![
        ("config.json", "config", "pinned:0", [0x11_u8; 32], 120_u64),
        (
            "model.safetensors",
            "weights",
            "pinned:1",
            [0x22; 32],
            u64::MAX,
        ),
        ("tokenizer.json", "tokenizer", "pinned:2", [0x33; 32], 0),
    ];
    vec![
        case("unit", ()),
        case("none", None::<u8>),
        case("true", true),
        case("false", false),
        case("zero u8", 0_u8),
        case("u64 max", u64::MAX),
        case("i64 min", i64::MIN),
        case("small i128", -42_i128),
        case("char", 'x'),
        case("zero", 0.0_f64),
        case("negative zero", -0.0_f64),
        case("one", 1.0_f64),
        case("a tenth", 0.1_f64),
        case("f64 max", f64::MAX),
        case("f64 min", f64::MIN),
        case("smallest normal", f64::MIN_POSITIVE),
        case("smallest subnormal", 5e-324_f64),
        case("large", 1e300_f64),
        case("f32 tenth", 0.1_f32),
        case("f32 max", f32::MAX),
        case("empty string", ""),
        case("plain string", "plain"),
        case(
            "escaped string",
            "quote \" back \\ slash / tab \t newline \n",
        ),
        case("control string", "nul \0 bell \u{7} del \u{7f}"),
        case("unicode string", "é 漢字 🙂 \u{2028}"),
        case("long string", long),
        case("some string", Some("x")),
        case("bytes as a list", vec![0_u8, 1, 255]),
        case("empty list", Vec::<u8>::new()),
        case("float list", vec![1.0, -0.0, 2.5e-7]),
        case("nested lists", vec![vec![1_u8], vec![], vec![2, 3]]),
        case("tuple", ("a", 1_u8, 2.5_f64)),
        case("empty map", BTreeMap::<String, u8>::new()),
        case(
            "map",
            BTreeMap::from([("b".to_owned(), 2_u8), ("a".to_owned(), 1)]),
        ),
        case("hash map", hashed),
        case(
            "integer keys",
            BTreeMap::from([(10_u32, "ten"), (9, "nine")]),
        ),
        case("pair keys", BTreeMap::from([((1_u8, 2_u8), 3_u8)])),
        case(
            "json in insertion order",
            json!({"b": 1, "a": {"d": [1, 2, {"z": null, "y": true}], "c": "s"}}),
        ),
        case(
            "json in name order",
            json!({"a": {"c": "s", "d": [1, 2, {"y": true, "z": null}]}, "b": 1}),
        ),
        case("json number", json!(12.5)),
        case(
            "plan",
            Plan {
                zeta: 9,
                alpha: "first".to_owned(),
                middle: Some(0.75),
                list: vec![3, 1, 2],
                upper: true,
            },
        ),
        case(
            "plan without a middle",
            Plan {
                zeta: 0,
                alpha: String::new(),
                middle: None,
                list: Vec::new(),
                upper: false,
            },
        ),
        case("unit variant", Shape::Unit),
        case("newtype variant", Shape::Newtype("n".to_owned())),
        case("tuple variant", Shape::Tuple(7, -1.5)),
        case(
            "struct variant",
            Shape::Struct {
                b: -3,
                a: vec!["y".to_owned(), "x".to_owned()],
            },
        ),
        case(
            "tagged probe",
            Tagged::Probe {
                input: json!({"text": "hi", "lang": "en"}),
                logit: 0.5,
            },
        ),
        case("tagged empty", Tagged::Empty {}),
        case("untagged number", Loose::Number(3.0)),
        case("untagged text", Loose::Text("3".to_owned())),
        case("newtype struct", Wrapped(77)),
        case(
            "checkpoint pin input",
            ("org/model-a", checkpoint_files.clone()),
        ),
        case(
            "checkpoint pin input, other model",
            ("org/model-b", checkpoint_files),
        ),
        case(
            "spec-like tuple",
            (
                json!({"harness": "h1", "probes": [{"id": "p", "input": {"x": 1}}]}),
                json!({"host": "nelly", "binding": [1, 2]}),
                vec![("row", [0x44_u8; 32])],
            ),
        ),
    ]
}

#[test]
fn the_pin_purposes_keep_main_s_recipe() {
    let training = purposes::training_pack::PIN;
    assert_eq!(training.tag(), "oneiron.training_pack.pin.v1");
    assert_eq!(training.hash(), LegacyHash::Blake3);
    assert_eq!(training.tag_mode(), TagMode::NotHashed);
    let drafter = purposes::drafter::PIN;
    assert_eq!(drafter.tag(), "oneiron.drafter.pin.v1");
    assert_eq!(drafter.hash(), LegacyHash::Blake3);
    assert_eq!(drafter.tag_mode(), TagMode::NotHashed);
}

#[test]
fn the_training_and_drafter_pins_keep_their_bytes() {
    let cases = cases();
    let mut pins = BTreeSet::new();
    let mut sorted = BTreeSet::new();
    let mut refused = 0;
    for (name, value) in &cases {
        let head_training = value.head_training();
        let main_training = value.main_training();
        let head_drafter = value.head_drafter();
        let main_drafter = value.main_drafter();
        assert_eq!(
            format!("{head_training:?}"),
            format!("{main_training:?}"),
            "training pin of {name}"
        );
        assert_eq!(
            format!("{head_drafter:?}"),
            format!("{main_drafter:?}"),
            "drafter pin of {name}"
        );
        match (head_training, head_drafter, value.sorted_json()) {
            (Ok(training), Ok(drafter), Some(json)) => {
                // One recipe: the two purposes write no tag, so they give one pin.
                assert_eq!(training, drafter, "{name}");
                pins.insert(training);
                sorted.insert(json);
            }
            (Err(_), Err(_), None) => refused += 1,
            other => panic!("{name}: the pins and the sorted JSON disagree: {other:?}"),
        }
    }
    assert_eq!(cases.len(), 54);
    assert_eq!(refused, 1, "the pair-keyed map has no sorted JSON");
    // Unit and None both write `null`, and the two JSON objects differ only in their
    // order: a pin is one per sorted JSON.
    assert_eq!(pins.len(), sorted.len());
}

#[test]
fn a_pin_is_the_blake3_of_the_sorted_json() {
    // Literal sorted JSON, so the proof does not lean on the shared encoder alone.
    let object = json!({"b": 1, "a": [true, null, "s"]});
    let expected: &[u8] = br#"{"a":[true,null,"s"],"b":1}"#;
    assert_eq!(
        door::training_pin(&object).expect("a pin"),
        *blake3::hash(expected).as_bytes()
    );
    assert_eq!(
        door::drafter_pin(&object).expect("a pin"),
        *blake3::hash(expected).as_bytes()
    );
    let plan = Plan {
        zeta: 9,
        alpha: "first".to_owned(),
        middle: Some(0.75),
        list: vec![3, 1, 2],
        upper: true,
    };
    let expected: &[u8] =
        br#"{"Upper":true,"alpha":"first","list":[3,1,2],"middle":0.75,"zeta":9}"#;
    assert_eq!(
        door::training_pin(&plan).expect("a pin"),
        *blake3::hash(expected).as_bytes()
    );
    assert_eq!(
        door::training_pin(&()).expect("a pin"),
        *blake3::hash(b"null").as_bytes()
    );
    assert_eq!(
        door::training_pin(&-0.0_f64).expect("a pin"),
        *blake3::hash(b"-0.0").as_bytes()
    );
}
