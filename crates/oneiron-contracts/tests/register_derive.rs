//! `#[derive(Register)]` writes, for every row, the name serde writes for the same enum: under
//! each of serde's eight `rename_all` rules, with a variant's own `rename`, and with no serde
//! attribute at all. An enum states its own spelling in `#[register(..)]`, and that replaces
//! serde's. `ROWS` holds every row in declaration order, `named` finds each row by its name and
//! nothing else, and `as_str` is a `const fn`.

use oneiron_contracts::register::Register;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The name serde writes for one row.
fn serde_name<T: Serialize>(row: T) -> String {
    match serde_json::to_value(row).expect("a unit variant serializes") {
        Value::String(name) => name,
        other => panic!("a unit variant serializes as a string, not {other}"),
    }
}

/// Every row's derived name is serde's, serde reads it back as the same row, and `named` finds it.
fn assert_names_are_serde<R>()
where
    R: Register + Serialize + for<'de> Deserialize<'de> + std::fmt::Debug,
{
    for &row in R::ROWS {
        assert_eq!(row.name(), serde_name(row), "{} row {row:?}", R::NAME);
        let read: R = serde_json::from_value(Value::String(row.name().to_owned()))
            .expect("serde reads the derived name");
        assert_eq!(read, row, "{} row {row:?}", R::NAME);
        assert_eq!(R::named(row.name()), Some(row), "{} row {row:?}", R::NAME);
    }
}

/// The rows of every case enum below: two words, a digit, an acronym, a one-letter word.
macro_rules! rows_of {
    ($register:ty) => {
        <$register as Register>::ROWS
            .iter()
            .copied()
            .map(<$register as Register>::name)
            .collect::<Vec<_>>()
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[serde(rename_all = "lowercase")]
#[register("test.lowercase")]
enum Lower {
    PendingReview,
    V2Beta,
    URLHost,
    A,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[serde(rename_all = "UPPERCASE")]
#[register("test.uppercase")]
enum Upper {
    PendingReview,
    V2Beta,
    URLHost,
    A,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[serde(rename_all = "PascalCase")]
#[register("test.pascal_case")]
enum Pascal {
    PendingReview,
    V2Beta,
    URLHost,
    A,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[serde(rename_all = "camelCase")]
#[register("test.camel_case")]
enum Camel {
    PendingReview,
    V2Beta,
    URLHost,
    A,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[serde(rename_all = "snake_case")]
#[register("test.snake_case")]
enum Snake {
    PendingReview,
    V2Beta,
    URLHost,
    A,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[register("test.screaming_snake_case")]
enum ScreamingSnake {
    PendingReview,
    V2Beta,
    URLHost,
    A,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[serde(rename_all = "kebab-case")]
#[register("test.kebab_case")]
enum Kebab {
    PendingReview,
    V2Beta,
    URLHost,
    A,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
#[register("test.screaming_kebab_case")]
enum ScreamingKebab {
    PendingReview,
    V2Beta,
    URLHost,
    A,
}

/// serde's default: the variant as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[register("test.serde_default")]
enum SerdeDefault {
    PendingReview,
    V2Beta,
}

/// A variant's own `rename` beats the enum's rule; other serde items are stepped over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[serde(
    expecting = "a test row",
    rename_all = "snake_case",
    bound(serialize = "")
)]
#[register("test.variant_rename")]
enum VariantRename {
    PendingReview,
    #[serde(rename = "booking.http_guard", alias = "http_guard")]
    HttpGuard,
}

/// The register's own rule replaces serde's spelling for every row, serde's variant rename
/// included, and a row's `#[register(name = ..)]` beats both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[register("test.tier", rename_all = "snake_case")]
enum OwnSpelling {
    Software,
    #[serde(rename = "Hardware")]
    HardwareKey,
    #[register(name = "tier.offline")]
    Offline,
}

/// No serde derive at all: the variant as written, unless a row is named.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Register)]
#[register("test.no_serde")]
pub(crate) enum NoSerde {
    Allow,
    #[register(name = "deny.hard")]
    Deny,
}

#[test]
fn each_rename_all_rule_writes_the_name_serde_writes() {
    assert_names_are_serde::<Lower>();
    assert_names_are_serde::<Upper>();
    assert_names_are_serde::<Pascal>();
    assert_names_are_serde::<Camel>();
    assert_names_are_serde::<Snake>();
    assert_names_are_serde::<ScreamingSnake>();
    assert_names_are_serde::<Kebab>();
    assert_names_are_serde::<ScreamingKebab>();
    assert_names_are_serde::<SerdeDefault>();
    assert_names_are_serde::<VariantRename>();
}

#[test]
fn the_names_are_serde_rules_spelled_out() {
    assert_eq!(rows_of!(Lower), ["pendingreview", "v2beta", "urlhost", "a"]);
    assert_eq!(rows_of!(Upper), ["PENDINGREVIEW", "V2BETA", "URLHOST", "A"]);
    assert_eq!(
        rows_of!(Pascal),
        ["PendingReview", "V2Beta", "URLHost", "A"]
    );
    assert_eq!(rows_of!(Camel), ["pendingReview", "v2Beta", "uRLHost", "a"]);
    assert_eq!(
        rows_of!(Snake),
        ["pending_review", "v2_beta", "u_r_l_host", "a"]
    );
    assert_eq!(
        rows_of!(ScreamingSnake),
        ["PENDING_REVIEW", "V2_BETA", "U_R_L_HOST", "A"]
    );
    assert_eq!(
        rows_of!(Kebab),
        ["pending-review", "v2-beta", "u-r-l-host", "a"]
    );
    assert_eq!(
        rows_of!(ScreamingKebab),
        ["PENDING-REVIEW", "V2-BETA", "U-R-L-HOST", "A"]
    );
    assert_eq!(rows_of!(SerdeDefault), ["PendingReview", "V2Beta"]);
    assert_eq!(
        rows_of!(VariantRename),
        ["pending_review", "booking.http_guard"]
    );
}

#[test]
fn the_register_attribute_replaces_serde_spelling() {
    assert_eq!(
        rows_of!(OwnSpelling),
        ["software", "hardware_key", "tier.offline"]
    );
    // serde still writes its own spelling: the two differ on purpose here (REG-4's case).
    assert_eq!(serde_name(OwnSpelling::Software), "Software");
    assert_eq!(serde_name(OwnSpelling::HardwareKey), "Hardware");
    assert_eq!(rows_of!(NoSerde), ["Allow", "deny.hard"]);
}

#[test]
fn rows_are_in_declaration_order_and_named_finds_only_a_declared_name() {
    assert_eq!(NoSerde::NAME, "test.no_serde");
    assert_eq!(OwnSpelling::NAME, "test.tier");
    assert_eq!(NoSerde::ROWS, &[NoSerde::Allow, NoSerde::Deny]);
    assert_eq!(NoSerde::named("Allow"), Some(NoSerde::Allow));
    assert_eq!(NoSerde::named("deny.hard"), Some(NoSerde::Deny));
    for unknown in ["Deny", "allow", "ALLOW", "", " Allow", "Allow "] {
        assert_eq!(NoSerde::named(unknown), None, "{unknown:?}");
    }
    assert_eq!(Snake::named("pending_review"), Some(Snake::PendingReview));
    assert_eq!(Snake::named("PendingReview"), None);
}

#[test]
fn as_str_is_a_const_fn_and_name_is_as_str() {
    const PENDING: &str = Snake::PendingReview.as_str();
    assert_eq!(PENDING, "pending_review");
    for &row in Snake::ROWS {
        assert_eq!(row.as_str(), row.name());
    }
}
