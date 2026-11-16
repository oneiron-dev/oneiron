//! PLAN-UC-08 PR 2; a lookup that took the first of two equal keys now refuses (or, for
//! `map_value`, reads the key as absent); no writer ever wrote such a body (K-proof in the
//! PR); red on main, where each returned the first value.

use rmpv::Value;

fn repeated(key: &str) -> Vec<(Value, Value)> {
    vec![
        (Value::from(key), Value::from("first")),
        (Value::from(key), Value::from("second")),
    ]
}

fn single(key: &str) -> Vec<(Value, Value)> {
    vec![(Value::from(key), Value::from("first"))]
}

#[test]
fn skill_hub_map_value_reads_a_repeated_key_as_absent() {
    use oneiron_store::write_envelope::skill_source::support::map_value;
    let repeated = Value::Map(vec![
        (Value::from("hubRef"), Value::from("a")),
        (Value::from("hubRef"), Value::from("b")),
    ]);
    assert_eq!(map_value(&repeated, "hubRef"), None);
    let single = Value::Map(vec![(Value::from("hubRef"), Value::from("a"))]);
    assert_eq!(map_value(&single, "hubRef"), Some(&Value::from("a")));
}

#[test]
fn skill_body_required_value_refuses_a_repeated_key() {
    use oneiron_store::write_envelope::skill_source::support::required_value;
    assert!(required_value(&repeated("kind"), "kind", "test body").is_err());
    assert!(required_value(&single("kind"), "kind", "test body").is_ok());
}

#[test]
fn psych_profile_required_value_refuses_a_repeated_key() {
    use oneiron_store::write_envelope::profile_snapshot::codec::required_value;
    assert!(required_value(&repeated("status"), "status").is_err());
    assert!(required_value(&single("status"), "status").is_ok());
}

#[test]
fn persona_record_field_refuses_a_repeated_key() {
    use oneiron_store::serialize::person_identity::field;
    assert!(field(&repeated("k"), "k").is_err());
    assert!(field(&single("k"), "k").is_ok());
}

#[test]
fn secret_lease_required_value_reads_a_repeated_key_as_absent() {
    use oneiron_store::secret_lease::codec::required_value;
    assert_eq!(required_value(&repeated("k"), "k"), None);
    assert_eq!(
        required_value(&single("k"), "k"),
        Some(&Value::from("first"))
    );
}

#[test]
fn scope_map_lookup_reports_a_repeated_key() {
    use oneiron_store::write_envelope::claim_body::{MapValue, single_map_value};
    assert!(matches!(
        single_map_value(&repeated("k"), "k"),
        MapValue::Duplicate
    ));
}

#[test]
fn task_body_field_refuses_a_repeated_key() {
    use oneiron_store::task_body_checks::task_body_field;
    assert!(task_body_field(&repeated("k"), "k").is_err());
}

#[test]
fn blob_body_refuses_a_trailing_byte() {
    use oneiron_store::blob_artifact::store_keys::read_value;
    let err = read_value(&[0xc0, 0xc0], "body").expect_err("trailing byte must be refused");
    assert!(
        err.to_string().contains("trailing bytes after body map"),
        "unexpected error: {err:?}"
    );
}
