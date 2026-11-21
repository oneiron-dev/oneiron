//! Each lookup below refuses a map key stored twice (no writer stores one), and a listing row
//! with a trailer names no id. Red on the base, where each lookup read the first match.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::msgpack_duplicate_key as door;

/// `entries` plus one more entry under `key`: a row with a repeated key.
fn with_repeat(
    mut entries: Vec<(rmpv::Value, rmpv::Value)>,
    key: &str,
    value: rmpv::Value,
) -> Vec<(rmpv::Value, rmpv::Value)> {
    entries.push((rmpv::Value::from(key), value));
    entries
}

/// The map row `entries` as a writer writes it.
fn encode_map(entries: Vec<(rmpv::Value, rmpv::Value)>) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(entries))
        .expect("a map row serializes");
    bytes
}

#[test]
fn human_task_wait_signal_refuses_a_repeated_key() {
    let a = oneiron_contracts::entity_id::EntityId::from_bytes([1; 16]).expect("fixed id");
    let b = oneiron_contracts::entity_id::EntityId::from_bytes([2; 16]).expect("fixed id");
    let c = oneiron_contracts::entity_id::EntityId::from_bytes([3; 16]).expect("fixed id");
    let plain = oneiron_store::human_task::storage::wait_signal_body(a, b);
    assert_eq!(
        oneiron_store::human_task::storage::decode_wait_signal(&plain).ok(),
        Some((a, b)),
        "the plain row reads"
    );
    let mut cursor = plain.as_slice();
    let value = rmpv::decode::read_value(&mut cursor).expect("the plain row decodes");
    let rmpv::Value::Map(entries) = value else {
        panic!("the plain row is a map");
    };
    let repeated = encode_map(with_repeat(
        entries,
        "signal_ref",
        rmpv::Value::Binary(c.as_bytes().to_vec()),
    ));
    assert!(
        oneiron_store::human_task::storage::decode_wait_signal(&repeated).is_err(),
        "the row with a repeated signal key is refused"
    );
}

#[test]
fn vault_cleanup_proposal_refuses_a_repeated_key() {
    let entries = vec![
        (
            rmpv::Value::from("schema_version"),
            rmpv::Value::from(door::cleanup_proposal_schema_version()),
        ),
        (
            rmpv::Value::from("attempt"),
            rmpv::Value::from("0123456789abcdef0123456789abcdef"),
        ),
        (rmpv::Value::from("created_at"), rmpv::Value::from(42)),
        (
            rmpv::Value::from("candidates"),
            rmpv::Value::Array(Vec::new()),
        ),
    ];
    let plain = encode_map(entries.clone());
    assert!(
        door::cleanup_proposal_decodes(&plain),
        "the plain row decodes"
    );
    let repeated = encode_map(with_repeat(entries, "created_at", rmpv::Value::from(99)));
    assert!(
        !door::cleanup_proposal_decodes(&repeated),
        "the row with a repeated created_at is refused"
    );
}

#[test]
fn vault_cleanup_erase_names_nothing_in_a_repeated_list() {
    let candidate_one = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("entity"),
            rmpv::Value::from("01010101010101010101010101010101"),
        ),
        (
            rmpv::Value::from("kind"),
            rmpv::Value::from("empty_summary"),
        ),
    ]);
    let candidate_two = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("entity"),
            rmpv::Value::from("02020202020202020202020202020202"),
        ),
        (
            rmpv::Value::from("kind"),
            rmpv::Value::from("empty_summary"),
        ),
    ]);
    let entries = vec![
        (
            rmpv::Value::from("schema_version"),
            rmpv::Value::from(door::cleanup_proposal_schema_version()),
        ),
        (
            rmpv::Value::from("attempt"),
            rmpv::Value::from("0123456789abcdef0123456789abcdef"),
        ),
        (rmpv::Value::from("created_at"), rmpv::Value::from(42)),
        (
            rmpv::Value::from("candidates"),
            rmpv::Value::Array(vec![candidate_one]),
        ),
    ];
    let plain = encode_map(entries.clone());
    assert_eq!(
        door::cleanup_proposal_named_id_count(&plain),
        1,
        "the plain row names 1 id"
    );
    let repeated = encode_map(with_repeat(
        entries,
        "candidates",
        rmpv::Value::Array(vec![candidate_two]),
    ));
    assert_eq!(
        door::cleanup_proposal_named_id_count(&repeated),
        0,
        "the row with a repeated candidates list names none"
    );
}

#[test]
fn vault_cleanup_erase_names_nothing_in_a_row_with_a_trailer() {
    let candidate = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("entity"),
            rmpv::Value::from("01010101010101010101010101010101"),
        ),
        (
            rmpv::Value::from("kind"),
            rmpv::Value::from("empty_summary"),
        ),
    ]);
    let entries = vec![
        (
            rmpv::Value::from("schema_version"),
            rmpv::Value::from(door::cleanup_proposal_schema_version()),
        ),
        (
            rmpv::Value::from("attempt"),
            rmpv::Value::from("0123456789abcdef0123456789abcdef"),
        ),
        (rmpv::Value::from("created_at"), rmpv::Value::from(42)),
        (
            rmpv::Value::from("candidates"),
            rmpv::Value::Array(vec![candidate]),
        ),
    ];
    let plain = encode_map(entries);
    assert_eq!(
        door::cleanup_proposal_named_id_count(&plain),
        1,
        "the plain row names 1 id"
    );
    let mut with_trailer = plain;
    with_trailer.push(0xc0);
    assert_eq!(
        door::cleanup_proposal_named_id_count(&with_trailer),
        0,
        "the row plus one trailer byte names none"
    );
}

#[test]
fn skill_reliability_outcome_row_refuses_a_repeated_key() {
    let entries = vec![
        (
            rmpv::Value::from("schema_version"),
            rmpv::Value::from(door::outcome_row_schema_version()),
        ),
        (rmpv::Value::from("win"), rmpv::Value::Boolean(true)),
        (rmpv::Value::from("at"), rmpv::Value::from(7)),
    ];
    let plain = encode_map(entries.clone());
    assert!(door::outcome_row_decodes(&plain), "the plain row reads");
    let repeated = encode_map(with_repeat(entries, "win", rmpv::Value::Boolean(false)));
    assert!(
        !door::outcome_row_decodes(&repeated),
        "the row with a repeated win is refused"
    );
}
