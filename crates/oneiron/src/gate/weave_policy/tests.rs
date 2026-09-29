use super::*;

#[test]
fn shipped_roles_and_nested_holder_narrowing() {
    let mut rows = parse(&default_value()).unwrap();
    let holder = crate::test_util::entity(0xD0);
    let vault_row = effective(&rows, "agent", holder, Precedence::NestedNarrowing).unwrap();
    assert_eq!(vault_row.sections, BTreeSet::from(["digest".to_string()]));
    assert_eq!(vault_row.max_sections, 16);
    rows.push(Row {
        role: "agent".into(),
        holder: Some(holder),
        sections: BTreeSet::from(["digest".into(), "projects".into()]),
        max_sections: 32,
        max_predicates: 64,
        max_edge_kinds: 64,
        max_rows: 10_000,
    });
    assert_eq!(
        effective(&rows, "agent", holder, Precedence::NestedNarrowing).unwrap(),
        vault_row
    );
    let other = crate::test_util::entity(0xD1);
    assert_eq!(
        effective(&rows, "agent", other, Precedence::NestedNarrowing).unwrap(),
        vault_row
    );
}

#[test]
fn malformed_rows_fail_closed_without_partial_role_grants() {
    for mutate in 0..4 {
        let mut value = default_value();
        let Value::Array(rows) = &mut value else {
            unreachable!()
        };
        if mutate == 0 {
            rows.push(rows[0].clone());
        } else {
            let Value::Map(fields) = &mut rows[0] else {
                unreachable!()
            };
            match mutate {
                1 => fields.push((Value::from("unknown"), Value::Boolean(true))),
                2 => fields.push((Value::from("role"), Value::from("person"))),
                _ => {
                    fields
                        .iter_mut()
                        .find(|(k, _)| k.as_str() == Some("max_sections"))
                        .unwrap()
                        .1 = Value::from(0);
                }
            }
        }
        assert!(parse(&value).is_none());
    }
}

#[test]
fn authored_large_ceilings_are_valid_and_precedence_is_evaluated() {
    let mut value = default_value();
    let Value::Array(rows) = &mut value else {
        unreachable!()
    };
    let Value::Map(fields) = &mut rows[0] else {
        unreachable!()
    };
    fields
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some("max_sections"))
        .unwrap()
        .1 = Value::from(65);
    fields
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some("max_rows"))
        .unwrap()
        .1 = Value::from(10_001);
    let rows = parse(&value).unwrap();
    let holder = crate::test_util::entity(0xD2);
    let row = effective(&rows, "person", holder, Precedence::NestedNarrowing).unwrap();
    assert_eq!(row.max_sections, 65);
    assert_eq!(row.max_rows, 10_001);
    assert!(effective(&rows, "person", holder, Precedence::HolderRequired).is_none());
    assert_eq!(
        Precedence::parse("holder_required"),
        Some(Precedence::HolderRequired)
    );
}

#[test]
fn manifest_precedence_row_is_explicit_and_unknown_value_fails_closed() {
    let bytes = crate::gate::default_policy_manifest().unwrap();
    assert!(crate::gate::decode::decode_policy_manifest(&bytes).is_some());
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap() else {
        panic!("manifest map")
    };
    entries
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some(PRECEDENCE_KEY))
        .unwrap()
        .1 = Value::from("replace_vault");
    let mut invalid = Vec::new();
    rmpv::encode::write_value(&mut invalid, &Value::Map(entries)).unwrap();
    assert!(crate::gate::decode::decode_policy_manifest(&invalid).is_none());
}
