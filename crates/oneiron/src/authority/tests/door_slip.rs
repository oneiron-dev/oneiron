//! Signed DAG replay and narrowing for door capability mints.
use super::support::*;
use super::*;

fn scope(class: &str, parent: Option<AuthorityEntryHash>, single_use: bool) -> AuthorityDoorSlip {
    AuthorityDoorSlip {
        holder_ref: "actor:registered".into(),
        verb_class: class.into(),
        records: ["secret.push".into()].into(),
        channels: ["door:receive-pack".into()].into(),
        parent,
        pact: None,
        issued_at: 10,
        expires_at: 100,
        single_use,
    }
}

#[test]
fn signed_child_cannot_widen_parent_class_and_spend_is_monotone_under_permutation() {
    let key = ed_key(21);
    let genesis = genesis_entry(21, DEFAULT_PENDING_WIDEN_DELAY_SECS, 0);
    let vault = genesis_vault_id(&genesis).unwrap();
    let mint = sign_ed(
        unsigned_entry(
            Some(vault),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::MintDoorSlip(scope("door.delegate", None, false)),
            authority_key_from_ed(&key),
            0,
        ),
        &key,
    );
    let mint_hash = authority_entry_hash(&mint).unwrap();
    let child = sign_ed(
        unsigned_entry(
            Some(vault),
            2,
            vec![mint_hash],
            AuthorityOp::MintDoorSlip(scope("door.redeem", Some(mint_hash), true)),
            authority_key_from_ed(&key),
            0,
        ),
        &key,
    );
    let child_hash = authority_entry_hash(&child).unwrap();
    let spend = sign_ed(
        unsigned_entry(
            Some(vault),
            3,
            vec![child_hash],
            AuthorityOp::SpendDoorSlip {
                mint_hash: child_hash,
            },
            authority_key_from_ed(&key),
            0,
        ),
        &key,
    );
    let entries = vec![genesis.clone(), mint.clone(), child.clone(), spend.clone()];
    let expected = fold_authority_log(&entries);
    for permutation in [
        vec![spend.clone(), child.clone(), genesis.clone(), mint.clone()],
        vec![
            mint.clone(),
            child.clone(),
            child.clone(),
            spend.clone(),
            genesis.clone(),
        ],
    ] {
        let folded = fold_authority_log(&permutation);
        assert_eq!(folded, expected);
        assert!(folded.live_door_slip(&child_hash).is_none());
        assert!(folded.live_door_slip(&mint_hash).is_some());
    }
    let invalid = sign_ed(
        unsigned_entry(
            Some(vault),
            4,
            vec![authority_entry_hash(&spend).unwrap()],
            AuthorityOp::MintDoorSlip(scope("door.delegate", Some(child_hash), false)),
            authority_key_from_ed(&key),
            0,
        ),
        &key,
    );
    let hash = authority_entry_hash(&invalid).unwrap();
    let mut entries = entries;
    entries.push(invalid);
    assert!(!fold_authority_log(&entries).valid_entries.contains(&hash));
}

#[test]
fn mint_wire_has_only_class_identifier_and_rejects_unknown_expanded_authority() {
    let key = ed_key(22);
    let genesis = genesis_entry(22, DEFAULT_PENDING_WIDEN_DELAY_SECS, 0);
    let mint = sign_ed(
        unsigned_entry(
            Some(genesis_vault_id(&genesis).unwrap()),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::MintDoorSlip(scope("door.redeem", None, true)),
            authority_key_from_ed(&key),
            0,
        ),
        &key,
    );
    let bytes = encode_authority_log_entry_body(&mint).unwrap();
    assert_eq!(decode_authority_log_entry_body(&bytes).unwrap(), mint);
    let mut malformed = mint.clone();
    if let AuthorityOp::MintDoorSlip(scope) = &mut malformed.op {
        scope.verb_class = "arbitrary-widen".into();
    }
    assert!(encode_authority_log_entry_body(&malformed).is_err());
    // Unknown fields are rejected even before they could be interpreted as
    // a signed expanded allow-list.
    let mut value = entry_value(&mint, true);
    let Value::Map(fields) = &mut value else {
        panic!("map");
    };
    let (_, Value::Map(op)) = fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("op"))
        .unwrap()
    else {
        panic!("op");
    };
    op.push((
        Value::from("verbs"),
        Value::Array(vec![Value::from("mint")]),
    ));
    let mut hostile = Vec::new();
    rmpv::encode::write_value(&mut hostile, &value).unwrap();
    assert!(decode_authority_log_entry_body(&hostile).is_err());
}
