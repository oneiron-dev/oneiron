//! The general grant act's wire and rule (Fable pass 28 R2): seven keys always, a nil act for a
//! rule's end and a nil `terms` for any end, and one rule per decider. A person gives or ends a
//! Grant of any family but the owner's agent Grant, whose mint and revoke are his own act; a
//! rule only ends that Grant; no giving commits to all-zero terms.

use oneiron_authority::authority::{
    ActBy, ActSurface, AuthorityOp, GRANT_ACT_SEEN, GrantActChange, GrantActRecord, GrantDecider,
    GrantFamily, OwnerAct, OwnerActKind, decode_op, op_value,
};
use oneiron_contracts::EntityId;
use rmpv::Value;

const FAMILIES: [GrantFamily; 5] = [
    GrantFamily::SharedMember,
    GrantFamily::Delegate,
    GrantFamily::HouseLink,
    GrantFamily::InquiryEdge,
    GrantFamily::OwnerAgent,
];

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("a valid entity id")
}

fn person_act(change: GrantActChange, subject: EntityId) -> OwnerAct {
    OwnerAct::by_owner(
        id(0x11),
        change.act_kind(),
        subject,
        ActSurface::ThisInstall,
        GRANT_ACT_SEEN,
    )
}

fn by_person(family: GrantFamily, change: GrantActChange) -> GrantActRecord {
    GrantActRecord {
        decider: GrantDecider::Person(person_act(change, id(0x33))),
        machine: id(0x22),
        subject: id(0x33),
        family,
        change,
    }
}

fn by_rule(family: GrantFamily, change: GrantActChange) -> GrantActRecord {
    GrantActRecord {
        decider: GrantDecider::Rule,
        machine: id(0x22),
        subject: id(0x33),
        family,
        change,
    }
}

const GIVE: GrantActChange = GrantActChange::Give { terms: [0x44; 32] };

fn entries(record: &GrantActRecord) -> Vec<(Value, Value)> {
    match op_value(&AuthorityOp::GrantAct(record.clone())) {
        Value::Map(entries) => entries,
        other => panic!("a grant act encodes as a map, not {other:?}"),
    }
}

fn value_of<'a>(entries: &'a [(Value, Value)], key: &str) -> &'a Value {
    &entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .unwrap_or_else(|| panic!("key {key} present"))
        .1
}

fn decodes(entries: Vec<(Value, Value)>) -> bool {
    decode_op(&Value::Map(entries)).is_ok()
}

/// Catches a codec that drops a key, writes a key for one change only, or reads a value in
/// another form than it writes.
#[test]
fn every_grant_act_round_trips_in_seven_keys() {
    let records = [
        by_person(GrantFamily::SharedMember, GIVE),
        by_person(GrantFamily::InquiryEdge, GrantActChange::End),
        by_rule(GrantFamily::OwnerAgent, GrantActChange::End),
    ];
    for record in records {
        let encoded = entries(&record);
        let keys: Vec<_> = encoded.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            [
                Some("kind"),
                Some("act"),
                Some("machine"),
                Some("subject"),
                Some("family"),
                Some("change"),
                Some("terms"),
            ],
            "{record:?}"
        );
        assert_eq!(value_of(&encoded, "kind").as_str(), Some("grant_act"));
        assert_eq!(
            value_of(&encoded, "act").is_nil(),
            record.decider == GrantDecider::Rule,
            "a nil act is a rule's, and only a rule's"
        );
        match record.change {
            GrantActChange::Give { terms } => {
                assert_eq!(value_of(&encoded, "terms"), &Value::Binary(terms.to_vec()));
            }
            GrantActChange::End => assert!(value_of(&encoded, "terms").is_nil()),
        }
        assert_eq!(
            decode_op(&Value::Map(encoded)).expect("the act decodes"),
            AuthorityOp::GrantAct(record)
        );
    }
}

/// Catches a decoder that accepts a key short or over, terms in another form, a giving with
/// no terms, an end with terms, an unknown family, or a non-canonical id.
#[test]
fn a_grant_act_in_any_other_form_does_not_decode() {
    let give = entries(&by_person(GrantFamily::SharedMember, GIVE));
    let end = entries(&by_person(GrantFamily::SharedMember, GrantActChange::End));
    let with = |base: &[(Value, Value)], key: &str, value: Value| {
        base.iter()
            .map(|(name, old)| {
                let value = if name.as_str() == Some(key) {
                    value.clone()
                } else {
                    old.clone()
                };
                (name.clone(), value)
            })
            .collect::<Vec<_>>()
    };
    let without_terms: Vec<_> = give
        .iter()
        .filter(|(name, _)| name.as_str() != Some("terms"))
        .cloned()
        .collect();
    let mut extra = give.clone();
    extra.push((Value::from("seen"), Value::Binary(vec![0; 32])));
    let upper = id(0x3a).to_hex().to_uppercase();
    let cases = [
        ("six keys", without_terms),
        ("eight keys", extra),
        ("terms as text", with(&give, "terms", Value::from("44"))),
        (
            "terms of 31 bytes",
            with(&give, "terms", Value::Binary(vec![0x44; 31])),
        ),
        ("a giving with nil terms", with(&give, "terms", Value::Nil)),
        (
            "an end with terms",
            with(&end, "terms", Value::Binary(vec![0x44; 32])),
        ),
        (
            "an unknown family",
            with(&give, "family", Value::from("owner")),
        ),
        (
            "an unknown change",
            with(&give, "change", Value::from("widen")),
        ),
        (
            "an upper-case subject",
            with(&give, "subject", Value::from(upper)),
        ),
    ];
    for (case, entries) in cases {
        assert!(!decodes(entries), "{case} decodes");
    }
}

/// Catches a rule that lets a person give or end the owner's agent Grant by this act, lets a
/// rule give any Grant, refuses a rule's end of any family (a direct delete of a member row or
/// a house link ends it by rule, GRANT-ROW-DELETE-NO-END = A), or lets a giving commit to
/// nothing.
#[test]
fn each_decider_gives_and_ends_only_what_its_rule_admits() {
    for family in FAMILIES {
        let person = family != GrantFamily::OwnerAgent;
        assert_eq!(
            by_person(family, GIVE).validate().is_ok(),
            person,
            "{family:?}"
        );
        assert_eq!(
            by_person(family, GrantActChange::End).validate().is_ok(),
            person,
            "{family:?}"
        );
        assert!(
            by_rule(family, GIVE).validate().is_err(),
            "a rule gives {family:?}"
        );
        assert!(
            by_rule(family, GrantActChange::End).validate().is_ok(),
            "a rule cannot end {family:?}"
        );
    }
    let nothing = GrantActChange::Give { terms: [0; 32] };
    assert!(
        by_person(GrantFamily::SharedMember, nothing)
            .validate()
            .is_err(),
        "a giving commits to all-zero terms"
    );
}

/// Catches a person's act that names another kind or row, an agent's or an ask's act, or a
/// stale `seen`.
#[test]
fn a_persons_act_is_their_own_say_so_on_this_row() {
    let base = by_person(GrantFamily::SharedMember, GIVE);
    let altered = |alter: fn(&mut OwnerAct)| {
        let mut record = base.clone();
        let GrantDecider::Person(act) = &mut record.decider else {
            unreachable!("a person's act");
        };
        alter(act);
        record
    };
    assert!(base.validate().is_ok());
    let cases: [(&str, fn(&mut OwnerAct)); 6] = [
        ("an end's kind on a giving", |act| {
            act.act = OwnerActKind::GrantEnd;
        }),
        ("an agent Grant mint's kind", |act| {
            act.act = OwnerActKind::GrantMint;
        }),
        ("another row", |act| act.target = id(0x55)),
        ("an agent's act", |act| {
            act.by = ActBy::Agent {
                agent: id(0x77),
                grant: id(0x33),
            };
        }),
        ("an answered ask", |act| act.answer = Some(id(0x66))),
        ("a seen revision", |act| act.seen = [1; 32]),
    ];
    for (case, alter) in cases {
        assert!(altered(alter).validate().is_err(), "{case} validates");
    }
}
