//! The agent definition family of the general grant act (Fable pass 28 R2d; Engine RULING
//! AGENT-DEF-OWN-LANE-FIX = B): a person's statement of an agent definition's switches, in
//! clear under `terms`. Only that family states switches, it does nothing else (no Grant
//! terms, no end), a rule never states them, and one statement has one byte form.

use oneiron_authority::authority::{
    ActSurface, AgentApproval, AgentSwitches, AuthorityOp, GRANT_ACT_SEEN, GrantActChange,
    GrantActRecord, GrantDecider, GrantFamily, MAX_STATED_MODEL_LEN, MAX_STATED_MODELS, OwnerAct,
    decode_op, op_value,
};
use oneiron_contracts::EntityId;
use rmpv::Value;

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("a valid entity id")
}

fn running() -> AgentSwitches {
    AgentSwitches {
        enabled: true,
        approval: AgentApproval::Approved,
        active: true,
        models: vec!["anthropic/claude".to_owned(), "openai/gpt".to_owned()],
        compaction_model: Some("anthropic/claude".to_owned()),
        model_tier: None,
        dreaming_model: Some("small".to_owned()),
    }
}

fn stated(switches: AgentSwitches) -> GrantActChange {
    GrantActChange::State { switches }
}

fn by_person(family: GrantFamily, change: GrantActChange) -> GrantActRecord {
    GrantActRecord {
        decider: GrantDecider::Person(OwnerAct::by_owner(
            id(0x11),
            change.act_kind(),
            id(0x33),
            ActSurface::ThisInstall,
            GRANT_ACT_SEEN,
        )),
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

fn entries(record: &GrantActRecord) -> Vec<(Value, Value)> {
    match op_value(&AuthorityOp::GrantAct(record.clone())) {
        Value::Map(entries) => entries,
        other => panic!("a grant act encodes as a map, not {other:?}"),
    }
}

fn terms_of(entries: &mut [(Value, Value)]) -> &mut Vec<(Value, Value)> {
    match entries
        .iter_mut()
        .find(|(name, _)| name.as_str() == Some("terms"))
        .map(|(_, value)| value)
    {
        Some(Value::Map(terms)) => terms,
        other => panic!("a statement's terms are a map, not {other:?}"),
    }
}

fn set(terms: &mut [(Value, Value)], key: &str, value: Value) {
    let slot = terms
        .iter_mut()
        .find(|(name, _)| name.as_str() == Some(key))
        .unwrap_or_else(|| panic!("key {key} present"));
    slot.1 = value;
}

/// Catches a codec that drops a switch, writes a choice not made as anything but nil, or
/// reads a value in another form than it writes.
#[test]
fn a_statement_round_trips_with_its_switches_in_clear() {
    let none_chosen = AgentSwitches {
        enabled: false,
        approval: AgentApproval::Rejected,
        active: false,
        models: Vec::new(),
        compaction_model: None,
        model_tier: None,
        dreaming_model: None,
    };
    for switches in [running(), none_chosen] {
        let record = by_person(GrantFamily::AgentDefinition, stated(switches.clone()));
        record.validate().expect("a statement of switches is valid");
        let mut encoded = entries(&record);
        let terms = terms_of(&mut encoded);
        let mut keys: Vec<&str> = terms.iter().filter_map(|(key, _)| key.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "active",
                "approval",
                "compaction_model",
                "dreaming_model",
                "enabled",
                "model_tier",
                "models",
            ]
        );
        let tier = terms
            .iter()
            .find(|(key, _)| key.as_str() == Some("model_tier"))
            .map(|(_, value)| value.clone());
        assert_eq!(tier, Some(Value::Nil), "a choice not made is nil");
        assert_eq!(
            decode_op(&Value::Map(encoded)).expect("the statement decodes"),
            AuthorityOp::GrantAct(record),
            "{switches:?}"
        );
    }
}

/// Catches an agent definition's line taking a Grant's giving or an end (an end would refuse
/// the owner's every later statement), switches stated for a Grant row, and a rule that
/// states them.
#[test]
fn only_an_agent_definition_act_states_switches_and_nothing_else() {
    let refused = [
        (
            "switches on a member row",
            by_person(GrantFamily::SharedMember, stated(running())),
        ),
        (
            "switches on the owner's agent Grant",
            by_person(GrantFamily::OwnerAgent, stated(running())),
        ),
        (
            "Grant terms on an agent definition",
            by_person(
                GrantFamily::AgentDefinition,
                GrantActChange::Give { terms: [0x44; 32] },
            ),
        ),
        (
            "a person's end of an agent definition",
            by_person(GrantFamily::AgentDefinition, GrantActChange::End),
        ),
        (
            "a rule's end of an agent definition",
            by_rule(GrantFamily::AgentDefinition, GrantActChange::End),
        ),
        (
            "a rule's statement",
            by_rule(GrantFamily::AgentDefinition, stated(running())),
        ),
    ];
    for (case, record) in refused {
        assert!(record.validate().is_err(), "{case} is refused");
    }
    assert_eq!(
        GrantFamily::from_name(GrantFamily::AgentDefinition.as_str()),
        Some(GrantFamily::AgentDefinition)
    );
}

/// Catches two byte forms of one statement (an unsorted or doubled model list), an empty or
/// unbounded model id, and a list longer than a statement takes, at validate and at decode.
#[test]
fn a_statement_has_one_byte_form() {
    let with = |edit: fn(&mut AgentSwitches)| {
        let mut switches = running();
        edit(&mut switches);
        by_person(GrantFamily::AgentDefinition, stated(switches))
    };
    let refused = [
        ("unsorted models", with(|s| s.models.reverse())),
        (
            "a model listed twice",
            with(|s| s.models.push("openai/gpt".to_owned())),
        ),
        (
            "an empty model id",
            with(|s| s.models.insert(0, String::new())),
        ),
        (
            "an unbounded model id",
            with(|s| s.models.push("z".repeat(MAX_STATED_MODEL_LEN + 1))),
        ),
        (
            "an empty tier",
            with(|s| s.model_tier = Some(String::new())),
        ),
        (
            "too many models",
            with(|s| {
                s.models = (0..=MAX_STATED_MODELS)
                    .map(|n| format!("model/{n:03}"))
                    .collect();
            }),
        ),
    ];
    for (case, record) in refused {
        assert!(record.validate().is_err(), "{case} is refused");
    }

    let well_formed = by_person(GrantFamily::AgentDefinition, stated(running()));
    let wire_cases: [(&str, fn(&mut Vec<(Value, Value)>)); 4] = [
        ("unsorted models on the wire", |terms| {
            set(
                terms,
                "models",
                Value::Array(vec![
                    Value::from("openai/gpt"),
                    Value::from("anthropic/claude"),
                ]),
            );
        }),
        ("an unknown approval", |terms| {
            set(terms, "approval", Value::from("blessed"));
        }),
        ("a missing switch", |terms| {
            terms.retain(|(key, _)| key.as_str() != Some("active"));
        }),
        ("a flag as text", |terms| {
            set(terms, "enabled", Value::from("yes"));
        }),
    ];
    for (case, edit) in wire_cases {
        let mut encoded = entries(&well_formed);
        edit(terms_of(&mut encoded));
        assert!(
            decode_op(&Value::Map(encoded)).is_err(),
            "{case} does not decode"
        );
    }
}
