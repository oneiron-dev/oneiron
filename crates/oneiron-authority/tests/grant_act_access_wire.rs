//! The access grant family of the general grant act (Fable pass 28 R2e; Engine RULING SR-5
//! ACCESS-GRANT-KIND = A): an ACCESS_GRANT row's write gives its whole body by a keyed
//! commitment, and its erase ends it. A person decides it, or an agent within its own Grant;
//! no other family takes an agent's act, and a rule only ends.

use oneiron_authority::authority::{
    ActBy, ActSurface, AuthorityOp, GRANT_ACT_SEEN, GrantActChange, GrantActRecord, GrantDecider,
    GrantFamily, OwnerAct, decode_op, op_value,
};
use oneiron_contracts::EntityId;

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("a valid entity id")
}

fn give() -> GrantActChange {
    GrantActChange::Give { terms: [0x5a; 32] }
}

fn act(by: ActBy, change: &GrantActChange) -> OwnerAct {
    OwnerAct {
        owner: id(0x11),
        by,
        surface: ActSurface::ThisInstall,
        act: change.act_kind(),
        target: id(0x33),
        seen: GRANT_ACT_SEEN,
        answer: None,
    }
}

fn record(family: GrantFamily, by: ActBy, change: GrantActChange) -> GrantActRecord {
    GrantActRecord {
        decider: GrantDecider::Person(act(by, &change)),
        machine: id(0x22),
        subject: id(0x33),
        family,
        change,
    }
}

fn agent() -> ActBy {
    ActBy::Agent {
        agent: id(0x44),
        grant: id(0x55),
    }
}

fn round_trip(record: &GrantActRecord) {
    record.validate().expect("the act is valid");
    let encoded = op_value(&AuthorityOp::GrantAct(record.clone()));
    assert_eq!(
        decode_op(&encoded).expect("the act decodes"),
        AuthorityOp::GrantAct(record.clone())
    );
}

#[test]
fn an_access_grant_family_names_itself_on_the_wire() {
    assert_eq!(GrantFamily::AccessGrant.as_str(), "access_grant");
    assert_eq!(
        GrantFamily::from_name("access_grant"),
        Some(GrantFamily::AccessGrant)
    );
}

#[test]
fn a_person_gives_and_ends_an_access_grant() {
    round_trip(&record(GrantFamily::AccessGrant, ActBy::Owner, give()));
    round_trip(&record(
        GrantFamily::AccessGrant,
        ActBy::Owner,
        GrantActChange::End,
    ));
}

#[test]
fn an_agent_within_its_own_grant_gives_an_access_grant_and_is_named() {
    let given = record(GrantFamily::AccessGrant, agent(), give());
    round_trip(&given);
    let GrantDecider::Person(act) = &given.decider else {
        panic!("an agent's act names a person's act");
    };
    assert_eq!(act.by, agent(), "the act names the agent, not the person");
    assert_eq!(given.decider_person(), Some(id(0x11)));
}

#[test]
fn no_other_family_takes_an_agents_act() {
    for family in [
        GrantFamily::SharedMember,
        GrantFamily::Delegate,
        GrantFamily::HouseLink,
        GrantFamily::InquiryEdge,
        GrantFamily::OwnerAgent,
    ] {
        assert!(
            record(family, agent(), give()).validate().is_err(),
            "an agent's giving in {family:?} is refused"
        );
        assert!(
            record(family, agent(), GrantActChange::End)
                .validate()
                .is_err(),
            "an agent's end in {family:?} is refused"
        );
    }
}

#[test]
fn a_rule_ends_an_access_grant_and_never_gives_one() {
    let ended = GrantActRecord {
        decider: GrantDecider::Rule,
        machine: id(0x22),
        subject: id(0x33),
        family: GrantFamily::AccessGrant,
        change: GrantActChange::End,
    };
    round_trip(&ended);
    let given = GrantActRecord {
        change: give(),
        ..ended
    };
    assert!(given.validate().is_err(), "a rule's giving is refused");
}

#[test]
fn an_agents_act_answering_an_ask_is_refused() {
    let mut answered = record(GrantFamily::AccessGrant, agent(), give());
    if let GrantDecider::Person(act) = &mut answered.decider {
        act.answer = Some(id(0x66));
    }
    assert!(answered.validate().is_err());
}
