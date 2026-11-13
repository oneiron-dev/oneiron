//! Engine RULING L6-03-WRITER-CARRY (14 Nov 06:16, "A now, C next"): the
//! person who wrote a found key and ruled it no secret carries the revoke
//! to the owner's other machines as their own act, `ActBy::Person`, never
//! as the owner's. A person's own act carries that one change and nothing
//! else, and its wire map keeps the key set every signed entry was written
//! with.
//!
//! `cargo test --locked -p oneiron-authority --test person_custody_revoke_act`.

use oneiron_authority::authority::{
    ActBy, ActSurface, CustodyChange, CustodyPermitSet, CustodyRecipientPermit,
    CustodyRequestAuthority, OwnerAct, OwnerActKind, OwnerWorkBody, OwnerWorkRequest,
    owner_act_from_value, owner_act_to_value,
};
use oneiron_contracts::EntityId;
use rmpv::Value;

/// The keys of an act's wire map, in their order.
const ACT_KEYS: [&str; 10] = [
    "owner",
    "by",
    "agent",
    "grant",
    "surface",
    "surface_machine",
    "act",
    "target",
    "seen",
    "answer",
];

fn keys(map: &Value) -> Vec<&str> {
    map.as_map()
        .expect("an act is a map")
        .iter()
        .map(|(key, _)| key.as_str().expect("a string key"))
        .collect()
}

fn field<'a>(map: &'a Value, key: &str) -> &'a Value {
    map.as_map()
        .expect("an act is a map")
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("the act map has no {key}"))
}

/// The byte-free revoke a carrier records and enacts itself.
fn revoke() -> OwnerWorkBody {
    OwnerWorkBody::Custody {
        change: CustodyChange::Revoke,
        generation: 0,
        input: None,
        holder: None,
        recipients: CustodyPermitSet::default(),
        pieces: None,
        authority: CustodyRequestAuthority::Install,
    }
}

/// An active change of `change` whose bytes `holder` holds and seals to
/// itself.
fn active(change: CustodyChange, holder: EntityId) -> OwnerWorkBody {
    OwnerWorkBody::Custody {
        change,
        generation: 1,
        input: Some([1; 32]),
        holder: Some(holder),
        recipients: CustodyPermitSet::from(vec![CustodyRecipientPermit {
            machine: holder,
            profile: [2; 32],
            encryption_key: [3; 32],
        }]),
        pieces: None,
        authority: CustodyRequestAuthority::Install,
    }
}

fn request(
    act: OwnerAct,
    carrier: EntityId,
    executor: EntityId,
    work: OwnerWorkBody,
) -> OwnerWorkRequest {
    OwnerWorkRequest {
        carrier,
        act,
        executor,
        work,
        privacy_basis: None,
    }
}

#[test]
fn a_persons_own_custody_revoke_round_trips_as_their_act() {
    let writer = EntityId::now();
    let secret = EntityId::now();
    let act = OwnerAct::by_person(
        writer,
        OwnerActKind::CustodyTransition,
        secret,
        ActSurface::ThisInstall,
        [5; 32],
    );
    assert_eq!(act.by, ActBy::Person);
    assert_eq!(act.owner, writer, "a person's own act names the person");
    let map = owner_act_to_value(&act);
    assert_eq!(
        keys(&map),
        ACT_KEYS,
        "the key set every entry was written with"
    );
    assert_eq!(field(&map, "by").as_str(), Some("person"));
    assert_eq!(
        field(&map, "owner").as_str(),
        Some(writer.to_hex().as_str())
    );
    assert_eq!(
        field(&map, "agent"),
        &Value::Nil,
        "a person act names no agent"
    );
    assert_eq!(
        field(&map, "grant"),
        &Value::Nil,
        "a person act names no Grant"
    );
    assert_eq!(
        owner_act_from_value(&map).expect("a person act decodes"),
        act,
        "the person act reads back as written"
    );
}

#[test]
fn owner_and_agent_acts_keep_their_wire_maps() {
    let owner = EntityId::now();
    let target = EntityId::now();
    let by_owner = OwnerAct::by_owner(
        owner,
        OwnerActKind::CustodyTransition,
        target,
        ActSurface::ThisInstall,
        [5; 32],
    );
    let map = owner_act_to_value(&by_owner);
    assert_eq!(keys(&map), ACT_KEYS);
    assert_eq!(field(&map, "by").as_str(), Some("owner"));
    assert_eq!(field(&map, "agent"), &Value::Nil);
    assert_eq!(field(&map, "grant"), &Value::Nil);
    assert_eq!(owner_act_from_value(&map).expect("an owner act"), by_owner);

    let (agent, grant) = (EntityId::now(), EntityId::now());
    let by_agent = OwnerAct {
        by: ActBy::Agent { agent, grant },
        act: OwnerActKind::WorldPrivacy,
        ..by_owner
    };
    let map = owner_act_to_value(&by_agent);
    assert_eq!(keys(&map), ACT_KEYS);
    assert_eq!(field(&map, "by").as_str(), Some("agent"));
    assert_eq!(field(&map, "agent").as_str(), Some(agent.to_hex().as_str()));
    assert_eq!(field(&map, "grant").as_str(), Some(grant.to_hex().as_str()));
    assert_eq!(owner_act_from_value(&map).expect("an agent act"), by_agent);

    // A person act that names an agent or a Grant is no act at all.
    let mut forged = owner_act_to_value(&OwnerAct {
        by: ActBy::Person,
        ..by_owner
    });
    if let Value::Map(entries) = &mut forged {
        for (key, value) in entries.iter_mut() {
            if key.as_str() == Some("agent") {
                *value = Value::from(agent.to_hex());
            }
        }
    }
    assert!(
        owner_act_from_value(&forged).is_err(),
        "a person act naming an agent is refused"
    );
}

#[test]
fn a_person_may_revoke_custody_and_nothing_else() {
    let (writer, owner) = (EntityId::now(), EntityId::now());
    let (secret, machine) = (EntityId::now(), EntityId::now());
    let kind = OwnerActKind::CustodyTransition;
    let surface = ActSurface::ThisInstall;
    let person = OwnerAct::by_person(writer, kind, secret, surface, [5; 32]);
    let by_owner = OwnerAct::by_owner(owner, kind, secret, surface, [5; 32]);

    // The revoke, carried and enacted by one install, is the person's.
    assert!(
        request(by_owner, machine, machine, revoke())
            .validate()
            .is_ok()
    );
    request(person, machine, machine, revoke())
        .validate()
        .expect("a person's own custody revoke is admitted");

    // Every active change stays the owner's.
    for change in [
        CustodyChange::Register,
        CustodyChange::Rotate,
        CustodyChange::Rewrap,
    ] {
        request(by_owner, machine, machine, active(change, machine))
            .validate()
            .unwrap_or_else(|error| {
                panic!("FIXTURE: the owner's {change:?} is well formed: {error:?}")
            });
        assert!(
            request(person, machine, machine, active(change, machine))
                .validate()
                .is_err(),
            "a person's own {change:?} is refused"
        );
    }

    // An agent's custody revoke stays refused: no Grant line names it.
    let by_agent = OwnerAct {
        by: ActBy::Agent {
            agent: EntityId::now(),
            grant: EntityId::now(),
        },
        ..by_owner
    };
    assert!(
        request(by_agent, machine, machine, revoke())
            .validate()
            .is_err()
    );

    // A person's own act carries no other kind, and answers no ask.
    let setting = OwnerAct {
        act: OwnerActKind::PolicySetting,
        ..person
    };
    assert!(
        setting
            .validate_carried(OwnerActKind::PolicySetting, secret)
            .is_err()
    );
    assert!(
        OwnerAct {
            act: OwnerActKind::PolicySetting,
            ..by_owner
        }
        .validate_carried(OwnerActKind::PolicySetting, secret)
        .is_ok(),
        "FIXTURE: the owner's setting act is carried"
    );
    let answering = OwnerAct {
        answer: Some(EntityId::now()),
        ..person
    };
    assert!(answering.validate_carried(kind, secret).is_err());
    assert!(person.validate_carried(kind, secret).is_ok());
}
