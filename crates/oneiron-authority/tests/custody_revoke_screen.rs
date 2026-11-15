//! Engine RULING 14 Nov 08:35 (NEXT-ROW-15 = A, L6-03-RULED-SCREEN-LOCAL):
//! a found-key ruling must hold on all of the owner's machines. The revoke
//! the ruling carries names the record and a keyed digest of the ruled value,
//! never the value. Only an install's revoke carries a screen, a screen's
//! digest is never zero, and a request with no screen keeps the key set
//! every signed entry was written with.
//!
//! `cargo test --locked -p oneiron-authority --test custody_revoke_screen`.

use oneiron_authority::authority::{
    ActSurface, AuthorityOp, CustodyChange, CustodyPermitSet, CustodyRecipientPermit,
    CustodyRequestAuthority, CustodyRevokeScreen, OwnerAct, OwnerActKind, OwnerWorkBody,
    OwnerWorkRequest, RecoveryRootId, decode_op, op_value,
};
use oneiron_contracts::EntityId;
use rmpv::Value;

/// The keys of a custody work map, in their order, before the screen.
const CUSTODY_KEYS: [&str; 7] = [
    "kind",
    "change",
    "generation",
    "input",
    "holder",
    "recipients",
    "authority",
];

fn entry<'a>(map: &'a Value, key: &str) -> &'a Value {
    map.as_map()
        .expect("a map")
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("the map has no {key}"))
}

/// The work map of `request` as its entry carries it.
fn work_keys(request: &OwnerWorkRequest) -> Vec<String> {
    let op = op_value(&AuthorityOp::OwnerWorkRequest(request.clone()));
    entry(&op, "work")
        .as_map()
        .expect("a work map")
        .iter()
        .map(|(key, _)| key.as_str().expect("a string key").to_owned())
        .collect()
}

fn round_trips(request: &OwnerWorkRequest) {
    let op = AuthorityOp::OwnerWorkRequest(request.clone());
    let decoded = decode_op(&op_value(&op)).expect("the request decodes");
    assert_eq!(decoded, op, "the request reads back as written");
}

fn revoke(screen: Option<CustodyRevokeScreen>) -> OwnerWorkBody {
    OwnerWorkBody::Custody {
        change: CustodyChange::Revoke,
        generation: 0,
        input: None,
        holder: None,
        recipients: CustodyPermitSet::default(),
        pieces: None,
        authority: CustodyRequestAuthority::Install,
        screen,
    }
}

fn active(
    change: CustodyChange,
    holder: EntityId,
    screen: Option<CustodyRevokeScreen>,
) -> OwnerWorkBody {
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
        screen,
    }
}

fn request(act: OwnerAct, machine: EntityId, work: OwnerWorkBody) -> OwnerWorkRequest {
    OwnerWorkRequest {
        carrier: machine,
        act,
        executor: machine,
        work,
        privacy_basis: None,
    }
}

fn screen() -> CustodyRevokeScreen {
    CustodyRevokeScreen {
        record: EntityId::now(),
        digest: [7; 32],
    }
}

#[test]
fn a_rulings_revoke_carries_its_screen_and_reads_it_back() {
    let (owner, writer) = (EntityId::now(), EntityId::now());
    let (secret, machine) = (EntityId::now(), EntityId::now());
    let kind = OwnerActKind::CustodyTransition;
    let surface = ActSurface::ThisInstall;
    let screen = screen();
    for act in [
        OwnerAct::by_owner(owner, kind, secret, surface, [5; 32]),
        OwnerAct::by_person(writer, kind, secret, surface, [5; 32]),
    ] {
        let screened = request(act, machine, revoke(Some(screen)));
        screened
            .validate()
            .expect("an install's revoke carries a ruling's screen");
        let mut keys = CUSTODY_KEYS.map(str::to_owned).to_vec();
        keys.push("screen".to_owned());
        assert_eq!(work_keys(&screened), keys, "the screen rides last");
        let op = op_value(&AuthorityOp::OwnerWorkRequest(screened.clone()));
        let carried = entry(entry(&op, "work"), "screen");
        assert_eq!(
            entry(carried, "record").as_str(),
            Some(screen.record.to_hex().as_str())
        );
        assert_eq!(
            entry(carried, "digest"),
            &Value::Binary(screen.digest.to_vec())
        );
        round_trips(&screened);
    }
}

#[test]
fn a_request_with_no_screen_keeps_its_key_set() {
    let owner = EntityId::now();
    let (secret, machine) = (EntityId::now(), EntityId::now());
    let act = OwnerAct::by_owner(
        owner,
        OwnerActKind::CustodyTransition,
        secret,
        ActSurface::ThisInstall,
        [5; 32],
    );
    for work in [
        revoke(None),
        active(CustodyChange::Register, machine, None),
        active(CustodyChange::Rotate, machine, None),
    ] {
        let plain = request(act, machine, work);
        plain.validate().expect("FIXTURE: a well-formed request");
        assert_eq!(
            work_keys(&plain),
            CUSTODY_KEYS.map(str::to_owned).to_vec(),
            "no screen key, as every entry before the screen was written"
        );
        round_trips(&plain);
    }
}

#[test]
fn only_an_installs_revoke_carries_a_screen() {
    let owner = EntityId::now();
    let (secret, machine) = (EntityId::now(), EntityId::now());
    let act = OwnerAct::by_owner(
        owner,
        OwnerActKind::CustodyTransition,
        secret,
        ActSurface::ThisInstall,
        [5; 32],
    );
    for change in [
        CustodyChange::Register,
        CustodyChange::Rotate,
        CustodyChange::Rewrap,
    ] {
        request(act, machine, active(change, machine, None))
            .validate()
            .unwrap_or_else(|error| panic!("FIXTURE: a well-formed {change:?}: {error:?}"));
        assert!(
            request(act, machine, active(change, machine, Some(screen())))
                .validate()
                .is_err(),
            "a {change:?} carries no screen"
        );
    }
    let zero = CustodyRevokeScreen {
        digest: [0; 32],
        ..screen()
    };
    assert!(
        request(act, machine, revoke(Some(zero)))
            .validate()
            .is_err(),
        "a zero digest screens nothing"
    );
    // The kit's rewrap is the only kit request; it carries no screen.
    let kit = |screen| OwnerWorkBody::Custody {
        change: CustodyChange::Rewrap,
        generation: 1,
        input: None,
        holder: None,
        recipients: CustodyPermitSet::from(vec![CustodyRecipientPermit {
            machine,
            profile: [2; 32],
            encryption_key: [3; 32],
        }]),
        pieces: None,
        authority: CustodyRequestAuthority::PinnedKit {
            root: RecoveryRootId([9; 32]),
        },
        screen,
    };
    let kit_request = |work| OwnerWorkRequest {
        carrier: secret,
        act,
        executor: secret,
        work,
        privacy_basis: None,
    };
    kit_request(kit(None))
        .validate()
        .expect("FIXTURE: the kit's rewrap is well formed");
    assert!(
        kit_request(kit(Some(screen()))).validate().is_err(),
        "a kit request carries no screen"
    );
}
