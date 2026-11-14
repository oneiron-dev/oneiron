//! Engine RULING 14 Nov 16:48 (PLAN-SEALED-FILE-RULING-CARRY = A): the
//! owner's "not a secret" on a file the write door sealed whole reaches every
//! install of his vault as an owner work request of its own kind,
//! `file_ruling`, whose act is `sealed_file_ruling`. The request names the
//! file by one keyed digest and nothing else, never its plain hash. The act is
//! the owner's alone, on a zero `seen`, and the install that carries it is
//! the one that executes it.
//!
//! The maps are written out as an entry carries them, so the test reads the
//! wire and not only the types.
//!
//! `cargo test --locked -p oneiron-authority --test sealed_file_ruling_work`.

use oneiron_authority::authority::{
    ActSurface, AuthorityOp, CustodyChange, CustodyPermitSet, CustodyRequestAuthority, OwnerAct,
    OwnerActKind, OwnerWorkBody, OwnerWorkRequest, decode_op, op_value,
};
use oneiron_contracts::EntityId;
use rmpv::Value;

const DIGEST: [u8; 32] = [7; 32];

fn entry_mut<'a>(map: &'a mut Value, key: &str) -> &'a mut Value {
    let Value::Map(entries) = map else {
        panic!("a map");
    };
    entries
        .iter_mut()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("the map has no {key}"))
}

fn work_map(digest: Value) -> Value {
    Value::Map(vec![
        (Value::from("kind"), Value::from("file_ruling")),
        (Value::from("digest"), digest),
    ])
}

/// A sealed-file ruling's request entry as `machine` carries and executes it
/// for `owner`, on the file's ASSET `record`. It is written from a revoke's
/// entry, with its act kind, its `seen` and its work map put in.
fn ruling_op(owner: EntityId, record: EntityId, machine: EntityId) -> Value {
    let act = OwnerAct::by_owner(
        owner,
        OwnerActKind::CustodyTransition,
        record,
        ActSurface::ThisInstall,
        [5; 32],
    );
    let revoke = OwnerWorkRequest {
        carrier: machine,
        act,
        executor: machine,
        work: OwnerWorkBody::Custody {
            change: CustodyChange::Revoke,
            generation: 0,
            input: None,
            holder: None,
            recipients: CustodyPermitSet::default(),
            pieces: None,
            authority: CustodyRequestAuthority::Install,
            screen: None,
        },
        privacy_basis: None,
    };
    let mut op = op_value(&AuthorityOp::OwnerWorkRequest(revoke));
    let carried = entry_mut(&mut op, "act");
    *entry_mut(carried, "act") = Value::from("sealed_file_ruling");
    *entry_mut(carried, "seen") = Value::Binary(vec![0; 32]);
    *entry_mut(&mut op, "work") = work_map(Value::Binary(DIGEST.to_vec()));
    op
}

fn ids() -> (EntityId, EntityId, EntityId) {
    (EntityId::now(), EntityId::now(), EntityId::now())
}

/// The request `op` reads as, which must decode.
fn decoded(op: &Value) -> OwnerWorkRequest {
    match decode_op(op) {
        Ok(AuthorityOp::OwnerWorkRequest(request)) => request,
        other => panic!("a sealed-file ruling's request decodes: {other:?}"),
    }
}

#[test]
fn a_sealed_file_ruling_reads_back_as_written() {
    let (owner, record, machine) = ids();
    let op = ruling_op(owner, record, machine);
    let request = decoded(&op);
    assert_eq!(request.kind().as_str(), "file_ruling");
    assert_eq!(request.act.act.as_str(), "sealed_file_ruling");
    assert_eq!(
        OwnerActKind::from_name("sealed_file_ruling"),
        Some(request.act.act),
        "the act kind has its own wire tag"
    );
    assert_eq!(request.kind().act(), request.act.act);
    assert_eq!(
        request.act.target, record,
        "the act targets the file's record"
    );
    assert_eq!(request.executor, request.carrier);
    request
        .validate()
        .expect("a sealed-file ruling's request is well formed");
    assert_eq!(
        op_value(&AuthorityOp::OwnerWorkRequest(request)),
        op,
        "the request encodes back to the same entry"
    );
}

#[test]
fn a_sealed_file_ruling_names_its_digest_and_nothing_else() {
    let (owner, record, machine) = ids();
    let op = ruling_op(owner, record, machine);
    decoded(&op);

    let mut with_hash = op.clone();
    let Value::Map(work) = entry_mut(&mut with_hash, "work") else {
        panic!("a work map");
    };
    work.push((Value::from("hash"), Value::Binary(vec![9; 32])));
    assert!(
        decode_op(&with_hash).is_err(),
        "a work map with any other key is refused"
    );

    let mut zero = op.clone();
    *entry_mut(&mut zero, "work") = work_map(Value::Binary(vec![0; 32]));
    assert!(decode_op(&zero).is_err(), "a zero digest names no file");

    let mut short = op;
    *entry_mut(&mut short, "work") = work_map(Value::Binary(vec![7; 16]));
    assert!(decode_op(&short).is_err(), "a digest is 32 bytes");
}

#[test]
fn a_sealed_file_ruling_is_the_owners_own_on_a_zero_seen_by_its_carrier() {
    let (owner, record, machine) = ids();
    let op = ruling_op(owner, record, machine);
    decoded(&op);

    let mut by_person = op.clone();
    *entry_mut(entry_mut(&mut by_person, "act"), "by") = Value::from("person");
    assert!(
        decode_op(&by_person).is_err(),
        "a person's act never rules a sealed file"
    );

    let mut seen = op.clone();
    *entry_mut(entry_mut(&mut seen, "act"), "seen") = Value::Binary(vec![5; 32]);
    assert!(decode_op(&seen).is_err(), "a ruling's seen is zero");

    let mut elsewhere = op;
    *entry_mut(&mut elsewhere, "executor") = Value::from(EntityId::now().to_hex());
    assert!(
        decode_op(&elsewhere).is_err(),
        "the install that carries a ruling executes it"
    );
}
