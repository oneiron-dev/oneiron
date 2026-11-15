//! [AUDIT-READ-POWER] (Engine RULING AUDITREAD-GRANT-HOME = A, 15 Nov 22:00):
//! an audit_read grant ends only through the owner's own revoke
//! (`vault.audit_read.revoke`), which records his act. Astra delta review
//! auditread-8435-pr1-delta found removals that pass neither delete guard of
//! the first fix:
//!
//! - D1: a peer's replayed tombstone, soft or hard, and a carried Shell
//!   cutoff remove or shell the grant on a receiving machine;
//! - D2: a delete whose header read found no row takes the headerless leg,
//!   and purges a grant the owner wrote after that read;
//! - D4: a DerivedFrom edge from the grant to a disposable row, then that
//!   row's deletion, marks the grant stale; the guard then read the stale
//!   grant as a shell, and a batch delete removed it.
//!
//! Each removal is refused, or leaves the grant as it was: the holder still
//! reads, the grant's history stays listed, and the owner's revoke still
//! finds it standing. Verbs go through the generated verb dispatch
//! (`task_verb::sdk::invoke`); the D1 and D2 removals go through the doors in
//! `oneiron::test_doors::audit_read_removal`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test audit_read_removal`
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::audit_read_removal::{
    delete_past_the_header_read, replay_peer_tombstone, withdraw_on_received_shell_cutoff,
};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CHALLENGE: &[u8] = b"oneiron-request:audit-read-removal";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
}

/// A device vault on a manual clock set to the wall clock, with its host root
/// and embedded owner.
fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let clock = ManualClock::new(start);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-audit-read-removal")?;
    vault.ensure_host_root_slip(&issuer)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(Fixture {
        _dir: dir,
        vault,
        issuer,
        owner,
    })
}

fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// A live PERSON, not the owner, with no power.
fn person(fixture: &Fixture, name: &str) -> Result<EntityId, Box<dyn std::error::Error>> {
    let person = EntityId::now();
    fixture.vault.put_entity(
        &person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        name.as_bytes(),
    )?;
    Ok(person)
}

/// The live `human` credential this host mints `holder`, with the host root's
/// whole reach, verified as a transport verifies it.
fn credential(
    fixture: &Fixture,
    holder: EntityId,
) -> Result<VerifiedSlip, Box<dyn std::error::Error>> {
    let root = fixture.vault.ensure_host_root_slip(&fixture.issuer)?;
    let mut claims = root.claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.records = BTreeSet::new();
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)?;
    let binding = fixture.issuer.binding_proof(&slip, CHALLENGE)?;
    Ok(fixture.vault.verify_capability_slip(
        &fixture.issuer.public_key(),
        &slip,
        CHALLENGE,
        &binding,
    )?)
}

/// The owner's own embedded handle.
fn owner(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

/// `person`'s handle, bound to its own live credential.
fn bound<'v>(fixture: &'v Fixture, person: EntityId, proof: &VerifiedSlip) -> Memory<'v> {
    fixture
        .vault
        .memory(person, EdgeActorClass::Human)
        .with_read_proof(proof)
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn refused(memory: &Memory<'_>, verb: &str, input: Value) -> MemoryError {
    match invoke(memory, verb, input) {
        Ok(answer) => panic!("{verb} is refused, but answered {answer}"),
        Err(error) => error,
    }
}

/// A holder with a live audit_read grant, and the grant's row.
struct Granted {
    holder: EntityId,
    proof: VerifiedSlip,
    grant_ref: EntityId,
}

/// The owner grants a new PERSON the audit_read power, with no end.
fn granted(fixture: &Fixture) -> Result<Granted, Box<dyn std::error::Error>> {
    let holder = person(fixture, "an auditor")?;
    let proof = credential(fixture, holder)?;
    let answer = call(
        &owner(fixture),
        "vault.audit_read.grant",
        json!({ "holder": holder.to_hex() }),
    );
    let grant_ref = EntityId::from_hex(
        answer["grant_ref"]
            .as_str()
            .ok_or("the grant names its row")?,
    )?;
    Ok(Granted {
        holder,
        proof,
        grant_ref,
    })
}

/// Whether `error` is the refusal that names the owner's revoke verb.
fn names_the_revoke<E: std::fmt::Display>(error: &E) -> bool {
    error.to_string().contains("vault.audit_read.revoke")
}

/// The grant stands as the owner made it, `when`: the holder still reads
/// the authority audit, a stranger is still refused, the owner's audit still
/// lists the grant's one act, and his revoke still finds it standing.
fn assert_the_grant_stands(fixture: &Fixture, granted: &Granted, when: &str) -> TestResult {
    let as_holder = bound(fixture, granted.holder, &granted.proof);
    let page = call(&as_holder, "vault.authority.audit", json!({}));
    assert!(
        page["audit_read_acts"].is_array(),
        "the holder still reads the authority audit {when}: {page}"
    );
    let stranger = person(fixture, "a stranger")?;
    let stranger_proof = credential(fixture, stranger)?;
    let refusal = refused(
        &bound(fixture, stranger, &stranger_proof),
        "vault.authority.audit",
        json!({}),
    );
    assert_eq!(
        refusal.code, MEMORY_CODE_FORBIDDEN,
        "a stranger is still refused {when}: {refusal:?}"
    );
    let owner_page = call(&owner(fixture), "vault.authority.audit", json!({}));
    let acts: Vec<(String, String)> = owner_page["audit_read_acts"]
        .as_array()
        .ok_or("the owner's page lists the audit_read acts")?
        .iter()
        .map(|row| {
            (
                row["grant_ref"].as_str().unwrap_or_default().to_owned(),
                row["change"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        acts,
        vec![(granted.grant_ref.to_hex(), "grant".to_owned())],
        "the grant's history stays listed {when}: {owner_page}"
    );
    let revoked = call(
        &owner(fixture),
        "vault.audit_read.revoke",
        json!({ "holder": granted.holder.to_hex() }),
    );
    assert_eq!(
        revoked["changed"],
        json!(true),
        "the owner's revoke still finds the grant standing {when}: {revoked}"
    );
    Ok(())
}

/// D1: a peer's tombstone carries no owner act. Replayed here, a soft or a
/// hard one is refused by the replay's protection gate, and the grant stands.
#[test]
fn a_replayed_peer_tombstone_removes_no_audit_read_grant() -> TestResult {
    let fixture = fixture()?;
    let granted = granted(&fixture)?;
    for hard in [false, true] {
        let replay = replay_peer_tombstone(&fixture.vault, &granted.grant_ref, hard);
        assert!(
            replay.as_ref().is_err_and(names_the_revoke),
            "a replayed peer tombstone (hard: {hard}) is refused: {replay:?}"
        );
    }
    assert_the_grant_stands(&fixture, &granted, "after the replayed tombstones")
}

/// D1: a Shell cutoff another machine carries is no owner act either. It
/// withdraws nothing of the grant, which stays live and whole.
#[test]
fn a_carried_shell_cutoff_withdraws_no_audit_read_grant() -> TestResult {
    let fixture = fixture()?;
    let granted = granted(&fixture)?;
    let withdrew = withdraw_on_received_shell_cutoff(&fixture.vault, &granted.grant_ref)?;
    assert!(
        !withdrew,
        "a carried Shell cutoff withdraws no audit_read grant"
    );
    assert_the_grant_stands(&fixture, &granted, "after the carried Shell cutoff")
}

/// D2: a delete whose header read found no row reaches the headerless leg.
/// A grant the owner wrote after that read is refused there, soft or purged.
#[test]
fn a_delete_past_its_header_read_removes_no_audit_read_grant() -> TestResult {
    let fixture = fixture()?;
    let granted = granted(&fixture)?;
    for purge in [true, false] {
        let delete = delete_past_the_header_read(&fixture.vault, &granted.grant_ref, purge);
        assert!(
            delete.as_ref().is_err_and(names_the_revoke),
            "the headerless leg (purge: {purge}) refuses an audit_read grant: {delete:?}"
        );
    }
    assert_the_grant_stands(&fixture, &granted, "after the headerless deletes")
}

/// D4: a DerivedFrom edge from the grant to a disposable row, then that
/// row's deletion, leaves the grant live (no stale mark), and the batch
/// delete that follows is refused.
#[test]
fn a_deleted_source_neither_stales_nor_frees_an_audit_read_grant() -> TestResult {
    let fixture = fixture()?;
    let granted = granted(&fixture)?;
    let source = person(&fixture, "a disposable source")?;
    fixture
        .vault
        .batch()
        .edge(&granted.grant_ref, EdgeKind::DerivedFrom, &source, 1.0)
        .commit()?;
    fixture.vault.batch().delete(&source).commit()?;
    let as_holder = bound(&fixture, granted.holder, &granted.proof);
    let page = call(&as_holder, "vault.authority.audit", json!({}));
    assert!(
        page["audit_read_acts"].is_array(),
        "the holder still reads once the source is deleted: {page}"
    );
    let delete = fixture.vault.batch().delete(&granted.grant_ref).commit();
    assert!(
        delete.as_ref().is_err_and(names_the_revoke),
        "the batch delete refuses the grant once its source is deleted: {delete:?}"
    );
    assert_the_grant_stands(&fixture, &granted, "after its source's deletion")
}
