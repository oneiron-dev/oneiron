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
//! Astra delta-2 (auditread-8435-pr1-delta2) found the ways left to disable
//! the grant without removing it:
//!
//! - F1: a grant the owner writes after a headerless delete's scope probe
//!   meets that delete's tombstone publication, which committed a deletion
//!   fence before the purge refused;
//! - F2: the public stale and tombstone ports mark the grant stale;
//! - F3: a dependent walk still pending reads the grant as withdrawn;
//! - F4: the sync receiver took the replay's refusal as a local failure and
//!   kept retrying the peer's tombstone.
//!
//! Astra delta-3 (auditread-8435-pr1-delta3) found three more:
//!
//! - N1: the generic sync-state writers plant a cleanup-archive marker
//!   (`ac:`) or a pending tombstone (`pt:`), and either reads the grant
//!   deleted;
//! - N2: the public entity port's delete removes the grant's row;
//! - N3: the owner's own hold on the grant refused a privacy erase before
//!   the grant's guard ran, and on a hosted vault that refusal's settlement
//!   limits the grant's use.
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
use oneiron::deletion::{DeleteReason, TombstoneReason, TombstoneValueV2};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::store::ports::{EntityStore, RetrievalIndex, TombstoneStore};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::audit_read_removal::{
    delete_past_the_header_read, peer_tombstone_refusal_is_quarantined,
    publish_purge_past_the_scope_probe, replay_peer_tombstone, withdraw_on_received_shell_cutoff,
};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use oneiron_store::window_key::window_label_from_timestamp;
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

/// Delta-2 F1: a grant the owner writes after a headerless delete's scope
/// probe meets that delete's tombstone publication, which commits before the
/// purge. The publication refuses it, so no deletion fence lands, and the
/// grant stands.
#[test]
fn a_purge_published_past_its_scope_probe_fences_no_audit_read_grant() -> TestResult {
    let fixture = fixture()?;
    let granted = granted(&fixture)?;
    let publish = publish_purge_past_the_scope_probe(&fixture.vault, &granted.grant_ref);
    assert!(
        publish.as_ref().is_err_and(names_the_revoke),
        "the purge's tombstone publication refuses an audit_read grant: {publish:?}"
    );
    assert_the_grant_stands(&fixture, &granted, "after the refused publication")
}

/// Delta-2 F2: the public stale port and the public tombstone port carry no
/// owner act. Each refuses to mark the grant stale, and it stands.
#[test]
fn the_public_stale_and_tombstone_ports_withdraw_no_audit_read_grant() -> TestResult {
    let fixture = fixture()?;
    let granted = granted(&fixture)?;
    let vault = &fixture.vault;
    let stale =
        vault.with_write_txn(|txn| vault.port_retrieval_mark_stale(txn, &granted.grant_ref));
    assert!(
        stale.as_ref().is_err_and(names_the_revoke),
        "the public stale port refuses an audit_read grant: {stale:?}"
    );
    let tombstone = TombstoneValueV2 {
        reason: TombstoneReason::UserHardDelete,
        deleted_at: 1,
        request_id: [7; 16],
    };
    let created =
        vault.with_write_txn(|txn| vault.port_tombstone_create(txn, &granted.grant_ref, tombstone));
    assert!(
        created.as_ref().is_err_and(names_the_revoke),
        "the public tombstone port refuses an audit_read grant: {created:?}"
    );
    assert_the_grant_stands(&fixture, &granted, "after the public ports")
}

/// Delta-2 F3: a dependent walk withdraws one batch per write transaction,
/// and reads honour the rows it has still to reach. With a batch of one and
/// a first dependent that sorts before the grant, the grant waits in the
/// walk's pending range once its source is deleted. The holder still reads
/// then, and once the walk has finished.
#[test]
fn a_pending_dependent_walk_withdraws_no_audit_read_grant() -> TestResult {
    let fixture = fixture()?;
    let granted = granted(&fixture)?;
    let mut policy = fixture.vault.dependent_walk_policy()?;
    policy.batch = 1;
    fixture.vault.set_dependent_walk_policy(policy)?;
    let source = person(&fixture, "a disposable source")?;
    let first = EntityId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])?;
    assert!(
        first.as_bytes() < granted.grant_ref.as_bytes(),
        "the first dependent sorts before the grant, so the walk's first batch takes it alone"
    );
    fixture.vault.put_entity(
        &first,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"a first dependent",
    )?;
    fixture
        .vault
        .batch()
        .edge(&first, EdgeKind::DerivedFrom, &source, 1.0)
        .edge(&granted.grant_ref, EdgeKind::DerivedFrom, &source, 1.0)
        .commit()?;
    fixture.vault.batch().delete(&source).commit()?;
    let as_holder = bound(&fixture, granted.holder, &granted.proof);
    let page = call(&as_holder, "vault.authority.audit", json!({}));
    assert!(
        page["audit_read_acts"].is_array(),
        "the holder still reads while the walk is pending: {page}"
    );
    fixture.vault.finish_dependent_walks()?;
    assert_the_grant_stands(&fixture, &granted, "once the dependent walk finished")
}

/// Delta-2 F4: the replay's refusal stands for good, since only the owner's
/// revoke ends a grant. The sync receiver takes it as the peer's rejected op
/// (quarantined, the window goes on), not as a local failure whose retry
/// marker every rematerialization drain meets again.
#[test]
fn a_refused_peer_tombstone_is_quarantined_not_retried() -> TestResult {
    let fixture = fixture()?;
    let granted = granted(&fixture)?;
    for hard in [false, true] {
        let quarantined =
            peer_tombstone_refusal_is_quarantined(&fixture.vault, &granted.grant_ref, hard);
        assert_eq!(
            quarantined,
            Some(true),
            "the refused peer tombstone (hard: {hard}) is quarantined, not retried"
        );
    }
    assert_the_grant_stands(&fixture, &granted, "after the quarantined tombstones")
}

/// Delta-3 N1: the generic sync-state writers carry no owner act. A
/// cleanup-archive marker or a pending tombstone each reads the grant
/// deleted, so each writer refuses either row naming the grant, and the
/// grant stands.
#[test]
fn a_generic_sync_state_marker_hides_no_audit_read_grant() -> TestResult {
    let fixture = fixture()?;
    let granted = granted(&fixture)?;
    let vault = &fixture.vault;
    let hex = granted.grant_ref.to_hex();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let window = window_label_from_timestamp(now);
    let marker = TombstoneValueV2 {
        reason: TombstoneReason::ArchivedByCleanup,
        deleted_at: 1,
        request_id: [9; 16],
    }
    .encode();
    for key in [format!("ac:{hex}"), format!("pt:{window}:{hex}")] {
        let put = vault.sync_state_put(&key, &marker);
        assert!(
            put.as_ref().is_err_and(names_the_revoke),
            "sync_state_put refuses {key}: {put:?}"
        );
        let put_in =
            vault.with_write_txn(|txn| vault.sync_state_put_in_write_txn(txn, &key, &marker));
        assert!(
            put_in.as_ref().is_err_and(names_the_revoke),
            "sync_state_put_in_write_txn refuses {key}: {put_in:?}"
        );
        let batch = vault.sync_state_put_telemetry_batch(&[(key.as_str(), marker.as_slice())]);
        assert!(
            batch.as_ref().is_err_and(names_the_revoke),
            "sync_state_put_telemetry_batch refuses {key}: {batch:?}"
        );
    }
    assert_the_grant_stands(&fixture, &granted, "after the refused sync-state markers")
}

/// Delta-3 N2: the public entity port's delete carries no owner act either.
/// It refuses the grant's row, and the grant stands.
#[test]
fn the_public_entity_delete_port_removes_no_audit_read_grant() -> TestResult {
    let fixture = fixture()?;
    let granted = granted(&fixture)?;
    let vault = &fixture.vault;
    let delete = vault.with_write_txn(|txn| vault.port_entity_delete(txn, &granted.grant_ref));
    assert!(
        delete.as_ref().is_err_and(names_the_revoke),
        "the public entity delete port refuses an audit_read grant: {delete:?}"
    );
    assert_the_grant_stands(&fixture, &granted, "after the refused entity port delete")
}

/// Delta-3 N3: with the owner's own hold on the grant, a privacy erase of
/// it meets the grant's refusal first, so no refused erase is settled
/// against the hold (on a hosted vault that settlement limits the grant's
/// use), and the holder still reads.
#[test]
fn a_held_audit_read_grant_refuses_a_privacy_erase_before_its_hold() -> TestResult {
    let fixture = fixture()?;
    let granted = granted(&fixture)?;
    call(
        &owner(&fixture),
        "vault.legal_holds.place",
        json!({ "targets": [{ "record": granted.grant_ref.to_hex() }] }),
    );
    let erase = fixture
        .vault
        .delete_entity_with_reason(&granted.grant_ref, DeleteReason::GdprDelete);
    assert!(
        erase.as_ref().is_err_and(names_the_revoke),
        "a privacy erase of a held audit_read grant meets the grant's refusal first: {erase:?}"
    );
    let as_holder = bound(&fixture, granted.holder, &granted.proof);
    let page = call(&as_holder, "vault.authority.audit", json!({}));
    assert!(
        page["audit_read_acts"].is_array(),
        "the holder still reads after the refused privacy erase: {page}"
    );
    Ok(())
}
