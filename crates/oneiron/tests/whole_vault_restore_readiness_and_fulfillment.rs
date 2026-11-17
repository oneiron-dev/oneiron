//! Fix list row WHOLE-VAULT-IMPORT-REFUSES-RESERVED-OWNER-EDGES, readiness and
//! fulfillment part: a whole-vault archive of a vault holding a `blocks` link
//! between two CODE_SYMBOLs and a brief fulfillment link (`fulfills` and its
//! inverse `discharged_by`) between a TASK brief and a `commitment.record`
//! imports, and keeps the three links.
//!
//! * `owner_restore_keeps_the_readiness_and_fulfillment_links`: the owner's
//!   restore into a fresh vault lands the three links with their rows.
//! * `actor_import_keeps_the_link_of_a_released_commitment`: through the
//!   actor-taking door; the commitment was released after its brief was
//!   linked, and the restored link still names it.
//! * `actorless_import_again_is_an_exact_repeat`: the actorless door lands
//!   the links, and the same archive again is an exact repeat.
//!
//! Red on the base (#9131's head 866f4d06bdec): each test fails at its first
//! import, which refuses the archived `blocks`, `fulfills` or `discharged_by`
//! edge with `Registry(ReservedEdgeKind(..))`; the source preconditions pass.
//!
//! Vaults in tempdirs, every write through its public door. Each destination
//! opens at least one wall-clock second after its source (sleep 1100 ms), as
//! in `whole_vault_restore_seeds.rs`. Run with `cargo test --locked -p
//! oneiron --all-features --test whole_vault_restore_readiness_and_fulfillment`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use oneiron::code_memory::BlocksWriteContext;
use oneiron::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind, CommitmentRecord, CommitmentStatus, CommitmentStrength,
};
use oneiron::commitment_lifecycle::link_brief_fulfillment;
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeKind;
use oneiron::habit::TaskRole;
use oneiron::registry::{ENTITY_TYPE_CODE_SYMBOL, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
    WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// A fresh SEEDED destination whose engine-seed seconds differ from the
/// source's: any 1100 ms interval crosses a second boundary.
fn open_later_vault() -> (tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    open_vault()
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn put_row(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, entity_type, TimeRange { start: 1, end: 1 }, 1, body)
        .expect("put the row");
    id
}

fn task_body() -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(
            Value::from("role"),
            Value::from(TaskRole::Task.role_byte()),
        )]),
    )
    .expect("a TASK body");
    body
}

/// What the source vault holds: `blocker` blocks `blocked`, `brief`
/// fulfills `commitment`, and its whole-vault archive.
struct Linked {
    archive: Vec<u8>,
    blocker: EntityId,
    blocked: EntityId,
    brief: EntityId,
    commitment: EntityId,
}

/// A source vault where a person marks one CODE_SYMBOL as blocking another
/// and links a TASK brief to an open commitment through the fulfillment
/// door. With `release`, the commitment is released after the link.
fn linked_archive(release: bool) -> Linked {
    let (_dir, source) = open_vault();
    let obligor = put_row(&source, ENTITY_TYPE_PERSON, b"person");
    let beneficiary = put_row(&source, ENTITY_TYPE_PERSON, b"person");
    let _issuer = oneiron::test_support::provision_engine_machines(&source);
    let actor = WriteActor::new(obligor, EdgeActorClass::Human);

    let blocker = put_row(&source, ENTITY_TYPE_CODE_SYMBOL, b"symbol");
    let blocked = put_row(&source, ENTITY_TYPE_CODE_SYMBOL, b"symbol");
    source
        .insert_blocks_edge(
            blocker,
            blocked,
            BlocksWriteContext {
                actor: &actor,
                source: ClaimSource::UserStated,
            },
        )
        .expect("blocker blocks blocked");

    let brief = put_row(&source, ENTITY_TYPE_TASK, &task_body());
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("readiness and fulfillment restore fixture"))
            .expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    let record = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, obligor),
        beneficiary,
        CommitmentContent::new("send the signed document", None).expect("content"),
        Value::Map(vec![
            (Value::from("kind"), Value::from("once")),
            (Value::from("due"), Value::from(10_000_u64)),
        ]),
        CommitmentStrength::Commitment,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::Brief, "brief:doc-1")
            .expect("birth provenance"),
    )
    .expect("commitment record");
    let commitment = EntityId::now();
    source
        .put_commitment_claim(
            &commitment,
            &record,
            &envelope,
            TimeRange {
                start: 100,
                end: 200,
            },
            300,
        )
        .expect("open commitment");
    link_brief_fulfillment(&source, &brief, &commitment, 300).expect("link the brief");
    if release {
        source
            .release_commitment(&commitment, &envelope, 301)
            .expect("release the commitment");
    }

    let linked = Linked {
        archive: Vec::new(),
        blocker,
        blocked,
        brief,
        commitment,
    };
    assert_links(&source, &linked, "precondition: the source");
    let archive = source
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    Linked { archive, ..linked }
}

/// `vault` holds the three links: `blocker` blocks `blocked` and nothing
/// else, and `brief` and `commitment` are linked in both ruled directions.
fn assert_links(vault: &Vault, linked: &Linked, holder: &str) {
    assert_eq!(
        vault
            .targets(&linked.blocker, EdgeKind::Blocks, None)
            .expect("read the blocker's links"),
        [linked.blocked],
        "{holder} keeps the blocks link"
    );
    assert!(
        vault
            .targets(&linked.blocked, EdgeKind::Blocks, None)
            .expect("read the blocked symbol's links")
            .is_empty(),
        "{holder} holds no reverse blocks link"
    );
    assert_eq!(
        vault
            .targets(&linked.brief, EdgeKind::Fulfills, None)
            .expect("read the brief's fulfills link"),
        [linked.commitment],
        "{holder} keeps the fulfills link"
    );
    assert_eq!(
        vault
            .targets(&linked.commitment, EdgeKind::DischargedBy, None)
            .expect("read the commitment's discharged_by link"),
        [linked.brief],
        "{holder} keeps the discharged_by link"
    );
}

#[test]
fn owner_restore_keeps_the_readiness_and_fulfillment_links() {
    let linked = linked_archive(false);
    let (_dir, dest) = open_later_vault();
    let owner = owner_proof(&dest);
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&linked.archive), &owner)
        .expect("the owner's restore lands the links");
    assert_links(&dest, &linked, "the restored vault");
}

#[test]
fn actor_import_keeps_the_link_of_a_released_commitment() {
    let linked = linked_archive(true);
    let (_dir, dest) = open_later_vault();
    let owner = dest.ensure_embedded_owner_actor().expect("embedded owner");
    dest.import_whole_vault_archive_with_actor(
        &linked.archive,
        &WriteActor::new(owner, EdgeActorClass::Human),
    )
    .expect("the actor import lands the links");
    assert_links(&dest, &linked, "the restored vault");
}

#[test]
fn actorless_import_again_is_an_exact_repeat() {
    let linked = linked_archive(false);
    let (_dir, dest) = open_later_vault();
    dest.import_whole_vault_archive_from(Cursor::new(&linked.archive))
        .expect("the actorless import lands the links");
    assert_links(&dest, &linked, "the restored vault");
    dest.import_whole_vault_archive_from(Cursor::new(&linked.archive))
        .expect("the same archive again is an exact repeat");
    assert_links(&dest, &linked, "the restored vault");
}
