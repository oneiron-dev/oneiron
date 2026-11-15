//! FIX WITNESS-TURN-NO-PROJECT-POSITION: a turn witnessed through
//! `vault.witness` keeps the default project position, so claims the Dreamer
//! derives from it land in the default project even when the caller keeps
//! its memory under a project anchor. The turn takes an optional project,
//! admitted only when the caller's slip audience covers it, and the turn
//! and its messages settle onto it at birth.
//!
//! The project rides the turn's wire shape, so the tests attach it on JSON.
//! These stamping tests read the stamp through a new test door, so they
//! compile only with the fix; the wire-shape test, which runs and fails on
//! main, is `witness_turn_wire_project.rs`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test witness_turn_no_project_position`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::claim::default_project_id;
use oneiron::federation::{ScopeAxis, ScopeId};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, Memory, WitnessReceipt, WitnessTurn,
};
use oneiron::off_record::OffRecordBackendClass;
use oneiron::test_doors::witness_project::stamped_project;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const CHALLENGE: &[u8] = b"oneiron-request:witness-turn-no-project-position";

/// One visible user MESSAGE of `content` in a fresh turn of `conversation`,
/// as `vault.witness` takes it without a project. Built on JSON, the shape
/// the facade decodes, so the helper compiles whether or not the turn
/// carries the row's project.
fn plain_turn(conversation: &str, content: &str) -> WitnessTurn {
    let value = json!({
        "conversation_ref": conversation,
        "messages": [{
            "author": "user",
            "message_type": "dialogue",
            "content": content,
            "is_visible": true,
            "order": 0,
        }],
        "occurred_at": 900,
    });
    serde_json::from_value(value).expect("the witness turn shape decodes")
}

/// [`plain_turn`] plus the row's optional project, attached on the wire the
/// way a facade caller sends it. On main the attachment is refused as an
/// unknown field, which is the defect: the turn cannot name a project.
fn turn_with_project(conversation: &str, content: &str, project: EntityId) -> WitnessTurn {
    let turn = plain_turn(conversation, content);
    let mut value = serde_json::to_value(&turn).expect("a witness turn serializes");
    value["project"] = json!(project.to_hex());
    match serde_json::from_value::<WitnessTurn>(value) {
        Ok(turn) => turn,
        Err(error) => panic!("vault.witness turns carry an optional project: {error}"),
    }
}

/// The MESSAGE the witness wrote, as its stamped row.
fn first_message(receipt: &WitnessReceipt) -> EntityId {
    let message = receipt
        .messages
        .first()
        .expect("the witness writes one MESSAGE row");
    EntityId::from_hex(&message.id).expect("the message record ref parses")
}

fn owner_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    (dir, vault, owner)
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-witness-project").expect("issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    Fixture {
        _dir: dir,
        vault,
        issuer,
        owner,
    }
}

/// A credential minted for the owner as a `human` with `audience` as its
/// slip audience and `records` as its records caveat, verified with its
/// holder's signature.
fn owner_credential(
    fixture: &Fixture,
    seed: u8,
    audience: ScopeAxis<ScopeId>,
    records: BTreeSet<String>,
) -> VerifiedSlip {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let root = fixture
        .vault
        .ensure_host_root_slip(&fixture.issuer)
        .expect("host root");
    let mut claims = root.claims;
    claims.slip_id = [seed; 32];
    claims.parent_id = None;
    claims.holder_ref = fixture.owner.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some("human".to_owned());
    claims.scope.audience = audience;
    claims.records = records;
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("mint the owner credential");
    let signature = key
        .sign(&slip.binding_transcript(CHALLENGE).expect("transcript"))
        .to_bytes();
    fixture
        .vault
        .verify_capability_slip(&fixture.issuer.public_key(), &slip, CHALLENGE, &signature)
        .expect("verify the owner credential")
}

fn memory_of(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

#[test]
fn witness_with_project_stamps_the_turn_and_its_message_under_it() {
    let (_dir, vault, owner) = owner_vault();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let conversation = EntityId::now().to_hex();
    let project = EntityId::now();

    let receipt = memory
        .witness(&turn_with_project(
            &conversation,
            "the lease ends in March",
            project,
        ))
        .expect("an in-process witness lands under its project");
    assert_eq!(
        stamped_project(&vault, receipt.turn_id).expect("the turn stamp reads"),
        Some(project),
        "the witnessed TURN keeps the default project instead of its own"
    );
    assert_eq!(
        stamped_project(&vault, first_message(&receipt)).expect("the message stamp reads"),
        Some(project),
        "the witnessed MESSAGE keeps the default project instead of its turn's"
    );
}

#[test]
fn witness_without_project_keeps_the_default_project() {
    let (_dir, vault, owner) = owner_vault();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let conversation = EntityId::now().to_hex();

    let receipt = memory
        .witness(&plain_turn(&conversation, "the lease ends in March"))
        .expect("a witness without a project lands");
    assert_eq!(
        stamped_project(&vault, receipt.turn_id).expect("the turn stamp reads"),
        Some(default_project_id()),
        "a witness without a project leaves the default project"
    );
    assert_eq!(
        stamped_project(&vault, first_message(&receipt)).expect("the message stamp reads"),
        Some(default_project_id()),
        "a witness without a project leaves its messages' default project"
    );
}

#[test]
fn transport_caller_without_credential_is_refused_a_project() {
    let (_dir, vault, owner) = owner_vault();
    let memory = vault
        .memory(owner, EdgeActorClass::Human)
        .with_transport_invocation();
    let conversation = EntityId::now().to_hex();

    let error = memory
        .witness(&turn_with_project(
            &conversation,
            "the lease ends in March",
            EntityId::now(),
        ))
        .expect_err("a transport witness without a credential is refused a project");
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);
}

#[test]
fn credential_whose_audience_covers_the_project_witnesses_under_it() {
    let fixture = fixture();
    let project = EntityId::now();
    let proof = owner_credential(
        &fixture,
        0x41,
        ScopeAxis::Some(BTreeSet::from([ScopeId(project)])),
        BTreeSet::new(),
    );
    let conversation = EntityId::now().to_hex();

    let receipt = memory_of(&fixture)
        .with_read_proof(&proof)
        .witness(&turn_with_project(
            &conversation,
            "the lease ends in March",
            project,
        ))
        .expect("the covered project lands");
    assert_eq!(
        stamped_project(&fixture.vault, receipt.turn_id).expect("the turn stamp reads"),
        Some(project),
        "the covered project did not settle onto the turn"
    );
}

#[test]
fn credential_whose_audience_misses_the_project_is_refused() {
    let fixture = fixture();
    let project = EntityId::now();
    let other = EntityId::now();
    let proof = owner_credential(
        &fixture,
        0x42,
        ScopeAxis::Some(BTreeSet::from([ScopeId(other)])),
        BTreeSet::new(),
    );
    let conversation = EntityId::now().to_hex();

    let error = memory_of(&fixture)
        .with_read_proof(&proof)
        .witness(&turn_with_project(
            &conversation,
            "the lease ends in March",
            project,
        ))
        .expect_err("a credential whose audience misses the project is refused it");
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);
}

#[test]
fn revoked_credential_is_refused_a_project() {
    let fixture = fixture();
    let project = EntityId::now();
    let proof = owner_credential(
        &fixture,
        0x43,
        ScopeAxis::Some(BTreeSet::from([ScopeId(project)])),
        BTreeSet::new(),
    );
    fixture
        .vault
        .revoke_capability_slip(&fixture.issuer, [0x43; 32])
        .expect("revoke the owner credential");
    let conversation = EntityId::now().to_hex();

    let error = memory_of(&fixture)
        .with_read_proof(&proof)
        .witness(&turn_with_project(
            &conversation,
            "the lease ends in March",
            project,
        ))
        .expect_err("a revoked credential is refused a project");
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);
}

#[test]
fn record_bound_credential_is_refused_a_project() {
    let fixture = fixture();
    let project = EntityId::now();
    let proof = owner_credential(
        &fixture,
        0x44,
        ScopeAxis::Some(BTreeSet::from([ScopeId(project)])),
        BTreeSet::from([EntityId::now().to_hex()]),
    );
    let conversation = EntityId::now().to_hex();

    let error = memory_of(&fixture)
        .with_read_proof(&proof)
        .witness(&turn_with_project(
            &conversation,
            "the lease ends in March",
            project,
        ))
        .expect_err("a record-bound credential is refused a project");
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);
}

#[test]
fn off_record_session_witness_with_project_is_refused() {
    let (_dir, vault, owner) = owner_vault();
    let session = vault
        .off_record_session_vault()
        .enter("witness-project", OffRecordBackendClass::Local)
        .expect("enter session");
    let memory = vault.memory(owner, EdgeActorClass::Human);

    let error = memory
        .witness_into_session(
            &session,
            &turn_with_project("", "nothing durable is said here", EntityId::now()),
            None,
            None,
        )
        .expect_err("a session witness takes no project");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
}
