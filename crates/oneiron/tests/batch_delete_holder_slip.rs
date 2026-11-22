//! A batch-deleted actor's capability slip authenticates nothing (RULING
//! DELETED-SLIP-BATCH-DELETE = A, 15 Nov 20:43: "a physical delete of an
//! actor row (PERSON, MACHINE, AGENT_DEF) also writes the hard-delete marker
//! or revokes the slips it holds"). A slip stops standing when its holder's
//! row is a deleted shell or gone under a hard-delete marker (RULING
//! DELETED-ACTOR-SLIP-AUTH = A), but a native batch delete
//! (`vault.batch().delete(&id).commit()`) tore the row and wrote no marker,
//! so the holder read as never stored and its slip kept standing. The
//! holder could even be born again at its derived id, and its old slip
//! stood with it.
//!
//! A batch-deleted PERSON or MACHINE now takes the hard-delete marker a hard
//! delete leaves. An AGENT_DEF needs none: the id pin a delete leaves (H215)
//! says the row was removed, and a definition reborn within its pin stands
//! again with its slips, as a restored row does. A live holder's slip beside
//! a batch-deleted one, and an id of another kind batch-deleted and put
//! again, are the controls.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test batch_delete_holder_slip`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_MACHINE};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:batch-delete-holder-slip";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
}

/// A device vault with a live install profile and its embedded owner, as
/// `deleted_holder_slip.rs` builds it.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (_owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    Fixture {
        vault,
        _dir: dir,
        issuer,
        owner_proof,
    }
}

/// The pairing Scope `oneiron token read` gives: every world, `core:read`.
fn read_slip_scope() -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
    scope
}

/// A slip a holder holds and the key it is bound to.
struct Paired {
    slip: CapabilitySlip,
    key: SigningKey,
}

/// `holder` pairs as class `agent` on a link the owner issues, and redeems
/// it under the key `binding_seed` names.
fn pair(fixture: &Fixture, holder: EntityId, binding_seed: u8) -> oneiron::Result<Paired> {
    let vault = &fixture.vault;
    let holder_ref = holder.to_hex();
    let link = vault.issue_owner_pairing_link(
        &fixture.issuer,
        &fixture.owner_proof,
        read_slip_scope(),
        3_600,
        PairingPrincipal {
            holder_ref: Some(holder_ref.clone()),
            actor_class: Some("agent".to_owned()),
            ..PairingPrincipal::default()
        },
    )?;
    let key = SigningKey::from_bytes(&[binding_seed; 32]);
    let binding_key = key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder_ref,
        link.pin.as_ref(),
    )?;
    let slip = vault.redeem_pairing_link(
        &fixture.issuer,
        &link.code,
        &holder_ref,
        binding_key,
        &key.sign(&transcript).to_bytes(),
    )?;
    Ok(Paired { slip, key })
}

/// A top-scope slip the host mints straight for `holder`, bound to the key
/// `binding_seed` names: a holder no pairing link names (a MACHINE, an
/// AGENT_DEF).
fn minted_slip(fixture: &Fixture, holder: EntityId, binding_seed: u8) -> Paired {
    let key = SigningKey::from_bytes(&[binding_seed; 32]);
    let root = fixture
        .vault
        .ensure_host_root_slip(&fixture.issuer)
        .expect("host root slip");
    let mut claims = root.claims;
    claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some("agent".to_owned());
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("a minted top-scope slip");
    Paired { slip, key }
}

/// The holder of `paired` proves possession of its slip over this test's
/// request challenge, as every request door has it prove.
fn verify(fixture: &Fixture, paired: &Paired) -> oneiron::Result<VerifiedSlip> {
    let signature = paired
        .key
        .sign(&paired.slip.binding_transcript(REQUEST_CHALLENGE)?)
        .to_bytes();
    fixture.vault.verify_capability_slip(
        &fixture.issuer.public_key(),
        &paired.slip,
        REQUEST_CHALLENGE,
        &signature,
    )
}

/// `paired` verifies and reads live: the precondition before a delete.
fn stands(fixture: &Fixture, paired: &Paired, holder: EntityId) -> VerifiedSlip {
    let verified = verify(fixture, paired)
        .unwrap_or_else(|error| panic!("holder={holder:?}: the slip does not verify: {error:?}"));
    assert!(
        fixture
            .vault
            .capability_slip_is_live(&verified)
            .expect("liveness read"),
        "holder={holder:?}: the slip does not read live"
    );
    verified
}

/// `paired`, verified earlier as `verified`, neither verifies nor reads live.
fn falls(fixture: &Fixture, paired: &Paired, verified: &VerifiedSlip, holder: EntityId) {
    assert!(
        verify(fixture, paired).is_err(),
        "holder={holder:?}: a batch-deleted holder's slip still verified"
    );
    assert!(
        !fixture
            .vault
            .capability_slip_is_live(verified)
            .expect("liveness read"),
        "holder={holder:?}: a slip verified before its holder's batch delete still reads live"
    );
}

/// A named agent's PERSON, the holder `oneiron token agent` mints for.
fn named_agent(fixture: &Fixture, name: &str) -> EntityId {
    fixture
        .vault
        .ensure_agent_principal(name)
        .expect("named agent principal")
}

/// Tears `holder` with a native batch delete and checks no row is left.
fn batch_delete(fixture: &Fixture, holder: EntityId) {
    fixture
        .vault
        .batch()
        .delete(&holder)
        .commit()
        .expect("the batch delete commits");
    assert!(
        fixture.vault.get_raw(&holder).expect("raw read").is_none(),
        "precondition: a batch delete leaves no row"
    );
}

fn at(seconds: u64) -> TimeRange {
    TimeRange {
        start: seconds,
        end: seconds,
    }
}

/// An owner's own agent, as `vault.agents.put` stores it.
fn custom_definition() -> AgentDefinition {
    AgentDefinition::new(
        "custom.batch_deleted_holder",
        "Batch-deleted holder fixture",
        "1.0.0",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        // A stored definition names where it came from (a non-empty map).
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("batch_delete_holder_slip fixture"),
        )]),
        None,
        true,
        None,
    )
}

#[test]
fn a_batch_deleted_agent_principals_slip_no_longer_verifies() {
    let fixture = fixture();
    let agent = named_agent(&fixture, "batch_deleted_holder_agent");
    let paired = pair(&fixture, agent, 0x41).expect("the owner pairs the named agent");
    let verified = stands(&fixture, &paired, agent);

    batch_delete(&fixture, agent);

    falls(&fixture, &paired, &verified, agent);
}

#[test]
fn a_batch_deleted_machine_holders_slip_no_longer_verifies() {
    let fixture = fixture();
    let machine = EntityId::now();
    fixture
        .vault
        .put_entity(&machine, ENTITY_TYPE_MACHINE, at(1), 1, b"machine")
        .expect("a MACHINE row");
    let paired = minted_slip(&fixture, machine, 0x42);
    let verified = stands(&fixture, &paired, machine);

    batch_delete(&fixture, machine);

    falls(&fixture, &paired, &verified, machine);
}

#[test]
fn a_batch_deleted_agent_principal_is_not_born_again_under_its_slip() {
    let fixture = fixture();
    let name = "batch_deleted_holder_reborn";
    let agent = named_agent(&fixture, name);
    let paired = pair(&fixture, agent, 0x43).expect("the owner pairs the named agent");
    let verified = stands(&fixture, &paired, agent);

    batch_delete(&fixture, agent);

    // The principal's id is derived from its name, so a new mint for the
    // name would land on the torn id; a hard-deleted principal is not
    // brought back, and the old slip must not stand on any row there.
    let reborn = fixture.vault.ensure_agent_principal(name);
    assert!(
        reborn.is_err(),
        "holder={agent:?}: a batch-deleted agent principal was born again: {reborn:?}"
    );
    falls(&fixture, &paired, &verified, agent);
}

#[test]
fn a_batch_deleted_definitions_slip_falls_and_stands_again_when_it_is_reborn() {
    let fixture = fixture();
    let definition = EntityId::now();
    let custom = custom_definition();
    fixture
        .vault
        .put_agent_definition(&definition, &custom, at(1), 1)
        .expect("the owner's own agent");
    let paired = minted_slip(&fixture, definition, 0x44);
    let verified = stands(&fixture, &paired, definition);

    batch_delete(&fixture, definition);

    falls(&fixture, &paired, &verified, definition);

    // H215: a deleted agent id comes back within its pin, and a reborn row
    // stands again with its slips, as a restored row does.
    fixture
        .vault
        .put_agent_definition(&definition, &custom, at(2), 2)
        .expect("the definition is put again within its pin");
    assert!(
        fixture
            .vault
            .get_agent_definition(&definition)
            .expect("definition read")
            .is_some(),
        "holder={definition:?}: a definition put again after its batch delete does not read back"
    );
    stands(&fixture, &paired, definition);
}

#[test]
fn a_live_holders_slip_still_verifies_beside_a_batch_deleted_one() {
    let fixture = fixture();
    let deleted = named_agent(&fixture, "batch_deleted_holder_gone");
    let kept = named_agent(&fixture, "batch_deleted_holder_kept");
    let _deleted_paired = pair(&fixture, deleted, 0x51).expect("the owner pairs the first agent");
    let kept_paired = pair(&fixture, kept, 0x52).expect("the owner pairs the second agent");

    batch_delete(&fixture, deleted);

    stands(&fixture, &kept_paired, kept);
}

#[test]
fn a_batch_deleted_row_of_another_kind_is_put_again_as_before() {
    let fixture = fixture();
    let asset = EntityId::now();
    fixture
        .vault
        .put_entity(&asset, ENTITY_TYPE_ASSET, at(1), 1, b"asset")
        .expect("an ASSET row");

    batch_delete(&fixture, asset);

    fixture
        .vault
        .put_entity(&asset, ENTITY_TYPE_ASSET, at(2), 2, b"asset again")
        .expect("the ASSET is put again");
    assert!(
        fixture.vault.get_raw(&asset).expect("raw read").is_some(),
        "id={asset:?}: an ASSET put again after its batch delete does not read back"
    );
    assert!(
        !fixture
            .vault
            .is_deleted_shell(&asset)
            .expect("deleted-shell read"),
        "id={asset:?}: an ASSET put again after its batch delete reads deleted"
    );
}
