//! A deleted actor's capability slip authenticates nothing (RULING
//! DELETED-ACTOR-SLIP-AUTH = A, 15 Nov 19:32). Slip verify checked the
//! signatures, the mint, revocation, expiry and the slip's refs, never the
//! holder's row, so a named agent whose PERSON was deleted still proved its
//! slip at every door, and the per-use liveness check still read it live.
//! The slip now follows its holder's row: a deleted shell's slip does not
//! stand, and neither does one minted for it after the delete. A live
//! holder's slip beside a deleted one is the control. A PROJECT write
//! proof, verified live at its put with no vault door, follows the same
//! rule (Sol review of #8289, P1 2).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test deleted_holder_slip`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::workspace_roster::{ProjectProofVersion, ProjectRecord, ProjectWriteProof};
use oneiron::{EntityId, Vault, VaultConfig};

const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:deleted-holder-slip";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
}

/// A device vault with a live install profile and its embedded owner, as
/// `agent_pair_default_grant.rs` builds it: the owner's pairing link for a
/// named agent mints that agent's default read Grant on this profile.
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

/// A slip `holder` redeemed and the key it is bound to.
struct Paired {
    slip: CapabilitySlip,
    key: SigningKey,
}

/// `holder` pairs as class `agent` on a link the owner issues, and redeems
/// it under the key `binding_seed` names. The issue or the redeem may refuse.
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

/// A named agent's PERSON, the holder `oneiron token agent` mints for.
fn named_agent(fixture: &Fixture, name: &str) -> EntityId {
    fixture
        .vault
        .ensure_agent_principal(name)
        .expect("named agent principal")
}

/// Soft-deletes `holder` and checks the delete left a deleted shell.
fn delete_to_shell(fixture: &Fixture, holder: EntityId) {
    assert!(
        fixture.vault.delete_entity(&holder).expect("plain delete"),
        "precondition: the holder's PERSON was deleted"
    );
    assert!(
        fixture
            .vault
            .is_deleted_shell(&holder)
            .expect("deleted-shell read"),
        "precondition: a plain delete leaves a deleted shell"
    );
}

#[test]
fn a_deleted_holders_slip_no_longer_verifies_and_reads_not_live() {
    let fixture = fixture();
    let agent = named_agent(&fixture, "deleted_holder_slip_agent");
    let paired = pair(&fixture, agent, 0x41).expect("the owner pairs the named agent");
    let verified = verify(&fixture, &paired).expect("the paired agent proves its slip");
    assert!(
        fixture
            .vault
            .capability_slip_is_live(&verified)
            .expect("liveness read"),
        "precondition: the agent's slip is live before the delete"
    );

    delete_to_shell(&fixture, agent);

    let after = verify(&fixture, &paired);
    assert!(
        after.is_err(),
        "holder={agent:?}: a deleted holder's slip still verified"
    );
    assert!(
        !fixture
            .vault
            .capability_slip_is_live(&verified)
            .expect("liveness read"),
        "holder={agent:?}: a slip verified before its holder was deleted still reads live"
    );
}

#[test]
fn a_live_holders_slip_still_verifies_beside_a_deleted_one() {
    let fixture = fixture();
    let deleted = named_agent(&fixture, "deleted_holder_slip_gone");
    let kept = named_agent(&fixture, "deleted_holder_slip_kept");
    let _deleted_paired = pair(&fixture, deleted, 0x51).expect("the owner pairs the first agent");
    let kept_paired = pair(&fixture, kept, 0x52).expect("the owner pairs the second agent");

    delete_to_shell(&fixture, deleted);

    let verified = verify(&fixture, &kept_paired)
        .expect("a live holder's slip verifies beside a deleted holder's");
    assert!(
        fixture
            .vault
            .capability_slip_is_live(&verified)
            .expect("liveness read"),
        "holder={kept:?}: a live holder's slip reads not live beside a deleted one"
    );
}

#[test]
fn a_slip_minted_for_a_holder_after_its_delete_does_not_verify() {
    let fixture = fixture();
    let agent = named_agent(&fixture, "deleted_holder_slip_late");
    delete_to_shell(&fixture, agent);

    // The issue or the redeem may refuse a deleted holder already; if a slip
    // comes back, it must not stand.
    match pair(&fixture, agent, 0x61) {
        Err(_) => {}
        Ok(paired) => {
            let verified = verify(&fixture, &paired);
            assert!(
                verified.is_err(),
                "holder={agent:?}: a slip minted after its holder's delete verified"
            );
        }
    }
}

/// A top-scope slip the host mints straight for `holder`, bound to the key
/// `binding_seed` names: a credential that signs a PROJECT write proof.
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

/// `project`'s stored record, signed afresh by `paired`'s holder over the
/// project's current anchor.
fn signed_by(fixture: &Fixture, project: EntityId, paired: &Paired) -> ProjectRecord {
    let mut body = fixture
        .vault
        .project(project)
        .expect("project read")
        .expect("the project is stored");
    let anchor = body.anchor().expect("the project's anchor");
    let signed_at = paired.slip.claims.issued_at;
    let version = ProjectProofVersion::V3;
    let challenge = body
        .authority_at(version)
        .write_challenge(project, version, signed_at, &anchor)
        .expect("the write challenge");
    let transcript = paired
        .slip
        .binding_transcript(&challenge)
        .expect("the holder's binding transcript");
    body.write_proof = Some(ProjectWriteProof {
        slip_wire: paired.slip.to_token().expect("slip token"),
        holder_signature: paired.key.sign(&transcript).to_bytes().to_vec(),
        signed_at,
        anchor,
        version,
    });
    body
}

#[test]
fn a_deleted_holders_slip_signs_no_live_project_write() {
    let fixture = fixture();
    let vault = &fixture.vault;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let root = vault.root_project().expect("the root project");
    let project = EntityId::now();
    let record = ProjectRecord::new(project, Some(root), root, owner).expect("a project record");
    vault
        .put_project(project, &record, 2)
        .expect("an owner-door project");
    let gone = named_agent(&fixture, "deleted_holder_slip_project_gone");
    let kept = named_agent(&fixture, "deleted_holder_slip_project_kept");
    let gone_slip = minted_slip(&fixture, gone, 0x71);
    let kept_slip = minted_slip(&fixture, kept, 0x72);

    delete_to_shell(&fixture, gone);

    // The put judges the fresh proof live; who may change the project is the
    // read's judgment, so a live holder's proof lands here either way.
    let refused = vault.put_project(project, &signed_by(&fixture, project, &gone_slip), 3);
    let error = refused.expect_err("a deleted holder's slip signed a live project write");
    assert!(
        format!("{error:?}").contains("holder is deleted"),
        "holder={gone:?}: refused for another reason: {error}"
    );
    vault
        .put_project(project, &signed_by(&fixture, project, &kept_slip), 3)
        .expect("a live holder's slip still signs a live project write");
}
