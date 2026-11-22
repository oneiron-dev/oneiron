//! A slip over an undecodable stored row is the vault failing to answer, not
//! the credential failing to verify (RATCHET-9413 review round 2, PR 9669
//! P1 1 and 2). A share-bound slip over a share whose entity header no
//! longer decodes, and an invitation-bound slip over a stored invitation
//! that no longer decodes, are store faults (`Error::CorruptedIndex`), never
//! the slip refusal. A missing invitation row stays a refusal.
//!
//! Red on the fix's parent (both store-fault asserts get the refusal) and
//! green on the head; the control passes on both.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test slip_store_fault_not_refusal`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::access_grant::AccessGrantStatus;
use oneiron::authority::{
    CapabilitySlip, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole, holder_proof,
    pairing_binding_transcript_pinned,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember, SharedInvitation};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::share::Share;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::slip_store_fault::{
    delete_invitation_row, overwrite_invitation_row, truncate_share_entity,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SHARED: u64 = 42;
const VIEW_SLIP_LIFETIME: u64 = 3_600;

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

fn put_person(vault: &Vault, id: &EntityId) {
    vault
        .put_entity(
            id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// A vault rooted under its own host issuer, with engine machines and this
/// install's profile, and its embedded owner. Copied from
/// `tests/delegation_expiry_wall_clock.rs::Fixture::open` (without its
/// manual clock).
fn rooted_vault(seed: u8) -> (tempfile::TempDir, Vault, HostSlipIssuer, EntityId) {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), test_config()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = HostSlipIssuer::from_seed(&[seed; HOST_ISSUER_SEED_BYTES]).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    (dir, vault, issuer, owner)
}

/// The shipped policy plus the owner's permission to create a brief share.
/// Copied from `tests/delegation_expiry_wall_clock.rs::permit_brief_share`.
fn permit_brief_share(vault: &Vault, owner: EntityId) {
    let id = oneiron_store::policy_record::default_policy_manifest_id()
        .expect("the default manifest id");
    let bytes = vault
        .get(&id)
        .expect("read default manifest")
        .expect("the shipped manifest is stored");
    let mut manifest: serde_json::Value =
        rmp_serde::from_slice(&bytes).expect("decode shipped manifest");
    manifest["scoped_grants"]
        .as_array_mut()
        .expect("the shipped scoped-grant table")
        .push(json!({
            "actor_ref": owner.to_hex(),
            "effector": "external:share_brief",
            "scope": oneiron::test_support::effect_preset(),
            "selectors": { "channel": "shared_brief" },
        }));
    oneiron::test_support::put_policy_manifest_bytes(
        vault,
        id,
        &rmp_serde::to_vec_named(&manifest).expect("encode share permission"),
    )
    .expect("store the share permission beside the shipped policy");
}

/// A holder proof for one request on `vault`'s clock: its timestamp, its
/// signature bytes and its nonce. Copied from
/// `tests/removal_import_body_digest.rs::request`.
fn request(vault: &Vault, slip: &CapabilitySlip, holder: &SigningKey) -> (u64, Vec<u8>, String) {
    let proof = holder_proof(slip, holder, vault.now_recorded_at()).expect("a holder proof");
    let signature = proof["signature"].as_str().expect("a signature");
    let signature = (0..signature.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&signature[at..at + 2], 16).expect("hex"))
        .collect();
    (
        proof["timestamp"].as_u64().expect("a timestamp"),
        signature,
        proof["nonce"].as_str().expect("a nonce").to_owned(),
    )
}

/// Whether `error` is the slip refusal: `invalid_authority()` is
/// `Error::Record(RecordError::InvalidAuthorityLogBody("body failed
/// validation"))` (`crates/oneiron-authority/src/authority/wire_decode.rs`).
fn is_slip_refusal(error: &oneiron::Error) -> bool {
    matches!(
        error,
        oneiron::Error::Record(oneiron::error::RecordError::InvalidAuthorityLogBody(_))
    )
}

/// An admitted share of an opaque brief to `recipient`, by `owner`.
fn admitted_share(vault: &Vault, owner: EntityId, recipient: EntityId) -> EntityId {
    let share_id = EntityId::now();
    let issuer = WriteActor::new(owner, EdgeActorClass::Human);
    vault
        .create_share(
            &share_id,
            &issuer,
            &Share {
                recipient_ref: recipient,
                brief_ref: "brief:opaque-report".to_owned(),
                world_refs: BTreeSet::new(),
                facet_refs: BTreeSet::new(),
                include_unscoped: true,
                status: AccessGrantStatus::Active,
                created_at: vault.now_recorded_at(),
                revoked_at: None,
                expires_at: None,
                mention: None,
            },
        )
        .expect("an admitted share");
    share_id
}

/// The recipient's redeemed view-only credential for `share`: its link is
/// issued, redeemed with a fresh binding key, and returned with that key.
/// Copied from `tests/home_clearance_share_view.rs::issue_and_redeem_view`
/// (without its holder verification, which the caller does through the
/// server's door instead).
fn issue_and_redeem_view(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: EntityId,
    share: EntityId,
    recipient: EntityId,
) -> (CapabilitySlip, SigningKey) {
    let issuer_actor = WriteActor::new(owner, EdgeActorClass::Human);
    let link = vault
        .issue_share_view_link(
            issuer,
            &issuer_actor,
            share,
            EdgeActorClass::Human,
            VIEW_SLIP_LIFETIME,
        )
        .expect("the share view link");
    let holder = SigningKey::from_bytes(&[0x77; 32]);
    let binding = holder.verifying_key().to_bytes();
    let holder_ref = recipient.to_hex();
    let transcript =
        pairing_binding_transcript_pinned(&link.code, &binding, &holder_ref, link.pin.as_ref())
            .expect("the pairing transcript");
    let signature = holder.sign(&transcript).to_bytes();
    let slip = vault
        .redeem_pairing_link(issuer, &link.code, &holder_ref, binding, &signature)
        .expect("the redeemed view slip");
    let share_hex = share.to_hex();
    assert_eq!(
        slip.claims.share_ref.as_deref(),
        Some(share_hex.as_str()),
        "the redeemed slip is bound to the share"
    );
    (slip, holder)
}

/// The shared vault with `owner` as its Owner.
fn shared_vault(vault: &Vault, owner: EntityId) {
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &[InitialSharedMember {
                member_ref: owner,
                role: Some(Role::Owner),
            }],
            1,
        )
        .expect("a shared vault");
}

/// `owner` invites `invitee` as a Member; returns the pending invitation.
/// Copied from `tests/shared_invitation_actor_erase.rs`.
fn invited(vault: &Vault, owner: EntityId, invitee: EntityId) -> SharedInvitation {
    vault
        .add_shared_member(&proof(vault, owner), SHARED, invitee, Some(Role::Member))
        .expect("the Owner invites a Member");
    let mut open = vault
        .shared_invitations(&proof(vault, invitee), SHARED)
        .expect("the invitee's invitations");
    assert_eq!(open.len(), 1, "one pending invitation: {open:?}");
    open.remove(0)
}

/// The invitee's slip for `invitation`, through an owner's invitation
/// pairing code: the owner issues the code, the invitee redeems it with a
/// fresh key, which binds the invitation to that key. Returned with the key.
fn issue_and_redeem_invitation(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: EntityId,
    invitee: EntityId,
    invitation: &SharedInvitation,
) -> (CapabilitySlip, SigningKey) {
    let link = vault
        .issue_invitation_pairing_link(
            &proof(vault, owner),
            SHARED,
            invitee,
            &invitation.id,
            issuer,
        )
        .expect("the invitation pairing code");
    let holder = SigningKey::from_bytes(&[0x69; 32]);
    let binding = holder.verifying_key().to_bytes();
    let holder_ref = invitee.to_hex();
    let transcript =
        pairing_binding_transcript_pinned(&link.code, &binding, &holder_ref, link.pin.as_ref())
            .expect("the pairing transcript");
    let signature = holder.sign(&transcript).to_bytes();
    let slip = vault
        .redeem_pairing_link(issuer, &link.code, &holder_ref, binding, &signature)
        .expect("the redeemed invitation slip");
    assert_eq!(
        slip.claims.invitation_ref.as_deref(),
        Some(invitation.id.as_str()),
        "the redeemed slip is bound to the invitation"
    );
    (slip, holder)
}

fn verify(
    vault: &Vault,
    slip: &CapabilitySlip,
    holder: &SigningKey,
) -> Result<oneiron::authority::VerifiedSlip, oneiron::Error> {
    let (timestamp, signature, nonce) = request(vault, slip, holder);
    vault.verify_logged_capability_slip_request(slip, timestamp, &signature, nonce.as_bytes())
}

#[test]
fn a_share_bound_slip_over_an_undecodable_share_header_is_a_store_fault() -> TestResult {
    let (_dir, vault, issuer, owner) = rooted_vault(0x7a);
    let recipient = EntityId::now();
    put_person(&vault, &recipient);
    permit_brief_share(&vault, owner);
    let share = admitted_share(&vault, owner, recipient);
    let (slip, holder) = issue_and_redeem_view(&vault, &issuer, owner, share, recipient);

    verify(&vault, &slip, &holder).expect("PRECONDITION: the fresh slip verifies");

    truncate_share_entity(&vault, share).expect("the share header no longer decodes");

    let error = verify(&vault, &slip, &holder).expect_err("the vault cannot answer");
    assert!(
        matches!(error, oneiron::Error::CorruptedIndex(_)),
        "an undecodable share header is a store fault, not a refusal: {error:?}"
    );
    assert!(
        !is_slip_refusal(&error),
        "the store fault is not the slip refusal: {error:?}"
    );
    Ok(())
}

#[test]
fn an_invitation_bound_slip_over_an_undecodable_stored_invitation_is_a_store_fault() -> TestResult {
    let (_dir, vault, issuer, owner) = rooted_vault(0x7b);
    let invitee = EntityId::now();
    put_person(&vault, &invitee);
    shared_vault(&vault, owner);
    let invitation = invited(&vault, owner, invitee);
    let (slip, holder) = issue_and_redeem_invitation(&vault, &issuer, owner, invitee, &invitation);

    verify(&vault, &slip, &holder).expect("PRECONDITION: the fresh slip verifies");

    overwrite_invitation_row(&vault, invitee, &invitation.id, b"not an invitation")
        .expect("the stored invitation no longer decodes");

    let error = verify(&vault, &slip, &holder).expect_err("the vault cannot answer");
    assert!(
        matches!(error, oneiron::Error::CorruptedIndex("shared invitation")),
        "an undecodable stored invitation is a store fault: {error:?}"
    );
    assert!(
        !is_slip_refusal(&error),
        "the store fault is not the slip refusal: {error:?}"
    );
    Ok(())
}

#[test]
fn an_invitation_bound_slip_whose_invitation_row_is_gone_is_refused() -> TestResult {
    let (_dir, vault, issuer, owner) = rooted_vault(0x7c);
    let invitee = EntityId::now();
    put_person(&vault, &invitee);
    shared_vault(&vault, owner);
    let invitation = invited(&vault, owner, invitee);
    let (slip, holder) = issue_and_redeem_invitation(&vault, &issuer, owner, invitee, &invitation);

    verify(&vault, &slip, &holder).expect("PRECONDITION: the fresh slip verifies");

    delete_invitation_row(&vault, invitee, &invitation.id).expect("the invitation row is gone");

    let error = verify(&vault, &slip, &holder).expect_err("a gone invitation refuses the slip");
    assert!(
        is_slip_refusal(&error),
        "a missing invitation row is the slip refusal: {error:?}"
    );
    assert!(
        !matches!(error, oneiron::Error::CorruptedIndex(_)),
        "a missing invitation row is not a store fault: {error:?}"
    );
    Ok(())
}
