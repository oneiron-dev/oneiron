use super::super::*;
use ed25519_dalek::Signer;

/// Test owner whose signer is the same seeded owner key as the authority log.
pub(crate) fn signed_depth(
    vault: &Vault,
    id: EntityId,
    depth: u8,
    writer: &crate::write_envelope::WriteActor,
    now: u64,
    seed: u8,
) -> Result<()> {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let authority_key = crate::authority::AuthorityKey::Ed25519(key.verifying_key().to_bytes());
    vault.set_project_depth(
        id,
        u64::from(depth),
        writer,
        now,
        authority_key,
        |message| Ok(key.sign(message).to_bytes().to_vec()),
    )
}

// FIX [LIBTEST-QUARANTINE-WORKSPACE-ROSTER-PROJECT-TESTS-SUPPORT-ITEMS]: not ported: create_project_with_owner now takes an AuthenticatedOwner that must revalidate as the vault owner equal to the writer, and an OwnerProjectSigner from a host the authority fold holds; every caller (sync::window and sync::bridge tests) births as a fresh PERSON writer rooted only by root_owner's BindActor, which is not the vault owner, and a person-authorized birth is what they pin; port it with a rooted fixture (as GATE-PROJECT-DEPTH-TESTS-ITEMS), then drop this gate
#[cfg(any())]
/// Person-authorized child birth whose immutable policy fact can cross sync.
#[cfg(feature = "sync")]
pub(crate) fn signed_birth(
    vault: &Vault,
    id: EntityId,
    parent: EntityId,
    leader: EntityId,
    writer: &crate::write_envelope::WriteActor,
    at: u64,
    seed: u8,
) -> Result<()> {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let authority_key = crate::authority::AuthorityKey::Ed25519(key.verifying_key().to_bytes());
    vault.create_project_with_owner(
        id,
        &ProjectRecord::new(id, Some(parent), parent, leader).unwrap(),
        writer,
        at,
        authority_key,
        |message| Ok(key.sign(message).to_bytes().to_vec()),
    )
}
