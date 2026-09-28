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
    vault.set_project_depth(id, depth, writer, now, authority_key, |message| {
        Ok(key.sign(message).to_bytes().to_vec())
    })
}

/// Person-authorized child birth whose immutable policy fact can cross sync.
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
