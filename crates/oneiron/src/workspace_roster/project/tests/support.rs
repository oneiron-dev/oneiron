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

/// Owner-authorized child birth whose immutable policy fact can cross sync.
///
/// The vault must already be rooted under the host `seed` names (see
/// `subject_model::tests::authorization::root_host_owner`), and `writer`
/// must be that bound owner: the depth birth signs with the host key, and
/// the owner authenticates against the same writer the door revalidates.
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
    let issuer = crate::subject_model::tests::authorization::host_issuer_for_seed(seed)?;
    let signing = crate::subject_model::tests::authorization::host_signing_for_seed(seed);
    let authority_key = crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let authenticated = vault.authenticate_owner(
        writer.entity_ref(),
        &writer.entity_ref().to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let project_signer = vault.owner_project_signer(&issuer)?;
    vault.create_project_with_owner(
        id,
        &ProjectRecord::new(id, Some(parent), parent, leader).unwrap(),
        writer,
        at,
        authority_key,
        |message| Ok(signing.sign(message).to_bytes().to_vec()),
        &authenticated,
        &project_signer,
    )
}
