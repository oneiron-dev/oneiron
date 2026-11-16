//! Fixture doors for the peer-route full-copy test (L7-47): a machine the
//! owner marks as their own, another machine's home candidacy and full-copy
//! mark signed under that machine's own key, and the fold reads the peer
//! order runs on.

use ed25519_dalek::{Signer, SigningKey};

use crate::authority::{
    ActSurface, AuthorityEntryHash, AuthorityOp, HomeCandidacy, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineRole, append_install_signed_in_txn,
    invalid_authority, machine_profile_proof_transcript,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{EntityId, Vault};

/// Enrols a fresh machine from `seed` as one of the owner's own (`Yours`),
/// and answers its id with the install key that signs as it. The request is
/// the enrolment proof its own key signs for this vault, computer class.
///
/// # Errors
///
/// A vault with no id yet, an enrolment the fold refuses, and storage
/// errors.
pub fn enroll_mine_machine(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    seed: u8,
) -> Result<(EntityId, SigningKey)> {
    let vault_id = vault
        .authority_fold()?
        .vault_id
        .ok_or_else(invalid_authority)?;
    let machine = EntityId::from_bytes([seed; 16])?;
    let key = SigningKey::from_bytes(&[seed; 32]);
    let machine_key = key.verifying_key().to_bytes();
    let device_class = MachineDeviceClass::Computer;
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let request = MachineEnrolmentRequest {
        vault_id,
        machine,
        machine_key,
        device_class,
        encryption_key: encryption_key.clone(),
        machine_proof: key
            .sign(&machine_profile_proof_transcript(
                &vault_id,
                machine,
                &machine_key,
                device_class,
                &encryption_key,
            ))
            .to_bytes(),
    };
    vault.enroll_machine(
        owner,
        ActSurface::ThisInstall,
        &request,
        MachineRole::Owned(MachineOwnership::Yours),
        None,
    )?;
    Ok((machine, key))
}

/// Appends `machine`'s home candidacy saying `node_id` and `always_on`,
/// signed by its install `key` (never primary, macro-ready or cloud). The
/// row lands as the machine's newest, or nothing is committed.
///
/// # Errors
///
/// [`crate::error::RecordError::AuthorityRefused`] for a frontier the join
/// did not fold; an invalid authority refusal for a row that lands anywhere
/// but newest; [`crate::error::Error::InvalidConfig`] for a frontier wider
/// than one entry names; storage errors.
pub fn declare_candidacy_for(
    vault: &Vault,
    machine: EntityId,
    key: &SigningKey,
    node_id: u64,
    always_on: bool,
) -> Result<()> {
    let declaration = HomeCandidacy {
        machine,
        node_id,
        always_on,
        primary: false,
        macro_ready: false,
        cloud: false,
    };
    let mut txn = vault.store.env.write_txn()?;
    let fold = vault.authority_view_readonly_in_txn(&txn)?;
    let act = append_install_signed_in_txn(
        vault,
        &mut txn,
        fold,
        machine,
        key,
        AuthorityOp::HomeCandidacy(declaration),
    )?;
    let after = vault.authority_view_readonly_in_txn(&txn)?;
    if after
        .home_candidacy
        .get(&machine)
        .is_none_or(|newest| newest.act != act)
    {
        return Err(invalid_authority());
    }
    txn.commit()?;
    Ok(())
}

/// Signs `machine`'s full-copy mark saying `held` under its install `key`,
/// committing only when the mark is new. Nothing is written when the fold's
/// newest mark of the machine already says this `held` under this key, or
/// when there is no mark and `held` is false.
///
/// # Errors
///
/// As [`declare_candidacy_for`]; storage errors.
pub fn sign_full_copy_mark(
    vault: &Vault,
    machine: EntityId,
    key: &SigningKey,
    held: bool,
) -> Result<Option<AuthorityEntryHash>> {
    let mut txn = vault.store.env.write_txn()?;
    let fold = vault.authority_view_readonly_in_txn(&txn)?;
    let written = vault.append_full_copy_mark_in_txn(&mut txn, fold, machine, key, held)?;
    if written.is_some() {
        txn.commit()?;
    }
    Ok(written)
}

/// Whether `machine` holds a full copy on this vault's fold: its newest
/// mark says held under the key it still proves here.
///
/// # Errors
///
/// A fold that does not read; storage errors.
pub fn holds_full_copy(vault: &Vault, machine: EntityId) -> Result<bool> {
    Ok(vault.authority_fold()?.holds_full_copy(machine))
}

/// The peer order over `granted` in one snapshot: every machine that holds
/// a full copy before every machine that does not, and the election's order
/// within each group.
///
/// # Errors
///
/// A fold or pick the snapshot cannot read; storage errors.
pub fn rank_sync_peers(
    vault: &Vault,
    granted: &[EntityId],
    local: EntityId,
    down_home: EntityId,
) -> Result<Vec<EntityId>> {
    crate::sync::peer_route::rank_sync_peers(vault, granted, local, down_home)
}
