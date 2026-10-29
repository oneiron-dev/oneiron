//! Credential-only re-pairing (FIX 8636): a machine the roster already holds
//! live pairs again under its own identity and class with a new link from the
//! owner. Nothing joins the roster and no revision is written: the machine's
//! identity, profile, role and keys stay exactly as they stand, and the
//! redemption issues the new credential alone. Its machine key signs this one
//! redemption, since the enrolment proof its request carries is the one the
//! log already holds and any replica could replay. Its earlier slips are left
//! to run out, as a renewal leaves the one it replaces (FIX 3377).

use ed25519_dalek::{Signature, Signer, VerifyingKey};

use super::*;
use crate::EntityId;

const MACHINE_POSSESSION_DOMAIN: &[u8] = b"oneiron/pairing-machine-possession/v1\0";

/// The bytes a machine signs with its machine key to pair again under its
/// own identity (FIX 8636): the vault, the machine row, its machine key, and
/// the BLAKE3 of the redemption's binding transcript
/// ([`pairing_binding_transcript_pinned`]), which names the one-use code, the
/// new connection key, the holder and the pin. A proof for one redemption
/// never spends another link or binds another connection key.
#[must_use]
pub fn machine_possession_transcript(
    vault_id: &[u8; 32],
    machine: EntityId,
    machine_key: &[u8; 32],
    binding_transcript: &[u8],
) -> Vec<u8> {
    let mut bytes = MACHINE_POSSESSION_DOMAIN.to_vec();
    bytes.extend_from_slice(vault_id);
    bytes.extend_from_slice(machine.as_bytes());
    bytes.extend_from_slice(machine_key);
    bytes.extend_from_slice(blake3::hash(binding_transcript).as_bytes());
    bytes
}

/// The standing a credential-only re-pairing keeps: the machine as the fold
/// holds it, or `None` when `request` is no re-pairing, as for a machine the
/// roster does not hold, or one whose host now declares another class (a
/// class-only revision, FIX 3835). The checks are a class-only revision's: a
/// live machine under the same id and both the same keys, in the role the
/// link answers; a removed or conflicted machine never comes back. Its
/// machine key must have signed `possession` over this redemption.
pub(super) fn re_paired_standing(
    fold: &AuthorityFold,
    request: &MachineEnrolmentRequest,
    role: MachineRole,
    possession: &[u8; 64],
    binding_transcript: &[u8],
) -> Result<Option<FoldedMachine>> {
    let Some(folded) = fold
        .machine(request.machine)
        .filter(|folded| folded.roster.is_some())
    else {
        return Ok(None);
    };
    let mut heads: Vec<_> = folded.chains().map(|(_, head)| head).collect();
    heads.sort_by_key(|head| head.profile.revision);
    let current = heads.last().ok_or_else(invalid_authority)?;
    if current.profile.device_class != request.device_class {
        return Ok(None);
    }
    let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
    if vault_id != request.vault_id
        || !folded.roster.as_ref().is_some_and(MachineRevision::is_live)
        || heads.iter().any(|head| {
            head.removed
                || head.conflicted
                || head.profile.machine_key != request.machine_key
                || head.profile.encryption_key != request.encryption_key
        })
        || current.profile.role != role
    {
        return Err(invalid_authority());
    }
    // Key possession: the key the roster holds signs this redemption.
    let key = VerifyingKey::from_bytes(&current.profile.machine_key)
        .map_err(|_| invalid_authority())?;
    key.verify_strict(
        &machine_possession_transcript(
            &vault_id,
            request.machine,
            &current.profile.machine_key,
            binding_transcript,
        ),
        &Signature::from_bytes(possession),
    )
    .map_err(|_| invalid_authority())?;
    Ok(Some(folded.clone()))
}

impl Vault {
    /// The client half: this install's machine key's signature over
    /// [`machine_possession_transcript`] for `request` and the redemption's
    /// `binding_transcript`, sent beside the request. A home that already
    /// holds this machine live in the same class and role pairs it again
    /// with it, its standing kept; any other home enrols the request as
    /// before. `request` must be this install's own
    /// ([`Vault::machine_enrolment_request`]).
    pub fn machine_possession_proof(
        &self,
        request: &MachineEnrolmentRequest,
        binding_transcript: &[u8],
    ) -> Result<[u8; 64]> {
        self.load_install_signing_if_minted()?;
        let txn = self.store.env.read_txn()?;
        let machine = crate::identity::read_machine_id_in_txn(self, &txn)?;
        let key = crate::identity::read_machine_signing_key_in_txn(self, &txn)?;
        let Some(key) = key.filter(|key| {
            machine == Some(request.machine)
                && key.verifying_key().to_bytes() == request.machine_key
        }) else {
            return Err(crate::world_keys::refused(
                "the enrolment request is not this install's own machine",
            ));
        };
        Ok(key
            .sign(&machine_possession_transcript(
                &request.vault_id,
                request.machine,
                &request.machine_key,
                binding_transcript,
            ))
            .to_bytes())
    }
}
