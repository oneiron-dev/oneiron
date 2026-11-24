//! The vault's [`MachineSignatures`]: this install signs as its machine with
//! its machine key, and a peer machine's signature is checked against the
//! machine key its MACHINE row proves in this replica, the key the mesh's
//! peer proof reads ([`Vault::mesh_peer_machine`]). One key path for the
//! organ call receipt (OF-575) and pass 33's job submit and job receipt.

use ed25519_dalek::{Signature, Signer, VerifyingKey};

use crate::machine_signature::{
    MachineSignatureError, MachineSignatures, machine_signature_transcript,
};
use crate::{EntityId, Vault};

impl MachineSignatures for Vault {
    /// Signs with the keys this install already holds: the loaded signer,
    /// else the one its keystore slot holds. It never mints a machine id or
    /// a seed to answer ([`Vault::read_install_signer`]).
    fn sign(
        &self,
        domain: &[u8],
        message: &[u8],
    ) -> Result<(EntityId, [u8; 64]), MachineSignatureError> {
        let signer = self
            .read_install_signer()
            .map_err(|error| MachineSignatureError::Store(error.to_string()))?
            .ok_or(MachineSignatureError::NoMachineKey)?;
        let signature = signer
            .machine_key
            .sign(&machine_signature_transcript(domain, message));
        Ok((signer.machine, signature.to_bytes()))
    }

    fn verify(
        &self,
        machine: EntityId,
        domain: &[u8],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), MachineSignatureError> {
        let store = |error: crate::Error| MachineSignatureError::Store(error.to_string());
        let key = {
            let txn = self
                .store
                .env
                .read_txn()
                .map_err(|error| store(error.into()))?;
            self.authority_view_readonly_in_txn(&txn)
                .map_err(store)?
                .machine_proof_key(machine)
        };
        let key = key
            .and_then(|key| VerifyingKey::from_bytes(&key).ok())
            .ok_or(MachineSignatureError::UnknownMachine { machine })?;
        key.verify_strict(
            &machine_signature_transcript(domain, message),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| MachineSignatureError::Mismatch { machine })
    }
}
