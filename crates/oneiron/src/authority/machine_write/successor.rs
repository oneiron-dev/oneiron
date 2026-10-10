//! Re-signing a MACHINE claim's successor with its writer's retained signer.

use rmpv::Value;

use super::{SIGNATURE_KEY, denied, machine_claim_transcript};
use crate::Vault;
use crate::claim::ClaimBody;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::write_envelope::{MachineWriteSignature, WriteEnvelope};

impl Vault {
    /// A successor the engine writes for a MACHINE's own claim (a Dreamer
    /// weakening) is a fresh birth, so it is signed like one: the signer the
    /// host retained for the envelope's actor signs the successor's own
    /// transcript, and that proof replaces the predecessor's in place. With
    /// no retained signer the successor cannot be written.
    pub(crate) fn resign_machine_successor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        body: &mut ClaimBody,
        envelope: &mut WriteEnvelope,
    ) -> Result<()> {
        if envelope.actor().actor_class() != EdgeActorClass::System {
            return Err(denied());
        }
        let (public_key, sign) =
            self.retained_successor_signer_in_txn(txn, envelope.actor().entity_ref())?;
        let vault_id = self
            .authority_fold_readonly_in_txn(txn)?
            .vault_id
            .ok_or_else(denied)?;
        let proof = MachineWriteSignature {
            public_key,
            signature: sign(&machine_claim_transcript(&vault_id, id, body)?)?,
        };
        let Some(Value::Map(entries)) = body.evidence.as_mut() else {
            return Err(denied());
        };
        let slot = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some(SIGNATURE_KEY))
            .ok_or_else(denied)?;
        slot.1 = Value::Array(vec![
            Value::Binary(proof.public_key.to_vec()),
            Value::Binary(proof.signature.to_vec()),
        ]);
        *envelope = envelope.clone().with_machine_signature(proof);
        Ok(())
    }

    /// The signer the host retained on this handle for `machine`. A reopened
    /// vault holds none until the host provisions the engine's identities
    /// again, and that missing setup step is named as such. A writer whose
    /// every binding is dead stays an authority denial: provisioning never
    /// revives a revoked key.
    fn retained_successor_signer_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        machine: EntityId,
    ) -> Result<([u8; 32], crate::store::MachineWriteSigner)> {
        if let Some(signer) = self.retained_machine_signer(machine)? {
            return Ok(signer);
        }
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        if fold
            .actor_bindings
            .values()
            .any(|binding| binding.actor_ref == machine)
            && !crate::authority::actor_binding_is_active(&fold, &machine, "system")
        {
            return Err(denied());
        }
        Err(Error::Claim(ClaimError::EngineIdentitiesNotProvisioned {
            machine,
        }))
    }
}
