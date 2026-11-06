//! Original-sender proof for an optional copy carried by a different peer.
//! This proof never authenticates the canonical update or its MESSAGE rows.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{HomeClaimDelivery, PreparedHomeClaimDelivery, SealedHomeClaimVector};
use crate::authority::PeerMachine;
use crate::embed::home_vectors::{
    ReceivedHomeClaimVector, own_peer_in_txn, vector_for_peer_in_txn,
};
use crate::{EntityId, Error, Result, Vault};

const COPY_ORIGIN_DOMAIN: &[u8] = b"oneiron/home-claim-copy-origin/v1\0";

/// Authenticates only this optional derived copy's origin. The raw delivery
/// keeps its real transport peer, including Unknown on a sealed world relay.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SenderSignedHomeClaimVector {
    copy: SealedHomeClaimVector,
    signature: Vec<u8>,
}

impl SenderSignedHomeClaimVector {
    /// Source ids the final release must judge for the actual recipient.
    pub(crate) fn release_rows(&self) -> &[EntityId] {
        self.copy.release_rows()
    }
}

/// Holds the exact native source and recipient key used by the sealer until
/// the actual send, not a serializable grant or a queued release certificate.
pub(crate) struct PreparedHomeClaimSend {
    vault: std::path::PathBuf,
    vault_id: [u8; 32],
    recipient: PeerMachine,
    recipient_encryption_key: Vec<u8>,
    source: Vec<u8>,
    signed: SenderSignedHomeClaimVector,
}

impl PreparedHomeClaimSend {
    pub(crate) fn release_rows(&self) -> &[EntityId] {
        self.signed.release_rows()
    }

    /// Rechecks the actual source and original native keys at release. The
    /// socket must also judge every release row for its real destination.
    /// Do not queue the returned copy and treat this snapshot as a later grant.
    pub(crate) fn into_copy_for(
        self,
        vault: &Vault,
        recipient: PeerMachine,
        delivery: &HomeClaimDelivery<'_>,
    ) -> Result<Option<SenderSignedHomeClaimVector>> {
        if self.vault != vault.store.env.path()
            || self.recipient != recipient
            || !self.signed.copy.matches_delivery(delivery)
        {
            return Ok(None);
        }
        let _acceptance = vault.device_only_acceptance();
        let txn = vault.store.env.read_txn()?;
        if vault.authority_view_readonly_in_txn(&txn)?.vault_id != Some(self.vault_id) {
            return Ok(None);
        }
        let origin = PeerMachine::Proven {
            machine: self.signed.copy.sender,
            key: self.signed.copy.sender_key,
        };
        if !own_peer_in_txn(vault, &txn, origin)? || !own_peer_in_txn(vault, &txn, recipient)? {
            return Ok(None);
        }
        let fold = vault.authority_fold_readonly_in_txn(&txn)?;
        let Some(key) =
            crate::secret_custody::linked_machine_encryption_key(&fold, self.signed.copy.recipient)
        else {
            return Ok(None);
        };
        if key.to_bytes().as_slice() != self.recipient_encryption_key.as_slice() {
            return Ok(None);
        }
        let Some(current) =
            vector_for_peer_in_txn(vault, &txn, recipient, &self.signed.copy.entity_id)?
        else {
            return Ok(None);
        };
        if current.source != self.source || current.release_rows != self.signed.copy.release_rows {
            return Ok(None);
        }
        Ok(Some(self.signed))
    }
}

fn origin_transcript(vault_id: &[u8; 32], copy: &SealedHomeClaimVector) -> Result<Vec<u8>> {
    // The whole copy includes recipient, full ciphertext and every release owner.
    rmp_serde::to_vec(&(COPY_ORIGIN_DOMAIN, vault_id, copy))
        .map_err(|_| Error::CorruptedIndex("home CLAIM copy origin binding"))
}

impl Vault {
    /// Seals as before, then signs the immutable result with this install's
    /// still-current original key. The final send must rejudge every source.
    pub(crate) fn prepare_relayed_home_claim_send(
        &self,
        peer: PeerMachine,
        delivery: &HomeClaimDelivery<'_>,
        id: &EntityId,
        source: &[u8],
    ) -> Result<Option<PreparedHomeClaimSend>> {
        let Some(prepared) = self.seal_home_claim_vector_for_send(peer, delivery, id, source)?
        else {
            return Ok(None);
        };
        let copy = prepared.copy;
        let txn = self.store.env.read_txn()?;
        let key = self.door_signing_key_in_txn(&txn, copy.sender)?;
        if key.verifying_key().to_bytes() != copy.sender_key
            || !own_peer_in_txn(
                self,
                &txn,
                PeerMachine::Proven {
                    machine: copy.sender,
                    key: copy.sender_key,
                },
            )?
        {
            return Ok(None);
        }
        let Some(vault_id) = self.authority_view_readonly_in_txn(&txn)?.vault_id else {
            return Ok(None);
        };
        let signature = key
            .sign(&origin_transcript(&vault_id, &copy)?)
            .to_bytes()
            .to_vec();
        Ok(Some(PreparedHomeClaimSend {
            vault: self.store.env.path().to_path_buf(),
            vault_id,
            recipient: peer,
            recipient_encryption_key: prepared.recipient_encryption_key,
            source: prepared.source,
            signed: SenderSignedHomeClaimVector { copy, signature },
        }))
    }

    /// Verifies the copy's original sender separately from the relay. The
    /// unchanged opener still checks recipient, native keys and full AEAD.
    pub(crate) fn open_relayed_home_claim_vector(
        &self,
        delivery: &HomeClaimDelivery<'_>,
        signed: &SenderSignedHomeClaimVector,
    ) -> Result<Option<ReceivedHomeClaimVector>> {
        if !signed.copy.matches_delivery(delivery) {
            return Ok(None);
        }
        let Ok(signature) = <&[u8; 64]>::try_from(signed.signature.as_slice()) else {
            return Ok(None);
        };
        let signature = Signature::from_bytes(signature);
        let Ok(key) = VerifyingKey::from_bytes(&signed.copy.sender_key) else {
            return Ok(None);
        };
        let origin = PeerMachine::Proven {
            machine: signed.copy.sender,
            key: signed.copy.sender_key,
        };
        let vault_id = {
            let txn = self.store.env.read_txn()?;
            if !own_peer_in_txn(self, &txn, origin)? {
                return Ok(None);
            }
            let Some(vault_id) = self.authority_view_readonly_in_txn(&txn)?.vault_id else {
                return Ok(None);
            };
            vault_id
        };
        if key
            .verify_strict(&origin_transcript(&vault_id, &signed.copy)?, &signature)
            .is_err()
        {
            return Ok(None);
        }
        self.open_home_claim_vector(origin, delivery, &signed.copy)
    }

    /// Prepares optional copies without lending their sender proof to raw
    /// import. Missing or invalid copies never refuse the canonical delivery.
    pub(crate) fn prepare_relayed_home_claim_delivery(
        &self,
        raw_peer: PeerMachine,
        delivery: &HomeClaimDelivery<'_>,
        copies: &[SenderSignedHomeClaimVector],
    ) -> PreparedHomeClaimDelivery {
        self.prepare_home_claim_delivery_from(
            raw_peer,
            delivery,
            copies
                .iter()
                .map(|copy| self.open_relayed_home_claim_vector(delivery, copy)),
        )
    }
}
