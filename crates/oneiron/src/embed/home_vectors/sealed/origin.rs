//! Original-sender proof for an optional copy carried by a different peer.
//! This proof never authenticates the canonical update or its MESSAGE rows.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{HomeClaimDelivery, PreparedHomeClaimDelivery, SealedHomeClaimVector};
use crate::authority::PeerMachine;
use crate::embed::home_vectors::{ReceivedHomeClaimVector, own_peer_in_txn};
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

fn origin_transcript(vault_id: &[u8; 32], copy: &SealedHomeClaimVector) -> Result<Vec<u8>> {
    // The whole copy includes recipient, full ciphertext and every release owner.
    rmp_serde::to_vec(&(COPY_ORIGIN_DOMAIN, vault_id, copy))
        .map_err(|_| Error::CorruptedIndex("home CLAIM copy origin binding"))
}

impl Vault {
    /// Seals as before, then signs the immutable result with this install's
    /// still-current original key. The final send must rejudge every source.
    pub(crate) fn seal_relayed_home_claim_vector(
        &self,
        peer: PeerMachine,
        delivery: &HomeClaimDelivery<'_>,
        id: &EntityId,
        source: &[u8],
    ) -> Result<Option<SenderSignedHomeClaimVector>> {
        let Some(copy) = self.seal_home_claim_vector(peer, delivery, id, source)? else {
            return Ok(None);
        };
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
        Ok(Some(SenderSignedHomeClaimVector { copy, signature }))
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
