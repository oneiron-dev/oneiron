//! Recipient-specific default CLAIM copies, separate from canonical windows.

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId, WrapType,
    seal_with_aad,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{ReceivedHomeClaimVector, own_peer_in_txn, vector_for_peer_in_txn};
use crate::authority::PeerMachine;
use crate::{EntityId, Error, Result, Vault};

const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
const EPOCH: u64 = 1;

/// The actual delivery being sent or received, not an envelope's claims.
pub(crate) struct HomeClaimDelivery<'a> {
    pub(crate) window: &'a str,
    pub(crate) payload: &'a [u8],
}

/// One machine's opaque copy. Sender authentication still comes from the
/// connection; knowing the recipient's public key does not authenticate a sender.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SealedHomeClaimVector {
    entity_id: EntityId,
    sender: EntityId,
    sender_key: [u8; 32],
    recipient: EntityId,
    window: String,
    payload_digest: [u8; 32],
    release_rows: Vec<EntityId>,
    envelope: Vec<u8>,
}

impl SealedHomeClaimVector {
    /// The original source identities, retained for the final send judgment.
    pub(crate) fn release_rows(&self) -> &[EntityId] {
        &self.release_rows
    }

    fn aad(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(
            self.entity_id,
            self.sender,
            self.sender_key,
            self.window.as_str(),
            self.payload_digest,
            &self.release_rows,
        ))
        .map_err(|_| Error::CorruptedIndex("home CLAIM copy binding"))
    }

    fn matches_delivery(&self, delivery: &HomeClaimDelivery<'_>) -> bool {
        self.window == delivery.window
            && self.payload_digest == *blake3::hash(delivery.payload).as_bytes()
    }
}

fn crypto_error(error: oneiron_crypto::Error) -> Error {
    match error {
        oneiron_crypto::Error::OutOfMemory => {
            Error::Io(std::io::Error::from(std::io::ErrorKind::OutOfMemory))
        }
        _ => Error::CorruptedIndex("home CLAIM copy envelope"),
    }
}

impl Vault {
    /// Seals only a settled vector whose complete source is exactly the selected
    /// source. The queue/send caller must rejudge the recipient at final release.
    pub(crate) fn seal_home_claim_vector(
        &self,
        peer: PeerMachine,
        delivery: &HomeClaimDelivery<'_>,
        id: &EntityId,
        source: &[u8],
    ) -> Result<Option<SealedHomeClaimVector>> {
        let (mut copy, vector, key, vault_id) = {
            let _acceptance = self.device_only_acceptance();
            let txn = self.store.env.read_txn()?;
            let PeerMachine::Proven { machine, .. } = peer else {
                return Ok(None);
            };
            let Some(vector) = vector_for_peer_in_txn(self, &txn, peer, id)? else {
                return Ok(None);
            };
            if vector.source.as_slice() != source {
                return Ok(None);
            }
            let fold = self.authority_fold_readonly_in_txn(&txn)?;
            let Some(key) = crate::secret_custody::linked_machine_encryption_key(&fold, machine)
            else {
                return Ok(None);
            };
            let Some(sender) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
                return Ok(None);
            };
            let sender_key = self
                .door_signing_key_in_txn(&txn, sender)?
                .verifying_key()
                .to_bytes();
            if fold.machine_proof_key(sender) != Some(sender_key) {
                return Ok(None);
            }
            let Some(vault_id) = self.authority_view_readonly_in_txn(&txn)?.vault_id else {
                return Ok(None);
            };
            let copy = SealedHomeClaimVector {
                entity_id: *id,
                sender,
                sender_key,
                recipient: machine,
                window: delivery.window.to_owned(),
                payload_digest: *blake3::hash(delivery.payload).as_bytes(),
                release_rows: vector.release_rows.clone(),
                envelope: Vec::new(),
            };
            (copy, vector, key, vault_id)
        };
        let plaintext = Zeroizing::new(
            rmp_serde::to_vec_named(&vector)
                .map_err(|_| Error::CorruptedIndex("home CLAIM copy"))?,
        );
        let params = SealParams {
            suite: AEAD,
            purpose: Purpose::HomeClaimVector,
            epoch: EPOCH,
            key_id: id.as_bytes(),
            recipient: copy.recipient.as_bytes(),
            vault_id: &vault_id,
        };
        copy.envelope = seal_with_aad(
            &params,
            SealKey::Hybrid {
                recipient: &key,
                kem_suite: KEM,
            },
            &plaintext,
            &copy.aad()?,
            &mut SysRng,
        )
        .map_err(crypto_error)?
        .to_bytes();
        Ok(Some(copy))
    }

    /// Opens a copy for this actual delivered payload and this authenticated
    /// connection. It does not install a vector or replace source admission.
    pub(crate) fn open_home_claim_vector(
        &self,
        peer: PeerMachine,
        delivery: &HomeClaimDelivery<'_>,
        copy: &SealedHomeClaimVector,
    ) -> Result<Option<ReceivedHomeClaimVector>> {
        if !copy.matches_delivery(delivery)
            || peer
                != (PeerMachine::Proven {
                    machine: copy.sender,
                    key: copy.sender_key,
                })
        {
            return Ok(None);
        }
        let secret = self.machine_secret_outside_txn()?;
        let vault_id = {
            let txn = self.store.env.read_txn()?;
            if secret.machine != copy.recipient
                || crate::identity::read_machine_id_in_txn(self, &txn)? != Some(secret.machine)
                || !own_peer_in_txn(self, &txn, peer)?
            {
                return Ok(None);
            }
            let local_key = self
                .door_signing_key_in_txn(&txn, secret.machine)?
                .verifying_key()
                .to_bytes();
            let fold = self.authority_fold_readonly_in_txn(&txn)?;
            if fold.machine_proof_key(secret.machine) != Some(local_key) {
                return Ok(None);
            }
            let Some(current_key) =
                crate::secret_custody::linked_machine_encryption_key(&fold, secret.machine)
            else {
                return Ok(None);
            };
            if current_key.to_bytes() != secret.secret.public_key().to_bytes() {
                return Ok(None);
            }
            let Some(vault_id) = self.authority_view_readonly_in_txn(&txn)?.vault_id else {
                return Ok(None);
            };
            vault_id
        };
        let policy = OpenPolicy {
            purpose: Purpose::HomeClaimVector,
            vault_id: &vault_id,
            recipient: copy.recipient.as_bytes(),
            key_id: copy.entity_id.as_bytes(),
            wraps: &[WrapType::HybridCapsule],
            aead_suites: &[AEAD],
            kem_suites: &[KEM],
            min_epoch: EPOCH,
            argon2_max: Argon2Cost::RFC9106_SECOND,
        };
        let plaintext = Envelope::parse(&copy.envelope)
            .map_err(crypto_error)?
            .open_with_aad(OpenKey::Hybrid(&secret.secret), &policy, &copy.aad()?)
            .map_err(crypto_error)?;
        let vector: super::HomeClaimVector = rmp_serde::from_slice(&plaintext)
            .map_err(|_| Error::CorruptedIndex("home CLAIM copy"))?;
        if vector.entity_id != copy.entity_id || vector.release_rows != copy.release_rows {
            return Ok(None);
        }
        Ok(Some(ReceivedHomeClaimVector { peer, vector }))
    }
}
