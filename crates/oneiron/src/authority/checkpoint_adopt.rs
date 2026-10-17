//! Checkpoint v2 adoption (OF-469): the one image a vault trusts in place of
//! replaying the history it covers. Trust comes only from a verified image: its
//! bytes decode strictly, their id is the pin's checkpoint, the image names the
//! pin's genesis and root policy, and the attestations reach the pin's quorum
//! with both signatures each. The pin itself must come from owner-authorized
//! pairing or recovery; a pin handed over beside the image proves nothing.
//!
//! The adopted pin and attestations are kept in one row; its pin names the
//! adopted image, so no second head row exists. Every read verifies again: a
//! stored row is not trusted for having been stored.
//!
//! Adoption is one transaction: it compares what the caller read (the v2
//! head, the adopted pin's digest, the authority cache generation), checks
//! the image against this vault (its storage id, a resident Genesis, its
//! owner-root pin, an empty unresolved closure, coverage that never shrinks),
//! then keeps the image as the head, stores the pin and attestations and
//! advances the generation. It publishes nothing into the process cache.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::checkpoint_image::checkpoint_image_id;
use super::*;
use crate::Vault;
use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// The adopted image's pin and the attestations that verified it. Key: ().
const ADOPTED: SideTable<(), AdoptedCheckpoint, Named> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_ADOPTED_PIN);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptedCheckpoint {
    pin: AuthorityCheckpointPin,
    attestations: Vec<AuthorityCheckpointAttestation>,
}

fn adopt_refused(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(reason))
}

/// A checkpoint image verified against an externally fixed pin. The only
/// constructor is [`VerifiedAuthorityCheckpoint::verify`].
#[derive(Debug, Clone)]
pub struct VerifiedAuthorityCheckpoint {
    id: [u8; 32],
    image: AuthorityCheckpointV2,
    pin: AuthorityCheckpointPin,
    attestations: Vec<AuthorityCheckpointAttestation>,
    roots: BTreeSet<AuthorityKey>,
}

impl VerifiedAuthorityCheckpoint {
    /// Decodes `bytes` strictly, takes their id, requires the image's genesis
    /// and root policy to be the pin's, and verifies the attestations against
    /// the pin (the id must be the pin's checkpoint). The caller vouches that
    /// `pin` came through owner-authorized pairing or recovery.
    pub fn verify(
        pin: &AuthorityCheckpointPin,
        bytes: &[u8],
        attestations: &[AuthorityCheckpointAttestation],
    ) -> Result<Self> {
        let image = AuthorityCheckpointV2::decode(bytes)?;
        let id = checkpoint_image_id(bytes);
        if image.genesis != pin.genesis {
            return Err(adopt_refused("checkpoint image genesis is not the pin's"));
        }
        if image.root_policy.digest()? != pin.policy.digest()? {
            return Err(adopt_refused("checkpoint image policy is not the pin's"));
        }
        let roots = verify_authority_checkpoint_attestations(pin, &id, attestations)?;
        Ok(Self {
            id,
            image,
            pin: pin.clone(),
            attestations: attestations.to_vec(),
            roots,
        })
    }

    /// The image id, equal to the pin's checkpoint.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    #[must_use]
    pub fn image(&self) -> &AuthorityCheckpointV2 {
        &self.image
    }

    #[must_use]
    pub fn pin(&self) -> &AuthorityCheckpointPin {
        &self.pin
    }

    #[must_use]
    pub fn attestations(&self) -> &[AuthorityCheckpointAttestation] {
        &self.attestations
    }

    /// The distinct eligible roots whose attestations verified.
    #[must_use]
    pub fn roots(&self) -> &BTreeSet<AuthorityKey> {
        &self.roots
    }
}

/// What an adoption expects to find, read in one snapshot: the v2 head, the
/// adopted pin's digest and the authority cache generation. Any of them
/// moving before the adoption commits refuses it as a concurrent write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityCheckpointExpectation {
    pub head: Option<[u8; 32]>,
    pub adopted_pin_digest: Option<[u8; 32]>,
    pub generation: u64,
}

/// A kept checkpoint image and the attestations stored for it under the
/// image's own root policy: what a paired device fetches to adopt the image
/// its pin names. Nothing here is trusted until it verifies against that pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCheckpointBundle {
    /// The image's canonical bytes; standard base64 on the wire.
    #[serde(with = "image_base64")]
    pub image: Vec<u8>,
    pub attestations: Vec<AuthorityCheckpointAttestation>,
}

/// Image bytes as one standard base64 string.
mod image_base64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(serde::de::Error::custom)
    }
}

fn expectation_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<AuthorityCheckpointExpectation> {
    Ok(AuthorityCheckpointExpectation {
        head: super::checkpoint::checkpoint_head_in_txn(store, txn)?,
        adopted_pin_digest: ADOPTED
            .get(store, txn, &())?
            .map(|adopted| adopted.pin.digest())
            .transpose()?,
        generation: super::readonly_fold::authority_cache_generation(store, txn)?,
    })
}

/// Whether this vault holds an adoption row, read without verifying it.
pub(super) fn checkpoint_adopted_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(ADOPTED.get(store, txn, &())?.is_some())
}

/// The image this vault adopted, verified again from the stored pin,
/// attestations and image bytes. None when nothing was adopted; a stored
/// adoption that no longer verifies is corruption, never "not adopted".
pub(super) fn adopted_authority_checkpoint_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<VerifiedAuthorityCheckpoint>> {
    let Some(adopted) = ADOPTED.get(store, txn, &())? else {
        return Ok(None);
    };
    let bytes =
        super::checkpoint::checkpoint_image_bytes_in_txn(store, txn, &adopted.pin.checkpoint)?
            .ok_or(Error::CorruptedIndex("adopted authority checkpoint image"))?;
    VerifiedAuthorityCheckpoint::verify(&adopted.pin, &bytes, &adopted.attestations)
        .map(Some)
        .map_err(|_| Error::CorruptedIndex("adopted authority checkpoint"))
}

impl Vault {
    /// What [`Vault::adopt_authority_checkpoint_in_txn`] compares, read in
    /// `txn`'s snapshot.
    pub fn authority_checkpoint_expectation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<AuthorityCheckpointExpectation> {
        expectation_in_txn(&self.store, txn)
    }

    /// Adopts `verified` in the caller's write transaction and returns its id;
    /// the caller commits, and aborts on any error. Refused unless `expected`
    /// is still what `wtxn` reads (else `ConcurrentWrite`), the pin names this
    /// vault's storage id, a resident Genesis is the pin's genesis, the image
    /// was built under this install's own owner-root pin, its unresolved
    /// closure is empty, and it covers every row the prior adoption covered.
    /// Adopting the adopted image again changes nothing.
    pub fn adopt_authority_checkpoint_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        verified: &VerifiedAuthorityCheckpoint,
        expected: &AuthorityCheckpointExpectation,
    ) -> Result<[u8; 32]> {
        let store = &self.store;
        if expectation_in_txn(store, wtxn)? != *expected {
            return Err(Error::ConcurrentWrite(
                "authority checkpoint adoption: the head, adoption or generation moved",
            ));
        }
        let (id, pin, image) = (verified.id(), verified.pin(), verified.image());
        if pin.vault_id != *self.vault_id().as_bytes() {
            return Err(adopt_refused("the checkpoint pin names another vault"));
        }
        // Read without folding: the fold is what the adoption installs.
        if super::machine_identity::resident_genesis_vault_id_in_txn(store, wtxn)?
            .is_some_and(|genesis| genesis != pin.genesis)
        {
            return Err(adopt_refused(
                "the checkpoint pin's genesis is not this vault's resident genesis",
            ));
        }
        if image.building_pin != super::pinned_root::read_pinned_root_in_txn(store, wtxn)? {
            return Err(adopt_refused(
                "the checkpoint image was built under another owner-root pin",
            ));
        }
        if image.unresolved != AuthorityCheckpointUnresolved::default() {
            return Err(adopt_refused("the checkpoint image holds unresolved rows"));
        }
        if let Some(prior) = adopted_authority_checkpoint_in_txn(store, wtxn)? {
            if prior.id() == id {
                return Ok(id);
            }
            if prior.pin().genesis != pin.genesis
                || prior
                    .image()
                    .covered
                    .iter()
                    .any(|hash| image.covered.binary_search(hash).is_err())
            {
                return Err(adopt_refused(
                    "the checkpoint image does not cover the adopted image",
                ));
            }
        }
        let bytes = image.encode()?;
        if checkpoint_image_id(&bytes) != id {
            return Err(Error::CorruptedIndex("verified authority checkpoint"));
        }
        super::checkpoint::keep_checkpoint_head_in_txn(store, wtxn, &id, bytes)?;
        ADOPTED.put(
            store,
            wtxn,
            &(),
            &AdoptedCheckpoint {
                pin: pin.clone(),
                attestations: verified.attestations().to_vec(),
            },
        )?;
        super::readonly_fold::advance_authority_cache_generation(store, wtxn)?;
        Ok(id)
    }

    /// Verifies `bytes` and `attestations` against `pin` and adopts the image
    /// in one write transaction; returns its id. The caller vouches that
    /// `pin` came through owner-authorized pairing or recovery.
    pub fn adopt_authority_checkpoint(
        &self,
        pin: &AuthorityCheckpointPin,
        bytes: &[u8],
        attestations: &[AuthorityCheckpointAttestation],
    ) -> Result<[u8; 32]> {
        let verified = VerifiedAuthorityCheckpoint::verify(pin, bytes, attestations)?;
        let mut wtxn = self.store.env.write_txn()?;
        let expected = self.authority_checkpoint_expectation_in_txn(&wtxn)?;
        let id = self.adopt_authority_checkpoint_in_txn(&mut wtxn, &verified, &expected)?;
        wtxn.commit()?;
        Ok(id)
    }

    /// The image this vault adopted, verified again; None when nothing was
    /// adopted.
    pub fn adopted_authority_checkpoint(&self) -> Result<Option<VerifiedAuthorityCheckpoint>> {
        let txn = self.store.env.read_txn()?;
        adopted_authority_checkpoint_in_txn(&self.store, &txn)
    }

    /// The kept image `id` names and the attestations stored for it under
    /// the image's own root policy, for a paired device to adopt. None when
    /// no image is kept at `id`.
    pub fn authority_checkpoint_bundle(
        &self,
        id: &[u8; 32],
    ) -> Result<Option<AuthorityCheckpointBundle>> {
        let txn = self.store.env.read_txn()?;
        let Some(image) = super::checkpoint::checkpoint_image_bytes_in_txn(&self.store, &txn, id)?
        else {
            return Ok(None);
        };
        if checkpoint_image_id(&image) != *id {
            return Err(Error::CorruptedIndex("kept authority checkpoint image"));
        }
        let policy = AuthorityCheckpointV2::decode(&image)?
            .root_policy
            .digest()?;
        let attestations = super::checkpoint_attest::checkpoint_attestations_under_in_txn(
            &self.store,
            &txn,
            id,
            &policy,
        )?;
        Ok(Some(AuthorityCheckpointBundle {
            image,
            attestations,
        }))
    }
}
