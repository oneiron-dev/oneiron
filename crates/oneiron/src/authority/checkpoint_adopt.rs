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
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::checkpoint_image::checkpoint_image_id;
use super::*;
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
