//! The two native custody forms in the existing embedding job copy slot.
//! Their named fields distinguish them; no transport or queue tag is added.

use serde::Deserialize;

use super::actor_copy::RetainedHomeClaimActors;
use super::retained::RetainedHomeClaimResponse;
use crate::{EntityId, Error, Result};

/// The original receive and its native prepared custody stay in one holder.
/// Neither serialization nor a copied instance id can reconstruct this value.
pub(crate) enum PreparedHomeClaimCopy {
    Response(super::retained::PreparedHomeClaimResponse),
    OriginActors(super::actor_copy::PreparedHomeClaimActors),
}

impl PreparedHomeClaimCopy {
    pub(crate) fn entity_id(&self) -> EntityId {
        match self {
            Self::Response(copy) => copy.entity_id(),
            Self::OriginActors(copy) => copy.entity_id(),
        }
    }

    pub(crate) fn retain_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<super::retained::RetainedHomeClaimState> {
        match self {
            Self::Response(copy) => copy.retain_in_txn(vault, txn),
            Self::OriginActors(copy) => copy.retain_in_txn(vault, txn),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum RetainedHomeClaimCopy {
    Response(RetainedHomeClaimResponse),
    OriginActors(RetainedHomeClaimActors),
}

impl RetainedHomeClaimCopy {
    /// Data validation only. Each native consumer still checks its own custody.
    pub(crate) fn decode(id: &EntityId, bytes: &[u8]) -> Result<Self> {
        let copy: Self = rmp_serde::from_slice(bytes)
            .map_err(|_| Error::CorruptedIndex("retained home CLAIM copy"))?;
        let found = match &copy {
            Self::Response(copy) => copy.vector.entity_id,
            Self::OriginActors(copy) => {
                copy.required()?;
                copy.entity_id()
            }
        };
        if found != *id {
            return Err(Error::CorruptedIndex("retained home CLAIM copy"));
        }
        Ok(copy)
    }
}
