//! Per-peer confidence for federated claims (OF-149, ARCH-0043): how far
//! this vault believes what one federation peer tells it. Admission scales
//! every claim a peer sends by its peer's scale, once, at the boundary;
//! admitted bytes replay unchanged. The scale is this device's local truth,
//! set by its owner and never synced or taken from the wire.

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// The scale a peer with no owner-set row gets: one conservative
/// multiplier for every federated role.
pub const DEFAULT_FEDERATED_CONFIDENCE_SCALE: f32 = 0.5;

/// The owner's scale for one peer principal.
const PEER_CONFIDENCE: SideTable<EntityId, PeerConfidence, Named> =
    SideTable::new(&side_table::FEDERATION_PEER_CONFIDENCE);

/// One peer's owner-set scale.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfidence {
    /// Multiplies a peer claim's confidence: above 0, at most 1. A peer is
    /// never believed above the owner's own word.
    pub scale: f32,
    pub set_at: u64,
}

fn valid_scale(scale: f32) -> bool {
    scale.is_finite() && scale > 0.0 && scale <= 1.0
}

/// The scale admission applies to what `peer` sends, read in `txn`.
pub(crate) fn peer_confidence_scale_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    peer: &EntityId,
) -> Result<f32> {
    Ok(PEER_CONFIDENCE
        .get(&vault.store, txn, peer)?
        .map(|row| row.scale)
        .filter(|scale| valid_scale(*scale))
        .unwrap_or(DEFAULT_FEDERATED_CONFIDENCE_SCALE))
}

impl Vault {
    /// The scale admission applies to claims `peer` sends.
    pub fn federation_peer_confidence(&self, peer: &EntityId) -> Result<f32> {
        let rtxn = self.store.env.read_txn()?;
        peer_confidence_scale_in_txn(self, &rtxn, peer)
    }

    /// Every peer with an owner-set scale.
    pub fn federation_peer_confidences(&self) -> Result<Vec<(EntityId, PeerConfidence)>> {
        let rtxn = self.store.env.read_txn()?;
        PEER_CONFIDENCE.scan(&self.store, &rtxn)
    }

    /// Sets `peer`'s scale, or with `None` returns it to the default. Applies
    /// to what the peer sends from now on; claims already admitted keep the
    /// confidence they were admitted with.
    pub fn set_federation_peer_confidence_as(
        &self,
        owner: &AuthenticatedOwner,
        peer: &EntityId,
        scale: Option<f32>,
        now: u64,
    ) -> Result<f32> {
        self.recheck_owner(owner)?;
        if scale.is_some_and(|scale| !valid_scale(scale)) {
            return Err(Error::InvalidConfig(
                "federation peer confidence must be above 0 and at most 1".to_owned(),
            ));
        }
        self.with_write_txn_grouped(|txn| {
            match scale {
                Some(scale) => PEER_CONFIDENCE.put(
                    &self.store,
                    txn,
                    peer,
                    &PeerConfidence { scale, set_at: now },
                )?,
                None => {
                    PEER_CONFIDENCE.delete(&self.store, txn, peer)?;
                }
            }
            Ok(scale.unwrap_or(DEFAULT_FEDERATED_CONFIDENCE_SCALE))
        })
    }
}
