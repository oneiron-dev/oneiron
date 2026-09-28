//! Vault-local turn cadence and the last queued projector image.

use crate::Vault;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};

/// Digest of the last queued wake projector image. Key: ().
const PROJECTION: SideTable<(), [u8; 32], Raw> =
    SideTable::new(&side_table::DREAMER_WAKE_PROJECTION);

/// Turns per cadence wake, read from the one Dreamer wake policy row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeGrain {
    pub turns_per_wake: u64,
}

impl WakeGrain {
    /// A zero grain cannot make progress.
    pub fn new(turns_per_wake: u64) -> Result<Self> {
        if turns_per_wake == 0 {
            return Err(Error::InvalidConfig("wake grain must be positive".into()));
        }
        Ok(Self { turns_per_wake })
    }

    /// Turn ordinals start at one. The Nth turn closes the first N-turn window.
    #[must_use]
    pub fn due(self, turn_ordinal: u64) -> bool {
        turn_ordinal != 0 && turn_ordinal.is_multiple_of(self.turns_per_wake)
    }
}

impl Vault {
    /// Read the authoritative per-vault rate from the host-used wake policy.
    pub fn wake_grain(&self) -> Result<WakeGrain> {
        WakeGrain::new(self.dreamer_wake_policy()?.wake_grain_turns)
    }

    pub(super) fn queued_wake_projection_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
    ) -> Result<Option<[u8; 32]>> {
        PROJECTION
            .get(&self.store, txn, &())
            .map_err(|error| match error {
                Error::Store(crate::error::StoreError::SideTableRow { .. }) => {
                    Error::InvalidConfig("invalid wake projection row".into())
                }
                other => other,
            })
    }

    pub(super) fn set_queued_wake_projection_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        digest: &[u8; 32],
    ) -> Result<()> {
        PROJECTION.put(&self.store, txn, &(), digest)
    }
}
