//! Vault-local turn cadence and the last queued projector image.

use crate::Vault;
use crate::error::{Error, Result};

const PROJECTION_KEY: &[u8] = b"dreamer:wake:projection:v1";

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
        self.store
            .vault_meta
            .get(txn, PROJECTION_KEY)?
            .map(|bytes| {
                let slice: &[u8] = bytes.as_ref();
                slice
                    .try_into()
                    .map_err(|_| Error::InvalidConfig("invalid wake projection row".into()))
            })
            .transpose()
    }

    pub(super) fn set_queued_wake_projection_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        digest: &[u8; 32],
    ) -> Result<()> {
        self.store.vault_meta.put(txn, PROJECTION_KEY, digest)?;
        Ok(())
    }
}
