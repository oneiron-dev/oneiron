//! Vault-local turn cadence and the last queued projector image.

use crate::Vault;
use crate::error::{Error, Result};

const GRAIN_KEY: &[u8] = b"dreamer:wake:grain:v1";
const PROJECTION_KEY: &[u8] = b"dreamer:wake:projection:v1";

/// Turns per cadence wake. An absent policy row means one wake per turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeGrain {
    pub turns_per_wake: u64,
}

impl Default for WakeGrain {
    fn default() -> Self {
        Self { turns_per_wake: 1 }
    }
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
    /// Read the vault's own wake policy, refusing corrupt or unknown rows.
    pub fn wake_grain(&self) -> Result<WakeGrain> {
        let txn = self.store.env.read_txn()?;
        self.wake_grain_in_txn(&txn)
    }

    pub(super) fn wake_grain_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<WakeGrain> {
        let Some(bytes) = self.store.vault_meta.get(txn, GRAIN_KEY)? else {
            return Ok(WakeGrain::default());
        };
        if bytes.len() != 9 || bytes[0] != 1 {
            return Err(Error::InvalidConfig("invalid wake grain row".into()));
        }
        let value = u64::from_be_bytes(
            bytes[1..]
                .try_into()
                .map_err(|_| Error::InvalidConfig("invalid wake grain row".into()))?,
        );
        WakeGrain::new(value)
    }

    /// Change the policy without changing another vault's clock or projection.
    pub fn set_wake_grain(&self, grain: WakeGrain) -> Result<()> {
        let grain = WakeGrain::new(grain.turns_per_wake)?;
        let mut bytes = [0_u8; 9];
        bytes[0] = 1;
        bytes[1..].copy_from_slice(&grain.turns_per_wake.to_be_bytes());
        let mut txn = self.store.env.write_txn()?;
        self.store.vault_meta.put(&mut txn, GRAIN_KEY, &bytes)?;
        txn.commit()?;
        Ok(())
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
