//! Core half of `store::derivation`: its store-layer items live in `oneiron_store::derivation` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::derivation::*;

use crate::side_table::{self, Raw, SideTable};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The bound owner of this holding vault. Key: `()` (singleton); value: 32 raw bytes.
const DERIVATION_OWNER: SideTable<(), [u8; 32], Raw> =
    SideTable::new(&side_table::DERIVATION_OWNER);

impl crate::Vault {
    /// Host-only initialization. The first owner binding is immutable.
    pub fn bind_derivation_owner(&self, owner: DerivationOwner) -> crate::Result<DerivationScope> {
        self.bind_derivation_owner_checked(owner)
            .map_err(|error| match error {
                DerivationBindError::Mismatch => {
                    crate::Error::InvalidConfig("derivation owner already bound".into())
                }
                DerivationBindError::Engine(error) => error,
            })
    }
    /// [`Self::bind_derivation_owner`] in the same transaction, with a bound
    /// owner that is not `owner` told apart from a failure to read or write.
    pub fn bind_derivation_owner_checked(
        &self,
        owner: DerivationOwner,
    ) -> Result<DerivationScope, DerivationBindError> {
        self.try_with_write_txn_grouped(|txn| {
            if let Some(existing) = DERIVATION_OWNER.get(&self.store, txn, &())? {
                if existing != owner.0 {
                    return Err(DerivationBindError::Mismatch);
                }
            } else {
                self.store.seal_pending_embeddings_for_owner(txn, owner)?;
                DERIVATION_OWNER.put(&self.store, txn, &(), &owner.0)?;
            }
            Ok(DerivationScope { owner })
        })
    }
    pub fn derivation_scope(&self) -> crate::Result<DerivationScope> {
        let txn = self.store.env.read_txn()?;
        let owner = DERIVATION_OWNER
            .get(&self.store, &txn, &())?
            .ok_or_else(|| crate::Error::InvalidConfig("derivation owner is not bound".into()))?;
        Ok(DerivationScope {
            owner: DerivationOwner(owner),
        })
    }
}

/// Shared read primitive for derivation-bearing storage codecs.
pub(crate) fn owner_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> crate::Result<Option<DerivationOwner>> {
    Ok(DERIVATION_OWNER.get(store, txn, &())?.map(DerivationOwner))
}

impl crate::Vault {
    /// Construct a derivation key from this holding vault's bytes and owner.
    pub fn derivation_key_for_entity(
        &self,
        kind: DerivationKind,
        computation: &[u8],
        entity: &crate::EntityId,
    ) -> crate::Result<Option<DerivationKey>> {
        let scope = self.derivation_scope()?;
        Ok(self
            .get(entity)?
            .map(|body| scope.key(kind, computation, &body)))
    }
}
