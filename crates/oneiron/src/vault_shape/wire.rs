//! The per-kind wire declaration (ARCH-0070 setup plane, ARCH-0043 "declared
//! per kind"; FIX 2300): whether one entity kind is on the wire, as the seed
//! declared it and the owner's apply landed it. One row per kind. It records
//! the declaration and effects nothing: a shape can propose a federation and
//! never effect one, so no sync path is opened or closed by it, and every
//! bilateral confirm and co-sign stands as it was.
use super::invalid;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

/// Every kind's wire declaration, keyed by the kind's name.
const WIRE: SideTable<String, StoredWireDeclaration, Named> =
    SideTable::new(&side_table::VAULT_SHAPE_WIRE);

/// One kind's declared wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredWireDeclaration {
    /// Whether the kind is declared on the wire.
    on_wire: bool,
    /// The owner whose apply landed it, hex.
    declared_by: String,
    declared_at: u64,
}

impl Vault {
    /// Every kind's declared wire, on the caller's snapshot, as (kind,
    /// on_wire) in kind order.
    pub(super) fn shape_wire_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<Vec<(String, bool)>> {
        Ok(WIRE
            .scan(&self.store, txn)?
            .into_iter()
            .map(|(kind, declared)| (kind, declared.on_wire))
            .collect())
    }

    /// Declares `entity_kind` on or off the wire, as `owner`. The same
    /// declaration again changes nothing. Returns the item's receipt: the
    /// kind and the wire it declared.
    ///
    /// # Errors
    ///
    /// A blank or oversized kind, an owner proof that no longer holds, or a
    /// store failure.
    pub(super) fn declare_shape_wire(
        &self,
        owner: &AuthenticatedOwner,
        entity_kind: &str,
        on_wire: bool,
        now: u64,
    ) -> Result<String> {
        if entity_kind.trim().is_empty() || entity_kind.len() > super::SHAPE_NAME_MAX_BYTES {
            return Err(invalid("an entity kind is 1 to 256 bytes and not blank"));
        }
        self.with_write_txn_grouped(|txn| {
            let author: EntityId = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let key = entity_kind.to_owned();
            let unchanged = WIRE
                .get(&self.store, &*txn, &key)?
                .is_some_and(|declared| declared.on_wire == on_wire);
            if !unchanged {
                let declared = StoredWireDeclaration {
                    on_wire,
                    declared_by: author.to_hex(),
                    declared_at: now,
                };
                WIRE.put(&self.store, txn, &key, &declared)?;
            }
            Ok(())
        })?;
        Ok(format!(
            "{entity_kind} declared {}",
            if on_wire {
                "on the wire"
            } else {
                "off the wire"
            }
        ))
    }

    /// Withdraws `entity_kind`'s wire declaration, as `owner`: the kind
    /// returns to undeclared. Returns the item's receipt.
    ///
    /// # Errors
    ///
    /// An owner proof that no longer holds, or a store failure.
    pub(super) fn withdraw_shape_wire(
        &self,
        owner: &AuthenticatedOwner,
        entity_kind: &str,
    ) -> Result<String> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            WIRE.delete(&self.store, txn, &entity_kind.to_owned())?;
            Ok(())
        })?;
        Ok(format!("{entity_kind} undeclared"))
    }
}
