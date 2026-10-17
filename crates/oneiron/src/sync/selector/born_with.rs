//! Born-with text on a copy to another vault (OF-491). Such a copy's births
//! go masked (owner Q26 = B) and carry no text. The text its owner lets
//! travel goes beside them in the window's `row_born_with` map, one entry per
//! row the copy carries: the fields the grant's travel choice names, prose
//! only, never a ref. The choice is bound to the grant on this device by the
//! owner, never taken from the wire, so a selector names its grant but cannot
//! widen what text it gets. A grant with no choice bound sends none.
//!
//! On the receiving vault, admission reads the entries for the rows it
//! admitted and keeps them out of the admitted bytes; the import then keeps
//! each beside its landed row, where [`Vault::born_with_text`] reads it.

use loro::LoroDoc;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::share_travel::{BornWith, TravelChoice};
use crate::side_table::{self, Named, SideTable};
use crate::sync::loro_support::{map_for_each_value_bytes, map_get_bytes, map_insert_bytes};
use crate::sync::window::Withhold;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The window map that carries born-with text beside the row births.
const ROW_BORN_WITH_MAP: &str = "row_born_with";

/// The owner's travel choice for one federation grant.
const GRANT_TRAVEL: SideTable<EntityId, GrantTravel, Named> =
    SideTable::new(&side_table::SYNC_BORN_WITH_GRANT);

/// The text a copy from another vault carried, by row.
const CARRIED: SideTable<EntityId, BornWith, Named> =
    SideTable::new(&side_table::SYNC_BORN_WITH_CARRIED);

/// One grant's owner-set travel choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantTravel {
    pub travel: TravelChoice,
    pub set_at: u64,
}

/// One row's carried text, with the kind the row came as.
pub(crate) type CarriedText = (EntityId, u8, BornWith);

fn encode(text: &BornWith) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(text)
        .map_err(|_| Error::InvalidConfig("born-with text does not encode".into()))
}

/// The carried text, when `bytes` is its canonical encoding.
fn decode(bytes: &[u8]) -> Option<BornWith> {
    let text: BornWith = rmp_serde::from_slice(bytes).ok()?;
    (encode(&text).ok()? == bytes).then_some(text)
}

/// Every row `doc` carries as an entity, by its canonical hex key.
fn carried_rows(doc: &LoroDoc) -> Vec<(EntityId, u8)> {
    let mut rows = Vec::new();
    map_for_each_value_bytes(&doc.get_map("entities"), |key, blob| {
        let Some(header) = blob.and_then(EntityMetadataHeader::parse) else {
            return;
        };
        if let Some(id) = EntityId::from_hex(key).ok().filter(|id| id.to_hex() == key) {
            rows.push((id, header.entity_type));
        }
    });
    rows
}

/// Writes into `doc`, beside its births, the born-with text the owner lets
/// `grant`'s windows carry, for each row `doc` carries: the bound choice's
/// fields of [`Vault::born_with_text`], none from a row a world `withhold`
/// keeps off the destination holds. Nothing here reads or writes a birth,
/// so its masked refs stay masked.
pub(super) fn carry_born_with(
    vault: &Vault,
    doc: &LoroDoc,
    grant: &EntityId,
    withhold: Withhold<'_>,
) -> Result<()> {
    let Some(bound) = vault.federation_grant_travel(grant)? else {
        return Ok(());
    };
    let kept = withhold.worlds(vault)?;
    let map = doc.get_map(ROW_BORN_WITH_MAP);
    for (id, _) in carried_rows(doc) {
        let text = bound
            .travel
            .project(vault.born_with_text_kept_off(&id, None, &kept)?);
        if !text.is_empty() {
            map_insert_bytes(&map, &id.to_hex(), &encode(&text)?)?;
        }
    }
    doc.commit();
    Ok(())
}

/// The text `remote` carries for each row `admitted` holds. An entry that
/// does not decode, holds nothing, or names a row admission dropped stays
/// behind.
pub(super) fn admitted_born_with(remote: &LoroDoc, admitted: &LoroDoc) -> Vec<CarriedText> {
    let map = remote.get_map(ROW_BORN_WITH_MAP);
    carried_rows(admitted)
        .into_iter()
        .filter_map(|(id, kind)| {
            let text = map_get_bytes(&map, &id.to_hex()).and_then(|bytes| decode(&bytes))?;
            (!text.is_empty()).then_some((id, kind, text))
        })
        .collect()
}

/// Keeps each carried text beside its row once that row is live here as the
/// kind it came as. A later copy's text replaces an earlier one's; no other
/// door writes it.
pub(super) fn keep_carried(vault: &Vault, carried: &[CarriedText]) -> Result<()> {
    if carried.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| {
        for (id, kind, text) in carried {
            if matches!(
                live_entity_row_in_txn(&vault.store, txn, id)?,
                LiveEntityRow::Live { entity_type, .. } if entity_type == *kind
            ) {
                CARRIED.put(&vault.store, txn, id, text)?;
            }
        }
        Ok(())
    })
}

/// The text a copy from another vault carried for `id`; empty for any other
/// row.
pub(crate) fn carried_born_with(vault: &Vault, id: &EntityId) -> Result<BornWith> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(CARRIED
        .get_lenient(&vault.store, &rtxn, id)?
        .unwrap_or_default())
}

impl Vault {
    /// The born-with text `grant`'s windows carry to another vault; `None`
    /// sends none.
    pub fn federation_grant_travel(&self, grant: &EntityId) -> Result<Option<GrantTravel>> {
        let rtxn = self.store.env.read_txn()?;
        GRANT_TRAVEL.get(&self.store, &rtxn, grant)
    }

    /// Binds `travel` to the live federation grant `grant`, or with `None`
    /// unbinds it. Windows exported from now on carry the text it names;
    /// text a guest already holds stays its copy.
    pub fn set_federation_grant_travel_as(
        &self,
        owner: &AuthenticatedOwner,
        grant: &EntityId,
        travel: Option<TravelChoice>,
        now: u64,
    ) -> Result<()> {
        self.recheck_owner(owner)?;
        self.with_write_txn_grouped(|txn| match travel {
            Some(travel) => {
                super::authorize::live_federation_grant_in(self, txn, grant)?;
                GRANT_TRAVEL.put(
                    &self.store,
                    txn,
                    grant,
                    &GrantTravel {
                        travel,
                        set_at: now,
                    },
                )
            }
            None => GRANT_TRAVEL.delete(&self.store, txn, grant).map(|_| ()),
        })
    }
}
