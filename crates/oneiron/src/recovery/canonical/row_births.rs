//! The row births a window carries (ARCH-0035 Rule A), through canonical
//! capture and rebuild (FIX 3069). A window rebuilt from the artifact alone
//! gets each row's birth back from the artifact, not from the vault's birth
//! rows, so a restore that lost those rows keeps the births.
//!
//! The window's carrier goes first, as the origin's own envelope; a birth
//! this vault stamped stands in only where the window carries none. Nothing
//! is invented: a row with neither stays unknown. Bytes that do not decode
//! are carried as they are, unknown, and the forward pass leaves them out
//! with a warning as it does a peer's: no row is refused or dropped for its
//! birth. A birth whose maker this vault erased goes, as its window carrier
//! does, but for a born row a legal hold keeps (FIX 6279, 6280).

use loro::LoroDoc;
#[cfg(feature = "sync")]
use loro::{LoroValue, ValueOrContainer};
use serde::{Deserialize, Serialize};

#[cfg(feature = "sync")]
use super::{ByteBudget, id};
use super::{CanonicalSnapshot, insert};
use crate::error::Result;

/// The window root map of row births, as sync files it.
const ROW_BIRTHS: &str = "row_births";

/// One row's birth: the Named MessagePack envelope, byte for byte as the
/// window or the vault holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRowBirth {
    pub id: [u8; 16],
    pub value: Vec<u8>,
}

/// Carries the birth of each row of the snapshot's final entity set, sorted
/// by id: the window's carrier first, else the birth stamped here. Each one
/// is measured, never refused, as a NOTE birth is (Rule 5, FIX 6540): an
/// overrun is logged. The rows must be sorted.
#[cfg(feature = "sync")]
pub(super) fn capture(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    doc: &LoroDoc,
    snapshot: &mut CanonicalSnapshot,
    budget: &mut ByteBudget,
) -> Result<()> {
    // FIX 10319: each birth is read straight from the window map for its
    // own row and measured as it is kept, so no whole-map copy rides
    // outside the budget. The root resolves as in `binary_rows`, without
    // creating it.
    let LoroValue::Map(containers) = doc.get_value() else {
        return Err(super::invalid("window root"));
    };
    let map = match containers.get(ROW_BIRTHS) {
        None => None,
        Some(LoroValue::Container(id)) => Some(
            doc.try_get_map(id)
                .ok_or(super::invalid("nonmap Layer-1 carrier"))?,
        ),
        Some(_) => return Err(super::invalid("nonmap Layer-1 carrier")),
    };
    let mut overrun = None;
    for entity in &snapshot.entity_blobs {
        let row = id(entity.id)?;
        let carried = match &map {
            None => None,
            Some(map) => match map.get(&row.to_hex()) {
                None => None,
                Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => Some(bytes.to_vec()),
                Some(_) => return Err(super::invalid("nonbinary Layer-1 carrier")),
            },
        };
        let value = match carried {
            Some(bytes) => bytes,
            None => match crate::provenance::birth::row_birth_in_txn(&vault.store, txn, &row)? {
                Some(birth) => rmp_serde::to_vec_named(&birth)
                    .map_err(|_| super::invalid("row birth encoding"))?,
                None => continue,
            },
        };
        if !crate::sync::row_birth::actor_erase::canonical_birth_kept_in_txn(
            vault, txn, &row, &value,
        )? {
            continue;
        }
        if let Some(over) = budget.measure(entity.id.len() + value.len()) {
            overrun = Some(over);
        }
        snapshot.row_births.push(CanonicalRowBirth {
            id: entity.id,
            value,
        });
    }
    if let Some(overrun) = overrun {
        tracing::warn!(
            required = overrun.required,
            limit = overrun.limit,
            "canonical recovery measured row births past its budget"
        );
    }
    Ok(())
}

/// The births sort by id, each once. Nothing else refuses: a birth whose
/// bytes do not decode, or whose row the window does not hold, rides as it
/// is, unknown.
pub(super) fn validate(snapshot: &CanonicalSnapshot) -> Result<()> {
    crate::recovery::validation::strict(snapshot.row_births.iter().map(|row| row.id))
}

/// Files the birth of one row back in the rebuilt window's map.
pub(super) fn rebuild_row(doc: &LoroDoc, row: &CanonicalRowBirth) -> Result<()> {
    let key = crate::entity_id::bytes_to_hex_lower(&row.id);
    insert(doc, ROW_BIRTHS, &key, &row.value)
}

#[cfg(feature = "sync")]
impl CanonicalSnapshot {
    /// The births as this vault recovers them: each whose maker this vault
    /// erased since the capture goes, but for a born row a legal hold keeps.
    pub(in crate::recovery) fn settle_row_births_here(
        &mut self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        let mut kept = Vec::with_capacity(self.row_births.len());
        for row in std::mem::take(&mut self.row_births) {
            // An id that names no row names nothing a hold keeps or an erase
            // settles: it rides as it is.
            let keep = match id(row.id) {
                Ok(born) => crate::sync::row_birth::actor_erase::canonical_birth_kept_in_txn(
                    vault, txn, &born, &row.value,
                )?,
                Err(_) => true,
            };
            if keep {
                kept.push(row);
            }
        }
        self.row_births = kept;
        Ok(())
    }
}
