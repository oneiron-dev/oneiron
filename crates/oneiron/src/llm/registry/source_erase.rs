//! An erased row out of the registry rows' source sets (FIX 6933).

use serde::{Deserialize, Serialize};

use super::{ModelRegistryRow, REGISTRY_ROW};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Erased, ErasedForm, LegacyJson, SideTable};

/// A stored registry row with one erased source id to forget. It encodes as
/// the row itself; the id rides along, never encoded.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct SourceForgotten {
    row: ModelRegistryRow,
    #[serde(skip)]
    erased: Option<EntityId>,
}

/// Its erased form forgets that id and nothing else, so the erase writes it
/// past the side-row wall (FIX 5718): an id gone from a set the wall already
/// admitted gives it nothing new to read, and no wall fails an erase.
impl ErasedForm for SourceForgotten {
    fn into_erased(mut self) -> Result<Self> {
        if let (Some(rows), Some(erased)) = (self.row.source_rows.as_mut(), self.erased) {
            rows.retain(|row| *row != erased);
        }
        Ok(self)
    }
}

/// [`REGISTRY_ROW`]'s rows as an erase writes them.
const ERASED_ROW: SideTable<String, SourceForgotten, LegacyJson> =
    SideTable::new(&side_table::LLM_REGISTRY_ROW);

/// Drops an erased row `id` from every registry row's source rows (FIX
/// 6933), rewriting only the rows that named it: their entry, prices,
/// scores, times, retirement and token ratio stay, and an unknown set stays
/// unknown. Registered on the registry table's declaration; a source may be
/// any row, so this reads every registry row for each erased id.
///
/// # Errors
///
/// Storage errors, or a stored row that does not decode.
pub(crate) fn erase_registry_source_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut named = Vec::new();
    for row in REGISTRY_ROW.iter_from(&vault.store, &*wtxn, &[])? {
        let (key, row) = row?;
        if names(&row.source_rows, id) {
            named.push((key, row));
        }
    }
    for (key, row) in named {
        let erased = Some(*id);
        let forgotten = Erased::of(SourceForgotten { row, erased })?;
        ERASED_ROW.put_erased(&vault.store, wtxn, &key, forgotten)?;
    }
    Ok(())
}

/// Whether a known source set names `id`.
fn names(rows: &Option<Vec<EntityId>>, id: &EntityId) -> bool {
    rows.as_ref().is_some_and(|rows| rows.contains(id))
}
