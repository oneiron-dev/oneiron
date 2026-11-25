//! Row RESIDENT-SHARE-NO-UNIT (Engine RESIDENT-SHARE-UNIT = A, 25 Nov 19:27): writes one
//! resident's share row in its stored shape from before shares named a unit, so a test reads it
//! back as a share in `micro_usd` only.

use serde::{Deserialize, Serialize};

use crate::llm::run_admission::ResidentShare;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// A resident row as stored before shares named a unit: one share, and no depletion.
#[derive(Serialize, Deserialize)]
struct UnitlessResidentRow {
    share: ResidentShare,
    usage: Vec<()>,
}

const UNITLESS_RESIDENTS: SideTable<EntityId, UnitlessResidentRow, Named> =
    SideTable::new(&side_table::BUDGET_RESIDENT_SHARE);

/// Writes `resident`'s share row in the shape stored before shares named a unit.
pub fn put_unitless_resident_share(
    vault: &Vault,
    resident: EntityId,
    share: ResidentShare,
) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    UNITLESS_RESIDENTS.put(
        &vault.store,
        &mut txn,
        &resident,
        &UnitlessResidentRow {
            share,
            usage: Vec::new(),
        },
    )?;
    txn.commit()?;
    Ok(())
}
