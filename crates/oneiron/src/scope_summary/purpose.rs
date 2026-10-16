//! Open, owner-approved summary-purpose descriptors, not a closed enum.

use super::codec::invalid;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use serde::{Deserialize, Serialize};

const PURPOSE: SideTable<String, SummaryPurpose, Named> =
    SideTable::new(&side_table::SCOPE_SUMMARY_PURPOSE);

/// A named purpose with host-editable descriptive text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryPurpose {
    pub id: String,
    pub description: String,
}

fn seeds() -> Result<Vec<SummaryPurpose>> {
    serde_json::from_str(include_str!("purposes.json"))
        .map_err(|_| invalid("invalid summary purpose seeds"))
}

pub(super) fn purpose_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &str,
) -> Result<SummaryPurpose> {
    if let Some(row) = PURPOSE.get(&vault.store, txn, &id.to_owned())? {
        return Ok(row);
    }
    seeds()?
        .into_iter()
        .find(|row| row.id == id)
        .ok_or_else(|| invalid("summary purpose is not owner-approved"))
}

impl Vault {
    /// The fourteen canon births plus owner-approved additions and edits.
    pub fn summary_purposes(&self) -> Result<Vec<SummaryPurpose>> {
        let txn = self.store.env.read_txn()?;
        let mut rows: std::collections::BTreeMap<_, _> = seeds()?
            .into_iter()
            .map(|row| (row.id.clone(), row))
            .collect();
        for row in PURPOSE.iter_from(&self.store, &txn, b"")? {
            let (id, row) = row?;
            rows.insert(id, row);
        }
        Ok(rows.into_values().collect())
    }

    /// Approves a new descriptor or edits an existing one; unknown strings
    /// never silently become a catch-all purpose.
    pub fn set_summary_purpose(
        &self,
        owner: &AuthenticatedOwner,
        purpose: SummaryPurpose,
    ) -> Result<()> {
        if purpose.id.is_empty()
            || purpose.id.chars().any(char::is_control)
            || purpose.description.trim().is_empty()
        {
            return Err(invalid("invalid summary purpose descriptor"));
        }
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            PURPOSE.put(&self.store, txn, &purpose.id, &purpose)
        })
    }
}
