//! A project's erase takes the project off the amendment rows that carry it
//! (FIX 6038). An evidence or judgment row whose project is the erased one
//! names one fresh opaque scope instead, as the attempt receipt it came from
//! does (`learning::scope_carriers`): a later pass lands its
//! `learning.edit_cost` rows apart from the vault's and never under the
//! erased id. A row that names the project but no longer decodes is deleted.

use super::stored::{StoredEvidence, StoredJudgment};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideCodec, SideTable};

/// Amendment evidence rows, by their raw key.
const EVIDENCE_RAW: SideTable<Vec<u8>, StoredEvidence, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_AMENDMENT_EVIDENCE);

/// Amendment judgment rows, by their raw key.
const JUDGMENT_RAW: SideTable<Vec<u8>, StoredJudgment, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_AMENDMENT_JUDGMENT);

/// Re-keys the project of every amendment evidence and judgment row naming
/// erased `entity` to one fresh opaque scope. Registered on both stores; the
/// first call does both, so a judgment keeps its evidence's scope.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_amendment_project_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let named = entity.to_hex();
    let mut scope = None;
    rescope_rows_in_txn(
        vault,
        wtxn,
        EVIDENCE_RAW,
        &named,
        &mut scope,
        evidence_project,
    )?;
    rescope_rows_in_txn(
        vault,
        wtxn,
        JUDGMENT_RAW,
        &named,
        &mut scope,
        judgment_project,
    )
}

/// Re-keys each row of `table` whose project is `named` to the erase's
/// opaque `scope`, minted on first need.
fn rescope_rows_in_txn<V>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    table: SideTable<Vec<u8>, V, Raw>,
    named: &str,
    scope: &mut Option<String>,
    project: fn(&mut V) -> &mut Option<String>,
) -> Result<()>
where
    Raw: SideCodec<V>,
{
    let rows = table
        .iter_raw_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for (key, value) in rows {
        if !value
            .windows(named.len())
            .any(|window| window == named.as_bytes())
        {
            continue;
        }
        match table.decode_value(&value) {
            Ok(mut row) => {
                let stamp = project(&mut row);
                if stamp.as_deref() != Some(named) {
                    continue;
                }
                if scope.is_none() {
                    *scope = Some(vault.store.clock.entity_id()?.to_hex());
                }
                stamp.clone_from(scope);
                table.put(&vault.store, wtxn, &key, &row)?;
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    table = table.decl().name,
                    "an amendment row that no longer decodes is deleted"
                );
                table.delete(&vault.store, wtxn, &key)?;
            }
        }
    }
    Ok(())
}

fn evidence_project(row: &mut StoredEvidence) -> &mut Option<String> {
    &mut row.project
}

fn judgment_project(row: &mut StoredJudgment) -> &mut Option<String> {
    &mut row.project
}
