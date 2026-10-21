//! The rows of an Arc's work generations (FIX 7509 PR3): one typed side
//! table, keyed by the generation's id and a typed suffix (`:m` its
//! manifest, `:c<id>` a part, `:r` its assembly), read and written only
//! here. A generation a newer one replaces is deleted whole by the Arc's
//! progress writer; its unchanged calls replay from their step memos.

use super::arc_work::{ArcChildRow, ArcManifest, ArcReduceRow, ArcWorkRow, work_id};
use super::codec::invalid;
use super::request::ScopeSummaryPlan;
use crate::Vault;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use heed::{RoTxn, RwTxn};
use std::collections::BTreeMap;

const ARC_WORK: SideTable<String, ArcWorkRow, Named> =
    SideTable::new(&side_table::SCOPE_SUMMARY_ARC_WORK);

fn manifest_key(work: &str) -> String {
    format!("{work}:m")
}

fn child_key(work: &str, id: u32) -> String {
    format!("{work}:c{id:08x}")
}

fn reduce_key(work: &str) -> String {
    format!("{work}:r")
}

/// The id of the generation `plan`'s Arc composes in under `memo`.
pub(super) fn work_id_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    plan: &ScopeSummaryPlan,
    memo: &[u8; 32],
) -> Result<[u8; 32]> {
    let arc = plan
        .arc
        .as_ref()
        .ok_or_else(|| invalid("only an arc composes in parts"))?;
    let (declaration, _, _) = super::arc_gate::row_in_txn(vault, txn, &plan.input)?;
    Ok(work_id(
        &declaration,
        memo,
        &arc.source_set,
        &plan.policy_frontier,
    ))
}

pub(super) fn manifest_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    work: &str,
) -> Result<Option<ArcManifest>> {
    match ARC_WORK.get(&vault.store, txn, &manifest_key(work))? {
        None => Ok(None),
        Some(ArcWorkRow::Manifest(manifest)) => Ok(Some(*manifest)),
        Some(_) => Err(invalid("an arc's work row is not its manifest")),
    }
}

pub(super) fn child_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    work: &str,
    id: u32,
) -> Result<Option<ArcChildRow>> {
    match ARC_WORK.get(&vault.store, txn, &child_key(work, id))? {
        None => Ok(None),
        Some(ArcWorkRow::Child(child)) => Ok(Some(child)),
        Some(_) => Err(invalid("an arc's work row is not a part")),
    }
}

pub(super) fn reduce_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    work: &str,
) -> Result<Option<ArcReduceRow>> {
    match ARC_WORK.get(&vault.store, txn, &reduce_key(work))? {
        None => Ok(None),
        Some(ArcWorkRow::Reduce(reduce)) => Ok(Some(reduce)),
        Some(_) => Err(invalid("an arc's work row is not its assembly")),
    }
}

pub(super) fn put_manifest_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    work: &str,
    manifest: &ArcManifest,
) -> Result<()> {
    ARC_WORK.put(
        &vault.store,
        txn,
        &manifest_key(work),
        &ArcWorkRow::Manifest(Box::new(manifest.clone())),
    )
}

/// Deletes every row of generation `work`.
pub(super) fn delete_generation_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    work: &str,
) -> Result<()> {
    let keys = ARC_WORK
        .iter_from(&vault.store, txn, format!("{work}:").as_bytes())?
        .map(|row| row.map(|(key, _)| key))
        .collect::<Result<Vec<_>>>()?;
    for key in keys {
        ARC_WORK.delete(&vault.store, txn, &key)?;
    }
    Ok(())
}

impl Vault {
    /// The id of the generation `plan`'s Arc composes in under `memo`
    /// (FIX 7509 PR3).
    pub(crate) fn arc_work_id(&self, plan: &ScopeSummaryPlan, memo: &[u8; 32]) -> Result<[u8; 32]> {
        let txn = self.store.env.read_txn()?;
        work_id_in_txn(self, &txn, plan, memo)
    }

    /// Generation `work`'s manifest and the rows of its parts, by part id,
    /// in one snapshot.
    pub(crate) fn arc_work_rows(
        &self,
        work: &[u8; 32],
    ) -> Result<(Option<ArcManifest>, BTreeMap<u32, ArcChildRow>)> {
        let work = bytes_to_hex_lower(work);
        let txn = self.store.env.read_txn()?;
        let Some(manifest) = manifest_in_txn(self, &txn, &work)? else {
            return Ok((None, BTreeMap::new()));
        };
        let mut children = BTreeMap::new();
        for child in &manifest.children {
            if let Some(row) = child_in_txn(self, &txn, &work, child.id)? {
                children.insert(child.id, row);
            }
        }
        Ok((Some(manifest), children))
    }

    /// Co-commits generation `work`'s progress: its manifest when it
    /// changed, each part row in `children`, a part `dropped` for its
    /// replacements, and its assembly. A generation a newer one replaced
    /// takes no more rows: the write refuses as a concurrent one.
    pub(crate) fn save_arc_work(
        &self,
        work: &[u8; 32],
        manifest: Option<&ArcManifest>,
        children: &[(u32, &ArcChildRow)],
        dropped: Option<u32>,
        reduce: Option<&ArcReduceRow>,
    ) -> Result<()> {
        let work = bytes_to_hex_lower(work);
        self.with_write_txn_grouped(|txn| {
            if !ARC_WORK.contains(&self.store, txn, &manifest_key(&work))? {
                return Err(Error::ConcurrentWrite("an arc's work was replaced"));
            }
            if let Some(manifest) = manifest {
                put_manifest_in_txn(self, txn, &work, manifest)?;
            }
            for (id, row) in children {
                ARC_WORK.put(
                    &self.store,
                    txn,
                    &child_key(&work, *id),
                    &ArcWorkRow::Child((*row).clone()),
                )?;
            }
            if let Some(id) = dropped {
                ARC_WORK.delete(&self.store, txn, &child_key(&work, id))?;
            }
            if let Some(reduce) = reduce {
                ARC_WORK.put(
                    &self.store,
                    txn,
                    &reduce_key(&work),
                    &ArcWorkRow::Reduce(reduce.clone()),
                )?;
            }
            Ok(())
        })
    }
}
