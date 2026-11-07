//! Snapshot enumeration for whole-vault exports, independent of type whitelists.
use super::copy_release::MailboxLineage;
use super::whole_vault_export_excludes_entity_in_txn;
use crate::batch::EntityMetadataHeader;
use crate::mail_pack::{MailboxExportNotice, MemberMailboxPlan};
use crate::{EntityId, Error, Result, Vault};

/// A row selected for export. Serialization owns credential nulling; this
/// enumerator returns identities, never raw credentials or unredacted bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WholeVaultExportRow {
    pub entity_id: EntityId,
    pub entity_type: u8,
}

/// The rows the Owner's whole-vault export carries, by id and type, and each
/// other member's personal mailbox it leaves out, named to the Owner (fix
/// list row 15416). A listing, not a copy. Fields are private: only the
/// listing's door produces one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WholeVaultExportListing {
    pub(crate) rows: Vec<WholeVaultExportRow>,
    pub(crate) mailbox_notices: Vec<MailboxExportNotice>,
}

impl WholeVaultExportListing {
    /// The rows listed, in the snapshot's order.
    pub fn rows(&self) -> &[WholeVaultExportRow] {
        &self.rows
    }
    /// Each other member's personal mailbox the listing left out, and why.
    pub fn mailbox_notices(&self) -> &[MailboxExportNotice] {
        &self.mailbox_notices
    }
}

impl Vault {
    /// Walks every entity row in one read snapshot. There is no type whitelist,
    /// approval filter, or refusal merely because an off-record room is open.
    ///
    /// It lists for the embedded owner, whose whole-vault export it is: in a
    /// shared vault it lists no row of another member's personal mailbox the
    /// vault's rule leaves out of that export, nor a row whose words came from
    /// one, judged by that rule in this same snapshot, and its answer names
    /// each such mailbox (fix list row 15416). A listing is not a copy: it
    /// uses no approval, writes no audit row and tells no mailbox's person.
    pub fn whole_vault_export_rows(&self) -> Result<WholeVaultExportListing> {
        let txn = self.store.env.read_txn()?;
        let exporter = crate::vault::embedded_owner_actor_id()?;
        let plan = MemberMailboxPlan::read_in(self, &txn, exporter, false)?;
        let dbs = self.store.read();
        let mut judge = plan
            .as_ref()
            .map(|plan| plan.judge(self, &dbs, &txn))
            .transpose()?;
        let mut lineage = MailboxLineage::read_in(&self.store, &txn, judge.is_some())?;
        let mut rows = Vec::new();
        for row in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, &txn)? {
            let (entity_id, raw) = row?;
            if whole_vault_export_excludes_entity_in_txn(&self.store, &txn, &entity_id)? {
                continue;
            }
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("export entity header"))?;
            if !lineage.row_admitted(
                judge.as_mut(),
                &self.store,
                &txn,
                entity_id,
                header.entity_type,
                &raw,
            )? {
                continue;
            }
            rows.push(WholeVaultExportRow {
                entity_id,
                entity_type: header.entity_type,
            });
        }
        // Only the mailboxes it left out: what the export would carry, and
        // the approvals it would use, are the export's own to record.
        let met = judge.map(crate::source_audience::ExportJudge::met);
        let mailbox_notices = match (plan, met) {
            (Some(plan), Some(met)) => plan.outcome(&met).0,
            _ => Vec::new(),
        };
        Ok(WholeVaultExportListing {
            rows,
            mailbox_notices,
        })
    }
}
