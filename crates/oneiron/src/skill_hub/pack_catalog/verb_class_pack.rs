//! Per-API verb-class tables as pack data (L8-57; ARCH-0069
//! #door-reads-action, OF-519): a pack of kind `capability` or `connector`
//! may carry one table in [`VERB_CLASS_TABLE_FILE`]. A provider's table and
//! its connector arrive as one pack, and a user brings a table for any API in
//! a data-only capability pack of their own, with no engine change.
//!
//! A table decides what a call is, so a table that lies (a `DELETE` as
//! `read`) widens every lending the owner narrowed. Only the packs the owner
//! put, and the packs installed from an admitted hub after its scan, may
//! class calls (RULING L8-57-TABLE-SOURCE = A). The vault's `local` pack,
//! which a resident agent writes, never carries one: its source is refused
//! at the put, and the registry never reads a `local` or agent-authored
//! install.
use heed::RoTxn;

use super::{
    LOCAL_PACK_NAME, PackInstallReceipt, PackInstallStatus, PackKind, PackManifest, admission,
    invalid,
};
use crate::credential_door::ApiVerbClassTable;
use crate::error::{ErrorKind, Result};
use crate::skill_hub::{HubFile, skill_scan_verdict_stands_in_store};
use crate::{EntityId, Vault};

/// Where a pack keeps its verb-class table.
pub const VERB_CLASS_TABLE_FILE: &str = "knowledge/verb-classes.json";

/// The source's verb-class table, when it carries one. A table in the `local`
/// pack, or in a pack of a kind other than `capability` or `connector`, and a
/// table that does not pass its load check, refuse the source.
pub(super) fn read_source_verb_class_table(
    manifest: &PackManifest,
    files: &[HubFile],
) -> Result<Option<ApiVerbClassTable>> {
    let Some(file) = files.iter().find(|file| file.path == VERB_CLASS_TABLE_FILE) else {
        return Ok(None);
    };
    if manifest.name == LOCAL_PACK_NAME {
        return Err(invalid(
            "the local pack carries no verb-class table: a resident agent writes it",
        ));
    }
    if !matches!(manifest.kind, PackKind::Capability | PackKind::Connector) {
        return Err(invalid(
            "a verb-class table rides a capability or connector pack",
        ));
    }
    ApiVerbClassTable::parse(&file.content).map(Some)
}

impl Vault {
    /// The verb-class table of every Active install that may class a call
    /// ([`install_may_class_calls`]), read in `txn` from the source its
    /// receipt names. An install whose source is gone, does not match its
    /// receipt's name, kind and content hash, or has no scan verdict
    /// standing on its bytes, is left out. A catalog row that does not read
    /// fails the read.
    pub(crate) fn installed_verb_class_tables_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<Vec<ApiVerbClassTable>> {
        let mut tables = Vec::new();
        for entry in admission::PACK_INSTALL.iter_from(&self.store, txn, &[])? {
            let (name, receipt) = entry.map_err(|error| {
                if error.kind() == ErrorKind::SideTableRow {
                    invalid("pack install catalog corrupt")
                } else {
                    error
                }
            })?;
            if !install_may_class_calls(&name, &receipt) {
                continue;
            }
            let Ok(source_id) = EntityId::from_hex(&receipt.source_id) else {
                continue;
            };
            let Some(source) = self.pack_source_in_txn(txn, &source_id)? else {
                continue;
            };
            let Some(table) = source.verb_class_table() else {
                continue;
            };
            if source.manifest().name != name
                || source.manifest().kind != receipt.kind
                || source.content_hash().to_hex() != receipt.content_hash
                || !skill_scan_verdict_stands_in_store(&self.store, txn, source.content_hash())?
            {
                continue;
            }
            tables.push(table.clone());
        }
        Ok(tables)
    }
}

/// Whether the install `receipt` under `name` may class API calls: Active, a
/// capability or connector pack, and neither the `local` pack nor an
/// agent-authored install.
fn install_may_class_calls(name: &str, receipt: &PackInstallReceipt) -> bool {
    receipt.status == PackInstallStatus::Active
        && matches!(receipt.kind, PackKind::Capability | PackKind::Connector)
        && receipt.pack_name == name
        && name != LOCAL_PACK_NAME
        && receipt.agent_author.is_none()
}
