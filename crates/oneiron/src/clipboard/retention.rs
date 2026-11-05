use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::deletion::DeleteReason;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// Low-disk cleanup targets this many free bytes. The host supplies a real
/// filesystem observation. Selected text bytes are not filesystem-free bytes.
pub const CLIPBOARD_LOW_DISK_FREE_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const DAY_SECONDS: u64 = 86_400;
const SETTINGS: SideTable<(), ClipboardRetention, Named> =
    SideTable::new(&side_table::CLIPBOARD_RETENTION);

/// The three owner cleanup arms. Only low-disk cleanup is enabled initially.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClipboardRetention {
    pub max_text_bytes: Option<u64>,
    pub low_disk: bool,
    pub older_than_days: Option<u32>,
}

impl Default for ClipboardRetention {
    fn default() -> Self {
        Self {
            max_text_bytes: None,
            low_disk: true,
            older_than_days: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClipboardCleanupReport {
    pub erased: Vec<EntityId>,
    /// Masked clip-text bytes selected under the policy, not measured freed
    /// filesystem pages, other vault content or secret-custody bytes.
    pub selected_text_bytes: u64,
}

impl Vault {
    /// The owner's current Clipboard cleanup settings; no clipboard text is read.
    pub fn clipboard_retention_as_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<ClipboardRetention> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        self.clipboard_retention_in_txn(&txn)
    }

    /// Changes the owner's standing cleanup policy. `None` disables the size
    /// or age arm; zero is an actual selected size/age, not another spelling
    /// of disabled. This changes no world privacy or private-copy policy.
    pub fn set_clipboard_retention_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        settings: &ClipboardRetention,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            SETTINGS.put(&self.store, txn, &(), settings)
        })
    }

    pub(super) fn clipboard_retention_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<ClipboardRetention> {
        Ok(SETTINGS.get(&self.store, txn, &())?.unwrap_or_default())
    }

    /// Applies the owner's enabled cleanup arms to ordinary clips, oldest
    /// first, through native policy-delete erasure. `free_bytes` is the host's
    /// observed free space on this vault's filesystem, never a guessed value.
    /// Age/size selection shares one snapshot. A policy change or owner cut
    /// before a destructive publication cancels its remaining old-policy work.
    /// Native refusal/errors stay errors; there is no shell-only "disk cleanup".
    pub fn cleanup_clipboard_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        free_bytes: u64,
    ) -> Result<ClipboardCleanupReport> {
        let (settings, mut rows, now) = {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
            (
                self.clipboard_retention_in_txn(&txn)?,
                self.clipboard_metadata_in_txn(&txn, false)?,
                self.now_recorded_at(),
            )
        };
        rows.sort_by_key(|row| (row.copied_at, row.clip));
        let total = rows
            .iter()
            .fold(0u64, |sum, row| sum.saturating_add(row.text_bytes));
        let mut selected = BTreeSet::new();
        let mut selected_text_bytes = 0u64;
        if let Some(days) = settings.older_than_days {
            let age = u64::from(days) * DAY_SECONDS;
            for row in &rows {
                if now.saturating_sub(row.copied_at) > age {
                    selected.insert(row.clip);
                    selected_text_bytes = selected_text_bytes.saturating_add(row.text_bytes);
                }
            }
        }
        let size_excess = settings
            .max_text_bytes
            .map_or(0, |max| total.saturating_sub(max));
        let disk_deficit = if settings.low_disk {
            CLIPBOARD_LOW_DISK_FREE_BYTES.saturating_sub(free_bytes)
        } else {
            0
        };
        let target = size_excess.max(disk_deficit);
        for row in &rows {
            if selected_text_bytes >= target {
                break;
            }
            if selected.insert(row.clip) {
                selected_text_bytes = selected_text_bytes.saturating_add(row.text_bytes);
            }
        }
        let mut erased = Vec::new();
        for row in rows.into_iter().filter(|row| selected.contains(&row.clip)) {
            if self.erase_clipboard_id(
                owner,
                row.clip,
                DeleteReason::PolicyDelete,
                Some(&settings),
                Some(row.copied_at),
            )? {
                erased.push(row.clip);
            }
        }
        Ok(ClipboardCleanupReport {
            erased,
            selected_text_bytes,
        })
    }
}
