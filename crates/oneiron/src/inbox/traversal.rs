//! The complete pending traversal (FIX 9523, 9873): every stamped Dreamer
//! run holding a pending consent, in the tray's order, read in one snapshot
//! with no count cut, and the browse page that walks its root groups past
//! unrelated and held rows until the page fills or the tray ends.
//! `Vault::pending_dreamer_run_ids` and `inbox_group_page` are its call
//! surface.

use std::collections::HashSet;

use crate::Vault;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;

use super::model::{InboxGroupCursor, InboxGroupPage, InboxQuery, InboxReviewDial};
use super::root_group::{RunGroups, root_group_card};

/// One stamped run and the tray position of its earliest pending row.
struct PendingRunStart {
    position: InboxGroupCursor,
    run_id: String,
}

/// Every stamped run holding a pending consent, in the order its earliest
/// row waits, read in `txn`. The tray read visits every row; nothing here
/// cuts it at a count. A row no run stamps is in no run.
fn pending_dreamer_runs_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<PendingRunStart>> {
    let mut seen = HashSet::new();
    let mut runs = Vec::new();
    for record in vault.store.pending_gate_consents_in_txn(txn, usize::MAX)? {
        let position = InboxGroupCursor::of(&record);
        let Some(run_id) = record.dreamer_run_id else {
            continue;
        };
        if seen.insert(run_id.clone()) {
            runs.push(PendingRunStart { position, run_id });
        }
    }
    Ok(runs)
}

impl Vault {
    /// Every stamped Dreamer run holding a pending consent, oldest waiting
    /// first, read in one snapshot over the whole tray (FIX 9523): a run
    /// whose proposals all wait behind thousands of others is in it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn pending_dreamer_run_ids(&self) -> Result<Vec<String>> {
        let txn = self.store.env.read_txn()?;
        Ok(pending_dreamer_runs_in_txn(self, &txn)?
            .into_iter()
            .map(|run| run.run_id)
            .collect())
    }
}

/// One browse page (FIX 9873): the root groups in the order their earliest
/// pending row waits, from the first one past `query.after`, each built
/// complete; groups with nothing visible under `dial` are passed over until
/// `query.limit` visible groups fill or the tray ends. `next` names the last
/// served group when any group lies past it.
pub(super) fn inbox_group_page(
    vault: &Vault,
    query: InboxQuery,
    dial: InboxReviewDial,
) -> Result<InboxGroupPage> {
    if query.limit == 0 {
        return Ok(InboxGroupPage {
            groups: Vec::new(),
            next: None,
        });
    }
    // Each root group once, at its earliest row: runs come in the order
    // their earliest row waits, so a root's first run carries its position.
    let starts: Vec<(InboxGroupCursor, String)> = {
        let txn = vault.store.env.read_txn()?;
        let mut seen = HashSet::new();
        let mut starts = Vec::new();
        for run in pending_dreamer_runs_in_txn(vault, &txn)? {
            let group_key =
                crate::attempt_queue::dreamer_run_root_id_in_txn(&vault.store, &txn, &run.run_id)?
                    .map_or_else(
                        || run.run_id.clone(),
                        |root| bytes_to_hex_lower(root.as_bytes()),
                    );
            if seen.insert(group_key.clone()) {
                starts.push((run.position, group_key));
            }
        }
        starts
    };
    let first = query.after.map_or(0, |after| {
        starts.partition_point(|(position, _)| *position <= after)
    });
    let mut runs = RunGroups::new(vault);
    let mut groups = Vec::new();
    for (index, (position, group_key)) in starts.iter().enumerate().skip(first) {
        let pending = vault.store.pending_gate_consents_for_group_key(group_key)?;
        let Some(group) = root_group_card(vault, &mut runs, group_key, pending, query.now, dial)?
        else {
            continue;
        };
        groups.push(group);
        if groups.len() == query.limit {
            return Ok(InboxGroupPage {
                groups,
                next: (index + 1 < starts.len()).then(|| position.to_token()),
            });
        }
    }
    Ok(InboxGroupPage { groups, next: None })
}
