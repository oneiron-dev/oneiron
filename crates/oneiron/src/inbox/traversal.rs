//! The complete pending traversal (FIX 9523, 9873): every stamped Dreamer
//! run holding a pending consent, in the tray's order, read in one snapshot
//! with no count cut, and the browse page that walks the open tray's root
//! groups past unrelated and held rows until the page fills or the tray
//! ends.
//! `Vault::pending_dreamer_run_ids` and `inbox_group_page` are its call
//! surface.

use std::collections::HashSet;

use crate::Vault;
use crate::error::Result;

use super::model::{InboxGroupPage, InboxQuery, InboxReviewDial};
use super::root_group::{OpenTray, RunGroups, root_group_card};

impl Vault {
    /// Every stamped Dreamer run holding a pending consent, oldest waiting
    /// first, read in one snapshot over the whole tray (FIX 9523): a run
    /// whose proposals all wait behind thousands of others is in it. A row
    /// no run stamps is in no run.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn pending_dreamer_run_ids(&self) -> Result<Vec<String>> {
        let pending = {
            let txn = self.store.env.read_txn()?;
            self.store.pending_gate_consents_in_txn(&txn, usize::MAX)?
        };
        let mut seen = HashSet::new();
        Ok(pending
            .into_iter()
            .filter_map(|record| record.dreamer_run_id)
            .filter(|run_id| seen.insert(run_id.clone()))
            .collect())
    }
}

/// One browse page (FIX 9873): the root groups in the order their earliest
/// open row waits, from the first one past `query.after`, each built
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
    let mut runs = RunGroups::new(vault);
    let tray = OpenTray::read(vault, &mut runs)?;
    let starts = tray.starts();
    let first = query.after.map_or(0, |after| {
        starts.partition_point(|(position, _)| *position <= after)
    });
    let mut groups = Vec::new();
    for (index, (position, group_key)) in starts.iter().enumerate().skip(first) {
        let Some(group) = root_group_card(vault, &tray, &mut runs, group_key, query.now, dial)?
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
