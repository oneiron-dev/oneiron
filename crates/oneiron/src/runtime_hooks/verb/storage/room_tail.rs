//! The Hook receipts a room staged itself, for a room chain's receipt tail
//! (FIX 5429).
//!
//! Base's receipt family does not hold a room's own runs, so a chain in the
//! room reads them here. Each receipt carries its source rows: the rows its
//! run read and the rows its input showed. A receipt reaches a call only
//! when the call's reader, on the room's view, reads every source row, and
//! it reaches each hook of the call's chain only when that hook's own view
//! (its grant reader, predicates and worlds) shows them too
//! (`Chain::project_tail`). A run whose input showed content no host names
//! rows for, a run on a write (its args and answer are its caller's own
//! content, which names no row), or one whose saved run is unknown, is
//! withheld: its provenance is unknown.

use crate::claim::ScopedReadActorKey;
use crate::receipt::ReceiptRecord;
use crate::runtime_hooks::store::{self, RunKey};
use crate::side_table::{RoutedDbs, SideTableDbs};
use crate::{EntityId, Result, Vault};

use super::{HooksTarget, SessionHooks};

impl SessionHooks<'_> {
    /// The Hook receipts this call's room staged itself, newest first, at
    /// most `limit`, each with its source rows. A receipt is listed only
    /// when `reader`, on the room's view, reads every source row. The
    /// in-memory keep, and a call with no reader, list none.
    ///
    /// # Errors
    ///
    /// The room's read refusals and storage errors.
    pub(in crate::runtime_hooks::verb) fn room_hook_receipts(
        &self,
        vault: &Vault,
        reader: Option<&ScopedReadActorKey>,
        limit: usize,
    ) -> Result<Vec<(ReceiptRecord, Vec<EntityId>)>> {
        let (HooksTarget::Room { session, .. }, Some(reader)) = (&self.target, reader) else {
            return Ok(Vec::new());
        };
        session.routed_side_read(|rtxn, dbs| {
            let RoutedDbs::Session(view) = dbs else {
                return Ok(Vec::new());
            };
            let Some(staged) = dbs.side_vault_meta().staged_rows() else {
                return Ok(Vec::new());
            };
            let prefix = crate::side_table::HOOKS_RECEIPT.prefix;
            let lane = vault.scoped_read_in_session(reader.clone(), view);
            let mut listed = Vec::new();
            for (row_key, value) in staged.rows {
                let (Some(run_key), Some(_)) = (row_key.strip_prefix(prefix), value) else {
                    continue;
                };
                let Ok(key) = RunKey::try_from(run_key) else {
                    continue;
                };
                let Some(receipt) = store::RECEIPTS.get(&dbs, rtxn, &key)? else {
                    continue;
                };
                let Some(sources) = store::hook_verb_run_source_rows_in(&dbs, rtxn, &key)? else {
                    continue;
                };
                let mut shown = true;
                for row in &sources {
                    if !lane.is_entity_readable_in(rtxn, row)? {
                        shown = false;
                        break;
                    }
                }
                if shown {
                    listed.push((receipt, sources));
                }
            }
            listed.sort_by(|(left, _), (right, _)| {
                crate::store::receipt_row::receipt_newest_first_order(left, right)
            });
            listed.truncate(limit);
            Ok(listed)
        })
    }
}
