//! A session-only call's chain commit (FIX 4283): what [`Chain::commit`]
//! hands the session's hook store in place of the vault's write. The rows
//! are the ones [`Chain::write_in_txn`] would write, each as the vault would
//! hold it; none of them reaches the vault.

use crate::Result;
use crate::off_record::session_hooks::SessionHookRow;
use crate::runtime_hooks::verb::ask;
use crate::runtime_hooks::verb::record::VERB_RUNS;
use crate::runtime_hooks::{block, lineage, store};
use crate::side_table::{SideCodec, SideKey, SideTable};
use crate::task_verb::verb_hook_boundary::HookSession;

use super::Chain;

impl Chain<'_> {
    /// Hands the chain's receipts, saved runs, blocks with their lineage and
    /// intents to `session`'s store, after a resumed chain uses its answer
    /// up there: its token names an ask only the session holds, so the
    /// session's store is where it is used, once. One used meanwhile keeps
    /// nothing, as a write that fails on it commits nothing.
    pub(super) fn commit_in_session(&self, session: &HookSession) -> Result<()> {
        let vault = self.vault;
        if let Some(token) = &self.token
            && !ask::in_session::use_answer(vault, session, token)
        {
            self.used.set(true);
            return Err(ask::used_error());
        }
        let at = vault.store.clock.now_recorded_at().saturating_mul(1_000);
        let mut rows = Vec::new();
        for run in &self.runs {
            rows.push(row(&store::RECEIPTS, &run.key, &self.receipt(run), true)?);
            rows.push(row(&VERB_RUNS, &run.key, &self.saved(run, at), true)?);
        }
        for (id, hook_block, links) in &self.blocks {
            rows.push(written_once(block::block_row(*id, hook_block)?));
            rows.push(written_once(lineage::lineage_row(id.as_bytes(), links)?));
        }
        for (key, intent, proposal) in &self.intents {
            if let Some(id) = proposal {
                rows.push(written_once(lineage::lineage_row(
                    id.as_bytes(),
                    &intent.lineage,
                )?));
            }
            rows.push(row(&store::INTENTS, key, intent, false)?);
        }
        vault.verb_hook_state.session.stage(vault, &session.0, rows);
        Ok(())
    }
}

/// `value` under `key` in `table`, as the vault would hold it.
fn row<K: SideKey, V, C: SideCodec<V>>(
    table: &SideTable<K, V, C>,
    key: &K,
    value: &V,
    replaces: bool,
) -> Result<SessionHookRow> {
    Ok(SessionHookRow {
        key: table.key_bytes(key),
        value: table.encode_value(value)?,
        replaces,
    })
}

/// A row a retried call writes once, its first write standing.
fn written_once((key, value): (Vec<u8>, Vec<u8>)) -> SessionHookRow {
    SessionHookRow {
        key,
        value,
        replaces: false,
    }
}
