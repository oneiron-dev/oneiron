//! The in-memory keep's records and paused calls ([`SessionHookKeep`]):
//! staging and reading one call's records, dropping a session's, and the
//! paused calls a retry reads, uses up, re-opens and a prune forgets.

use std::sync::{Arc, PoisonError};

use super::{HookRecordsKept, SessionHookKeep, SessionHookKey, SessionVerbAsk};
use crate::code_run::SessionHookNotKept;
use crate::session_overlay::TxnSegmentGuard;
use crate::side_table::RoutedDbs;
use crate::{EntityId, Result, Vault};

impl SessionHookKeep {
    /// Stages one call's records under `key`: `rows` reads through the
    /// keep's composed view and puts or deletes in it, in one segment. A key
    /// whose session closed meanwhile keeps none of them.
    ///
    /// # Errors
    ///
    /// Storage errors; a keep that refuses the segment answers
    /// [`HookRecordsKept::NotKept`] instead.
    pub(crate) fn stage(
        &self,
        vault: &Vault,
        key: &SessionHookKey,
        rows: impl FnOnce(&mut heed::RwTxn<'_>, RoutedDbs<'_>, RoutedDbs<'_>) -> Result<()>,
    ) -> Result<HookRecordsKept> {
        let Some(overlay) = self.with_live(vault, key, |kept| Arc::clone(&kept.overlay)) else {
            return Ok(HookRecordsKept::NotKept(SessionHookNotKept::NoRetention));
        };
        HookRecordsKept::of(vault.with_write_txn_grouped_after_commit(
            |wtxn| {
                let segment = overlay.install_txn_segment()?;
                let view = vault.store.session_view(Arc::clone(&overlay))?;
                rows(wtxn, RoutedDbs::Session(&view), RoutedDbs::Session(&view))?;
                Ok(segment)
            },
            TxnSegmentGuard::commit,
        ))
    }

    /// Reads `key`'s kept records through the keep's composed view; `None`
    /// while it keeps none.
    #[expect(
        dead_code,
        reason = "a projector of a session's kept hook records reads them here; none does yet"
    )]
    pub(crate) fn read<T>(
        &self,
        vault: &Vault,
        key: &SessionHookKey,
        f: impl FnOnce(&heed::RoTxn<'_>, RoutedDbs<'_>) -> Result<T>,
    ) -> Result<Option<T>> {
        let Some(overlay) = self
            .kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .map(|kept| Arc::clone(&kept.overlay))
        else {
            return Ok(None);
        };
        let view = vault.store.session_view(overlay)?;
        let rtxn = vault.store.env.read_txn()?;
        f(&rtxn, RoutedDbs::Session(&view)).map(Some)
    }

    /// Drops every record and paused call kept under `key`, as its session
    /// ends: nothing resumes a call it paused.
    pub(crate) fn drop_session(&self, key: &SessionHookKey) {
        self.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
    }

    /// The call `invocation`'s hook ask paused under `key`, if this process
    /// holds one.
    pub(in crate::runtime_hooks::verb) fn ask(
        &self,
        key: &SessionHookKey,
        invocation: [u8; 16],
    ) -> Option<SessionVerbAsk> {
        self.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .and_then(|kept| kept.asks.get(&invocation))
            .map(|row| row.ask.clone())
    }

    /// Uses ask `ask`'s proceed answer up for `invocation` under `key`,
    /// once: false when no unused call of that ask stands there (used
    /// already, a newer ask's call, or its session gone).
    pub(in crate::runtime_hooks::verb) fn use_ask(
        &self,
        vault: &Vault,
        key: &SessionHookKey,
        invocation: [u8; 16],
        ask: EntityId,
    ) -> bool {
        let now = vault.store.clock.now_recorded_at();
        let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        match kept
            .get_mut(key)
            .and_then(|kept| kept.asks.get_mut(&invocation))
        {
            Some(row) if row.ask.ask == ask && !row.ask.used => {
                row.ask.used = true;
                row.used_at = Some(now);
                true
            }
            _ => false,
        }
    }

    /// Clears the used mark `use_ask` set (FIX 1431), under the same guard:
    /// false when no used call of that ask stands there. `used_at` clears
    /// with it so the prune horizon keeps the re-opened pause.
    pub(in crate::runtime_hooks::verb) fn unuse_ask(
        &self,
        key: &SessionHookKey,
        invocation: [u8; 16],
        ask: EntityId,
    ) -> bool {
        let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        match kept
            .get_mut(key)
            .and_then(|kept| kept.asks.get_mut(&invocation))
        {
            Some(row) if row.ask.ask == ask && row.ask.used => {
                row.ask.used = false;
                row.used_at = None;
                true
            }
            _ => false,
        }
    }

    /// Forgets the paused calls `cutoff` (vault-clock seconds) left behind,
    /// as the drain's pass forgets saved ones (`ask::prune`, FIX 5528): a
    /// used one used before it, and an unused one paused before it whose ask
    /// `declined` reads as settled without a proceed. A pending pause and an
    /// approved one not yet used stay, whatever their age; nothing is
    /// forgotten on a count or a size. `declined` runs outside the keep's
    /// lock, as its read may settle a lapsed ask in a vault write. A retry
    /// that names a forgotten pause reads it gone, as after its session
    /// ended. Returns how many it forgot.
    pub(in crate::runtime_hooks::verb) fn prune(
        &self,
        cutoff: u64,
        declined: impl Fn(&SessionVerbAsk) -> bool,
    ) -> usize {
        let mut forgot = 0;
        let mut unsettled = Vec::new();
        {
            let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
            for (key, held) in kept.iter_mut() {
                held.asks.retain(|invocation, row| {
                    if row.used_at.is_some_and(|used_at| used_at < cutoff) {
                        forgot += 1;
                        return false;
                    }
                    if !row.ask.used && row.paused_at < cutoff {
                        unsettled.push((key.clone(), *invocation, row.ask.clone()));
                    }
                    true
                });
            }
        }
        let declined: Vec<_> = unsettled
            .into_iter()
            .filter(|(_, _, row)| declined(row))
            .collect();
        if declined.is_empty() {
            return forgot;
        }
        let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        for (key, invocation, row) in declined {
            let Some(asks) = kept.get_mut(&key).map(|held| &mut held.asks) else {
                continue;
            };
            if asks.get(&invocation).is_some_and(|now| {
                now.ask.ask == row.ask && !now.ask.used && now.paused_at < cutoff
            }) {
                asks.remove(&invocation);
                forgot += 1;
            }
        }
        forgot
    }
}
