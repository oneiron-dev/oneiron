//! The derived per-vault rollup, kept from the stamped events. A recorded
//! call never waits on it (FIX 6407): the event's own write only marks the
//! cached rollup behind it, and a later write brings it up to date.
use super::{
    codec::*,
    keys::*,
    ledger::{StoredUsageEvent, UsageLedger},
    model::*,
};
use serde::{Deserialize, Serialize};

/// The cached rollup as stored.
#[derive(Debug, Serialize, Deserialize)]
pub(super) enum CachedRollup {
    /// Sums every recorded call, or says a sum overflowed.
    Folded(UsageRollup),
    /// Sums every recorded call but the one under `event_key`, written after
    /// it was cached.
    Behind {
        rollup: UsageRollup,
        event_key: String,
    },
    /// Sums an unknown part of the calls: rebuilt from them on the next read.
    Stale,
}

/// Marks the cached rollup as not summing the event just written under
/// `event_key`, in that event's own write, so it is never read stale. A
/// cache that sums every call is left one behind, folded on the next read;
/// one already behind turns stale. No cache, one that does not decode and
/// one that overflowed need no mark: the first two are rebuilt on read, and
/// more calls only add to a sum that overflowed.
pub(super) fn mark_rollup_behind_in_txn(
    vault: &oneiron::Vault,
    txn: &mut heed::RwTxn<'_>,
    rollup_key: &str,
    event_key: &str,
) -> Result<(), UsageError> {
    let Some(raw) = vault.sync_state_get_in_write_txn(txn, rollup_key)? else {
        return Ok(());
    };
    let marked = match decode_rollup(&raw) {
        Ok(CachedRollup::Folded(rollup)) if rollup.status == UsageRollupStatus::Current => {
            CachedRollup::Behind {
                rollup,
                event_key: event_key.to_owned(),
            }
        }
        Ok(CachedRollup::Behind { .. }) => CachedRollup::Stale,
        Ok(CachedRollup::Folded(_) | CachedRollup::Stale) | Err(_) => return Ok(()),
    };
    vault.sync_state_put_in_write_txn(txn, rollup_key, &encode_rollup(&marked)?)?;
    Ok(())
}

impl UsageLedger {
    /// Checks that `owner` and `vault_id` name a usage scope whose keys fit.
    pub(crate) fn validate_scope(owner: &str, vault_id: &str) -> Result<(), UsageError> {
        validate_dimension("owner", owner, MAX_DIMENSION_LEN)?;
        validate_dimension("vaultId", vault_id, MAX_DIMENSION_LEN)?;
        validate_key(&vault_rollup_key(owner, vault_id))
    }

    /// The vault's rollup of its recorded calls, `None` before the first. A
    /// cache that sums them is read as it is; one a recorded call left
    /// behind, a stale one, and one that does not decode are brought up to
    /// date from the stamped events first. A sum that would pass what a
    /// counter holds marks the rollup and never fails the read; a stored
    /// event that does not decode or names another scope fails it.
    pub fn vault_rollup(
        &self,
        owner: &str,
        vault_id: &str,
    ) -> Result<Option<UsageRollup>, UsageError> {
        Self::validate_scope(owner, vault_id)?;
        let key = vault_rollup_key(owner, vault_id);
        if let Some(raw) = self.vault.sync_state_get(&key)?
            && let Ok(CachedRollup::Folded(rollup)) = decode_rollup(&raw)
        {
            return Ok(Some(rollup));
        }
        self.vault
            .try_with_write_txn_grouped(|txn| -> Result<_, UsageError> {
                let cached = self
                    .vault
                    .sync_state_get_in_write_txn(txn, &key)?
                    .and_then(|raw| decode_rollup(&raw).ok());
                let rollup = match cached {
                    Some(CachedRollup::Folded(rollup)) => return Ok(Some(rollup)),
                    Some(CachedRollup::Behind {
                        mut rollup,
                        event_key,
                    }) => match self.vault.sync_state_get_in_write_txn(txn, &event_key)? {
                        Some(raw) => {
                            fold(
                                &mut rollup,
                                &checked_event(owner, vault_id, &event_key, &raw)?,
                            );
                            Some(rollup)
                        }
                        None => self.rebuild_rollup_in_txn(txn, owner, vault_id)?,
                    },
                    Some(CachedRollup::Stale) | None => {
                        self.rebuild_rollup_in_txn(txn, owner, vault_id)?
                    }
                };
                if let Some(rollup) = &rollup {
                    self.vault.sync_state_put_in_write_txn(
                        txn,
                        &key,
                        &encode_rollup(&CachedRollup::Folded(rollup.clone()))?,
                    )?;
                }
                Ok(rollup)
            })
    }

    /// The rollup a write of one call returns, brought up to date after that
    /// write committed. It never fails the write: a rollup that cannot be
    /// read is logged and returned as unavailable.
    pub(super) fn rollup_after_write(
        &self,
        owner: &str,
        vault_id: &str,
    ) -> (Option<UsageRollup>, UsageRollupStatus) {
        match self.vault_rollup(owner, vault_id) {
            Ok(rollup) => {
                let status = rollup
                    .as_ref()
                    .map_or(UsageRollupStatus::Unavailable, |rollup| rollup.status);
                (rollup, status)
            }
            Err(error) => {
                tracing::warn!(
                    vault_id = %vault_id,
                    ?error,
                    "a vault usage rollup could not be brought up to date; the call is recorded"
                );
                (None, UsageRollupStatus::Unavailable)
            }
        }
    }

    /// The rollup rebuilt from every stored event of the scope, read under
    /// the caller's write; `None` when there is none.
    fn rebuild_rollup_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        owner: &str,
        vault_id: &str,
    ) -> Result<Option<UsageRollup>, UsageError> {
        let mut rollup = None;
        self.vault.sync_state_visit_prefix_in_write_txn(
            txn,
            &usage_event_prefix(owner, vault_id),
            |key, raw| -> Result<(), UsageError> {
                let stored = checked_event(owner, vault_id, key, raw)?;
                fold(
                    rollup.get_or_insert_with(|| UsageRollup::vault(owner, vault_id)),
                    &stored,
                );
                Ok(())
            },
        )?;
        Ok(rollup)
    }
}

/// One stored event of the scope, as a rollup reads it: it decodes,
/// validates, and sits under its own key.
fn checked_event(
    owner: &str,
    vault: &str,
    key: &str,
    raw: &[u8],
) -> Result<StoredUsageEvent, UsageError> {
    let stored = decode_entry(raw)?;
    stored.event.validate()?;
    if let Some(cost) = &stored.cost {
        cost.validate()?;
    }
    if stored.event.owner != owner
        || stored.event.vault_id != vault
        || usage_event_key(owner, vault, &stored.event.idempotency_key) != key
    {
        return Err(oneiron::Error::CorruptedIndex("usage event scope").into());
    }
    Ok(stored)
}

/// Adds one checked event to `rollup` at its stamped money, never today's
/// rate table. A sum that would pass what a counter holds leaves the
/// counters as they were and marks the rollup, which then takes no more
/// calls.
fn fold(rollup: &mut UsageRollup, stored: &StoredUsageEvent) {
    if rollup.status != UsageRollupStatus::Current {
        return;
    }
    if rollup
        .add_event(&stored.event, stored.cost.as_ref())
        .is_err()
    {
        rollup.status = UsageRollupStatus::ArithmeticOverflow;
        tracing::warn!(
            vault_id = %rollup.vault_id,
            "a vault usage rollup sum would overflow; it counts the calls before that one"
        );
    }
}
