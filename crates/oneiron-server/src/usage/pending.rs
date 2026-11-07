//! Durable redelivery of the same frozen automatic settlement (FIX 737).
use super::codec::{UsageError, decode_entry};
use super::keys::{
    settlement_pending_key, settlement_pending_prefix, usage_event_key, validate_key,
};
use super::ledger::{StoredUsageEvent, UsageLedger};

impl UsageLedger {
    /// Commits pending custody before the final ledger write. An existing event
    /// or pending row keeps its first payload; only event + source define replay.
    pub(crate) fn stage_settlement(&self, raw: &[u8]) -> Result<(), UsageError> {
        let stored = decode_entry(raw)?;
        stored.event.validate()?;
        let pending_key = pending_key(&stored)?;
        let event_key = usage_event_key(
            &stored.event.owner,
            &stored.event.vault_id,
            &stored.event.idempotency_key,
        );
        self.vault.try_with_write_txn_grouped(|txn| {
            if let Some(first) = self.vault.sync_state_get_in_write_txn(txn, &event_key)? {
                return same_settlement(&decode_entry(&first)?, &stored);
            }
            if let Some(first) = self.vault.sync_state_get_in_write_txn(txn, &pending_key)? {
                return same_settlement(&decode_entry(&first)?, &stored);
            }
            let live = self
                .vault
                .usage_event_with_live_sources_in_write_txn(txn, raw)?;
            self.vault
                .sync_state_put_in_write_txn(txn, &pending_key, &live)?;
            Ok(())
        })
    }

    /// The pending row, final event and rollup marker share the SAME writer.
    /// A concurrent delivery may have removed pending only after recording it.
    pub(crate) fn record_staged_settlement(
        &self,
        raw: &[u8],
    ) -> Result<super::UsageRecordResult, UsageError> {
        let expected = decode_entry(raw)?;
        let key = pending_key(&expected)?;
        let (owner, vault_id, written) = self.vault.try_with_write_txn_grouped(|txn| {
            let queued = self.vault.sync_state_get_in_write_txn(txn, &key)?;
            let queued = queued.as_deref().map(decode_entry).transpose()?;
            let stored = queued.as_ref().unwrap_or(&expected);
            same_settlement(stored, &expected)?;
            let written = self.record_stored_in_txn(txn, stored)?;
            self.vault.sync_state_delete_in_write_txn(txn, &key)?;
            Ok::<_, UsageError>((
                stored.event.owner.clone(),
                stored.event.vault_id.clone(),
                written,
            ))
        })?;
        Ok(self.record_result(&owner, &vault_id, written))
    }

    /// One lexical page for this vault, including every frozen billing owner.
    /// The cursor advances past retained faults and wraps at the prefix end.
    /// No read cursor or caller lock survives into the grouped write.
    pub(crate) fn drain_settlement_page(
        &self,
        vault_id: &str,
        after: &mut Option<String>,
        limit: usize,
    ) -> Result<(), UsageError> {
        let mut keys = Vec::new();
        let next = self.vault.sync_state_prefix_page(
            &settlement_pending_prefix(vault_id),
            after.as_deref(),
            limit,
            |key, _| {
                keys.push(key.to_owned());
                Ok(())
            },
        )?;
        *after = next;
        if keys.is_empty() {
            return Ok(());
        }
        let written = self.vault.try_with_write_txn_grouped(|txn| {
            let mut written = Vec::new();
            for key in &keys {
                let Some(raw) = self.vault.sync_state_get_in_write_txn(txn, key)? else {
                    continue;
                };
                let stored = match decode_pending(key, &raw, vault_id) {
                    Ok(stored) => stored,
                    Err(error) => {
                        tracing::warn!(%key, ?error, "a pending usage settlement needs repair; its bytes remain");
                        continue;
                    }
                };
                let result = match self.record_stored_in_txn(txn, &stored) {
                    Ok(result) => result,
                    Err(UsageError::IdempotencyConflict) => {
                        tracing::warn!(%key, "pending usage conflicts with the first event; both remain for repair");
                        continue;
                    }
                    Err(error @ UsageError::Decode(_)) => {
                        // The existing event is decoded before the first put.
                        // Storage and any error after a put still abort the batch.
                        tracing::warn!(%key, ?error, "an existing usage event needs repair; its pending settlement remains");
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                self.vault.sync_state_delete_in_write_txn(txn, key)?;
                written.push((stored.event.owner, stored.event.vault_id, result));
            }
            Ok::<_, UsageError>(written)
        })?;
        // A rollup failure never rolls back the already durable events.
        for (owner, vault_id, result) in written {
            self.record_result(&owner, &vault_id, result);
        }
        Ok(())
    }
}

/// The same validity check used by redelivery and a reviewed pending repair.
pub(super) fn decode_pending(
    key: &str,
    raw: &[u8],
    vault_id: &str,
) -> Result<StoredUsageEvent, UsageError> {
    let stored = decode_entry(raw)?;
    stored.event.validate()?;
    if stored.event.vault_id != vault_id || pending_key(&stored)? != key {
        return Err(oneiron::Error::CorruptedIndex("pending usage scope").into());
    }
    Ok(stored)
}

fn pending_key(stored: &StoredUsageEvent) -> Result<String, UsageError> {
    let key = settlement_pending_key(
        &stored.event.owner,
        &stored.event.vault_id,
        &stored.event.idempotency_key,
    );
    validate_key(&key)?;
    Ok(key)
}

fn same_settlement(
    first: &StoredUsageEvent,
    expected: &StoredUsageEvent,
) -> Result<(), UsageError> {
    if first.event != expected.event || first.source != expected.source {
        return Err(UsageError::IdempotencyConflict);
    }
    Ok(())
}
