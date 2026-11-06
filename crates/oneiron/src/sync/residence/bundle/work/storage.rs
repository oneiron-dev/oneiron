//! Physical cleanup and disk inventory for the durable bundle-work record.
use super::*;
use crate::sync::residence::{bundle_stage::SealedBundleStaged, sealed_digest_from_hex};

/// Removes one obsolete physical part, with its cleanup progress in the same
/// writer. This requires no caller authority because it only pays a deletion
/// already owed by a terminal outcome; pending source bytes are never swept.
pub fn cleanup_sealed_bundle_work(vault: &Vault) -> Result<bool> {
    cleanup_one(vault, None)
}

pub(super) fn cleanup_one(vault: &Vault, only: Option<[u8; 32]>) -> Result<bool> {
    vault.with_write_txn_grouped(|txn| {
        let mut selected = None;
        let prefix = only
            .as_ref()
            .map_or_else(|| WORK_PREFIX.to_owned(), work_key);
        for row in WORK.iter_raw_from(&vault.store, txn, prefix.as_bytes())? {
            let (key, raw) = row?;
            let record: Record = serde_json::from_slice(&raw).map_err(|_| Error::InvalidKey)?;
            if record.terminal() && !record.cleanup_done {
                let key = std::str::from_utf8(&key).map_err(|_| Error::InvalidKey)?;
                let id =
                    sealed_digest_from_hex(key.strip_prefix(WORK_PREFIX).ok_or(Error::InvalidKey)?)
                        .ok_or(Error::InvalidKey)?;
                selected = Some((id, record));
                break;
            }
        }
        let Some((id, mut record)) = selected else {
            return Ok(false);
        };
        for index in 0..2 {
            let prefix = stage_parts_prefix(&stage_identity(&record.sources[index].header)?);
            let first = STAGE_PARTS
                .iter_raw_from(&vault.store, txn, prefix.as_bytes())?
                .next()
                .transpose()?;
            if let Some((key, value)) = first {
                STAGE_PARTS.delete(
                    &vault.store,
                    txn,
                    &String::from_utf8(key).map_err(|_| Error::InvalidKey)?,
                )?;
                record.sources[index].cleaned = record.sources[index]
                    .cleaned
                    .saturating_add(value.len() as u64);
                save_in(vault, txn, &id, &record)?;
                return Ok(true);
            }
        }
        if record.phase != Phase::Committed && owns_in(vault, txn, &id, &record)? {
            let generation = record.input()?.generation;
            let prefix = format!("{}:", sealed_generation_hex(&generation));
            let first = PARTS
                .iter_raw_from(&vault.store, txn, prefix.as_bytes())?
                .next()
                .transpose()?;
            if let Some((key, value)) = first {
                let key = String::from_utf8(key).map_err(|_| Error::InvalidKey)?;
                let index = usize::from(key.split(':').nth(1) == Some("k"));
                PARTS.delete(&vault.store, txn, &key)?;
                record.prepared[index] = record.prepared[index].saturating_sub(value.len() as u64);
                save_in(vault, txn, &id, &record)?;
                return Ok(true);
            }
            WORK.delete(&vault.store, txn, &reservation_key(&generation))?;
        }
        for source in &record.sources {
            super::super::stage_parts::release_identity(
                vault,
                txn,
                &stage_identity(&source.header)?,
            )?;
        }
        record.cleanup_done = true;
        save_in(vault, txn, &id, &record)?;
        Ok(true)
    })
}

/// Work-owned source and destination bytes, including terminal cleanup, for
/// the host's existing disk-floor ledger. Nothing pending has an idle expiry.
pub(in crate::sync::residence::bundle) fn stages_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<SealedBundleStaged>> {
    let mut stages = Vec::new();
    for row in WORK.iter_raw_from(&vault.store, txn, WORK_PREFIX.as_bytes())? {
        let (key, raw) = row?;
        let record: Record = serde_json::from_slice(&raw).map_err(|_| Error::InvalidKey)?;
        if record.cleanup_done {
            continue;
        }
        let key = std::str::from_utf8(&key).map_err(|_| Error::InvalidKey)?;
        let id = sealed_digest_from_hex(key.strip_prefix(WORK_PREFIX).ok_or(Error::InvalidKey)?)
            .ok_or(Error::InvalidKey)?;
        for index in 0..2 {
            let stage = record.stage(index)?;
            stages.push(SealedBundleStaged {
                machine: record.executor,
                object: object(index),
                total: stage.total,
                staged: stage.total.saturating_sub(record.sources[index].cleaned),
                work_id: Some(id),
                prepared: record.prepared[index],
                terminal: record.terminal(),
            });
        }
    }
    Ok(stages)
}
